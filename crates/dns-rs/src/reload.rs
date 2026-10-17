//! Applies configuration and blocklist changes while dns-rs runs.
//!
//! Only `[blocking]` changes apply live; settings that set up sockets, the
//! upstream client or the cache are reported as needing a restart.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};

use crate::blocking::Policy;
use crate::config::ListConfig;
use crate::config::{BlockingConfig, Config, ConfigError, LocalConfig};
use crate::handler::Handler;
use crate::http::ApiTokenSlot;
use crate::metrics::{Metrics, ReloadResult};
use crate::sources::{FetchError, ListLoader, ListResult, ListStore};
use crate::status::Status;
use crate::upstream::Upstream;

/// What reading the API token file again did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenChange {
    /// Same token, or no token file to read.
    Unchanged,
    /// The new token is in force.
    Rotated,
    /// The file is missing or holds an invalid token; the previous token
    /// stays in force.
    Rejected(String),
}

/// What a configuration reload did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigChange {
    /// The configuration is the same as the last one seen.
    Unchanged,
    /// The new live settings (`[blocking]`, `[local]`) are in force. Settings listed in
    /// `restart_required` changed too but were not applied.
    Applied { restart_required: Vec<&'static str> },
    /// The new configuration is invalid or unreadable; the previous one
    /// stays in force.
    Rejected(String),
}

/// How often the configuration file is read again. Kubernetes updates a
/// mounted `ConfigMap` within about a minute, so a few seconds is plenty.
pub const CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(10);

type Lookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

pub struct Reloader<U> {
    handler: Arc<Handler<U>>,
    metrics: Arc<Metrics>,
    status: Arc<Status>,
    loader: ListLoader,
    lookup: Lookup,
    /// In force: restart-only settings keep their startup values.
    active: Config,
    /// The last valid configuration read, to report each change once.
    last_seen: Config,
    /// The last rejection logged, to log a broken file once, not every poll.
    last_rejection: Option<String>,
    store: ListStore,
    api_token: Option<ApiTokenSlot>,
    /// The last token rejection logged, to log a broken file once.
    last_token_rejection: Option<String>,
}

impl<U: Upstream> Reloader<U> {
    /// Also keeps `slot` in step with the API token file, if one is set.
    #[must_use]
    pub fn with_api_token(mut self, slot: ApiTokenSlot) -> Self {
        self.api_token = Some(slot);
        self
    }

    /// Reads the API token again: a rotated Secret, mounted as a file,
    /// reaches every replica without a restart.
    pub async fn reload_api_token(&mut self) -> TokenChange {
        let Some(slot) = &self.api_token else {
            return TokenChange::Unchanged;
        };
        let (config, lookup) = (self.active.clone(), Arc::clone(&self.lookup));
        // File I/O off the runtime threads, as for the configuration.
        let read = tokio::task::spawn_blocking(move || {
            config
                .api_token(lookup.as_ref())
                .map_err(|error| error.to_string())
        })
        .await
        .unwrap_or_else(|error| Err(format!("reading the API token failed: {error}")));
        let token = match read {
            Ok(token) => token,
            Err(reason) => {
                if self.last_token_rejection.as_ref() != Some(&reason) {
                    // The message names the source, never the token.
                    tracing::error!(error = %reason, "API token rejected, keeping the previous one");
                    self.last_token_rejection = Some(reason.clone());
                }
                return TokenChange::Rejected(reason);
            }
        };
        self.last_token_rejection = None;
        if token.is_none() || **slot.load() == token {
            return TokenChange::Unchanged;
        }
        slot.store(Arc::new(token));
        tracing::info!("API token rotated");
        TokenChange::Rotated
    }

    /// Loads the blocklists of `config` and installs the first policy.
    /// `lookup` reads environment variables, as [`Config::load`] does.
    pub async fn start(
        handler: Arc<Handler<U>>,
        metrics: Arc<Metrics>,
        status: Arc<Status>,
        loader: ListLoader,
        config: Config,
        lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Result<Self, ConfigError> {
        let mut store = ListStore::default();
        status.set_lists(&config.blocking.lists);
        let results = loader.load_each(&config.blocking.lists).await;
        record_lists(&metrics, &status, &outcomes(&results));
        store.update(results);
        let policy = build_policy(&config.blocking, &store).await?;
        install(&handler, &metrics, &status, policy);
        install_local(&handler, &config.local);
        Ok(Self {
            handler,
            metrics,
            status,
            loader,
            lookup: Arc::new(lookup),
            active: config.clone(),
            last_seen: config,
            last_rejection: None,
            store,
            api_token: None,
            last_token_rejection: None,
        })
    }

    /// The configuration in force.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.active
    }

    /// Reads the configuration again and applies its blocking settings.
    pub async fn reload_config(&mut self) -> ConfigChange {
        // File I/O off the runtime threads: a slow volume must not stall them.
        let lookup = Arc::clone(&self.lookup);
        let next = match tokio::task::spawn_blocking(move || Config::load(lookup.as_ref())).await {
            Ok(Ok(next)) => next,
            Ok(Err(error)) => return self.reject(error.to_string()),
            Err(error) => return self.reject(format!("reading the configuration failed: {error}")),
        };
        self.last_rejection = None;
        // Valid again, even if identical to the last configuration seen.
        self.metrics.set_config_valid(true);
        self.status.set_config_valid(true);
        if next == self.last_seen {
            return ConfigChange::Unchanged;
        }

        let restart_required = self.active.restart_required(&next);
        if !restart_required.is_empty() {
            tracing::warn!(settings = ?restart_required, "configuration changes need a restart to apply");
        }
        if next.blocking != self.active.blocking {
            // Lists already loaded are kept as they are: only new ones are
            // downloaded now; all are downloaded again at the next refresh.
            // Work on a copy (cheap: lists are shared): if the new policy
            // cannot be built, the lists of the configuration still in force
            // must keep their last valid versions. Validation already rejects
            // every known cause (including regex sets too large together),
            // so this guards against unknown ones, such as a panic in the
            // build thread; no test can reach it through a configuration.
            let mut store = self.store.clone();
            store.retain(&next.blocking.lists);
            let missing = store.missing(&next.blocking.lists);
            let mut loaded = Vec::new();
            if !missing.is_empty() {
                let results = self.loader.load_each(&missing).await;
                loaded = outcomes(&results);
                store.update(results);
            }
            match build_policy(&next.blocking, &store).await {
                Ok(policy) => {
                    // Metrics and status describe the new lists only once
                    // they are in force.
                    self.status.set_lists(&next.blocking.lists);
                    record_lists(&self.metrics, &self.status, &loaded);
                    install(&self.handler, &self.metrics, &self.status, policy);
                    self.store = store;
                }
                Err(error) => return self.reject(error.to_string()),
            }
            for removed in &self.active.blocking.lists {
                if !next
                    .blocking
                    .lists
                    .iter()
                    .any(|list| list.source == removed.source)
                {
                    self.metrics.forget_list(&removed.source);
                }
            }
            self.active.blocking = next.blocking.clone();
        }
        // After blocking, which can still reject the configuration: nothing
        // of a rejected one is applied.
        if next.local != self.active.local {
            install_local(&self.handler, &next.local);
            self.active.local = next.local.clone();
        }
        self.last_seen = next;
        self.metrics.record_config_reload(ReloadResult::Applied);
        tracing::info!("configuration reloaded");
        ConfigChange::Applied { restart_required }
    }

    /// Downloads every configured list again; a list that fails keeps its
    /// last valid version.
    pub async fn refresh_lists(&mut self) {
        let results = self.loader.load_each(&self.active.blocking.lists).await;
        record_lists(&self.metrics, &self.status, &outcomes(&results));
        self.store.update(results);
        match build_policy(&self.active.blocking, &self.store).await {
            Ok(policy) => install(&self.handler, &self.metrics, &self.status, policy),
            Err(error) => {
                tracing::error!(%error, "cannot rebuild the blocking policy, keeping the previous one");
            }
        }
    }

    /// Runs until `reload_now` is closed: reads the configuration every
    /// `poll` and on each `reload_now` message (SIGHUP in production), and
    /// downloads the lists again every `blocking.refresh`.
    ///
    /// One thing at a time: a reload requested during a long refresh (slow
    /// list servers, up to their timeout) is handled when the refresh ends.
    pub async fn run(mut self, poll: Duration, mut reload_now: mpsc::Receiver<()>) {
        let mut poll_timer = tokio::time::interval(poll);
        poll_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The first tick is immediate: the configuration was just loaded.
        poll_timer.tick().await;
        let mut last_refresh = Instant::now();
        loop {
            // Recomputed each turn, so a new `blocking.refresh` applies at once.
            let next_refresh = last_refresh + self.active.blocking.refresh;
            tokio::select! {
                _ = poll_timer.tick() => {
                    self.reload_config().await;
                    self.reload_api_token().await;
                }
                message = reload_now.recv() => match message {
                    Some(()) => {
                        tracing::info!("reload requested");
                        self.reload_config().await;
                        self.reload_api_token().await;
                    }
                    None => return,
                },
                () = tokio::time::sleep_until(next_refresh) => {
                    tracing::info!("refreshing blocklists");
                    self.refresh_lists().await;
                    last_refresh = Instant::now();
                }
            }
        }
    }

    fn reject(&mut self, reason: String) -> ConfigChange {
        self.metrics.set_config_valid(false);
        self.status.set_config_valid(false);
        if self.last_rejection.as_ref() != Some(&reason) {
            tracing::error!(error = %reason, "configuration rejected, keeping the previous one");
            self.metrics.record_config_reload(ReloadResult::Rejected);
            self.last_rejection = Some(reason.clone());
        }
        ConfigChange::Rejected(reason)
    }
}

fn install_local<U: Upstream>(handler: &Handler<U>, local: &LocalConfig) {
    let records = local.records();
    tracing::info!(names = records.len(), "local records loaded");
    handler.set_local_records(records);
}

fn install<U: Upstream>(handler: &Handler<U>, metrics: &Metrics, status: &Status, policy: Policy) {
    metrics.set_blocking_rules(policy.filter.deny_count());
    status.set_policy(policy.mode, policy.filter.deny_count());
    handler.set_policy(policy);
}

/// What metrics and status need from load results: rule counts or errors,
/// without the lists themselves (cheap to keep until the policy is built).
type Outcome = (ListConfig, Result<usize, FetchError>);

fn outcomes(results: &[(ListConfig, ListResult)]) -> Vec<Outcome> {
    results
        .iter()
        .map(|(config, result)| {
            (
                config.clone(),
                result
                    .as_ref()
                    .map(|list| list.deny.len())
                    .map_err(Clone::clone),
            )
        })
        .collect()
}

fn record_lists(metrics: &Metrics, status: &Status, outcomes: &[Outcome]) {
    for (config, outcome) in outcomes {
        match outcome {
            Ok(rules) => {
                metrics.record_list_loaded(&config.source, *rules);
                status.list_loaded(config, *rules);
            }
            Err(error) => {
                metrics.record_list_failed(&config.source, error);
                status.list_failed(config, error);
            }
        }
    }
}

/// Compiles the policy on a blocking thread: hundreds of thousands of rules
/// take long enough to delay queries if built on a runtime worker.
async fn build_policy(blocking: &BlockingConfig, store: &ListStore) -> Result<Policy, ConfigError> {
    let blocking = blocking.clone();
    let lists = store.snapshot();
    let policy =
        tokio::task::spawn_blocking(move || blocking.policy(lists.iter().map(AsRef::as_ref)))
            .await
            .map_err(|error| ConfigError::Invalid {
                field: "blocking".to_owned(),
                reason: format!("policy build failed: {error}"),
            })??;
    tracing::info!(rules = policy.filter.deny_count(), mode = ?policy.mode, "blocking policy loaded");
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::{Path, PathBuf};

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    use std::time::SystemTime;

    use super::*;
    use crate::cache::DnsCache;
    use crate::handler::Source;
    use crate::sources::Limits;
    use crate::upstream::UpstreamError;

    /// Fails every query: these tests only look at whether a name is blocked.
    struct NoUpstream;

    impl Upstream for NoUpstream {
        fn query(
            &self,
            _query: &Message,
        ) -> impl Future<Output = Result<Message, UpstreamError>> + Send {
            std::future::ready(Err(UpstreamError::Timeout))
        }
    }

    /// A temporary directory holding the config file and list files.
    struct Setup {
        dir: tempfile::TempDir,
        metrics: Arc<Metrics>,
        status: Arc<Status>,
    }

    impl Setup {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
                metrics: Arc::new(
                    Metrics::new()
                        .with_clock(|| SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
                ),
                status: Arc::new(
                    Status::new()
                        .with_clock(|| SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
                ),
            }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        fn write(&self, name: &str, content: &str) {
            let mut file = std::fs::File::create(self.path(name)).unwrap();
            file.write_all(content.as_bytes()).unwrap();
        }

        fn list_url(&self, name: &str) -> String {
            format!("file://{}", self.path(name).display())
        }

        fn config(&self, toml: &str) {
            self.write("dns-rs.toml", toml);
        }

        async fn reloader(&self) -> (Reloader<NoUpstream>, Arc<Handler<NoUpstream>>) {
            self.reloader_with_env(&[]).await
        }

        /// A reloader that also sees the environment variables `env`.
        async fn reloader_with_env(
            &self,
            env: &[(&str, &str)],
        ) -> (Reloader<NoUpstream>, Arc<Handler<NoUpstream>>) {
            let handler = Arc::new(Handler::new(NoUpstream, DnsCache::new(10)));
            let config_path = self.path("dns-rs.toml");
            let env: Vec<(String, String)> = env
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            let lookup = move |var: &str| {
                if var == "DNS_RS_CONFIG" {
                    return Some(config_path.display().to_string());
                }
                env.iter().find(|(k, _)| k == var).map(|(_, v)| v.clone())
            };
            let config = Config::load(&lookup).unwrap();
            let loader = ListLoader::new(Limits::default()).unwrap();
            let reloader = Reloader::start(
                Arc::clone(&handler),
                Arc::clone(&self.metrics),
                Arc::clone(&self.status),
                loader,
                config,
                lookup,
            )
            .await
            .unwrap();
            (reloader, handler)
        }
    }

    async fn blocked(handler: &Handler<NoUpstream>, name: &str) -> bool {
        let mut request = Message::new(1, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        handler.handle(&request).await.source == Source::Blocked
    }

    fn remove(path: &Path) {
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn start_installs_rules_from_config_and_lists() {
        let setup = Setup::new();
        setup.write("list.txt", "listed.example.com\n");
        setup.config(&format!(
            "[blocking]\ndeny = ['denied.example.com']\nlists = ['{}']",
            setup.list_url("list.txt")
        ));

        let (_reloader, handler) = setup.reloader().await;

        assert!(blocked(&handler, "denied.example.com.").await);
        assert!(blocked(&handler, "listed.example.com.").await);
        assert!(!blocked(&handler, "example.com.").await);
    }

    #[tokio::test]
    async fn edited_config_applies_its_rules() {
        let setup = Setup::new();
        setup.config("[blocking]\ndeny = ['a.example.com']");
        let (mut reloader, handler) = setup.reloader().await;

        setup.config("[blocking]\ndeny = ['b.example.com']");
        let change = reloader.reload_config().await;

        assert_eq!(
            change,
            ConfigChange::Applied {
                restart_required: vec![]
            }
        );
        assert!(!blocked(&handler, "a.example.com.").await);
        assert!(blocked(&handler, "b.example.com.").await);
    }

    #[tokio::test]
    async fn same_config_is_unchanged() {
        let setup = Setup::new();
        setup.config("[blocking]\ndeny = ['a.example.com']");
        let (mut reloader, _handler) = setup.reloader().await;

        assert_eq!(reloader.reload_config().await, ConfigChange::Unchanged);
    }

    #[tokio::test]
    async fn invalid_config_is_rejected_and_rules_stay() {
        let setup = Setup::new();
        setup.config("[blocking]\ndeny = ['a.example.com']");
        let (mut reloader, handler) = setup.reloader().await;

        setup.config("[blocking]\ndenny = ['b.example.com']");
        let change = reloader.reload_config().await;

        assert!(
            matches!(&change, ConfigChange::Rejected(reason) if reason.contains("denny")),
            "{change:?}"
        );
        assert!(blocked(&handler, "a.example.com.").await);
    }

    #[tokio::test]
    async fn deleted_config_file_is_rejected_and_rules_stay() {
        let setup = Setup::new();
        setup.config("[blocking]\ndeny = ['a.example.com']");
        let (mut reloader, handler) = setup.reloader().await;

        remove(&setup.path("dns-rs.toml"));
        let change = reloader.reload_config().await;

        assert!(
            matches!(&change, ConfigChange::Rejected(reason) if reason.contains("dns-rs.toml")),
            "{change:?}"
        );
        assert!(blocked(&handler, "a.example.com.").await);
    }

    #[tokio::test]
    async fn restart_only_changes_are_reported_once_and_not_applied() {
        let setup = Setup::new();
        setup.config("[server]\nlisten = '127.0.0.1:5300'");
        let (mut reloader, _handler) = setup.reloader().await;

        setup.config("[server]\nlisten = '127.0.0.1:5400'");
        let first = reloader.reload_config().await;
        let second = reloader.reload_config().await;

        assert_eq!(
            first,
            ConfigChange::Applied {
                restart_required: vec!["server.listen"]
            }
        );
        assert_eq!(second, ConfigChange::Unchanged);
        assert_eq!(
            reloader.config().server.listen,
            "127.0.0.1:5300".parse().unwrap()
        );
    }

    // Each regex compiles alone, but not both in one set: the new policy
    // cannot be built. The lists of the configuration still in force must
    // survive that rejected reload.
    #[tokio::test]
    async fn rejected_reload_keeps_the_lists_in_force() {
        let setup = Setup::new();
        setup.write("list.txt", "listed.example.com\n");
        setup.config(&format!(
            "[blocking]\nlists = ['{}']",
            setup.list_url("list.txt")
        ));
        let (mut reloader, handler) = setup.reloader().await;

        setup.config("[blocking]\ndeny_regex = ['\\w{200}a', '\\w{200}b']");
        let change = reloader.reload_config().await;
        remove(&setup.path("list.txt"));
        reloader.refresh_lists().await;

        assert!(
            matches!(&change, ConfigChange::Rejected(reason) if reason.contains("regex")),
            "{change:?}"
        );
        assert!(blocked(&handler, "listed.example.com.").await);
    }

    #[tokio::test]
    async fn list_added_to_config_is_loaded() {
        let setup = Setup::new();
        setup.write("list.txt", "listed.example.com\n");
        setup.config("");
        let (mut reloader, handler) = setup.reloader().await;

        setup.config(&format!(
            "[blocking]\nlists = ['{}']",
            setup.list_url("list.txt")
        ));
        reloader.reload_config().await;

        assert!(blocked(&handler, "listed.example.com.").await);
    }

    #[tokio::test]
    async fn list_removed_from_config_stops_blocking() {
        let setup = Setup::new();
        setup.write("list.txt", "listed.example.com\n");
        setup.config(&format!(
            "[blocking]\nlists = ['{}']",
            setup.list_url("list.txt")
        ));
        let (mut reloader, handler) = setup.reloader().await;

        setup.config("");
        reloader.reload_config().await;

        assert!(!blocked(&handler, "listed.example.com.").await);
    }

    #[tokio::test]
    async fn refresh_picks_up_new_list_content() {
        let setup = Setup::new();
        setup.write("list.txt", "old.example.com\n");
        setup.config(&format!(
            "[blocking]\nlists = ['{}']",
            setup.list_url("list.txt")
        ));
        let (mut reloader, handler) = setup.reloader().await;

        setup.write("list.txt", "new.example.com\n");
        reloader.refresh_lists().await;

        assert!(!blocked(&handler, "old.example.com.").await);
        assert!(blocked(&handler, "new.example.com.").await);
    }

    #[tokio::test]
    async fn list_failing_on_refresh_keeps_blocking() {
        let setup = Setup::new();
        setup.write("list.txt", "listed.example.com\n");
        setup.config(&format!(
            "[blocking]\nlists = ['{}']",
            setup.list_url("list.txt")
        ));
        let (mut reloader, handler) = setup.reloader().await;

        remove(&setup.path("list.txt"));
        reloader.refresh_lists().await;

        assert!(blocked(&handler, "listed.example.com.").await);
    }

    // A config reload must not download lists that are already loaded: the
    // list changes on disk, and only a refresh may pick that up.
    #[tokio::test]
    async fn config_reload_keeps_loaded_lists_without_downloading_them() {
        let setup = Setup::new();
        setup.write("list.txt", "listed.example.com\n");
        setup.config(&format!(
            "[blocking]\nlists = ['{}']",
            setup.list_url("list.txt")
        ));
        let (mut reloader, handler) = setup.reloader().await;

        setup.write("list.txt", "changed.example.com\n");
        setup.config(&format!(
            "[blocking]\ndeny = ['other.example.com']\nlists = ['{}']",
            setup.list_url("list.txt")
        ));
        let change = reloader.reload_config().await;

        assert_eq!(
            change,
            ConfigChange::Applied {
                restart_required: vec![]
            }
        );
        assert!(blocked(&handler, "other.example.com.").await);
        assert!(blocked(&handler, "listed.example.com.").await);
        assert!(!blocked(&handler, "changed.example.com.").await);
    }

    mod run {
        use super::*;

        /// Starts the loop in the background, polling every 10 s.
        async fn running(setup: &Setup) -> (Arc<Handler<NoUpstream>>, mpsc::Sender<()>) {
            let (reloader, handler) = setup.reloader().await;
            let (reload_now, receiver) = mpsc::channel(1);
            tokio::spawn(reloader.run(Duration::from_secs(10), receiver));
            (handler, reload_now)
        }

        /// Waits (in paused time) until `name` is blocked, at most `limit`.
        async fn blocked_within(
            handler: &Handler<NoUpstream>,
            name: &str,
            limit: Duration,
        ) -> bool {
            let deadline = tokio::time::Instant::now() + limit;
            while tokio::time::Instant::now() < deadline {
                if blocked(handler, name).await {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            false
        }

        #[tokio::test(start_paused = true)]
        async fn config_changes_apply_at_the_next_poll() {
            let setup = Setup::new();
            setup.config("");
            let (handler, _reload_now) = running(&setup).await;

            setup.config("[blocking]\ndeny = ['new.example.com']");

            assert!(!blocked(&handler, "new.example.com.").await);
            assert!(blocked_within(&handler, "new.example.com.", Duration::from_secs(11)).await);
        }

        #[tokio::test(start_paused = true)]
        async fn reload_signal_applies_changes_before_the_next_poll() {
            let setup = Setup::new();
            setup.config("");
            let (handler, reload_now) = running(&setup).await;

            setup.config("[blocking]\ndeny = ['new.example.com']");
            reload_now.send(()).await.unwrap();

            assert!(blocked_within(&handler, "new.example.com.", Duration::from_secs(1)).await);
        }

        #[tokio::test(start_paused = true)]
        async fn lists_are_refreshed_every_refresh_interval() {
            let setup = Setup::new();
            setup.write("list.txt", "old.example.com\n");
            setup.config(&format!(
                "[blocking]\nrefresh = '1m'\nlists = ['{}']",
                setup.list_url("list.txt")
            ));
            let (handler, _reload_now) = running(&setup).await;

            setup.write("list.txt", "new.example.com\n");

            assert!(!blocked_within(&handler, "new.example.com.", Duration::from_secs(50)).await);
            assert!(blocked_within(&handler, "new.example.com.", Duration::from_secs(15)).await);
        }

        #[tokio::test(start_paused = true)]
        async fn refresh_interval_change_takes_effect() {
            let setup = Setup::new();
            setup.write("list.txt", "old.example.com\n");
            let list = setup.list_url("list.txt");
            setup.config(&format!("[blocking]\nrefresh = '24h'\nlists = ['{list}']"));
            let (handler, reload_now) = running(&setup).await;

            setup.config(&format!("[blocking]\nrefresh = '1m'\nlists = ['{list}']"));
            reload_now.send(()).await.unwrap();
            setup.write("list.txt", "new.example.com\n");

            assert!(blocked_within(&handler, "new.example.com.", Duration::from_secs(70)).await);
        }
    }

    mod metrics {
        use super::*;

        fn has(setup: &Setup, series: &str) -> bool {
            setup.metrics.encode().lines().any(|line| line == series)
        }

        fn text(setup: &Setup) -> String {
            setup.metrics.encode()
        }

        fn list_series(setup: &Setup, metric: &str) -> String {
            format!(r#"{metric}{{list="{}"}}"#, setup.list_url("list.txt"))
        }

        #[tokio::test]
        async fn start_exposes_rules_and_lists() {
            let setup = Setup::new();
            setup.write("list.txt", "a.example.com\nb.example.com\n");
            setup.config(&format!(
                "[blocking]\ndeny = ['c.example.com']\nlists = ['{}']",
                setup.list_url("list.txt")
            ));

            let _reloader = setup.reloader().await;

            assert!(has(&setup, "dns_rs_blocking_rules 3"), "{}", text(&setup));
            let rules = format!("{} 2", list_series(&setup, "dns_rs_blocklist_rules"));
            assert!(has(&setup, &rules), "{}", text(&setup));
            let success = format!(
                "{} 1700000000",
                list_series(&setup, "dns_rs_blocklist_last_success_timestamp_seconds")
            );
            assert!(has(&setup, &success), "{}", text(&setup));
        }

        #[tokio::test]
        async fn failed_refresh_is_counted_and_keeps_the_rules_shown() {
            let setup = Setup::new();
            setup.write("list.txt", "a.example.com\n");
            setup.config(&format!(
                "[blocking]\nlists = ['{}']",
                setup.list_url("list.txt")
            ));
            let (mut reloader, _handler) = setup.reloader().await;

            remove(&setup.path("list.txt"));
            reloader.refresh_lists().await;

            let failures = format!(
                r#"dns_rs_blocklist_failures_total{{list="{}",reason="failed"}} 1"#,
                setup.list_url("list.txt")
            );
            assert!(has(&setup, &failures), "{}", text(&setup));
            let rules = format!("{} 1", list_series(&setup, "dns_rs_blocklist_rules"));
            assert!(has(&setup, &rules), "{}", text(&setup));
        }

        #[tokio::test]
        async fn successful_refresh_updates_rules() {
            let setup = Setup::new();
            setup.write("list.txt", "a.example.com\n");
            setup.config(&format!(
                "[blocking]\nlists = ['{}']",
                setup.list_url("list.txt")
            ));
            let (mut reloader, _handler) = setup.reloader().await;

            setup.write("list.txt", "a.example.com\nb.example.com\nc.example.com\n");
            reloader.refresh_lists().await;

            assert!(has(&setup, "dns_rs_blocking_rules 3"), "{}", text(&setup));
            let rules = format!("{} 3", list_series(&setup, "dns_rs_blocklist_rules"));
            assert!(has(&setup, &rules), "{}", text(&setup));
        }

        #[tokio::test]
        async fn removed_list_leaves_no_series() {
            let setup = Setup::new();
            setup.write("list.txt", "a.example.com\n");
            setup.config(&format!(
                "[blocking]\nlists = ['{}']",
                setup.list_url("list.txt")
            ));
            let (mut reloader, _handler) = setup.reloader().await;

            setup.config("");
            reloader.reload_config().await;

            assert!(!text(&setup).contains("list.txt"), "{}", text(&setup));
            assert!(has(&setup, "dns_rs_blocking_rules 0"), "{}", text(&setup));
        }

        #[tokio::test]
        async fn applied_reload_is_counted_and_updates_rules() {
            let setup = Setup::new();
            setup.config("[blocking]\ndeny = ['a.example.com']");
            let (mut reloader, _handler) = setup.reloader().await;

            setup.config("[blocking]\ndeny = ['a.example.com', 'b.example.com']");
            reloader.reload_config().await;

            assert!(
                has(&setup, r#"dns_rs_config_reloads_total{result="applied"} 1"#),
                "{}",
                text(&setup)
            );
            assert!(has(&setup, "dns_rs_blocking_rules 2"), "{}", text(&setup));
        }

        // Polling a broken file every 10 s must not inflate the counter.
        #[tokio::test]
        async fn rejected_config_is_counted_once_and_marked_invalid() {
            let setup = Setup::new();
            setup.config("[blocking]\ndeny = ['a.example.com']");
            let (mut reloader, _handler) = setup.reloader().await;

            setup.config("[blocking]\ndenny = []");
            reloader.reload_config().await;
            reloader.reload_config().await;

            assert!(
                has(
                    &setup,
                    r#"dns_rs_config_reloads_total{result="rejected"} 1"#
                ),
                "{}",
                text(&setup)
            );
            assert!(has(&setup, "dns_rs_config_valid 0"), "{}", text(&setup));
        }

        #[tokio::test]
        async fn fixed_config_is_marked_valid_again() {
            let setup = Setup::new();
            setup.config("[blocking]\ndeny = ['a.example.com']");
            let (mut reloader, _handler) = setup.reloader().await;
            setup.config("[blocking]\ndenny = []");
            reloader.reload_config().await;

            setup.config("[blocking]\ndeny = ['b.example.com']");
            reloader.reload_config().await;

            assert!(has(&setup, "dns_rs_config_valid 1"), "{}", text(&setup));
        }

        // Reverting to the last valid content is "unchanged", yet the file
        // is valid again: the alert must clear.
        #[tokio::test]
        async fn reverted_config_is_marked_valid_again() {
            let setup = Setup::new();
            setup.config("[blocking]\ndeny = ['a.example.com']");
            let (mut reloader, _handler) = setup.reloader().await;
            setup.config("[blocking]\ndenny = []");
            reloader.reload_config().await;

            setup.config("[blocking]\ndeny = ['a.example.com']");
            let change = reloader.reload_config().await;

            assert_eq!(change, ConfigChange::Unchanged);
            assert!(has(&setup, "dns_rs_config_valid 1"), "{}", text(&setup));
        }
    }

    mod status {
        use super::*;
        use crate::blocking::BlockingMode;
        use crate::status::ListFailure;

        #[tokio::test]
        async fn start_reports_policy_and_lists() {
            let setup = Setup::new();
            setup.write("list.txt", "a.example.com\nb.example.com\n");
            setup.config(&format!(
                "[blocking]\nmode = 'refused'\ndeny = ['c.example.com']\nlists = ['{}']",
                setup.list_url("list.txt")
            ));

            let _reloader = setup.reloader().await;

            let report = setup.status.report();
            assert_eq!(report.blocking.rules, 3);
            assert_eq!(report.blocking.mode, BlockingMode::Refused);
            assert_eq!(report.lists.len(), 1);
            assert_eq!(report.lists[0].list, setup.list_url("list.txt"));
            assert_eq!(report.lists[0].rules, Some(2));
            assert_eq!(report.lists[0].last_success, Some(1_700_000_000));
        }

        #[tokio::test]
        async fn failed_refresh_is_reported_next_to_the_last_success() {
            let setup = Setup::new();
            setup.write("list.txt", "a.example.com\n");
            setup.config(&format!(
                "[blocking]\nlists = ['{}']",
                setup.list_url("list.txt")
            ));
            let (mut reloader, _handler) = setup.reloader().await;

            remove(&setup.path("list.txt"));
            reloader.refresh_lists().await;

            let entry = &setup.status.report().lists[0];
            assert_eq!(entry.rules, Some(1));
            assert_eq!(
                entry.last_failure,
                Some(ListFailure {
                    reason: "failed",
                    http_status: None,
                    at: 1_700_000_000
                })
            );
        }

        #[tokio::test]
        async fn reload_reports_the_new_lists() {
            let setup = Setup::new();
            setup.write("a.txt", "a.example.com\n");
            setup.write("b.txt", "b.example.com\n");
            setup.config(&format!(
                "[blocking]\nlists = ['{}']",
                setup.list_url("a.txt")
            ));
            let (mut reloader, _handler) = setup.reloader().await;

            setup.config(&format!(
                "[blocking]\nlists = ['{}']",
                setup.list_url("b.txt")
            ));
            reloader.reload_config().await;

            let report = setup.status.report();
            assert_eq!(report.lists.len(), 1);
            assert_eq!(report.lists[0].list, setup.list_url("b.txt"));
            assert_eq!(report.lists[0].rules, Some(1));
            assert_eq!(report.blocking.rules, 1);
        }

        #[tokio::test]
        async fn invalid_config_is_reported_until_fixed() {
            let setup = Setup::new();
            setup.config("[blocking]\ndeny = ['a.example.com']");
            let (mut reloader, _handler) = setup.reloader().await;

            setup.config("[blocking]\ndenny = []");
            reloader.reload_config().await;
            let broken = setup.status.report().config.valid;
            setup.config("[blocking]\ndeny = ['a.example.com']");
            reloader.reload_config().await;

            assert!(!broken);
            assert!(setup.status.report().config.valid);
        }
    }

    mod api_token {
        use arc_swap::ArcSwap;

        use super::*;

        const OLD: &str = "old-token-0123456789";
        const NEW: &str = "new-token-0123456789";
        const ENV: &str = "env-token-0123456789";

        async fn reloader_with_token(setup: &Setup) -> (Reloader<NoUpstream>, ApiTokenSlot) {
            setup.write("token", OLD);
            setup.config(&format!(
                "[http]\napi_token_file = '{}'",
                setup.path("token").display()
            ));
            let (reloader, _handler) = setup.reloader().await;
            let config = reloader.config().clone();
            let slot: ApiTokenSlot =
                Arc::new(ArcSwap::from_pointee(config.api_token(|_| None).unwrap()));
            (reloader.with_api_token(Arc::clone(&slot)), slot)
        }

        fn current(slot: &ApiTokenSlot) -> Option<String> {
            let token = slot.load();
            [OLD, NEW]
                .into_iter()
                .find(|t| token.as_ref().as_ref().is_some_and(|k| k.matches(t)))
                .map(str::to_owned)
        }

        #[tokio::test]
        async fn rotated_token_file_takes_effect() {
            let setup = Setup::new();
            let (mut reloader, slot) = reloader_with_token(&setup).await;

            setup.write("token", NEW);
            let change = reloader.reload_api_token().await;

            assert_eq!(change, TokenChange::Rotated);
            assert_eq!(current(&slot).as_deref(), Some(NEW));
        }

        // DNS_RS_API_TOKEN wins over the file and is fixed for the process
        // lifetime (ADR 0015): a file rotated next to it changes nothing.
        #[tokio::test]
        async fn environment_token_stays_fixed_when_the_file_changes() {
            let setup = Setup::new();
            setup.write("token", OLD);
            setup.config(&format!(
                "[http]\napi_token_file = '{}'",
                setup.path("token").display()
            ));
            let (reloader, _handler) = setup.reloader_with_env(&[("DNS_RS_API_TOKEN", ENV)]).await;
            let config = reloader.config().clone();
            let slot: ApiTokenSlot = Arc::new(ArcSwap::from_pointee(
                config
                    .api_token(|var| (var == "DNS_RS_API_TOKEN").then(|| ENV.to_owned()))
                    .unwrap(),
            ));
            let mut reloader = reloader.with_api_token(Arc::clone(&slot));

            setup.write("token", NEW);
            let change = reloader.reload_api_token().await;

            assert_eq!(change, TokenChange::Unchanged);
            assert!(
                slot.load()
                    .as_ref()
                    .as_ref()
                    .is_some_and(|t| t.matches(ENV))
            );
        }

        #[tokio::test]
        async fn same_token_is_unchanged() {
            let setup = Setup::new();
            let (mut reloader, slot) = reloader_with_token(&setup).await;

            assert_eq!(reloader.reload_api_token().await, TokenChange::Unchanged);
            assert_eq!(current(&slot).as_deref(), Some(OLD));
        }

        #[tokio::test]
        async fn invalid_rotated_token_keeps_the_previous_one() {
            let setup = Setup::new();
            let (mut reloader, slot) = reloader_with_token(&setup).await;

            setup.write("token", "short");
            let change = reloader.reload_api_token().await;

            assert!(
                matches!(&change, TokenChange::Rejected(reason) if reason.contains("16")),
                // Not the change itself: test output must not echo token data.
                "expected a rejection naming the 16-character minimum"
            );
            assert_eq!(current(&slot).as_deref(), Some(OLD));
        }

        // A Secret being recreated briefly removes the file: keep serving.
        #[tokio::test]
        async fn missing_token_file_keeps_the_previous_token() {
            let setup = Setup::new();
            let (mut reloader, slot) = reloader_with_token(&setup).await;

            remove(&setup.path("token"));
            let change = reloader.reload_api_token().await;

            assert!(
                matches!(change, TokenChange::Rejected(_)),
                "expected rejected token change"
            );
            assert_eq!(current(&slot).as_deref(), Some(OLD));
        }

        #[tokio::test]
        async fn without_a_slot_nothing_is_read() {
            let setup = Setup::new();
            setup.config("");
            let (mut reloader, _handler) = setup.reloader().await;

            assert_eq!(reloader.reload_api_token().await, TokenChange::Unchanged);
        }

        #[tokio::test(start_paused = true)]
        async fn token_is_read_again_at_each_poll() {
            let setup = Setup::new();
            let (reloader, slot) = reloader_with_token(&setup).await;
            let (_reload_now, receiver) = mpsc::channel(1);
            tokio::spawn(reloader.run(Duration::from_secs(10), receiver));

            setup.write("token", NEW);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(11);
            while tokio::time::Instant::now() < deadline && current(&slot).as_deref() != Some(NEW) {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            assert_eq!(current(&slot).as_deref(), Some(NEW));
        }
    }

    mod local_records {
        use super::*;

        const NAS: &str = "[local]\nrecords = [{ name = 'nas.home.arpa', ip = '192.168.1.10' }]";
        const PRINTER: &str =
            "[local]\nrecords = [{ name = 'printer.home.arpa', ip = '192.168.1.20' }]";

        async fn source(handler: &Handler<NoUpstream>, name: &str) -> Source {
            let mut request = Message::new(1, MessageType::Query, OpCode::Query);
            request.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
            handler.handle(&request).await.source
        }

        #[tokio::test]
        async fn records_are_in_force_from_startup() {
            let setup = Setup::new();
            setup.config(NAS);

            let (_reloader, handler) = setup.reloader().await;

            assert_eq!(source(&handler, "nas.home.arpa.").await, Source::Local);
        }

        // ADR 0016: [local] applies live, like [blocking].
        #[tokio::test]
        async fn changed_records_apply_without_a_restart() {
            let setup = Setup::new();
            setup.config(NAS);
            let (mut reloader, handler) = setup.reloader().await;

            setup.config(PRINTER);
            let change = reloader.reload_config().await;

            assert_eq!(
                change,
                ConfigChange::Applied {
                    restart_required: vec![]
                }
            );
            assert_eq!(source(&handler, "printer.home.arpa.").await, Source::Local);
            assert_ne!(source(&handler, "nas.home.arpa.").await, Source::Local);
        }

        #[tokio::test]
        async fn changed_ttl_alone_applies_without_a_restart() {
            let setup = Setup::new();
            setup.config(NAS);
            let (mut reloader, handler) = setup.reloader().await;

            setup.config(&format!("{NAS}\nttl = 60"));
            reloader.reload_config().await;

            let mut request = Message::new(1, MessageType::Query, OpCode::Query);
            request.add_query(Query::query(
                Name::from_ascii("nas.home.arpa.").unwrap(),
                RecordType::A,
            ));
            let response = handler.handle(&request).await.response;
            assert_eq!(response.answers[0].ttl, 60);
        }

        #[tokio::test]
        async fn invalid_records_keep_the_previous_ones() {
            let setup = Setup::new();
            setup.config(NAS);
            let (mut reloader, handler) = setup.reloader().await;

            setup.config("[local]\nrecords = [{ name = 'nas', ip = '192.168.1.10' }]");
            let change = reloader.reload_config().await;

            assert!(
                matches!(&change, ConfigChange::Rejected(reason) if reason.contains("local.records")),
                "{change:?}"
            );
            assert_eq!(source(&handler, "nas.home.arpa.").await, Source::Local);
        }
    }
}

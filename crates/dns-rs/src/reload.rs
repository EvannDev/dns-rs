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
use crate::config::{BlockingConfig, Config, ConfigError};
use crate::handler::Handler;
use crate::metrics::{Metrics, ReloadResult};
use crate::sources::{ListLoader, ListResult, ListStore};
use crate::upstream::Upstream;

/// What a configuration reload did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigChange {
    /// The configuration is the same as the last one seen.
    Unchanged,
    /// The new blocking settings are in force. Settings listed in
    /// `restart_required` changed too but were not applied.
    Applied { restart_required: Vec<&'static str> },
    /// The new configuration is invalid or unreadable; the previous one
    /// stays in force.
    Rejected(String),
}

/// How often the configuration file is read again. Kubernetes updates a
/// mounted `ConfigMap` within about a minute, so a few seconds is plenty.
pub const CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(10);

type Lookup = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

pub struct Reloader<U> {
    handler: Arc<Handler<U>>,
    metrics: Arc<Metrics>,
    loader: ListLoader,
    lookup: Lookup,
    /// In force: restart-only settings keep their startup values.
    active: Config,
    /// The last valid configuration read, to report each change once.
    last_seen: Config,
    /// The last rejection logged, to log a broken file once, not every poll.
    last_rejection: Option<String>,
    store: ListStore,
}

impl<U: Upstream> Reloader<U> {
    /// Loads the blocklists of `config` and installs the first policy.
    /// `lookup` reads environment variables, as [`Config::load`] does.
    pub async fn start(
        handler: Arc<Handler<U>>,
        metrics: Arc<Metrics>,
        loader: ListLoader,
        config: Config,
        lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Result<Self, ConfigError> {
        let mut store = ListStore::default();
        let results = loader.load_each(&config.blocking.lists).await;
        record_lists(&metrics, &results);
        store.update(results);
        let policy = build_policy(&config.blocking, &store).await?;
        install(&handler, &metrics, policy);
        Ok(Self {
            handler,
            metrics,
            loader,
            lookup: Box::new(lookup),
            active: config.clone(),
            last_seen: config,
            last_rejection: None,
            store,
        })
    }

    /// The configuration in force.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.active
    }

    /// Reads the configuration again and applies its blocking settings.
    pub async fn reload_config(&mut self) -> ConfigChange {
        let next = match Config::load(&self.lookup) {
            Ok(next) => next,
            Err(error) => return self.reject(error.to_string()),
        };
        self.last_rejection = None;
        // Valid again, even if identical to the last configuration seen.
        self.metrics.set_config_valid(true);
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
            if !missing.is_empty() {
                let results = self.loader.load_each(&missing).await;
                // Recorded now, before the policy is built: if the build
                // failed, these series would describe lists not in force,
                // but validation leaves no known cause for that failure.
                record_lists(&self.metrics, &results);
                store.update(results);
            }
            match build_policy(&next.blocking, &store).await {
                Ok(policy) => {
                    install(&self.handler, &self.metrics, policy);
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
        self.last_seen = next;
        self.metrics.record_config_reload(ReloadResult::Applied);
        tracing::info!("configuration reloaded");
        ConfigChange::Applied { restart_required }
    }

    /// Downloads every configured list again; a list that fails keeps its
    /// last valid version.
    pub async fn refresh_lists(&mut self) {
        let results = self.loader.load_each(&self.active.blocking.lists).await;
        record_lists(&self.metrics, &results);
        self.store.update(results);
        match build_policy(&self.active.blocking, &self.store).await {
            Ok(policy) => install(&self.handler, &self.metrics, policy),
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
                }
                message = reload_now.recv() => match message {
                    Some(()) => {
                        tracing::info!("reload requested");
                        self.reload_config().await;
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
        if self.last_rejection.as_ref() != Some(&reason) {
            tracing::error!(error = %reason, "configuration rejected, keeping the previous one");
            self.metrics.record_config_reload(ReloadResult::Rejected);
            self.last_rejection = Some(reason.clone());
        }
        ConfigChange::Rejected(reason)
    }
}

fn install<U: Upstream>(handler: &Handler<U>, metrics: &Metrics, policy: Policy) {
    metrics.set_blocking_rules(policy.filter.deny_count());
    handler.set_policy(policy);
}

fn record_lists(metrics: &Metrics, results: &[(ListConfig, ListResult)]) {
    for (config, result) in results {
        match result {
            Ok(list) => {
                metrics.record_list_loaded(&config.source, list.deny.len());
            }
            Err(error) => metrics.record_list_failed(&config.source, error),
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
    }

    impl Setup {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
                metrics: Arc::new(
                    Metrics::new()
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
            let handler = Arc::new(Handler::new(NoUpstream, DnsCache::new(10)));
            let config_path = self.path("dns-rs.toml");
            let lookup = move |var: &str| {
                (var == "DNS_RS_CONFIG").then(|| config_path.display().to_string())
            };
            let config = Config::load(&lookup).unwrap();
            let loader = ListLoader::new(Limits::default()).unwrap();
            let reloader = Reloader::start(
                Arc::clone(&handler),
                Arc::clone(&self.metrics),
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
}

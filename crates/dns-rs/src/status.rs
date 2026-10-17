//! What `/api/v1/status` reports: the state the Reloader keeps in force.
//!
//! List failures carry their reason, never their message: HTTP errors embed
//! the full URL, which may hold a token.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::blocking::BlockingMode;
use crate::config::ListConfig;
use crate::lists::BareDomains;
use crate::sources::FetchError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusReport {
    pub version: &'static str,
    pub blocking: BlockingStatus,
    pub config: ConfigStatus,
    pub cache: CacheStatus,
    /// In configuration order.
    pub lists: Vec<ListStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockingStatus {
    pub mode: BlockingMode,
    pub rules: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigStatus {
    /// Whether the configuration file, as last read, is valid.
    pub valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacheStatus {
    pub entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListStatus {
    /// The list's label, without credentials, query or fragment.
    pub list: String,
    pub wildcard: bool,
    /// Deny rules of the last successful load, if any.
    pub rules: Option<usize>,
    /// Unix time of the last successful load, if any.
    pub last_success: Option<u64>,
    /// The last failure, if it happened after the last success.
    pub last_failure: Option<ListFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListFailure {
    /// `timeout`, `too_large`, `status` or `failed`.
    pub reason: &'static str,
    /// The HTTP status, for `status` failures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// Unix time of the failure.
    pub at: u64,
}

type Clock = Box<dyn Fn() -> SystemTime + Send + Sync>;
type Counter = Box<dyn Fn() -> usize + Send + Sync>;

/// The state reported by `/api/v1/status`, updated by the Reloader.
pub struct Status {
    state: Mutex<State>,
    clock: Clock,
    cache_entries: Counter,
}

struct State {
    mode: BlockingMode,
    rules: usize,
    config_valid: bool,
    lists: Vec<(ListConfig, ListStatus)>,
}

impl Status {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                mode: BlockingMode::default(),
                rules: 0,
                config_valid: true,
                lists: Vec::new(),
            }),
            clock: Box::new(SystemTime::now),
            cache_entries: Box::new(|| 0),
        }
    }

    /// Takes the time from `clock` instead of the system clock (tests).
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> SystemTime + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// Reads the number of cached responses from `entries` at each report.
    #[must_use]
    pub fn with_cache_entries(
        mut self,
        entries: impl Fn() -> usize + Send + Sync + 'static,
    ) -> Self {
        self.cache_entries = Box::new(entries);
        self
    }

    pub fn set_policy(&self, mode: BlockingMode, rules: usize) {
        let mut state = self.lock();
        state.mode = mode;
        state.rules = rules;
    }

    /// The configured lists, in order: known ones keep their history, new
    /// ones start empty, removed ones are dropped.
    pub fn set_lists(&self, lists: &[ListConfig]) {
        let mut state = self.lock();
        let mut previous = std::mem::take(&mut state.lists);
        state.lists = lists
            .iter()
            .map(|config| {
                let known = previous.iter().position(|(known, _)| known == config);
                let entry = known.map_or_else(
                    || ListStatus {
                        list: config.source.label(),
                        wildcard: config.bare_domains == BareDomains::WithSubdomains,
                        rules: None,
                        last_success: None,
                        last_failure: None,
                    },
                    |index| previous.swap_remove(index).1,
                );
                (config.clone(), entry)
            })
            .collect();
    }

    pub fn list_loaded(&self, list: &ListConfig, rules: usize) {
        let now = self.now();
        self.update(list, |entry| {
            entry.rules = Some(rules);
            entry.last_success = Some(now);
            entry.last_failure = None;
        });
    }

    pub fn list_failed(&self, list: &ListConfig, error: &FetchError) {
        // The reason only: messages may hold the full URL and its token.
        let (reason, http_status) = match error {
            FetchError::Timeout => ("timeout", None),
            FetchError::TooLarge(_) => ("too_large", None),
            FetchError::Status(code) => ("status", Some(*code)),
            FetchError::Failed(_) => ("failed", None),
        };
        let at = self.now();
        self.update(list, |entry| {
            entry.last_failure = Some(ListFailure {
                reason,
                http_status,
                at,
            });
        });
    }

    pub fn set_config_valid(&self, valid: bool) {
        self.lock().config_valid = valid;
    }

    #[must_use]
    pub fn report(&self) -> StatusReport {
        let entries = (self.cache_entries)();
        let state = self.lock();
        StatusReport {
            version: env!("CARGO_PKG_VERSION"),
            blocking: BlockingStatus {
                mode: state.mode,
                rules: state.rules,
            },
            config: ConfigStatus {
                valid: state.config_valid,
            },
            cache: CacheStatus { entries },
            lists: state.lists.iter().map(|(_, entry)| entry.clone()).collect(),
        }
    }

    /// Applies `change` to the entry of `list`; outcomes of lists no longer
    /// configured are ignored.
    fn update(&self, list: &ListConfig, change: impl FnOnce(&mut ListStatus)) {
        if let Some((_, entry)) = self
            .lock()
            .lists
            .iter_mut()
            .find(|(known, _)| known == list)
        {
            change(entry);
        }
    }

    fn now(&self) -> u64 {
        (self.clock)()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // Updates are single assignments: a panic cannot leave the state
        // half-written, so a poisoned lock is safe to reuse.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for Status {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::config::ListSource;

    const T0: u64 = 1_700_000_000;

    fn status_at(seconds: u64) -> Status {
        Status::new().with_clock(move || UNIX_EPOCH + Duration::from_secs(seconds))
    }

    fn list(url: &str) -> ListConfig {
        ListSource::try_from(url.to_owned()).unwrap().into()
    }

    #[test]
    fn report_carries_version_policy_and_config_validity() {
        let status = status_at(T0);

        status.set_policy(BlockingMode::NxDomain, 42);
        status.set_config_valid(false);
        let report = status.report();

        assert_eq!(report.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            report.blocking,
            BlockingStatus {
                mode: BlockingMode::NxDomain,
                rules: 42
            }
        );
        assert_eq!(report.config, ConfigStatus { valid: false });
    }

    #[test]
    fn config_is_valid_until_said_otherwise() {
        assert!(Status::new().report().config.valid);
    }

    #[test]
    fn lists_are_reported_in_configuration_order() {
        let status = status_at(T0);
        let (a, b) = (
            list("https://a.example/hosts"),
            list("https://b.example/hosts"),
        );

        status.set_lists(&[b.clone(), a.clone()]);
        status.list_loaded(&a, 10);

        let lists = status.report().lists;
        assert_eq!(lists.len(), 2);
        assert_eq!(lists[0].list, "https://b.example/hosts");
        assert_eq!(lists[0].rules, None);
        assert_eq!(lists[0].last_success, None);
        assert_eq!(lists[1].list, "https://a.example/hosts");
        assert_eq!(lists[1].rules, Some(10));
        assert_eq!(lists[1].last_success, Some(T0));
        assert_eq!(lists[1].last_failure, None);
    }

    #[test]
    fn wildcard_setting_is_reported() {
        let status = status_at(T0);
        let wildcard = ListConfig {
            bare_domains: BareDomains::WithSubdomains,
            ..list("https://a.example/hosts")
        };

        status.set_lists(&[wildcard]);

        assert!(status.report().lists[0].wildcard);
    }

    #[test]
    fn failure_keeps_the_last_success() {
        let status = status_at(T0);
        let a = list("https://a.example/hosts");
        status.set_lists(std::slice::from_ref(&a));
        status.list_loaded(&a, 10);

        status.list_failed(&a, &FetchError::Status(503));

        let entry = &status.report().lists[0];
        assert_eq!(entry.rules, Some(10));
        assert_eq!(entry.last_success, Some(T0));
        assert_eq!(
            entry.last_failure,
            Some(ListFailure {
                reason: "status",
                http_status: Some(503),
                at: T0
            })
        );
    }

    #[test]
    fn success_clears_an_earlier_failure() {
        let status = status_at(T0);
        let a = list("https://a.example/hosts");
        status.set_lists(std::slice::from_ref(&a));
        status.list_failed(&a, &FetchError::Timeout);

        status.list_loaded(&a, 3);

        assert_eq!(status.report().lists[0].last_failure, None);
    }

    #[test]
    fn failure_reasons_are_named() {
        let status = status_at(T0);
        let a = list("https://a.example/hosts");
        status.set_lists(std::slice::from_ref(&a));

        for (error, reason) in [
            (FetchError::Timeout, "timeout"),
            (FetchError::TooLarge(1), "too_large"),
            (FetchError::Failed("dns".to_owned()), "failed"),
        ] {
            status.list_failed(&a, &error);
            let failure = status.report().lists[0].last_failure.clone().unwrap();
            assert_eq!((failure.reason, failure.http_status), (reason, None));
        }
    }

    // HTTP error messages embed the full URL, token included.
    #[test]
    fn failure_message_is_never_reported() {
        let status = status_at(T0);
        let private = list("https://a.example/hosts?token=SeCrEt42");
        status.set_lists(std::slice::from_ref(&private));
        let message = "error sending request for url (https://a.example/hosts?token=SeCrEt42)";

        status.list_failed(&private, &FetchError::Failed(message.to_owned()));

        let report = format!("{:?}", status.report());
        assert!(!report.contains("SeCrEt42"), "{report}");
    }

    #[test]
    fn removed_lists_are_dropped_and_kept_ones_keep_their_history() {
        let status = status_at(T0);
        let (a, b) = (
            list("https://a.example/hosts"),
            list("https://b.example/hosts"),
        );
        status.set_lists(&[a.clone(), b.clone()]);
        status.list_loaded(&a, 10);

        status.set_lists(std::slice::from_ref(&a));

        let lists = status.report().lists;
        assert_eq!(lists.len(), 1);
        assert_eq!(lists[0].rules, Some(10));
    }

    #[test]
    fn unknown_list_outcomes_are_ignored() {
        let status = status_at(T0);

        status.list_loaded(&list("https://a.example/hosts"), 10);

        assert_eq!(status.report().lists, []);
    }

    #[test]
    fn cache_entries_are_read_at_each_report() {
        let status = Status::new().with_cache_entries(|| 7);

        assert_eq!(status.report().cache, CacheStatus { entries: 7 });
    }
}

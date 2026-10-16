//! Decides whether a domain is blocked, from allow and deny rules.
//!
//! Pure and synchronous: no I/O, so it can be rebuilt off the hot path and
//! swapped in atomically.

use std::collections::{BTreeMap, HashMap};

use regex::RegexSet;

/// A single matching rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// Matches this domain only.
    Exact(String),
    /// Matches this domain and every subdomain of it.
    Subtree(String),
    /// Matches domains (lowercase, without trailing dot) against a regex.
    Regex(String),
}

impl Rule {
    /// Parses the config syntax: `*.example.com` is a [`Rule::Subtree`],
    /// anything else a [`Rule::Exact`]. Regexes are configured separately.
    #[must_use]
    pub fn from_pattern(pattern: &str) -> Self {
        match pattern.strip_prefix("*.") {
            Some(domain) => Self::Subtree(domain.to_owned()),
            None => Self::Exact(pattern.to_owned()),
        }
    }
}

/// How a rule matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchKind {
    Exact,
    Subtree,
    Regex,
}

/// A rule that matched, and where it comes from.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Match {
    pub kind: MatchKind,
    /// The rule as written: `ads.example.com`, `*.example.com`, a regex.
    pub rule: String,
    pub origin: String,
}

/// Why a domain is blocked or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    pub verdict: Verdict,
    /// The first deny rule that matches, if any.
    pub denied_by: Option<Match>,
    /// The first allow rule that matches, if any; it wins over deny rules.
    pub allowed_by: Option<Match>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    Blocked,
}

#[derive(Debug, Default)]
pub struct FilterBuilder {
    deny: RulesBuilder,
    allow: RulesBuilder,
}

impl FilterBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a deny rule coming from `origin` (`config:deny`, a list label…).
    pub fn deny_from(&mut self, rule: Rule, origin: &str) -> &mut Self {
        self.deny.add(rule, origin);
        self
    }

    /// Adds an allow rule coming from `origin`.
    pub fn allow_from(&mut self, rule: Rule, origin: &str) -> &mut Self {
        self.allow.add(rule, origin);
        self
    }

    /// Adds a deny rule of unknown origin.
    pub fn deny(&mut self, rule: Rule) -> &mut Self {
        self.deny_from(rule, "")
    }

    /// Adds an allow rule of unknown origin.
    pub fn allow(&mut self, rule: Rule) -> &mut Self {
        self.allow_from(rule, "")
    }

    /// Compiles the rules; fails on the first invalid regex.
    pub fn build(self) -> Result<Filter, regex::Error> {
        Ok(Filter {
            deny: self.deny.build()?,
            allow: self.allow.build()?,
        })
    }
}

/// Index into a [`Rules`]' origins: a few bytes per rule instead of a string.
type OriginId = u32;

#[derive(Debug, Default)]
struct RulesBuilder {
    origins: Vec<Box<str>>,
    origin_ids: HashMap<Box<str>, OriginId>,
    exact: HashMap<Box<str>, OriginId>,
    subtree: HashMap<Box<str>, OriginId>,
    // Ordered so the compiled set is deterministic.
    regex: BTreeMap<String, OriginId>,
}

impl RulesBuilder {
    /// Adds `rule`; a rule already present keeps its first origin.
    fn add(&mut self, rule: Rule, origin: &str) {
        let id = self.origin_id(origin);
        match rule {
            Rule::Exact(domain) => self.exact.entry(normalize(&domain).into()).or_insert(id),
            Rule::Subtree(domain) => self.subtree.entry(normalize(&domain).into()).or_insert(id),
            Rule::Regex(pattern) => self.regex.entry(pattern).or_insert(id),
        };
    }

    fn origin_id(&mut self, origin: &str) -> OriginId {
        if let Some(&id) = self.origin_ids.get(origin) {
            return id;
        }
        // Origins are config keys and lists: far fewer than u32::MAX.
        let id = OriginId::try_from(self.origins.len()).unwrap_or(OriginId::MAX);
        self.origins.push(origin.into());
        self.origin_ids.insert(origin.into(), id);
        id
    }

    fn build(self) -> Result<Rules, regex::Error> {
        let (patterns, regex_origins): (Vec<String>, Vec<OriginId>) =
            self.regex.into_iter().unzip();
        Ok(Rules {
            regex: RegexSet::new(&patterns)?,
            regex_patterns: patterns,
            regex_origins,
            exact: self.exact,
            subtree: self.subtree,
            origins: self.origins,
        })
    }
}

#[derive(Debug)]
struct Rules {
    exact: HashMap<Box<str>, OriginId>,
    subtree: HashMap<Box<str>, OriginId>,
    regex: RegexSet,
    regex_patterns: Vec<String>,
    regex_origins: Vec<OriginId>,
    origins: Vec<Box<str>>,
}

impl Rules {
    fn empty() -> Self {
        Self {
            exact: HashMap::new(),
            subtree: HashMap::new(),
            regex: RegexSet::empty(),
            regex_patterns: Vec::new(),
            regex_origins: Vec::new(),
            origins: Vec::new(),
        }
    }

    /// `domain` must already be normalized.
    fn matches(&self, domain: &str) -> bool {
        self.exact.contains_key(domain)
            || suffixes(domain).any(|suffix| self.subtree.contains_key(suffix))
            || self.regex.is_match(domain)
    }

    /// The most specific matching rule: exact, then the closest subtree,
    /// then the first regex. `domain` must already be normalized.
    fn first_match(&self, domain: &str) -> Option<Match> {
        if let Some(&id) = self.exact.get(domain) {
            return Some(self.found(MatchKind::Exact, domain.to_owned(), id));
        }
        if let Some((suffix, &id)) =
            suffixes(domain).find_map(|suffix| self.subtree.get(suffix).map(|id| (suffix, id)))
        {
            return Some(self.found(MatchKind::Subtree, format!("*.{suffix}"), id));
        }
        let index = self.regex.matches(domain).into_iter().next()?;
        Some(self.found(
            MatchKind::Regex,
            self.regex_patterns[index].clone(),
            self.regex_origins[index],
        ))
    }

    fn found(&self, kind: MatchKind, rule: String, origin: OriginId) -> Match {
        let origin = usize::try_from(origin)
            .ok()
            .and_then(|index| self.origins.get(index))
            .map_or_else(String::new, ToString::to_string);
        Match { kind, rule, origin }
    }

    fn len(&self) -> usize {
        self.exact.len() + self.subtree.len() + self.regex.len()
    }
}

#[derive(Debug)]
pub struct Filter {
    deny: Rules,
    allow: Rules,
}

impl Filter {
    /// A filter that blocks nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            deny: Rules::empty(),
            allow: Rules::empty(),
        }
    }

    /// Checks `domain`, case-insensitively, with or without trailing dot.
    #[must_use]
    pub fn check(&self, domain: &str) -> Verdict {
        let domain = normalize(domain);
        if self.deny.matches(&domain) && !self.allow.matches(&domain) {
            Verdict::Blocked
        } else {
            Verdict::Allowed
        }
    }

    /// Like [`Filter::check`], with the rules that decided.
    #[must_use]
    pub fn explain(&self, domain: &str) -> Explanation {
        let domain = normalize(domain);
        let denied_by = self.deny.first_match(&domain);
        let allowed_by = self.allow.first_match(&domain);
        let verdict = if denied_by.is_some() && allowed_by.is_none() {
            Verdict::Blocked
        } else {
            Verdict::Allowed
        };
        Explanation {
            verdict,
            denied_by,
            allowed_by,
        }
    }

    /// Number of deny rules, for logs and metrics.
    #[must_use]
    pub fn deny_count(&self) -> usize {
        self.deny.len()
    }
}

/// Lowercase, without surrounding whitespace or trailing dot.
fn normalize(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// `a.b.c` yields `a.b.c`, `b.c`, `c`.
fn suffixes(domain: &str) -> impl Iterator<Item = &str> {
    std::iter::once(domain).chain(
        domain
            .match_indices('.')
            .map(move |(i, _)| &domain[i + 1..]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(s: &str) -> Rule {
        Rule::Exact(s.to_owned())
    }

    fn subtree(s: &str) -> Rule {
        Rule::Subtree(s.to_owned())
    }

    fn regex(s: &str) -> Rule {
        Rule::Regex(s.to_owned())
    }

    fn filter(deny: Vec<Rule>, allow: Vec<Rule>) -> Filter {
        let mut builder = FilterBuilder::new();
        for rule in deny {
            builder.deny(rule);
        }
        for rule in allow {
            builder.allow(rule);
        }
        builder.build().unwrap()
    }

    #[test]
    fn empty_filter_allows_everything() {
        assert_eq!(Filter::empty().check("ads.example.com"), Verdict::Allowed);
    }

    #[test]
    fn exact_rule_blocks_only_that_domain() {
        let f = filter(vec![exact("ads.example.com")], vec![]);

        assert_eq!(f.check("ads.example.com"), Verdict::Blocked);
        assert_eq!(f.check("sub.ads.example.com"), Verdict::Allowed);
        assert_eq!(f.check("example.com"), Verdict::Allowed);
    }

    #[test]
    fn subtree_rule_blocks_domain_and_subdomains() {
        let f = filter(vec![subtree("tracker.com")], vec![]);

        assert_eq!(f.check("tracker.com"), Verdict::Blocked);
        assert_eq!(f.check("a.b.tracker.com"), Verdict::Blocked);
        assert_eq!(f.check("nottracker.com"), Verdict::Allowed);
        assert_eq!(f.check("tracker.com.evil"), Verdict::Allowed);
    }

    #[test]
    fn regex_rule_matches_domain_without_trailing_dot() {
        let f = filter(vec![regex(r"^ad[0-9]+\.")], vec![]);

        assert_eq!(f.check("ad42.example.com."), Verdict::Blocked);
        assert_eq!(f.check("adx.example.com."), Verdict::Allowed);
    }

    #[test]
    fn regex_end_anchor_sees_no_trailing_dot() {
        let f = filter(vec![regex(r"\.com$")], vec![]);

        assert_eq!(f.check("example.com."), Verdict::Blocked);
    }

    #[test]
    fn matching_is_case_insensitive() {
        let f = filter(
            vec![exact("Ads.Example.COM"), subtree("TRACKER.com")],
            vec![],
        );

        assert_eq!(f.check("ADS.example.com"), Verdict::Blocked);
        assert_eq!(f.check("x.Tracker.Com"), Verdict::Blocked);
    }

    #[test]
    fn trailing_dot_is_ignored_in_rules_and_queries() {
        let f = filter(vec![exact("ads.example.com.")], vec![]);

        assert_eq!(f.check("ads.example.com"), Verdict::Blocked);
        assert_eq!(f.check("ads.example.com."), Verdict::Blocked);
    }

    #[test]
    fn allow_wins_over_deny() {
        let f = filter(
            vec![subtree("example.com")],
            vec![exact("good.example.com")],
        );

        assert_eq!(f.check("good.example.com"), Verdict::Allowed);
        assert_eq!(f.check("bad.example.com"), Verdict::Blocked);
    }

    #[test]
    fn allow_regex_wins_over_deny() {
        let f = filter(vec![exact("cdn.example.com")], vec![regex(r"^cdn\.")]);

        assert_eq!(f.check("cdn.example.com"), Verdict::Allowed);
    }

    #[test]
    fn invalid_regex_fails_the_build() {
        let mut builder = FilterBuilder::new();
        builder.deny(regex("("));

        assert!(builder.build().is_err());
    }

    #[test]
    fn duplicate_rules_are_counted_once() {
        let f = filter(
            vec![
                exact("a.com"),
                exact("A.com."),
                subtree("b.com"),
                regex("x"),
            ],
            vec![],
        );

        assert_eq!(f.deny_count(), 3);
    }

    #[test]
    fn pattern_with_wildcard_prefix_is_a_subtree() {
        assert_eq!(Rule::from_pattern("*.example.com"), subtree("example.com"));
        assert_eq!(Rule::from_pattern("example.com"), exact("example.com"));
    }

    mod explain {
        use super::*;

        fn filter() -> Filter {
            let mut builder = FilterBuilder::new();
            builder
                .deny_from(exact("ads.example.com"), "config:deny")
                .deny_from(subtree("tracker.net"), "https://lists.example/hosts")
                .deny_from(regex(r"^ad[0-9]+\."), "config:deny_regex")
                .allow_from(exact("ok.tracker.net"), "config:allow");
            builder.build().unwrap()
        }

        #[expect(clippy::unnecessary_wraps, reason = "compared with Option fields")]
        fn found(kind: MatchKind, rule: &str, origin: &str) -> Option<Match> {
            Some(Match {
                kind,
                rule: rule.to_owned(),
                origin: origin.to_owned(),
            })
        }

        #[test]
        fn exact_rule_is_named_with_its_origin() {
            let explanation = filter().explain("ADS.example.com.");

            assert_eq!(explanation.verdict, Verdict::Blocked);
            assert_eq!(
                explanation.denied_by,
                found(MatchKind::Exact, "ads.example.com", "config:deny")
            );
            assert_eq!(explanation.allowed_by, None);
        }

        #[test]
        fn subtree_rule_is_written_as_a_wildcard() {
            let explanation = filter().explain("a.b.tracker.net");

            assert_eq!(
                explanation.denied_by,
                found(
                    MatchKind::Subtree,
                    "*.tracker.net",
                    "https://lists.example/hosts"
                )
            );
        }

        #[test]
        fn regex_rule_is_named_by_its_pattern() {
            let explanation = filter().explain("ad42.example.org");

            assert_eq!(
                explanation.denied_by,
                found(MatchKind::Regex, r"^ad[0-9]+\.", "config:deny_regex")
            );
        }

        #[test]
        fn allow_rule_explains_why_a_denied_name_passes() {
            let explanation = filter().explain("ok.tracker.net");

            assert_eq!(explanation.verdict, Verdict::Allowed);
            assert_eq!(
                explanation.denied_by,
                found(
                    MatchKind::Subtree,
                    "*.tracker.net",
                    "https://lists.example/hosts"
                )
            );
            assert_eq!(
                explanation.allowed_by,
                found(MatchKind::Exact, "ok.tracker.net", "config:allow")
            );
        }

        #[test]
        fn unmatched_name_has_no_rules() {
            let explanation = filter().explain("example.com");

            assert_eq!(explanation.verdict, Verdict::Allowed);
            assert_eq!(explanation.denied_by, None);
            assert_eq!(explanation.allowed_by, None);
        }

        // The most specific rule is the most useful to show.
        #[test]
        fn exact_wins_over_subtree_and_closest_subtree_wins() {
            let mut builder = FilterBuilder::new();
            builder
                .deny_from(subtree("example.com"), "list:a")
                .deny_from(subtree("ads.example.com"), "list:b")
                .deny_from(exact("x.ads.example.com"), "list:c");
            let filter = builder.build().unwrap();

            assert_eq!(
                filter
                    .explain("x.ads.example.com")
                    .denied_by
                    .unwrap()
                    .origin,
                "list:c"
            );
            assert_eq!(
                filter
                    .explain("y.ads.example.com")
                    .denied_by
                    .unwrap()
                    .origin,
                "list:b"
            );
        }

        // A rule present in several sources keeps the first one added.
        #[test]
        fn duplicate_rule_keeps_its_first_origin() {
            let mut builder = FilterBuilder::new();
            builder
                .deny_from(exact("ads.example.com"), "list:first")
                .deny_from(exact("ads.example.com"), "list:second");

            let filter = builder.build().unwrap();

            assert_eq!(
                filter.explain("ads.example.com").denied_by.unwrap().origin,
                "list:first"
            );
            assert_eq!(filter.deny_count(), 1);
        }

        #[test]
        fn explain_agrees_with_check() {
            let filter = filter();

            for name in [
                "ads.example.com",
                "x.tracker.net",
                "ok.tracker.net",
                "ad1.x",
                "example.com",
            ] {
                assert_eq!(filter.explain(name).verdict, filter.check(name), "{name}");
            }
        }
    }
}

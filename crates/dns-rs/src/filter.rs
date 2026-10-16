//! Decides whether a domain is blocked, from allow and deny rules.
//!
//! Pure and synchronous: no I/O, so it can be rebuilt off the hot path and
//! swapped in atomically.

use std::collections::{BTreeSet, HashSet};

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

    pub fn deny(&mut self, rule: Rule) -> &mut Self {
        self.deny.add(rule);
        self
    }

    pub fn allow(&mut self, rule: Rule) -> &mut Self {
        self.allow.add(rule);
        self
    }

    /// Compiles the rules; fails on the first invalid regex.
    pub fn build(self) -> Result<Filter, regex::Error> {
        Ok(Filter {
            deny: self.deny.build()?,
            allow: self.allow.build()?,
        })
    }
}

#[derive(Debug, Default)]
struct RulesBuilder {
    exact: HashSet<Box<str>>,
    subtree: HashSet<Box<str>>,
    // Ordered so the compiled set is deterministic.
    regex: BTreeSet<String>,
}

impl RulesBuilder {
    fn add(&mut self, rule: Rule) {
        match rule {
            Rule::Exact(domain) => self.exact.insert(normalize(&domain).into()),
            Rule::Subtree(domain) => self.subtree.insert(normalize(&domain).into()),
            Rule::Regex(pattern) => self.regex.insert(pattern),
        };
    }

    fn build(self) -> Result<Rules, regex::Error> {
        Ok(Rules {
            regex: RegexSet::new(&self.regex)?,
            exact: self.exact,
            subtree: self.subtree,
        })
    }
}

#[derive(Debug)]
struct Rules {
    exact: HashSet<Box<str>>,
    subtree: HashSet<Box<str>>,
    regex: RegexSet,
}

impl Rules {
    fn empty() -> Self {
        Self {
            exact: HashSet::new(),
            subtree: HashSet::new(),
            regex: RegexSet::empty(),
        }
    }

    /// `domain` must already be normalized.
    fn matches(&self, domain: &str) -> bool {
        self.exact.contains(domain)
            || suffixes(domain).any(|suffix| self.subtree.contains(suffix))
            || self.regex.is_match(domain)
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
}

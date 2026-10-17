//! Domains whose queries go to their own server instead of the upstream
//! (ADR 0017).

use std::collections::HashMap;

/// Servers by domain. Domains are compared without case or trailing dot.
#[derive(Debug)]
pub struct Forwards<U> {
    by_domain: HashMap<String, U>,
}

impl<U> Default for Forwards<U> {
    fn default() -> Self {
        Self {
            by_domain: HashMap::new(),
        }
    }
}

impl<U> Forwards<U> {
    /// Rules from `(domain, server)` pairs. Validation rejects duplicate
    /// domains; here the last one given wins.
    pub fn new<'a>(rules: impl IntoIterator<Item = (&'a str, U)>) -> Self {
        Self {
            by_domain: rules
                .into_iter()
                .map(|(domain, server)| (key(domain), server))
                .collect(),
        }
    }

    /// Number of forwarded domains.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_domain.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_domain.is_empty()
    }

    /// The server for `name`: the rule of the longest domain that is `name`
    /// or one of its parents, `None` if no rule covers it.
    #[must_use]
    pub fn route(&self, name: &str) -> Option<&U> {
        let mut domain = key(name);
        loop {
            if domain.is_empty() {
                return None;
            }
            if let Some(server) = self.by_domain.get(&domain) {
                return Some(server);
            }
            domain = match domain.split_once('.') {
                Some((_, parent)) => parent.to_owned(),
                None => String::new(),
            };
        }
    }
}

/// `name` without case or trailing dot.
fn key(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forwards() -> Forwards<&'static str> {
        Forwards::new([
            ("home.arpa", "router"),
            ("lab.home.arpa", "lab"),
            ("lan", "lan"),
        ])
    }

    #[test]
    fn the_domain_itself_is_forwarded() {
        assert_eq!(forwards().route("home.arpa."), Some(&"router"));
    }

    #[test]
    fn names_under_the_domain_are_forwarded() {
        assert_eq!(forwards().route("nas.home.arpa."), Some(&"router"));
        assert_eq!(forwards().route("a.b.c.home.arpa."), Some(&"router"));
    }

    #[test]
    fn the_longest_domain_wins() {
        assert_eq!(forwards().route("pc.lab.home.arpa."), Some(&"lab"));
        assert_eq!(forwards().route("lab.home.arpa."), Some(&"lab"));
    }

    #[test]
    fn a_single_label_domain_covers_its_names() {
        assert_eq!(forwards().route("printer.lan."), Some(&"lan"));
    }

    #[test]
    fn matching_ignores_case_and_the_trailing_dot() {
        let forwards = Forwards::new([("Home.ARPA.", "router")]);

        assert_eq!(forwards.route("NAS.home.Arpa."), Some(&"router"));
        assert_eq!(forwards.route("nas.home.arpa"), Some(&"router"));
    }

    // Label by label: a domain is not a mere string suffix.
    #[test]
    fn a_name_merely_ending_with_the_domain_is_not_forwarded() {
        assert_eq!(forwards().route("myhome.arpa."), None);
        assert_eq!(forwards().route("plan."), None);
    }

    #[test]
    fn parents_of_the_domain_and_other_names_are_not_forwarded() {
        assert_eq!(forwards().route("arpa."), None);
        assert_eq!(forwards().route("example.com."), None);
        assert_eq!(forwards().route("."), None);
    }

    #[test]
    fn no_rules_forward_nothing() {
        let forwards = Forwards::<&str>::default();

        assert!(forwards.is_empty());
        assert_eq!(forwards.route("nas.home.arpa."), None);
    }

    #[test]
    fn counts_domains_once_whatever_their_case() {
        let forwards = Forwards::new([("home.arpa", "a"), ("HOME.arpa.", "b")]);

        assert_eq!(forwards.len(), 1);
    }
}

//! Parsing of blocklists: hosts files, plain domain lists and the DNS subset
//! of Adblock Plus syntax (`||domain^`, `@@||domain^`).

use std::net::IpAddr;

use crate::filter::Rule;

/// Names every hosts file maps to loopback; they are not blocklist entries.
const HOSTS_BOILERPLATE: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
];

const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedList {
    pub deny: Vec<Rule>,
    /// Exceptions (`@@||domain^`) shipped by the list itself.
    pub allow: Vec<Rule>,
    /// Lines that were neither rules nor comments, for diagnostics.
    pub skipped: usize,
}

/// What a domain listed without syntax (`example.com`, or a hosts entry)
/// blocks. `*.example.com` lines always block the domain and its subdomains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BareDomains {
    /// That name only, as in Pi-hole and hosts files.
    #[default]
    Exact,
    /// The name and its subdomains, as lists like OISD `domainswild2` intend.
    WithSubdomains,
}

/// Parses a list, keeping every line it understands and counting the others.
/// Bare domains are exact matches.
#[must_use]
pub fn parse_list(text: &str) -> ParsedList {
    parse_list_with(text, BareDomains::Exact)
}

/// Parses a list whose bare domains mean `bare`.
#[must_use]
pub fn parse_list_with(text: &str, bare: BareDomains) -> ParsedList {
    let mut list = ParsedList::default();
    for line in text.lines() {
        let line = strip_comment(line).trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
            continue;
        }
        if let Some(rule) = line.strip_prefix("@@") {
            match adblock_domain(rule) {
                Some(domain) => list.allow.push(Rule::Subtree(domain.to_owned())),
                None => list.skipped += 1,
            }
        } else if line.starts_with("||") {
            match adblock_domain(line) {
                Some(domain) => list.deny.push(Rule::Subtree(domain.to_owned())),
                None => list.skipped += 1,
            }
        } else {
            parse_hosts_or_domain(line, bare, &mut list);
        }
    }
    list
}

/// Removes a `#` comment, unless the `#` is part of a token such as the
/// cosmetic filter `example.com##.ad` (which then fails domain validation).
fn strip_comment(line: &str) -> &str {
    if line.trim_start().starts_with('#') {
        return "";
    }
    line.find(" #")
        .or_else(|| line.find("\t#"))
        .map_or(line, |i| &line[..i])
}

/// The domain of `||domain^`, if the rule has no options or other syntax.
fn adblock_domain(rule: &str) -> Option<&str> {
    let domain = rule.strip_prefix("||")?.strip_suffix('^')?;
    is_valid_domain(domain).then_some(domain)
}

/// A hosts line (`<ip> <name>...`), a single domain or a `*.domain`.
fn parse_hosts_or_domain(line: &str, bare: BareDomains, list: &mut ParsedList) {
    let mut tokens = line.split_whitespace();
    let Some(first) = tokens.next() else {
        return;
    };
    let names: Vec<&str> = if is_address(first) {
        tokens.collect()
    } else if tokens.next().is_none() {
        if let Some(domain) = first.strip_prefix("*.") {
            if is_valid_domain(domain) {
                list.deny.push(Rule::Subtree(domain.to_owned()));
            } else {
                list.skipped += 1;
            }
            return;
        }
        vec![first]
    } else {
        list.skipped += 1;
        return;
    };
    for name in names {
        if HOSTS_BOILERPLATE.contains(&name) || is_address(name) {
            continue;
        }
        if is_valid_domain(name) {
            list.deny.push(match bare {
                BareDomains::Exact => Rule::Exact(name.to_owned()),
                BareDomains::WithSubdomains => Rule::Subtree(name.to_owned()),
            });
        } else {
            list.skipped += 1;
        }
    }
}

/// An IP address, possibly with an IPv6 zone ID (`fe80::1%lo0`).
fn is_address(token: &str) -> bool {
    let address = token
        .split_once('%')
        .map_or(token, |(address, _zone)| address);
    address.parse::<IpAddr>().is_ok()
}

/// At least two labels of letters, digits, `-` or `_`, within DNS limits.
pub(crate) fn is_valid_domain(domain: &str) -> bool {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    domain.len() <= MAX_DOMAIN_LEN
        && domain.contains('.')
        && domain.split('.').all(|label| {
            (1..=MAX_LABEL_LEN).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
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

    #[test]
    fn plain_domains_are_exact_rules() {
        let list = parse_list("ads.example.com\ntracker.example.net\n");

        assert_eq!(
            list.deny,
            vec![exact("ads.example.com"), exact("tracker.example.net")]
        );
        assert_eq!(list.skipped, 0);
    }

    #[test]
    fn wildcard_line_is_a_subtree() {
        let list = parse_list("*.ads.example.com");

        assert_eq!(list.deny, vec![subtree("ads.example.com")]);
        assert_eq!(list.skipped, 0);
    }

    #[test]
    fn wildcard_over_a_tld_is_skipped() {
        let list = parse_list("*.com");

        assert_eq!(list.deny, []);
        assert_eq!(list.skipped, 1);
    }

    // Hosts files map names to addresses; a wildcard there is a mistake.
    #[test]
    fn wildcard_in_a_hosts_line_is_skipped() {
        let list = parse_list("0.0.0.0 *.ads.example.com");

        assert_eq!(list.deny, []);
        assert_eq!(list.skipped, 1);
    }

    #[test]
    fn malformed_wildcards_are_skipped() {
        for line in [
            "*.",
            "*.*.example.com",
            "*.com",
            "*example.com",
            "a.*.example.com",
        ] {
            let list = parse_list_with(line, BareDomains::WithSubdomains);

            assert_eq!(list.deny, [], "{line}");
            assert_eq!(list.skipped, 1, "{line}");
        }
    }

    #[test]
    fn wildcard_line_is_one_subtree_whatever_the_bare_mode() {
        let list = parse_list_with("*.ads.example.com", BareDomains::WithSubdomains);

        assert_eq!(list.deny, vec![subtree("ads.example.com")]);
    }

    #[test]
    fn bare_domains_can_cover_subdomains() {
        let list = parse_list_with("ads.example.com", BareDomains::WithSubdomains);

        assert_eq!(list.deny, vec![subtree("ads.example.com")]);
    }

    #[test]
    fn hosts_entries_can_cover_subdomains() {
        let list = parse_list_with(
            "0.0.0.0 ads.example.com t.example.net",
            BareDomains::WithSubdomains,
        );

        assert_eq!(
            list.deny,
            vec![subtree("ads.example.com"), subtree("t.example.net")]
        );
    }

    #[test]
    fn exact_is_the_default_for_bare_domains() {
        assert_eq!(BareDomains::default(), BareDomains::Exact);
        assert_eq!(
            parse_list("ads.example.com").deny,
            vec![exact("ads.example.com")]
        );
    }

    #[test]
    fn hosts_lines_yield_every_hostname() {
        let list = parse_list(
            "0.0.0.0 a.example.com\n127.0.0.1\tb.example.com c.example.com\n:: d.example.com",
        );

        assert_eq!(
            list.deny,
            vec![
                exact("a.example.com"),
                exact("b.example.com"),
                exact("c.example.com"),
                exact("d.example.com"),
            ]
        );
    }

    // StevenBlack's hosts file ships `fe80::1%lo0 localhost`.
    #[test]
    fn ipv6_with_zone_id_is_a_hosts_address() {
        let list = parse_list("fe80::1%lo0 localhost\nfe80::1%lo0 ads.example.com");

        assert_eq!(list.deny, vec![exact("ads.example.com")]);
        assert_eq!(list.skipped, 0);
    }

    #[test]
    fn hosts_boilerplate_entries_are_ignored() {
        let list = parse_list(
            "127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n\
             255.255.255.255 broadcasthost\n0.0.0.0 0.0.0.0\n127.0.0.1 localhost.localdomain",
        );

        assert!(list.deny.is_empty(), "{:?}", list.deny);
        assert_eq!(list.skipped, 0);
    }

    #[test]
    fn adblock_domain_rule_is_a_subtree() {
        let list = parse_list("||ads.example.com^");

        assert_eq!(list.deny, vec![subtree("ads.example.com")]);
    }

    #[test]
    fn adblock_exception_is_an_allow_rule() {
        let list = parse_list("@@||good.example.com^");

        assert_eq!(list.allow, vec![subtree("good.example.com")]);
        assert_eq!(list.deny, []);
    }

    // Options such as $third-party or $client change the meaning of the rule;
    // applying it without them would block more than the list author meant.
    #[test]
    fn adblock_rule_with_options_is_skipped() {
        let list = parse_list("||ads.example.com^$third-party");

        assert_eq!(list.deny, []);
        assert_eq!(list.skipped, 1);
    }

    #[test]
    fn comments_headers_and_blank_lines_are_not_rules() {
        let list = parse_list("# hosts comment\n! adblock comment\n[Adblock Plus 2.0]\n\n   \n");

        assert_eq!(list, ParsedList::default());
    }

    #[test]
    fn inline_comments_are_stripped() {
        let list = parse_list("ads.example.com # added 2024\n0.0.0.0 t.example.com #tracker");

        assert_eq!(
            list.deny,
            vec![exact("ads.example.com"), exact("t.example.com")]
        );
    }

    #[test]
    fn tab_before_inline_comment_is_stripped() {
        let list = parse_list("ads.example.com\t# tab comment");

        assert_eq!(list.deny, vec![exact("ads.example.com")]);
    }

    // Cosmetic filters hide page elements; they must not block the domain.
    #[test]
    fn cosmetic_filter_does_not_block_its_domain() {
        let list = parse_list("example.com##.ad-banner");

        assert!(list.deny.is_empty(), "{:?}", list.deny);
        assert_eq!(list.skipped, 1);
    }

    #[test]
    fn windows_line_endings_are_accepted() {
        let list = parse_list("a.example.com\r\nb.example.com\r\n");

        assert_eq!(
            list.deny,
            vec![exact("a.example.com"), exact("b.example.com")]
        );
    }

    #[test]
    fn invalid_domains_are_skipped() {
        let label_64 = "a".repeat(64);
        let text = format!("bad domain.com\nexa$mple.com\n{label_64}.com\n-\n");

        let list = parse_list(&text);

        assert!(list.deny.is_empty(), "{:?}", list.deny);
        assert_eq!(list.skipped, 4);
    }

    // A bare TLD in a list would be a typo at best; as a subtree it would
    // block a whole TLD.
    #[test]
    fn single_label_names_are_skipped() {
        let list = parse_list("com\n||net^");

        assert_eq!(list.deny, []);
        assert_eq!(list.skipped, 2);
    }

    #[test]
    fn underscores_are_allowed_in_labels() {
        let list = parse_list("_dmarc.example.com");

        assert_eq!(list.deny, vec![exact("_dmarc.example.com")]);
    }
}

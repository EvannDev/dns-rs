//! Fetching the blocklists named in the configuration.

use crate::config::ListSource;
use crate::lists::{ParsedList, parse_list};

/// Loads and parses every list. A list that cannot be loaded is logged and
/// skipped: DNS must keep working without it.
pub async fn load_lists(sources: &[ListSource]) -> Vec<ParsedList> {
    let mut lists = Vec::with_capacity(sources.len());
    for source in sources {
        match source {
            ListSource::File(path) => match tokio::fs::read_to_string(path).await {
                Ok(text) => {
                    let list = parse_list(&text);
                    tracing::info!(
                        list = %path.display(),
                        deny = list.deny.len(),
                        allow = list.allow.len(),
                        skipped = list.skipped,
                        "blocklist loaded"
                    );
                    lists.push(list);
                }
                Err(error) => {
                    tracing::warn!(list = %path.display(), %error, "cannot read blocklist, skipped");
                }
            },
            ListSource::Http(url) => {
                tracing::warn!(list = %url, "HTTP blocklists are not supported yet, skipped");
            }
        }
    }
    lists
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::filter::Rule;

    fn list_file(content: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    #[tokio::test]
    async fn file_list_is_read_and_parsed() {
        let file = list_file("0.0.0.0 ads.example.com\n||tracker.example^\n");

        let lists = load_lists(&[ListSource::File(file.path().into())]).await;

        assert_eq!(lists.len(), 1);
        assert_eq!(
            lists[0].deny,
            vec![
                Rule::Exact("ads.example.com".to_owned()),
                Rule::Subtree("tracker.example".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn unreadable_list_is_skipped() {
        let file = list_file("ads.example.com");

        let lists = load_lists(&[
            ListSource::File("/nonexistent/list.txt".into()),
            ListSource::File(file.path().into()),
        ])
        .await;

        assert_eq!(lists.len(), 1);
        assert_eq!(
            lists[0].deny,
            vec![Rule::Exact("ads.example.com".to_owned())]
        );
    }

    #[tokio::test]
    async fn http_lists_are_skipped_until_supported() {
        let lists = load_lists(&[ListSource::Http("https://example.org/hosts".to_owned())]).await;

        assert_eq!(lists, []);
    }
}

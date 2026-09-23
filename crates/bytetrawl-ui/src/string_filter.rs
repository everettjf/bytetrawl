use bytetrawl_analysis::ExtractedString;
use std::sync::Arc;

pub struct StringFilter {
    strings: Arc<Vec<ExtractedString>>,
    query: String,
    minimum: usize,
    pub indices: Arc<Vec<usize>>,
}

impl StringFilter {
    pub fn matches(
        &self,
        strings: &Arc<Vec<ExtractedString>>,
        query: &str,
        minimum: usize,
    ) -> bool {
        Arc::ptr_eq(&self.strings, strings) && self.query == query && self.minimum == minimum
    }

    pub fn new(strings: Arc<Vec<ExtractedString>>, query: String, minimum: usize) -> Self {
        let indices = strings
            .iter()
            .enumerate()
            .filter_map(|(index, string)| {
                (string.value.chars().take(minimum).count() >= minimum
                    && (query.is_empty() || string.value.to_lowercase().contains(&query)))
                .then_some(index)
            })
            .collect();
        Self {
            strings,
            query,
            minimum,
            indices: Arc::new(indices),
        }
    }
}

#[cfg(test)]
mod string_filter_tests {
    use super::*;

    #[test]
    fn string_filter_preserves_unicode_length_and_invalidates_on_input_changes() {
        let strings = Arc::new(vec![
            ExtractedString {
                offset: 0,
                encoding: bytetrawl_analysis::StringEncoding::Utf8,
                value: "你好世界".into(),
                section: None,
                virtual_address: None,
            },
            ExtractedString {
                offset: 20,
                encoding: bytetrawl_analysis::StringEncoding::Ascii,
                value: "HELLO".into(),
                section: None,
                virtual_address: None,
            },
        ]);
        let filter = StringFilter::new(strings.clone(), String::new(), 4);
        assert_eq!(*filter.indices, vec![0, 1]);
        assert!(filter.matches(&strings, "", 4));
        assert!(!filter.matches(&strings, "hello", 4));
        assert!(!filter.matches(&strings, "", 5));
        assert!(!filter.matches(&Arc::new((*strings).clone()), "", 4));
        let filter = StringFilter::new(strings.clone(), "hello".into(), 4);
        assert_eq!(*filter.indices, vec![1]);
        let filter = StringFilter::new(strings, String::new(), 5);
        assert_eq!(*filter.indices, vec![1]);
    }
}

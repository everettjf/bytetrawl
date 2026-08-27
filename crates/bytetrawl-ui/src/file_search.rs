#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FileSearchMode {
    #[default]
    Text,
    Bytes,
}

pub fn parse_search_bytes(query: &str, mode: FileSearchMode) -> Result<Vec<u8>, String> {
    match mode {
        FileSearchMode::Text => Ok(query.as_bytes().to_vec()),
        FileSearchMode::Bytes => {
            let compact: String = query
                .trim()
                .strip_prefix("0x")
                .unwrap_or(query.trim())
                .chars()
                .filter(|character| !character.is_ascii_whitespace() && *character != '_')
                .collect();
            if compact.is_empty()
                || !compact.len().is_multiple_of(2)
                || !compact.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err("Byte search expects an even number of hexadecimal digits".into());
            }
            (0..compact.len())
                .step_by(2)
                .map(|index| {
                    u8::from_str_radix(&compact[index..index + 2], 16)
                        .map_err(|error| error.to_string())
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_mode_is_unambiguous() {
        assert_eq!(
            parse_search_bytes("dead", FileSearchMode::Text),
            Ok(b"dead".to_vec())
        );
        assert_eq!(
            parse_search_bytes("de ad", FileSearchMode::Bytes),
            Ok(vec![0xde, 0xad])
        );
        assert!(parse_search_bytes("abc", FileSearchMode::Bytes).is_err());
    }
}

use crate::error::Error;
use std::collections::BTreeMap;

pub fn parse_env_bytes(input: &[u8]) -> Result<BTreeMap<String, String>, Error> {
    let content = std::str::from_utf8(input)
        .map_err(|err| Error::EnvParse(format!("env file is not valid utf-8: {}", err)))?;
    let mut vars = BTreeMap::new();

    for (index, raw_line) in content.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let line = line
            .strip_prefix("export ")
            .map(str::trim_start)
            .unwrap_or(line);
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            return Err(Error::EnvParse(format!(
                "line {} must contain KEY=VALUE",
                line_number
            )));
        };

        let key = raw_key.trim();
        if key.is_empty() {
            return Err(Error::EnvParse(format!(
                "line {} has an empty key",
                line_number
            )));
        }
        if !validate_env_key(key) {
            return Err(Error::EnvParse(format!(
                "line {} has an invalid key '{}'",
                line_number, key
            )));
        }

        let value = parse_value(raw_value.trim(), line_number)?;
        vars.insert(key.to_string(), value);
    }

    Ok(vars)
}

fn parse_value(raw_value: &str, line_number: usize) -> Result<String, Error> {
    if raw_value.starts_with('"') {
        return parse_double_quoted(raw_value, line_number);
    }
    if raw_value.starts_with('\'') {
        return parse_single_quoted(raw_value, line_number);
    }
    if let Some((value, _comment)) = raw_value.split_once(" #") {
        return Ok(value.trim_end().to_string());
    }
    Ok(raw_value.to_string())
}

fn parse_double_quoted(raw_value: &str, line_number: usize) -> Result<String, Error> {
    if !raw_value.ends_with('"') || raw_value.len() < 2 {
        return Err(Error::EnvParse(format!(
            "line {} has an unterminated double-quoted value",
            line_number
        )));
    }

    let inner = &raw_value[1..raw_value.len() - 1];
    let mut out = String::new();
    let mut escaped = false;
    for ch in inner.chars() {
        if escaped {
            let resolved = match ch {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '\\' => '\\',
                '"' => '"',
                other => other,
            };
            out.push(resolved);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
        } else {
            out.push(ch);
        }
    }

    if escaped {
        return Err(Error::EnvParse(format!(
            "line {} ends with an incomplete escape sequence",
            line_number
        )));
    }

    Ok(out)
}

fn parse_single_quoted(raw_value: &str, line_number: usize) -> Result<String, Error> {
    if !raw_value.ends_with('\'') || raw_value.len() < 2 {
        return Err(Error::EnvParse(format!(
            "line {} has an unterminated single-quoted value",
            line_number
        )));
    }
    Ok(raw_value[1..raw_value.len() - 1].to_string())
}

pub fn validate_env_key(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(ch) if ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::{parse_env_bytes, validate_env_key};

    #[test]
    fn parses_env_lines() {
        let vars = parse_env_bytes(
            br#"
            # comment
            export API_URL=https://example.com
            NAME="hello world"
            SINGLE='ok'
            RAW=value # comment
            "#,
        )
        .unwrap();

        assert_eq!(vars.get("API_URL").unwrap(), "https://example.com");
        assert_eq!(vars.get("NAME").unwrap(), "hello world");
        assert_eq!(vars.get("SINGLE").unwrap(), "ok");
        assert_eq!(vars.get("RAW").unwrap(), "value");
    }

    #[test]
    fn validates_env_keys() {
        assert!(validate_env_key("API_KEY"));
        assert!(!validate_env_key("1API_KEY"));
        assert!(!validate_env_key("API-KEY"));
    }
}

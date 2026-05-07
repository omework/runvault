use crate::error::Error;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Map, Number, Value};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtOptions {
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub subject: Option<String>,
    pub ttl_seconds: u64,
    pub claims: Vec<String>,
}

pub fn generate_hs256(secret: &str, options: &JwtOptions) -> Result<String, Error> {
    let now = current_unix_timestamp()?;
    let exp = now
        .checked_add(options.ttl_seconds)
        .ok_or_else(|| Error::Jwt("token expiration overflowed".to_string()))?;

    let mut claims = parse_custom_claims(&options.claims)?;
    claims.insert("iat".to_string(), Value::Number(Number::from(now)));
    claims.insert("exp".to_string(), Value::Number(Number::from(exp)));

    if let Some(issuer) = &options.issuer {
        claims.insert("iss".to_string(), Value::String(issuer.clone()));
    }
    if let Some(audience) = &options.audience {
        claims.insert("aud".to_string(), Value::String(audience.clone()));
    }
    if let Some(subject) = &options.subject {
        claims.insert("sub".to_string(), Value::String(subject.clone()));
    }

    let header = Header::new(Algorithm::HS256);
    encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|err| Error::Jwt(err.to_string()))
}

pub fn parse_ttl_seconds(input: &str) -> Result<u64, Error> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidDuration {
            value: input.to_string(),
        });
    }

    let (number_part, multiplier) = match trimmed.chars().last() {
        Some('s') => (&trimmed[..trimmed.len() - 1], 1_u64),
        Some('m') => (&trimmed[..trimmed.len() - 1], 60_u64),
        Some('h') => (&trimmed[..trimmed.len() - 1], 60_u64 * 60),
        Some('d') => (&trimmed[..trimmed.len() - 1], 60_u64 * 60 * 24),
        Some(ch) if ch.is_ascii_digit() => (trimmed, 1_u64),
        _ => {
            return Err(Error::InvalidDuration {
                value: input.to_string(),
            });
        }
    };

    let amount = number_part
        .parse::<u64>()
        .map_err(|_| Error::InvalidDuration {
            value: input.to_string(),
        })?;

    amount
        .checked_mul(multiplier)
        .ok_or_else(|| Error::InvalidDuration {
            value: input.to_string(),
        })
}

fn parse_custom_claims(values: &[String]) -> Result<Map<String, Value>, Error> {
    let mut claims = Map::new();
    for value in values {
        let Some((key, raw_value)) = value.split_once('=') else {
            return Err(Error::InvalidJwtClaim {
                value: value.clone(),
            });
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(Error::InvalidJwtClaim {
                value: value.clone(),
            });
        }
        if matches!(key, "iat" | "exp" | "iss" | "aud" | "sub") {
            return Err(Error::ReservedJwtClaim {
                key: key.to_string(),
            });
        }
        claims.insert(key.to_string(), Value::String(raw_value.to_string()));
    }
    Ok(claims)
}

fn current_unix_timestamp() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| Error::Jwt(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{JwtOptions, generate_hs256, parse_ttl_seconds};
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    use serde_json::{Map, Value};

    #[test]
    fn parses_ttl_with_suffixes() {
        assert_eq!(parse_ttl_seconds("30").unwrap(), 30);
        assert_eq!(parse_ttl_seconds("15m").unwrap(), 900);
        assert_eq!(parse_ttl_seconds("2h").unwrap(), 7200);
        assert_eq!(parse_ttl_seconds("1d").unwrap(), 86400);
    }

    #[test]
    fn rejects_invalid_ttl() {
        assert!(parse_ttl_seconds("abc").is_err());
        assert!(parse_ttl_seconds("10w").is_err());
    }

    #[test]
    fn generates_signed_token_with_standard_and_custom_claims() {
        let token = generate_hs256(
            "secret",
            &JwtOptions {
                issuer: Some("runvault".to_string()),
                audience: Some("tempo".to_string()),
                subject: Some("worker".to_string()),
                ttl_seconds: 60,
                claims: vec!["scope=traces.write".to_string()],
            },
        )
        .unwrap();

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["runvault"]);
        validation.set_audience(&["tempo"]);
        let decoded = decode::<Map<String, Value>>(
            &token,
            &DecodingKey::from_secret("secret".as_bytes()),
            &validation,
        )
        .unwrap();

        assert_eq!(decoded.claims.get("sub").unwrap(), "worker");
        assert_eq!(decoded.claims.get("scope").unwrap(), "traces.write");
        assert!(decoded.claims.get("iat").is_some());
        assert!(decoded.claims.get("exp").is_some());
    }
}

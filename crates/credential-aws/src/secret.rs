use std::fmt;

/// A value no log line, error message or `Debug` output may show: a secret
/// access key, a session token, an SSO access token. Only `env` hands one
/// back, through [`Secret::expose`].
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn debug_never_shows_the_value() {
        let secret = Secret::new("test-secret-value");
        assert_eq!(format!("{secret:?}"), "Secret(redacted)");
        assert_eq!(secret.expose(), "test-secret-value");
    }
}

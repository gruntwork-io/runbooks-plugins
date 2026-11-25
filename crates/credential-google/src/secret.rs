use std::fmt;

use serde::Deserialize;

/// A credential value: a private key, a refresh token, an access token, a
/// client secret, a whole credentials document. `Debug` prints a placeholder,
/// there is no `Display` or `Serialize`, and only [`Secret::expose`] reads it,
/// so a secret reaches output only where code asks for it by name.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
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
        f.write_str("Secret([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn debug_never_prints_the_value() {
        let secret = Secret::new("ya29.hunter2");
        assert_eq!(format!("{secret:?}"), "Secret([redacted])");
        assert_eq!(secret.expose(), "ya29.hunter2");
    }
}

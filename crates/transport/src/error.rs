use std::io;

use runbooks_plugin_protocol::base::RpcErrorData;
use runbooks_plugin_protocol::credential::{
    ErrorKind, Requirement, RequirementNotMetData, ToolMissingData,
};
use serde_json::Map;

/// An error a plugin method answers with. The app branches on its kind; the
/// message is for a person and never carries a secret.
#[derive(Clone, Debug, thiserror::Error)]
#[error("{kind}: {message}")]
pub struct PluginError {
    kind: ErrorKind,
    message: String,
    detail: Detail,
}

/// The fields of `data` beyond `kind` that some kinds carry.
#[derive(Clone, Debug)]
enum Detail {
    None,
    RequirementNotMet(RequirementNotMetData),
    ToolMissing(ToolMissingData),
}

impl PluginError {
    /// An error of `kind` with no fields beyond it.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            detail: Detail::None,
        }
    }

    /// Kind `requirementNotMet`, with the requirements the credential does not meet.
    pub fn requirement_not_met(unmet: Vec<Requirement>, message: impl Into<String>) -> Self {
        let kind = ErrorKind::RequirementNotMet;
        Self {
            kind,
            message: message.into(),
            detail: Detail::RequirementNotMet(RequirementNotMetData {
                kind: kind.to_string().into(),
                unmet,
            }),
        }
    }

    /// Kind `toolMissing`, with the tool's name and where to install it.
    pub fn tool_missing(
        tool: impl Into<String>,
        install_url: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let kind = ErrorKind::ToolMissing;
        Self {
            kind,
            message: message.into(),
            detail: Detail::ToolMissing(ToolMissingData {
                install_url: install_url.into(),
                kind: kind.to_string().into(),
                tool: tool.into(),
            }),
        }
    }

    /// What the app branches on.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// For a person to read. It never carries a secret.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The response's `data`: the kind, and the kind's own fields.
    pub(crate) fn data(&self) -> Result<RpcErrorData, serde_json::Error> {
        let detail = match &self.detail {
            Detail::None => {
                return Ok(RpcErrorData {
                    kind: self.kind.to_string(),
                    extra: Map::new(),
                });
            }
            Detail::RequirementNotMet(data) => serde_json::to_value(data)?,
            Detail::ToolMissing(data) => serde_json::to_value(data)?,
        };
        serde_json::from_value(detail)
    }
}

/// `name` as an error may show it: a name that isn't an identifier could be
/// pasted material.
#[must_use]
pub fn shown_name(name: &str) -> &str {
    let identifier = name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if identifier {
        name
    } else {
        "(a name that is not an identifier)"
    }
}

/// Why [`serve`](crate::serve) stopped before its input ended.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServeError {
    /// The input could not be read.
    #[error("reading the plugin's input")]
    Read(#[source] io::Error),
    /// The output could not be written.
    #[error("writing the plugin's output")]
    Write(#[source] io::Error),
    /// A bug: a generated protocol type failed to serialize.
    #[error("encoding a message")]
    Encode(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::shown_name;

    #[test]
    fn shown_name_shows_only_an_identifier_of_64_bytes_or_fewer() {
        let longest = format!("a_{}", "9".repeat(62));
        let too_long = format!("{longest}0");
        let hidden = "(a name that is not an identifier)";
        for (name, shown) in [
            ("noSuchField", "noSuchField"),
            (longest.as_str(), longest.as_str()),
            (too_long.as_str(), hidden),
            ("SENTINEL VALUE", hidden),
            ("tenant-id", hidden),
        ] {
            assert_eq!(shown_name(name), shown, "{name}");
        }
    }
}

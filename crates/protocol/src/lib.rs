//! The Runbooks plugin protocol: its version, and Rust types generated from
//! the JSON Schemas in `schema/`. [`base`] is the transport every plugin
//! kind shares; [`credential`] is the credential kind.

mod timestamp;

pub use timestamp::Timestamp;

/// The protocol version these types describe. A plugin answers `configure`
/// with any other version with error kind `unsupportedProtocolVersion`.
pub const PROTOCOL_VERSION: &str = "1";

/// The value of every message's `jsonrpc` member.
pub const JSONRPC_VERSION: &str = "2.0";

pub mod base {
    //! The transport every plugin kind shares, from `schema/base.schema.json`.

    include!(concat!(env!("OUT_DIR"), "/base.rs"));

    impl RpcErrorCode {
        /// Every error kind except `invalidParams`.
        pub const SERVER_ERROR: Self = Self(-32000);
        /// Kind `invalidParams`.
        pub const INVALID_PARAMS: Self = Self(-32602);
        /// A line that is not a request. Kind `invalidParams`.
        pub const INVALID_REQUEST: Self = Self(-32600);
        /// A method the plugin does not have. Kind `invalidParams`.
        pub const METHOD_NOT_FOUND: Self = Self(-32601);
        /// A line that is not JSON. Kind `invalidParams`.
        pub const PARSE_ERROR: Self = Self(-32700);
    }
}

pub mod credential {
    //! The credential kind, from `schema/credential.schema.json`.

    include!(concat!(env!("OUT_DIR"), "/credential.rs"));

    impl DetectResult {
        /// A credential found in `source` that matches the pins and meets the
        /// requirements.
        pub fn found(identity: Identity, source: impl Into<String>) -> Self {
            Self::Variant0 {
                found: true.into(),
                identity,
                source: source.into(),
            }
        }

        /// No source held a credential that matches.
        pub fn not_found() -> Self {
            Self::Variant1 {
                found: false.into(),
            }
        }
    }
}

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
}

pub mod credential {
    //! The credential kind, from `schema/credential.schema.json`.

    include!(concat!(env!("OUT_DIR"), "/credential.rs"));
}

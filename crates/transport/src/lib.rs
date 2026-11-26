//! The plugin's side of the Runbooks plugin transport: the JSON-RPC 2.0 loop
//! every credential binary runs, so none writes its own. A binary implements
//! [`CredentialPlugin`] and calls [`serve_stdio`].
//!
//! - One JSON object per line. Requests arrive on standard input; responses
//!   and notifications leave on standard output, and nothing else does. Logs
//!   go to standard error.
//! - `configure` comes first: any other call before one has succeeded gets
//!   error kind `notConfigured`. A `configure` for a protocol version other
//!   than [`PROTOCOL_VERSION`](runbooks_plugin_protocol::PROTOCOL_VERSION)
//!   gets `unsupportedProtocolVersion`.
//! - A call still running a second before the app's limit on its method,
//!   from `configure`'s `callTimeoutsMillis`, is cancelled and gets error
//!   kind `timedOut`. A `configure` is held to the limit it brings.
//! - Errors carry their kind in `data.kind`. A line that is not a request
//!   gets its JSON-RPC error code with kind `invalidParams`, and the next line
//!   is read. Unknown fields are ignored.
//! - Closing standard input stops the loop and cancels every call in flight.
//!   That is how a sign-in is cancelled.
//! - Only `env` returns secret values. The transport's own error messages
//!   never repeat a value from a request.

mod error;
mod line;
mod plugin;
mod serve;
mod wire;

pub use error::{PluginError, ServeError};
pub use plugin::{CredentialPlugin, Prompts};
pub use serve::{MAX_LINE_BYTES, serve, serve_stdio};

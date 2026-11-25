//! The protocol errors the plugin answers with. Each message says what to do
//! and never repeats a secret: the values it shows are regions, account ids,
//! ARNs, names, and AWS's own error codes and messages.

use runbooks_plugin_protocol::credential::ErrorKind;
use runbooks_plugin_transport::PluginError;

use crate::aws::{AwsError, AwsErrorKind};

/// Kind `invalidParams`: the call named something the plugin does not have.
pub(crate) fn invalid_params(error: &impl ToString) -> PluginError {
    PluginError::new(ErrorKind::InvalidParams, error.to_string())
}

/// An AWS call that failed while the plugin was `doing` something, such as
/// "checking the credentials in us-east-1".
pub(crate) fn aws(error: &AwsError, doing: &str) -> PluginError {
    let AwsError {
        service,
        kind,
        detail,
    } = error;
    let (kind, message) = match kind {
        AwsErrorKind::Refused => (
            ErrorKind::AccessDenied,
            format!(
                "AWS {service} refused the credentials while {doing} ({detail}): check them, or sign in again"
            ),
        ),
        AwsErrorKind::Expired => (
            ErrorKind::Expired,
            format!("the credentials have expired ({detail}): sign in again"),
        ),
        AwsErrorKind::Unavailable => (
            ErrorKind::Network,
            format!(
                "AWS {service} could not answer while {doing} ({detail}): try again in a moment"
            ),
        ),
        AwsErrorKind::Network => (
            ErrorKind::Network,
            format!(
                "could not reach AWS {service} while {doing} ({detail}): check the network connection and proxy"
            ),
        ),
        AwsErrorKind::TimedOut => (
            ErrorKind::TimedOut,
            format!(
                "AWS {service} did not answer in time while {doing} ({detail}): check the network connection and try again"
            ),
        ),
        AwsErrorKind::Tls => (
            ErrorKind::TlsError,
            format!(
                "the TLS connection to AWS {service} failed while {doing} ({detail}): if a proxy inspects TLS, give Runbooks its CA certificate"
            ),
        ),
        AwsErrorKind::Unexpected => (
            ErrorKind::Internal,
            format!("AWS {service} answered unexpectedly while {doing}: {detail}"),
        ),
    };
    PluginError::new(kind, message)
}

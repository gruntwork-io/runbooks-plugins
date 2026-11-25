//! Lines in and out: requests parsed into [`Request`], and responses and
//! notifications built from the generated protocol types.

use std::fmt;

use runbooks_plugin_protocol::JSONRPC_VERSION;
use runbooks_plugin_protocol::base::{
    ErrorResponse, Id, Notification, NotificationParams, Request as WireRequest, ResultResponse,
    RpcError, RpcErrorCode, RpcErrorData,
};
use runbooks_plugin_protocol::credential::{ErrorKind, SignInPrompt};
use serde::Deserialize;
use serde_json::{Map, Value};

const SIGN_IN_PROMPT: &str = "signIn.prompt";

/// A credential plugin's methods: a closed set the loop dispatches on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RpcMethod {
    Configure,
    Detect,
    SignIn,
    Targets,
    Select,
    Env,
    SignOut,
}

impl RpcMethod {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "configure" => Some(Self::Configure),
            "detect" => Some(Self::Detect),
            "signIn" => Some(Self::SignIn),
            "targets" => Some(Self::Targets),
            "select" => Some(Self::Select),
            "env" => Some(Self::Env),
            "signOut" => Some(Self::SignOut),
            _ => None,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Configure => "configure",
            Self::Detect => "detect",
            Self::SignIn => "signIn",
            Self::Targets => "targets",
            Self::Select => "select",
            Self::Env => "env",
            Self::SignOut => "signOut",
        }
    }
}

impl fmt::Display for RpcMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A line that parsed as a request for one of the plugin's methods.
pub(crate) struct Request {
    pub(crate) id: Id,
    pub(crate) method: RpcMethod,
    pub(crate) params: Map<String, Value>,
}

/// A line the plugin cannot answer as a call: it gets a JSON-RPC error code
/// with kind `invalidParams`, and the request's id if one could be read.
pub(crate) struct Rejection {
    pub(crate) id: Option<Id>,
    pub(crate) code: RpcErrorCode,
    pub(crate) message: String,
}

impl Rejection {
    pub(crate) fn too_long(max: usize) -> Self {
        Self {
            id: None,
            code: RpcErrorCode::INVALID_REQUEST,
            message: format!("the line is longer than {max} bytes"),
        }
    }
}

pub(crate) fn read_request(line: &[u8]) -> Result<Request, Rejection> {
    // A syntax error names a position, never the line's content.
    let value: Value = serde_json::from_slice(line).map_err(|error| Rejection {
        id: None,
        code: RpcErrorCode::PARSE_ERROR,
        message: format!("the line is not JSON: {error}"),
    })?;
    let id = value.get("id").and_then(|id| Id::deserialize(id).ok());
    let invalid = |message: &str| Rejection {
        id: id.clone(),
        code: RpcErrorCode::INVALID_REQUEST,
        message: message.to_owned(),
    };
    let request: WireRequest = serde_json::from_value(value).map_err(|_mismatch| {
        invalid("the line is not a request: it needs jsonrpc, an integer or string id, a method, and params that are an object")
    })?;
    if request.jsonrpc != JSONRPC_VERSION {
        return Err(invalid("jsonrpc must be \"2.0\""));
    }
    let Some(method) = RpcMethod::parse(&request.method) else {
        return Err(Rejection {
            id: Some(request.id),
            code: RpcErrorCode::METHOD_NOT_FOUND,
            message: format!("a credential plugin has no method {:?}", request.method),
        });
    };
    Ok(Request {
        id: request.id,
        method,
        params: request.params,
    })
}

pub(crate) fn result_line(id: Id, result: Map<String, Value>) -> serde_json::Result<String> {
    serde_json::to_string(&ResultResponse {
        id,
        jsonrpc: JSONRPC_VERSION.into(),
        result,
    })
}

pub(crate) fn rejection_line(rejection: Rejection) -> serde_json::Result<String> {
    error_line(
        rejection.id,
        rejection.code,
        rejection.message,
        RpcErrorData {
            kind: ErrorKind::InvalidParams.to_string(),
            extra: Map::new(),
        },
    )
}

/// The code follows the kind: `invalidParams` has its JSON-RPC code, and
/// every other kind shares the server error code.
pub(crate) fn plugin_error_line(id: Id, error: &crate::PluginError) -> serde_json::Result<String> {
    let code = match error.kind() {
        ErrorKind::InvalidParams => RpcErrorCode::INVALID_PARAMS,
        ErrorKind::NotConfigured
        | ErrorKind::UnsupportedProtocolVersion
        | ErrorKind::NotSignedIn
        | ErrorKind::Expired
        | ErrorKind::PinMismatch
        | ErrorKind::RequirementNotMet
        | ErrorKind::AccessDenied
        | ErrorKind::Cancelled
        | ErrorKind::TimedOut
        | ErrorKind::Network
        | ErrorKind::TlsError
        | ErrorKind::ToolMissing
        | ErrorKind::Internal => RpcErrorCode::SERVER_ERROR,
    };
    error_line(Some(id), code, error.message().to_owned(), error.data()?)
}

fn error_line(
    id: Option<Id>,
    code: RpcErrorCode,
    message: String,
    data: RpcErrorData,
) -> serde_json::Result<String> {
    serde_json::to_string(&ErrorResponse {
        error: RpcError {
            code,
            data,
            message,
        },
        id,
        jsonrpc: JSONRPC_VERSION.into(),
    })
}

pub(crate) fn sign_in_prompt_line(prompt: &SignInPrompt) -> serde_json::Result<String> {
    let params: NotificationParams = serde_json::from_value(serde_json::to_value(prompt)?)?;
    serde_json::to_string(&Notification {
        jsonrpc: JSONRPC_VERSION.into(),
        method: SIGN_IN_PROMPT.to_owned(),
        params,
    })
}

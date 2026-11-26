use std::future::Future;

use runbooks_plugin_protocol::base::Id;
use runbooks_plugin_protocol::credential::{
    ConfigureParams, ConfigureResult, DetectParams, DetectResult, EnvResult, ErrorKind,
    SelectParams, SelectResult, SignInParams, SignInPrompt, SignInPromptKind, SignInResult,
    SignOutResult, TargetsParams, TargetsResult,
};
use tokio::sync::mpsc;

use crate::PluginError;
use crate::{serve, wire};

/// A credential plugin: one method per protocol method, each given its
/// parsed params. [`serve`](crate::serve) runs calls concurrently, so each
/// takes `&self`.
///
/// Dropping a call's future cancels it: when standard input closes, every
/// call in flight stops at its next await. A method that starts a child
/// process should have it killed on drop.
pub trait CredentialPlugin: Send + Sync + 'static {
    /// Called once the protocol version has been checked. Answers what the
    /// plugin offers. Every other method is refused with `notConfigured`
    /// until a `configure` has succeeded.
    fn configure(
        &self,
        params: ConfigureParams,
    ) -> impl Future<Output = Result<ConfigureResult, PluginError>> + Send;

    /// Looks in the sources for a credential that matches the pins and meets
    /// the requirements, without signing in.
    fn detect(
        &self,
        params: DetectParams,
    ) -> impl Future<Output = Result<DetectResult, PluginError>> + Send;

    /// Tells the person what to do through `prompts` while it waits.
    fn sign_in(
        &self,
        params: SignInParams,
        prompts: Prompts,
    ) -> impl Future<Output = Result<SignInResult, PluginError>> + Send;

    /// The targets at one level, under a parent target if the level has one.
    fn targets(
        &self,
        params: TargetsParams,
    ) -> impl Future<Output = Result<TargetsResult, PluginError>> + Send;

    /// Takes the chosen target at each level.
    fn select(
        &self,
        params: SelectParams,
    ) -> impl Future<Output = Result<SelectResult, PluginError>> + Send;

    /// The only method that returns secret values.
    fn env(&self) -> impl Future<Output = Result<EnvResult, PluginError>> + Send;

    /// Drops the credential the plugin holds.
    fn sign_out(&self) -> impl Future<Output = Result<SignOutResult, PluginError>> + Send;
}

/// Sends `signIn.prompt` notifications for one `signIn` call. Each names that
/// call's request, so the app shows it on the right block.
#[derive(Clone, Debug)]
pub struct Prompts {
    request: Id,
    lines: mpsc::Sender<String>,
}

impl Prompts {
    pub(crate) const fn new(request: Id, lines: mpsc::Sender<String>) -> Self {
        Self { request, lines }
    }

    /// Asks the person to open `url`, with the `code` to enter there if it
    /// needs one.
    ///
    /// # Errors
    ///
    /// Kind `cancelled` if the plugin's output has closed, or `internal` if
    /// the prompt is longer than a line may be.
    pub async fn open_url(
        &self,
        url: impl Into<String>,
        code: Option<String>,
    ) -> Result<(), PluginError> {
        self.send(SignInPromptKind::OpenUrl, Some(url.into()), code)
            .await
    }

    /// Shows the person a code to enter somewhere they already are.
    ///
    /// # Errors
    ///
    /// Kind `cancelled` if the plugin's output has closed, or `internal` if
    /// the prompt is longer than a line may be.
    pub async fn show_code(&self, code: impl Into<String>) -> Result<(), PluginError> {
        self.send(SignInPromptKind::ShowCode, None, Some(code.into()))
            .await
    }

    /// Tells the person the sign-in is waiting on them.
    ///
    /// # Errors
    ///
    /// Kind `cancelled` if the plugin's output has closed, or `internal` if
    /// the prompt is longer than a line may be.
    pub async fn waiting(&self) -> Result<(), PluginError> {
        self.send(SignInPromptKind::Waiting, None, None).await
    }

    async fn send(
        &self,
        kind: SignInPromptKind,
        url: Option<String>,
        code: Option<String>,
    ) -> Result<(), PluginError> {
        let prompt = SignInPrompt {
            code,
            kind,
            request: self.request.clone(),
            url,
        };
        let line = wire::sign_in_prompt_line(&prompt).map_err(|error| {
            PluginError::new(
                ErrorKind::Internal,
                format!("encoding a signIn.prompt: {error}"),
            )
        })?;
        let line = serve::fit(line, "a signIn.prompt")?;
        self.lines
            .send(line)
            .await
            .map_err(|_closed| PluginError::new(ErrorKind::Cancelled, "the plugin is stopping"))
    }
}

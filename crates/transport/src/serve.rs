use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::num::NonZeroU64;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use runbooks_plugin_protocol::PROTOCOL_VERSION;
use runbooks_plugin_protocol::base::Id;
use runbooks_plugin_protocol::credential::{ConfigureParams, ErrorKind};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::task::{self, JoinError, JoinSet};
use tokio::time;

use crate::line::{Line, LineReader};
use crate::wire::{self, Rejection, Request, RpcMethod};
use crate::{CredentialPlugin, PluginError, Prompts, ServeError};

/// The longest line the plugin reads. A longer one is answered as an invalid
/// request and skipped. The app caps the plugin's own lines at the same size.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// Calls answered at once. With this many in flight, the plugin reads no
/// further line until one finishes.
pub(crate) const MAX_CALLS: usize = 16;

/// Lines waiting to be written to the output.
const OUTPUT_QUEUE: usize = 64;

/// How long before its method's limit a call still running is answered
/// `timedOut`.
const ANSWER_BEFORE_LIMIT: Duration = Duration::from_secs(1);

/// Answers requests from `input` with `plugin` until `input` ends.
///
/// Writes responses and notifications to `output`. Returns `Ok` once `input`
/// has ended, every call still in flight has been cancelled, and every line
/// already answered has been written.
///
/// # Errors
///
/// [`ServeError`] if reading `input` or writing `output` fails.
pub async fn serve<P, R, W>(plugin: P, input: R, output: W) -> Result<(), ServeError>
where
    P: CredentialPlugin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (lines, queue) = mpsc::channel(OUTPUT_QUEUE);
    let calls = Calls {
        plugin: Arc::new(plugin),
        lines,
        running: JoinSet::new(),
        open: HashMap::new(),
        limits: Arc::default(),
    };
    let write = async { write_lines(queue, output).await.map_err(ServeError::Write) };
    tokio::try_join!(calls.run(BufReader::new(input)), write)?;
    Ok(())
}

/// Runs `plugin` on this process's standard input and output.
///
/// # Errors
///
/// [`ServeError`] if reading standard input or writing standard output fails.
pub async fn serve_stdio<P: CredentialPlugin>(plugin: P) -> Result<(), ServeError> {
    serve(plugin, tokio::io::stdin(), tokio::io::stdout()).await
}

/// The only writer of the output: one line per message, flushed as it goes.
async fn write_lines<W: AsyncWrite + Unpin>(
    mut queue: mpsc::Receiver<String>,
    mut output: W,
) -> io::Result<()> {
    while let Some(line) = queue.recv().await {
        output.write_all(line.as_bytes()).await?;
        output.write_all(b"\n").await?;
        output.flush().await?;
    }
    Ok(())
}

type Outcome = Result<Map<String, Value>, PluginError>;

/// The app's limit on each method's answer: `configure`'s `callTimeoutsMillis`.
struct Limits(HashMap<String, NonZeroU64>);

struct Calls<P> {
    plugin: Arc<P>,
    lines: mpsc::Sender<String>,
    running: JoinSet<Outcome>,
    /// The request id of every task in `running`, so a call whose task
    /// panicked is still answered.
    open: HashMap<task::Id, Id>,
    /// Set by the first `configure` that succeeds, before its response is
    /// written, so the app cannot send a call that finds them unset after
    /// reading that response.
    limits: Arc<OnceLock<Limits>>,
}

impl<P: CredentialPlugin> Calls<P> {
    async fn run<R: AsyncBufRead + Unpin>(mut self, input: R) -> Result<(), ServeError> {
        let mut reader = LineReader::new(input, MAX_LINE_BYTES);
        loop {
            tokio::select! {
                line = reader.next_line(), if self.running.len() < MAX_CALLS => {
                    match line.map_err(ServeError::Read)? {
                        Some(line) => self.answer(line).await?,
                        None => break,
                    }
                }
                Some(joined) = self.running.join_next_with_id() => self.finish(joined).await?,
            }
        }
        // The input has ended: cancel every call still in flight. Their
        // responses would have no reader.
        self.running.shutdown().await;
        Ok(())
    }

    async fn answer(&mut self, line: Line) -> Result<(), ServeError> {
        let request = match line {
            Line::Complete(bytes) => wire::read_request(&bytes),
            Line::TooLong => Err(Rejection::too_long(MAX_LINE_BYTES)),
        };
        match request {
            Err(rejection) => self.write(wire::rejection_line(rejection)?).await,
            Ok(Request { id, method, .. })
                if self.limits.get().is_none() && method != RpcMethod::Configure =>
            {
                let error = PluginError::new(
                    ErrorKind::NotConfigured,
                    format!("{method} was called before configure"),
                );
                self.write(wire::plugin_error_line(id, &error)?).await
            }
            Ok(Request { id, method, params }) => {
                let prompts = Prompts::new(id.clone(), self.lines.clone());
                let task = self.running.spawn(call(
                    Arc::clone(&self.plugin),
                    Arc::clone(&self.limits),
                    method,
                    params,
                    prompts,
                ));
                self.open.insert(task.id(), id);
                Ok(())
            }
        }
    }

    async fn finish(
        &mut self,
        joined: Result<(task::Id, Outcome), JoinError>,
    ) -> Result<(), ServeError> {
        let (task, outcome) = match joined {
            Ok(finished) => finished,
            // Aborts happen only after the loop, so this is a panic. Its
            // message stays on standard error: it may hold anything.
            Err(failed) => (
                failed.id(),
                Err(PluginError::new(
                    ErrorKind::Internal,
                    "the plugin failed while answering",
                )),
            ),
        };
        // Every task in `running` was recorded when `answer` spawned it.
        let Some(id) = self.open.remove(&task) else {
            return Ok(());
        };
        let line = match outcome {
            Ok(result) => wire::result_line(id, result)?,
            Err(error) => wire::plugin_error_line(id, &error)?,
        };
        self.write(line).await
    }

    async fn write(&self, line: String) -> Result<(), ServeError> {
        // The queue closes only when `write_lines` has failed, and `serve`
        // returns that error, not this one.
        self.lines
            .send(line)
            .await
            .map_err(|_closed| ServeError::Write(io::ErrorKind::BrokenPipe.into()))
    }
}

/// One call, within the app's limit on its method: its params parsed into
/// the method's type, the plugin's answer, and that answer as the response's
/// `result`. A `configure` is held to the limits it brings, and sets them for
/// every later call once it succeeds.
async fn call<P: CredentialPlugin>(
    plugin: Arc<P>,
    limits: Arc<OnceLock<Limits>>,
    method: RpcMethod,
    params: Map<String, Value>,
    prompts: Prompts,
) -> Outcome {
    let answer = async {
        match method {
            RpcMethod::Configure => {
                let params: ConfigureParams = parse(method, params)?;
                if params.protocol_version != PROTOCOL_VERSION {
                    return Err(PluginError::new(
                        ErrorKind::UnsupportedProtocolVersion,
                        format!(
                            "protocol version {:?} is not supported: this plugin speaks {PROTOCOL_VERSION:?}",
                            params.protocol_version
                        ),
                    ));
                }
                let asked = Limits(params.call_timeouts_millis.clone());
                let answer = within(Some(&asked), method, plugin.configure(params)).await?;
                let result = result(method, answer)?;
                limits.get_or_init(|| asked);
                Ok(result)
            }
            RpcMethod::Detect => result(method, plugin.detect(parse(method, params)?).await?),
            RpcMethod::SignIn => result(
                method,
                plugin.sign_in(parse(method, params)?, prompts).await?,
            ),
            RpcMethod::Targets => result(method, plugin.targets(parse(method, params)?).await?),
            RpcMethod::Select => result(method, plugin.select(parse(method, params)?).await?),
            RpcMethod::Env => result(method, plugin.env().await?),
            RpcMethod::SignOut => result(method, plugin.sign_out().await?),
        }
    };
    within(limits.get(), method, answer).await
}

/// `answer`, or `timedOut` once it has run until a second before the app's
/// limit on `method`. A method with no limit waits for its answer.
async fn within<T>(
    limits: Option<&Limits>,
    method: RpcMethod,
    answer: impl Future<Output = Result<T, PluginError>>,
) -> Result<T, PluginError> {
    let Some(limit) = limits.and_then(|limits| limits.0.get(method.name())) else {
        return answer.await;
    };
    let wait = Duration::from_millis(limit.get()).saturating_sub(ANSWER_BEFORE_LIMIT);
    time::timeout(wait, answer)
        .await
        .unwrap_or_else(|_elapsed| {
            Err(PluginError::new(
                ErrorKind::TimedOut,
                format!("{method} did not finish in time: the app waits {limit} ms for it"),
            ))
        })
}

fn parse<T: DeserializeOwned>(
    method: RpcMethod,
    params: Map<String, Value>,
) -> Result<T, PluginError> {
    // serde's message can quote the value it refused, which may be a secret
    // typed into a sign-in field, so it is dropped.
    serde_json::from_value(Value::Object(params)).map_err(|_refused| {
        PluginError::new(
            ErrorKind::InvalidParams,
            format!(
                "the params of {method} do not match credential.schema.json#/$defs/{method}Params"
            ),
        )
    })
}

fn result<T: Serialize>(method: RpcMethod, answer: T) -> Outcome {
    match serde_json::to_value(answer) {
        Ok(Value::Object(result)) => Ok(result),
        Ok(_) | Err(_) => Err(PluginError::new(
            ErrorKind::Internal,
            format!("the plugin's {method} result is not a JSON object"),
        )),
    }
}

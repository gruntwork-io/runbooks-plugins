//! Runs the binary that ships, with the real AWS SDK, and no network: its
//! only route out is the proxy `configure` names, on a loopback port that
//! refuses every tunnel.

use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

#[path = "support/tls.rs"]
mod tls;

type TestResult = Result<(), Box<dyn Error>>;

/// Longer than a refused loopback connection takes, even on Windows.
const WAIT: Duration = Duration::from_secs(30);

const SECRET: &str = "test-secret-access-key-as-long-as-a-real";

/// The member of `value` at JSON Pointer `pointer`, or `null` if there is none.
fn at(value: &Value, pointer: &str) -> Value {
    value.pointer(pointer).cloned().unwrap_or(Value::Null)
}

/// What Runbooks sends in `callTimeoutsMillis`.
fn runbooks_limits() -> Value {
    json!({"configure": 30_000, "detect": 120_000, "targets": 120_000, "select": 120_000, "env": 120_000, "signOut": 60_000, "signIn": 900_000})
}

/// A proxy on a loopback port that refuses every tunnel, and the first line
/// of each request it got.
fn refusing_proxy() -> std::io::Result<(String, Arc<Mutex<Vec<String>>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}", listener.local_addr()?);
    let asked = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&asked);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let _refused: std::io::Result<()> = stream.and_then(|stream| refuse(&stream, &seen));
        }
    });
    Ok((url, asked))
}

fn refuse(stream: &TcpStream, seen: &Mutex<Vec<String>>) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut head = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.trim_end().is_empty() {
            break;
        }
        head.push(line.trim_end().to_owned());
    }
    seen.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(head.join("\n"));
    let mut stream = reader.into_inner();
    stream.write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
}

/// The hosts the proxy was asked to tunnel to, a retry's repeats once.
/// Fails if any request showed the secret.
fn tunnels(asked: &Mutex<Vec<String>>) -> Vec<String> {
    let asked = asked.lock().unwrap_or_else(PoisonError::into_inner).clone();
    assert!(asked.iter().all(|head| !head.contains(SECRET)), "{asked:?}");
    let mut hosts: Vec<String> = asked
        .iter()
        .map(|head| head.strip_prefix("CONNECT ").unwrap_or(head))
        .filter_map(|target| Some(target.split(' ').next()?.to_owned()))
        .collect();
    hosts.dedup();
    hosts
}

#[test]
fn the_binary_answers_over_stdio_and_reports_an_unreachable_aws_as_network() -> TestResult {
    let (proxy, asked) = refusing_proxy()?;
    // The environment's proxy, on a port that was free a moment ago, is
    // not the plugin's: only the app's `proxy` is.
    let closed_port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let env_proxy = format!("http://127.0.0.1:{closed_port}");
    let mut command = Command::new(env!("CARGO_BIN_EXE_runbooks-credential-aws"));
    command
        .env_clear()
        .env("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
        .env("AWS_SECRET_ACCESS_KEY", SECRET)
        .env("HTTPS_PROXY", &env_proxy)
        .env("ALL_PROXY", &env_proxy)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Windows cannot open a socket without SystemRoot.
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take().ok_or("stdin")?;
    let stdout = child.stdout.take().ok_or("stdout")?;

    let (lines, received) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let mut call = move |id: i64, method: &str, params: Value| -> Result<Value, Box<dyn Error>> {
        let request = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(stdin, "{request}")?;
        let line = received.recv_timeout(WAIT)??;
        Ok(serde_json::from_str(&line)?)
    };

    // A CA bundle the real client cannot use is refused by name, and a
    // proxy is never repeated.
    let not_a_bundle = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let not_a_bundle = not_a_bundle.to_str().ok_or("a UTF-8 path")?;
    let refused = call(
        1,
        "configure",
        json!({"protocolVersion": "1", "caller": "runbooks/0.31.0", "stateDir": "/unused",
            "callTimeoutsMillis": runbooks_limits(), "caBundleFile": not_a_bundle, "proxy": proxy}),
    )?;
    assert_eq!(
        at(&refused, "/error/message"),
        format!("caBundleFile {not_a_bundle} holds no PEM certificate"),
        "{refused}"
    );
    let certificates = tempfile::tempdir()?;
    tls::make_certificates(certificates.path())?;
    let bundle = certificates.path().join("ca.pem");
    let configured = call(
        2,
        "configure",
        json!({"protocolVersion": "1", "caller": "runbooks/0.31.0", "stateDir": "/unused",
            "callTimeoutsMillis": runbooks_limits(),
            "caBundleFile": bundle.to_str().ok_or("a UTF-8 path")?, "proxy": proxy}),
    )?;
    assert_eq!(at(&configured, "/result/cloud"), "aws", "{configured}");

    let detected = call(
        3,
        "detect",
        json!({"sources": [{"kind": "env"}], "pins": {}, "requirements": []}),
    )?;
    assert_eq!(at(&detected, "/error/data/kind"), "network", "{detected}");
    let message = detected
        .pointer("/error/message")
        .and_then(Value::as_str)
        .ok_or("message")?;
    assert!(
        message.contains("STS") && message.contains("us-east-1"),
        "{message}"
    );

    // The SSO sign-in's first call takes the same route out.
    let signed_in = call(
        4,
        "signIn",
        json!({"method": "sso", "fields": {"ssoStartUrl": "https://my-org.awsapps.com/start", "ssoRegion": "eu-west-1"}, "pins": {}, "requirements": []}),
    )?;
    assert_eq!(at(&signed_in, "/error/data/kind"), "network", "{signed_in}");
    let message = signed_in
        .pointer("/error/message")
        .and_then(Value::as_str)
        .ok_or("message")?;
    assert!(
        message.contains("SSO OIDC") && message.contains("eu-west-1"),
        "{message}"
    );

    assert_eq!(
        tunnels(&asked),
        [
            "sts.us-east-1.amazonaws.com:443",
            "oidc.eu-west-1.amazonaws.com:443"
        ]
    );

    // Closing standard input, which `call` owns, stops the plugin.
    drop(call);
    let (exited, status) = mpsc::channel();
    thread::spawn(move || {
        // The test has already failed if nothing is waiting for this.
        let _unwatched = exited.send(child.wait());
    });
    assert!(status.recv_timeout(WAIT)??.success());
    Ok(())
}

#[test]
fn the_binary_exits_with_failure_when_it_cannot_write_its_output_or_its_error() -> TestResult {
    let mut child = Command::new(env!("CARGO_BIN_EXE_runbooks-credential-aws"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // With both readers gone, writing the answer fails, and so does writing
    // that failure to standard error.
    drop(child.stdout.take());
    drop(child.stderr.take());
    let mut stdin = child.stdin.take().ok_or("stdin")?;
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "configure", "params": {
        "protocolVersion": "1", "caller": "runbooks/0.31.0", "stateDir": "/unused",
        "callTimeoutsMillis": runbooks_limits()}});
    writeln!(stdin, "{request}")?;

    let (exited, status) = mpsc::channel();
    thread::spawn(move || {
        // The test has already failed if nothing is waiting for this.
        let _unwatched = exited.send(child.wait());
    });
    // Standard input stays open: the failed write alone ends the plugin.
    let status = status.recv_timeout(WAIT)??;
    drop(stdin);
    assert_eq!(status.code(), Some(1), "{status}");
    Ok(())
}

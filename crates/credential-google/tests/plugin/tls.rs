//! The real HTTPS client through a proxy that inspects TLS, as some networks
//! run: it opens each tunnel itself and answers inside it with a certificate
//! its own CA signed. The plugin trusts it only when `caBundleFile` holds
//! that CA. Every connection stays on loopback.

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;

use runbooks_credential_google::{GooglePlugin, HttpApi};
use runbooks_plugin_protocol::PROTOCOL_VERSION;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{Map, Value, json};

use crate::support::{
    App, BARE_TOKEN, CLOUD_PLATFORM, NOW, TestResult, USER_EMAIL, WAIT, at, detect, host,
    openssl_output, runbooks_limits,
};

/// A self-signed CA. Made fresh each time, no platform trusts it.
const CA_CONFIG: &str = "\
[req]
prompt = no
distinguished_name = dn
x509_extensions = ext
[dn]
CN = Runbooks Google plugin test CA (tests only)
[ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign
subjectKeyIdentifier = hash
";

/// The certificate the proxy answers with, for Google's API hosts.
const GOOGLE_CONFIG: &str = "\
[req]
prompt = no
distinguished_name = dn
[dn]
CN = oauth2.googleapis.com
[ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:oauth2.googleapis.com,DNS:cloudresourcemanager.googleapis.com
";

/// An EC P-256 key, its curve named: rustls takes only a named curve, and
/// macOS's openssl writes the curve's parameters out in full unless told.
const P256: [&str; 6] = [
    "-algorithm",
    "EC",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-pkeyopt",
    "ec_param_enc:named_curve",
];

/// The longest request head the proxy reads.
const MAX_HEAD: u64 = 64 * 1024;

/// Writes to `dir` a new test CA, `ca.pem`, and a certificate it signs for
/// Google's API hosts, `google.pem`, with its key, `google-key.pem`. All are
/// EC P-256 and valid for two days. A missing `openssl` fails the test.
fn make_certificates(dir: &Path) -> TestResult {
    fs::write(dir.join("ca.cnf"), CA_CONFIG)?;
    fs::write(dir.join("google.cnf"), GOOGLE_CONFIG)?;
    let openssl = |args: &[&str]| openssl_output(dir, args, b"");
    openssl(&[&["genpkey"], &P256[..], &["-out", "ca-key.pem"]].concat())?;
    openssl(&[
        "req",
        "-new",
        "-x509",
        "-config",
        "ca.cnf",
        "-key",
        "ca-key.pem",
        "-sha256",
        "-days",
        "2",
        "-out",
        "ca.pem",
    ])?;
    openssl(&[&["genpkey"], &P256[..], &["-out", "google-key.pem"]].concat())?;
    openssl(&[
        "req",
        "-new",
        "-config",
        "google.cnf",
        "-key",
        "google-key.pem",
        "-sha256",
        "-out",
        "google.csr",
    ])?;
    openssl(&[
        "x509",
        "-req",
        "-in",
        "google.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca-key.pem",
        "-set_serial",
        "2",
        "-sha256",
        "-days",
        "2",
        "-extfile",
        "google.cnf",
        "-extensions",
        "ext",
        "-out",
        "google.pem",
    ])?;
    Ok(())
}

/// A proxy on a loopback port that inspects TLS, with the certificates in
/// `dir`. Its URL, and the request line of every request it reads, the
/// tunnel's `CONNECT` among them.
fn inspecting_proxy(dir: &Path) -> TestResult<(String, Arc<Mutex<Vec<String>>>)> {
    let chain =
        CertificateDer::pem_file_iter(dir.join("google.pem"))?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(dir.join("google-key.pem"))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, key)?,
    );
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}", listener.local_addr()?);
    let lines = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&lines);
    thread::spawn(move || {
        for stream in listener.incoming() {
            // A connection that fails fails only its own call.
            let _served: io::Result<()> = stream.and_then(|stream| tunnel(stream, &config, &seen));
        }
    });
    Ok((url, lines))
}

/// Accepts the tunnel `stream` asks for but reaches nowhere: it answers the
/// one request inside itself, as tokeninfo would for the test's token.
fn tunnel(
    stream: TcpStream,
    config: &Arc<ServerConfig>,
    seen: &Mutex<Vec<String>>,
) -> io::Result<()> {
    stream.set_read_timeout(Some(WAIT))?;
    let connect = request_head((&stream).take(MAX_HEAD))?;
    seen.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(connect.line);
    (&stream).write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;

    let connection = ServerConnection::new(Arc::clone(config)).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(connection, stream);
    let request = request_head((&mut tls).take(MAX_HEAD))?;
    let lacks_length = request.lacks_length();
    seen.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(request.line);
    let (status, body) = if lacks_length {
        (
            "411 Length Required",
            "POST requests require a Content-length header.".to_owned(),
        )
    } else {
        let info = json!({
            "email": USER_EMAIL,
            "sub": "1234567890",
            "scope": CLOUD_PLATFORM,
            "exp": (NOW + 1800).to_string(),
        });
        ("200 OK", info.to_string())
    };
    write!(
        tls,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    tls.conn.send_close_notify();
    tls.flush()
}

/// A request's head: its request line and its header lines.
struct Head {
    line: String,
    headers: Vec<String>,
}

impl Head {
    /// Google answers 411 to a POST that gives its body no length.
    fn lacks_length(&self) -> bool {
        self.line.starts_with("POST ")
            && !self.headers.iter().any(|header| {
                header.split_once(':').is_some_and(|(name, _)| {
                    name.eq_ignore_ascii_case("content-length")
                        || name.eq_ignore_ascii_case("transfer-encoding")
                })
            })
    }
}

/// The head `stream` starts with. The client sends nothing past a tunnel's
/// head until it is answered, and the tokeninfo request has no body, so
/// nothing past the head is lost.
fn request_head(stream: impl Read) -> io::Result<Head> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 || header.trim_end().is_empty() {
            return Ok(Head {
                line: line.trim_end().to_owned(),
                headers,
            });
        }
        headers.push(header.trim_end().to_owned());
    }
}

/// Starts the plugin with its real HTTPS client and a bare access token in
/// the environment, and configures it with the `network` params, such as
/// `proxy`.
async fn start(dir: &Path, network: &[(&str, &str)]) -> TestResult<App> {
    let mut app = App::serving(GooglePlugin::new(
        host(&[("GOOGLE_OAUTH_ACCESS_TOKEN", BARE_TOKEN)]),
        Box::new(HttpApi::new),
    ))?;
    let state_dir = dir.join("state");
    let mut params = Map::from_iter([
        ("protocolVersion".to_owned(), json!(PROTOCOL_VERSION)),
        ("caller".to_owned(), json!("runbooks/0.31.0")),
        ("callTimeoutsMillis".to_owned(), runbooks_limits()),
        (
            "stateDir".to_owned(),
            json!(state_dir.to_str().ok_or("a temp dir is UTF-8")?),
        ),
    ]);
    params.extend(
        network
            .iter()
            .map(|(name, value)| ((*name).to_owned(), json!(value))),
    );
    app.ok("configure", "configureResult", Value::Object(params))
        .await?;
    Ok(app)
}

#[tokio::test]
async fn without_its_ca_a_proxy_that_inspects_tls_is_a_tls_error() -> TestResult {
    let dir = tempfile::tempdir()?;
    make_certificates(dir.path())?;
    let (proxy, seen) = inspecting_proxy(dir.path())?;
    let mut app = start(dir.path(), &[("proxy", &proxy)]).await?;

    app.error("detect", detect(&json!([{"kind": "env"}])), "tlsError")
        .await?;
    assert_eq!(
        *seen.lock().unwrap_or_else(PoisonError::into_inner),
        ["CONNECT oauth2.googleapis.com:443 HTTP/1.1"],
        "the handshake fails before any request"
    );
    for (method, line) in app.close().await? {
        assert!(!line.contains(BARE_TOKEN), "{method}: {line}");
    }
    Ok(())
}

#[tokio::test]
async fn with_its_ca_in_ca_bundle_file_the_plugin_reaches_google_through_it() -> TestResult {
    let dir = tempfile::tempdir()?;
    make_certificates(dir.path())?;
    let (proxy, seen) = inspecting_proxy(dir.path())?;
    let bundle = dir.path().join("ca.pem");
    let bundle = bundle.to_str().ok_or("a temp dir is UTF-8")?;
    let mut app = start(dir.path(), &[("proxy", &proxy), ("caBundleFile", bundle)]).await?;

    let found = app
        .ok("detect", "detectResult", detect(&json!([{"kind": "env"}])))
        .await?;
    assert_eq!(at(&found, "/identity/principal"), USER_EMAIL, "{found}");
    assert_eq!(
        *seen.lock().unwrap_or_else(PoisonError::into_inner),
        [
            "CONNECT oauth2.googleapis.com:443 HTTP/1.1",
            "POST /tokeninfo HTTP/1.1"
        ]
    );
    Ok(())
}

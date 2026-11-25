//! Test certificates, made when a test runs with the `openssl` CLI, so no
//! key is checked in. Shared by the unit tests, the protocol tests and the
//! binary's tests.

use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

/// A self-signed CA. Made fresh each time, no platform trusts it.
const CA_CONFIG: &str = "\
[req]
prompt = no
distinguished_name = dn
x509_extensions = ext
[dn]
CN = Runbooks AWS plugin test CA (tests only)
[ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign
subjectKeyIdentifier = hash
";

/// A server certificate for localhost and 127.0.0.1.
const LOCALHOST_CONFIG: &str = "\
[req]
prompt = no
distinguished_name = dn
[dn]
CN = localhost
[ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
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

/// Writes to `dir` a new test CA, `ca.pem`, and a certificate it signs for
/// localhost and 127.0.0.1, `localhost.pem`, with its key,
/// `localhost-key.pem`. All are EC P-256 and valid for two days.
///
/// A missing `openssl` fails the test.
pub(crate) fn make_certificates(dir: &Path) -> Result<(), Box<dyn Error>> {
    fs::write(dir.join("ca.cnf"), CA_CONFIG)?;
    fs::write(dir.join("localhost.cnf"), LOCALHOST_CONFIG)?;
    openssl(
        dir,
        &[&["genpkey"], &P256[..], &["-out", "ca-key.pem"]].concat(),
    )?;
    openssl(
        dir,
        &[
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
        ],
    )?;
    openssl(
        dir,
        &[&["genpkey"], &P256[..], &["-out", "localhost-key.pem"]].concat(),
    )?;
    openssl(
        dir,
        &[
            "req",
            "-new",
            "-config",
            "localhost.cnf",
            "-key",
            "localhost-key.pem",
            "-sha256",
            "-out",
            "localhost.csr",
        ],
    )?;
    openssl(
        dir,
        &[
            "x509",
            "-req",
            "-in",
            "localhost.csr",
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
            "localhost.cnf",
            "-extensions",
            "ext",
            "-out",
            "localhost.pem",
        ],
    )
}

/// Runs `openssl` in `dir`, where its seed file goes if it keeps one.
fn openssl(dir: &Path, args: &[&str]) -> Result<(), Box<dyn Error>> {
    let output = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("RANDFILE", dir.join("rnd"))
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("running openssl {}: {error}", args.join(" ")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "openssl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )
        .into())
    }
}

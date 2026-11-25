//! A script in place of `az`, for tests of the real adapter on every OS CI
//! runs. It answers `az <a> <b>` from `<a>-<b>.out` (standard output) and
//! `<a>-<b>.err` (standard error) in its directory, and exits 1 if
//! `<a>-<b>.fail` is there; `login` and `rest` are keyed by their first word.
//! It records each call in `calls`, and what a `login` read on standard
//! input in `stdin`.

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use runbooks_credential_azure::host::Host;
use runbooks_credential_azure::process_tree::Killer;
use serde_json::json;
use tempfile::TempDir;

/// A token for ana@contoso.com in Contoso, built from its claims. Its
/// signature stands for the part that must never reach the app.
pub(crate) fn token() -> String {
    let claims = json!({
        "oid": "00000000-0000-4000-8000-0000000000a1",
        "tid": "11111111-1111-4111-8111-111111111111",
        "upn": "ana@contoso.com",
    });
    format!(
        "{}.{}.SECRET-SIGNATURE",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

/// How `main` ends `az` and what it started, on this OS.
pub(crate) fn killer() -> Killer {
    Host::new(std::env::vars_os(), cfg!(windows)).tree_killer()
}

pub(crate) const DEVICE_LINE: &str = "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code SCRIPTED1 to authenticate.";

#[cfg(not(windows))]
const SCRIPT: (&str, &str) = (
    "az",
    r#"#!/bin/sh
responses="$FAKE_AZ_RESPONSES"
case "$1" in
  login|rest) key="$1" ;;
  *) key="$1-$2" ;;
esac
printf '%s|%s|%s|%s\n' "$AZURE_CONFIG_DIR" "$AZURE_EXTENSION_DIR" "$AZURE_CORE_ONLY_SHOW_ERRORS" "$*" >> "$responses/calls"
if [ "$1" = login ]; then cat > "$responses/stdin"; fi
if [ -f "$responses/$key.err" ]; then cat "$responses/$key.err" >&2; fi
if [ -f "$responses/$key.out" ]; then cat "$responses/$key.out"; fi
if [ -f "$responses/$key.fail" ]; then exit 1; fi
exit 0
"#,
);

/// The Azure CLI on Windows is `az.cmd` too, so this runs the way it does.
#[cfg(windows)]
const SCRIPT: (&str, &str) = (
    "az.cmd",
    "@echo off\r\n\
set \"key=%~1-%~2\"\r\n\
if \"%~1\"==\"login\" set \"key=login\"\r\n\
if \"%~1\"==\"rest\" set \"key=rest\"\r\n\
>>\"%FAKE_AZ_RESPONSES%\\calls\" echo %AZURE_CONFIG_DIR%^|%AZURE_EXTENSION_DIR%^|%AZURE_CORE_ONLY_SHOW_ERRORS%^|%*\r\n\
if not \"%~1\"==\"login\" goto respond\r\n\
set \"stdin=\"\r\n\
set /p \"stdin=\"\r\n\
>\"%FAKE_AZ_RESPONSES%\\stdin\" echo(%stdin%\r\n\
:respond\r\n\
if exist \"%FAKE_AZ_RESPONSES%\\%key%.err\" type \"%FAKE_AZ_RESPONSES%\\%key%.err\" 1>&2\r\n\
if exist \"%FAKE_AZ_RESPONSES%\\%key%.out\" type \"%FAKE_AZ_RESPONSES%\\%key%.out\"\r\n\
if exist \"%FAKE_AZ_RESPONSES%\\%key%.fail\" exit /b 1\r\n\
exit /b 0\r\n",
);

pub(crate) struct ScriptedAz {
    /// Holds the script, and the responses and calls beside it.
    dir: TempDir,
}

/// One call the script recorded.
#[derive(Debug)]
pub(crate) struct ScriptCall {
    /// `AZURE_CONFIG_DIR`.
    pub config_dir: String,
    /// `AZURE_EXTENSION_DIR`, empty when unset.
    pub extension_dir: String,
    /// `AZURE_CORE_ONLY_SHOW_ERRORS`.
    pub only_show_errors: String,
    /// Each argument as az reads it, joined by spaces.
    pub args: String,
}

impl ScriptedAz {
    pub(crate) fn new() -> Result<Self, Box<dyn Error>> {
        let dir = tempfile::tempdir()?;
        let program = dir.path().join(SCRIPT.0);
        fs::write(&program, SCRIPT.1)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&program, fs::Permissions::from_mode(0o755))?;
        }
        Ok(Self { dir })
    }

    pub(crate) fn program(&self) -> PathBuf {
        self.dir.path().join(SCRIPT.0)
    }

    /// The environment `main` would pass: the test process's own, without
    /// its `az` config variables, plus where the script's responses are.
    pub(crate) fn env(&self) -> Vec<(OsString, OsString)> {
        let mut env = Host::new(std::env::vars_os(), cfg!(windows)).az_env();
        env.push(("FAKE_AZ_RESPONSES".into(), self.dir.path().into()));
        env
    }

    pub(crate) fn respond(&self, file: &str, contents: &str) -> Result<(), Box<dyn Error>> {
        fs::write(self.dir.path().join(file), contents)?;
        Ok(())
    }

    /// What the last `login` read on standard input, without line endings.
    pub(crate) fn stdin(&self) -> Result<String, Box<dyn Error>> {
        let stdin = fs::read_to_string(self.dir.path().join("stdin"))?;
        Ok(stdin.trim_end_matches(['\r', '\n']).to_owned())
    }

    pub(crate) fn calls(&self) -> Result<Vec<ScriptCall>, Box<dyn Error>> {
        let calls = fs::read_to_string(self.dir.path().join("calls"))?;
        Ok(calls
            .lines()
            .filter_map(|line| {
                let mut parts = line.splitn(4, '|').map(|part| part.trim().to_owned());
                Some(ScriptCall {
                    config_dir: parts.next()?,
                    extension_dir: parts.next()?,
                    only_show_errors: parts.next()?,
                    args: args_as_az_reads(&parts.next()?),
                })
            })
            .collect())
    }
}

/// Each argument the script recorded as az reads it, joined by spaces. The
/// shell script records `"$*"`, which is that already.
#[cfg(not(windows))]
fn args_as_az_reads(recorded: &str) -> String {
    recorded.to_owned()
}

/// Each argument the script recorded as az reads it, joined by spaces.
///
/// `az.cmd` records `%*`: the command line Rust wrote for a batch file, which
/// quotes any argument holding a character such as `~` or `=`. The real
/// `az.cmd` hands `%*` to `python.exe`, whose C runtime splits it into
/// `sys.argv`, so this splits it by the same rules.
#[cfg(windows)]
fn args_as_az_reads(recorded: &str) -> String {
    let mut chars = recorded.chars().peekable();
    std::iter::from_fn(|| next_arg(&mut chars))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The next argument by the C runtime's rules: whitespace outside quotes ends
/// one, `""` inside quotes is a `"`, and before a `"`, 2n backslashes stand
/// for n backslashes and 2n + 1 for n and a literal `"`.
#[cfg(windows)]
fn next_arg(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<String> {
    while chars.next_if(|c| matches!(c, ' ' | '\t')).is_some() {}
    chars.peek()?;
    let mut arg = String::new();
    let mut quoted = false;
    loop {
        let mut backslashes = 0_usize;
        while chars.next_if_eq(&'\\').is_some() {
            backslashes += 1;
        }
        if chars.next_if_eq(&'"').is_some() {
            arg.extend(std::iter::repeat_n('\\', backslashes / 2));
            if !backslashes.is_multiple_of(2) || (quoted && chars.next_if_eq(&'"').is_some()) {
                arg.push('"');
            } else {
                quoted = !quoted;
            }
        } else {
            arg.extend(std::iter::repeat_n('\\', backslashes));
            let Some(next) = chars.next_if(|c| quoted || !matches!(c, ' ' | '\t')) else {
                return Some(arg);
            };
            arg.push(next);
        }
    }
}

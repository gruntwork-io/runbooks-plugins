//! The process environment, read once by `main`, and what it says about the
//! machine: where `az` is, and where the person's own `az` login lives.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};

use runbooks_plugin_transport::OwnerOnly;

use crate::process_tree::Killer;

/// Variables that point `az` at a config directory. The plugin sets its own
/// for every `az` it runs.
const AZ_DIR_VARS: [&str; 2] = ["AZURE_CONFIG_DIR", "AZURE_EXTENSION_DIR"];

/// The program extensions Windows tries when `PATHEXT` is unset.
const DEFAULT_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";

/// A snapshot of the process environment.
#[derive(Clone)]
pub struct Host {
    vars: Vec<(OsString, OsString)>,
    windows: bool,
}

/// The variables' names only: their values may hold the person's secrets.
impl fmt::Debug for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Host")
            .field(
                "vars",
                &self.vars.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            )
            .field("windows", &self.windows)
            .finish()
    }
}

/// The person's own `az` login, which the `cli` source copies.
#[derive(Clone, Debug, Default)]
pub struct LocalLogin {
    /// `AZURE_CONFIG_DIR`, or `.azure` in the home directory.
    pub config_dir: Option<PathBuf>,
    /// `AZURE_EXTENSION_DIR`, or `cliextensions` in the config directory.
    pub extension_dir: Option<PathBuf>,
}

impl Host {
    /// `windows` says whether names compare without case and programs need
    /// an extension from `PATHEXT`, as on Windows.
    pub fn new(vars: impl IntoIterator<Item = (OsString, OsString)>, windows: bool) -> Self {
        Self {
            vars: vars.into_iter().collect(),
            windows,
        }
    }

    /// A variable's value. Unset and empty are the same.
    #[must_use]
    pub fn var(&self, name: &str) -> Option<&OsStr> {
        self.vars
            .iter()
            .find(|(key, _)| self.same_name(key, name))
            .map(|(_, value)| value.as_os_str())
            .filter(|value| !value.is_empty())
    }

    fn same_name(&self, key: &OsStr, name: &str) -> bool {
        match key.to_str() {
            Some(key) if self.windows => key.eq_ignore_ascii_case(name),
            Some(key) => key == name,
            None => false,
        }
    }

    /// The environment every `az` the plugin runs starts from: all of it,
    /// except the variables that choose `az`'s config directory.
    #[must_use]
    pub fn az_env(&self) -> Vec<(OsString, OsString)> {
        self.vars
            .iter()
            .filter(|(key, _)| !AZ_DIR_VARS.iter().any(|name| self.same_name(key, name)))
            .cloned()
            .collect()
    }

    /// The first `name` on `PATH`. On Windows only names with an extension
    /// from `PATHEXT` count: the Azure CLI's `wbin` also holds an `az` shell
    /// script for Git Bash, which Windows cannot run.
    pub fn find_program(&self, name: &str) -> Option<PathBuf> {
        let path = self.var("PATH")?;
        let candidates: Vec<String> = if self.windows {
            let pathext = self
                .var("PATHEXT")
                .and_then(OsStr::to_str)
                .unwrap_or(DEFAULT_PATHEXT);
            pathext
                .split(';')
                .filter(|ext| !ext.is_empty())
                .map(|ext| format!("{name}{}", ext.to_ascii_lowercase()))
                .collect()
        } else {
            vec![name.to_owned()]
        };
        std::env::split_paths(path)
            .filter(|dir| !dir.as_os_str().is_empty())
            .flat_map(|dir| candidates.iter().map(move |file| dir.join(file)))
            .find(|candidate| self.is_program(candidate))
    }

    fn is_program(&self, path: &Path) -> bool {
        path.metadata()
            .is_ok_and(|meta| meta.is_file() && (self.windows || executable(&meta)))
    }

    /// How to end `az` and what it started. On Windows that is
    /// `taskkill.exe` in `%SystemRoot%\System32`, never one from `PATH`.
    #[must_use]
    pub fn tree_killer(&self) -> Killer {
        if self.windows {
            self.var("SystemRoot").map_or(Killer::ChildOnly, |root| {
                Killer::Taskkill(Path::new(root).join("System32").join("taskkill.exe"))
            })
        } else {
            Killer::ProcessGroup
        }
    }

    /// How a sign-in directory is kept to its owner. On Windows that is
    /// icacls in `%SystemRoot%\System32`.
    #[must_use]
    pub fn owner_only(&self) -> OwnerOnly {
        if self.windows {
            OwnerOnly::icacls(self.var("SystemRoot"))
        } else {
            OwnerOnly::Mode
        }
    }

    /// Where the environment says the person's own `az` login is.
    pub fn local_login(&self) -> LocalLogin {
        let home = if self.windows { "USERPROFILE" } else { "HOME" };
        let config_dir = self
            .var("AZURE_CONFIG_DIR")
            .map(PathBuf::from)
            .or_else(|| self.var(home).map(|home| Path::new(home).join(".azure")));
        let extension_dir = self
            .var("AZURE_EXTENSION_DIR")
            .map(PathBuf::from)
            .or_else(|| config_dir.as_ref().map(|dir| dir.join("cliextensions")));
        LocalLogin {
            config_dir,
            extension_dir,
        }
    }
}

/// Whether a file may be run. Only Unix has an execute bit; elsewhere any
/// file may.
fn executable(meta: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        meta.is_file()
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};

    use runbooks_plugin_transport::OwnerOnly;

    use super::Host;
    use crate::process_tree::Killer;

    type TestResult = Result<(), Box<dyn Error>>;

    fn host(vars: &[(&str, &OsString)], windows: bool) -> Host {
        Host::new(
            vars.iter()
                .map(|(key, value)| (OsString::from(key), (*value).clone())),
            windows,
        )
    }

    fn path_of(dirs: &[&Path]) -> Result<OsString, Box<dyn Error>> {
        Ok(std::env::join_paths(dirs)?)
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
        Ok(())
    }

    #[test]
    fn finds_the_first_program_on_path() -> TestResult {
        let temp = tempfile::tempdir()?;
        let (empty, first, second) = (
            temp.path().join("empty"),
            temp.path().join("first"),
            temp.path().join("second"),
        );
        for dir in [&empty, &first, &second] {
            fs::create_dir_all(dir)?;
        }
        for dir in [&first, &second] {
            fs::write(dir.join("az"), "#!/bin/sh\n")?;
            #[cfg(unix)]
            make_executable(&dir.join("az"))?;
        }
        let path = path_of(&[&empty, &first, &second])?;
        assert_eq!(
            host(&[("PATH", &path)], false).find_program("az"),
            Some(first.join("az"))
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_file_that_is_not_executable_is_not_a_program() -> TestResult {
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("az"), "#!/bin/sh\n")?;
        let path = path_of(&[temp.path()])?;
        assert_eq!(host(&[("PATH", &path)], false).find_program("az"), None);
        Ok(())
    }

    #[test]
    fn on_windows_a_program_needs_an_extension_from_pathext() -> TestResult {
        let temp = tempfile::tempdir()?;
        let (bash_only, cli) = (temp.path().join("bash"), temp.path().join("cli"));
        fs::create_dir_all(&bash_only)?;
        fs::create_dir_all(&cli)?;
        fs::write(bash_only.join("az"), "#!/usr/bin/env bash\n")?;
        fs::write(cli.join("az"), "#!/usr/bin/env bash\n")?;
        fs::write(cli.join("az.cmd"), "@echo off\r\n")?;
        let path = path_of(&[&bash_only, &cli])?;
        let pathext = OsString::from(".EXE;.CMD");
        let host = host(&[("Path", &path), ("PATHEXT", &pathext)], true);
        assert_eq!(host.find_program("az"), Some(cli.join("az.cmd")));
        Ok(())
    }

    /// Off Windows a variable's name must match exactly.
    #[test]
    fn a_variables_name_ignores_case_only_on_windows() {
        let value = OsString::from("/usr/bin");
        assert_eq!(host(&[("path", &value)], false).var("PATH"), None);
        assert_eq!(
            host(&[("path", &value)], true).var("PATH"),
            Some(value.as_os_str())
        );
    }

    #[test]
    fn with_no_path_there_is_no_program() {
        assert_eq!(host(&[], false).find_program("az"), None);
    }

    #[test]
    fn the_local_login_is_azure_config_dir_or_dot_azure_in_home() {
        let home = OsString::from("/home/ana");
        let config = OsString::from("/srv/az");
        let empty = OsString::new();
        let login = host(&[("HOME", &home), ("AZURE_CONFIG_DIR", &empty)], false).local_login();
        assert_eq!(login.config_dir, Some(PathBuf::from("/home/ana/.azure")));
        assert_eq!(
            login.extension_dir,
            Some(PathBuf::from("/home/ana/.azure/cliextensions"))
        );

        let login = host(&[("HOME", &home), ("AZURE_CONFIG_DIR", &config)], false).local_login();
        assert_eq!(login.config_dir, Some(PathBuf::from("/srv/az")));

        let profile = OsString::from(r"C:\Users\ana");
        let login = host(&[("USERPROFILE", &profile), ("HOME", &home)], true).local_login();
        assert_eq!(
            login.config_dir,
            Some(Path::new(r"C:\Users\ana").join(".azure"))
        );
    }

    #[test]
    fn az_runs_without_the_hosts_config_directory_variables() {
        let value = OsString::from("x");
        let env = host(
            &[
                ("PATH", &value),
                ("azure_config_dir", &value),
                ("AZURE_EXTENSION_DIR", &value),
            ],
            true,
        )
        .az_env();
        let names: Vec<_> = env.iter().map(|(key, _)| key.clone()).collect();
        assert_eq!(names, [OsString::from("PATH")]);
    }

    #[test]
    fn taskkill_comes_from_system_root_and_unix_signals_the_group() {
        let root = OsString::from("C:\\Windows");
        let taskkill = Path::new("C:\\Windows")
            .join("System32")
            .join("taskkill.exe");
        assert_eq!(
            host(&[("SYSTEMROOT", &root)], true).tree_killer(),
            Killer::Taskkill(taskkill)
        );
        assert_eq!(host(&[], true).tree_killer(), Killer::ChildOnly);
        assert_eq!(
            host(&[("SystemRoot", &root)], false).tree_killer(),
            Killer::ProcessGroup
        );
    }

    #[test]
    fn windows_restricts_with_icacls_from_system_root_and_unix_with_the_mode() {
        let root = OsString::from("C:\\Windows");
        assert!(matches!(
            host(&[("SYSTEMROOT", &root)], true).owner_only(),
            OwnerOnly::Icacls { system_root: Some(found), .. } if found == Path::new("C:\\Windows")
        ));
        assert!(matches!(
            host(&[("SystemRoot", &root)], false).owner_only(),
            OwnerOnly::Mode
        ));
    }

    #[test]
    fn debug_shows_variable_names_but_not_their_values() {
        let secret = OsString::from("hunter2");
        let shown = format!("{:?}", host(&[("ARM_CLIENT_SECRET", &secret)], false));
        assert!(shown.contains("ARM_CLIENT_SECRET"), "{shown}");
        assert!(!shown.contains("hunter2"), "{shown}");
    }
}

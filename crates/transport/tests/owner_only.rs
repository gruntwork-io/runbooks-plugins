//! Leaving a path to its owner. On Unix, scripts stand in for `whoami.exe`
//! and `icacls.exe` and record what they were given. On Windows the real
//! tools run, and PowerShell reads the access list back.

use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

#[cfg(unix)]
mod fake_tools {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::Duration;

    use runbooks_plugin_transport::{OwnerOnly, OwnerOnlyError, PathKind};

    use super::TestResult;

    const SID: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";

    /// A `SystemRoot` whose `System32` holds the two scripts.
    fn system_root(
        whoami: &str,
        icacls: &str,
    ) -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let system32 = root.path().join("System32");
        fs::create_dir_all(&system32)?;
        for (name, body) in [("whoami.exe", whoami), ("icacls.exe", icacls)] {
            let path = system32.join(name);
            fs::write(&path, format!("#!/bin/sh\n{body}\n"))?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        }
        Ok(root)
    }

    /// Prints the table `whoami /user` prints.
    fn whoami_prints_the_user() -> String {
        format!(
            r"printf '%s\r\n' '' 'USER INFORMATION' '----------------' '' 'User Name SID' '========= =====' 'host\user {SID}'"
        )
    }

    /// Records each call's arguments, as one line, beside itself.
    const RECORDING_ICACLS: &str = r#"printf '%s\n' "$*" >> "$0.args""#;

    fn icacls(root: &Path) -> OwnerOnly {
        OwnerOnly::icacls(Some(root.as_os_str()))
    }

    fn recorded(root: &Path) -> Result<String, std::io::Error> {
        fs::read_to_string(root.join("System32").join("icacls.exe.args"))
    }

    #[test]
    fn icacls_stops_inheritance_and_gives_the_users_sid_full_control() -> TestResult {
        let root = system_root(&whoami_prints_the_user(), RECORDING_ICACLS)?;
        let target = root.path().join("state");
        fs::create_dir_all(&target)?;
        let target = target.to_str().ok_or("a temp dir is UTF-8")?;

        icacls(root.path()).restrict(Path::new(target), PathKind::Folder)?;
        icacls(root.path()).restrict(Path::new(target), PathKind::File)?;
        assert_eq!(
            recorded(root.path())?,
            format!(
                "{target} /inheritance:r /grant:r *{SID}:(OI)(CI)F\n\
                 {target} /inheritance:r /grant:r *{SID}:F\n"
            )
        );
        Ok(())
    }

    #[test]
    fn mode_runs_nothing() -> TestResult {
        let root = system_root(&whoami_prints_the_user(), RECORDING_ICACLS)?;
        OwnerOnly::Mode.restrict(root.path(), PathKind::Folder)?;
        assert!(
            !root
                .path()
                .join("System32")
                .join("icacls.exe.args")
                .exists()
        );
        Ok(())
    }

    #[test]
    fn each_way_it_can_fail_is_its_own_error() -> TestResult {
        let root = system_root(&whoami_prints_the_user(), RECORDING_ICACLS)?;
        let error = OwnerOnly::icacls(None).restrict(root.path(), PathKind::Folder);
        assert!(
            matches!(error, Err(OwnerOnlyError::NoSystemRoot)),
            "{error:?}"
        );

        let root = system_root("echo 'no SID here'", RECORDING_ICACLS)?;
        let error = icacls(root.path()).restrict(root.path(), PathKind::Folder);
        assert!(matches!(error, Err(OwnerOnlyError::NoSid)), "{error:?}");
        assert!(recorded(root.path()).is_err(), "icacls ran without a SID");

        let root = system_root(&whoami_prints_the_user(), "exit 5")?;
        let error = icacls(root.path()).restrict(root.path(), PathKind::Folder);
        assert!(
            matches!(&error, Err(OwnerOnlyError::Failed { program, status })
                if program.ends_with("icacls.exe") && status.code() == Some(5)),
            "{error:?}"
        );

        let root = system_root("exec sleep 5", RECORDING_ICACLS)?;
        let slow = OwnerOnly::Icacls {
            system_root: Some(root.path().to_owned()),
            wait: Duration::from_millis(100),
        };
        let error = slow.restrict(root.path(), PathKind::Folder);
        assert!(
            matches!(&error, Err(OwnerOnlyError::TimedOut { program, .. }) if program.ends_with("whoami.exe")),
            "{error:?}"
        );

        let empty = tempfile::tempdir()?;
        let error = icacls(empty.path()).restrict(empty.path(), PathKind::Folder);
        assert!(
            matches!(&error, Err(OwnerOnlyError::Start { program, .. }) if program.ends_with("whoami.exe")),
            "{error:?}"
        );
        Ok(())
    }
}

#[cfg(windows)]
mod real_tools {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use runbooks_plugin_transport::{OwnerOnly, PathKind};

    use super::TestResult;

    /// The current user's SID, then the path's: whether its rules are
    /// protected from inheritance, and each rule as `<SID> <rights> <inherited>`.
    /// SIDs and enum names, so a localized runner reads the same. .NET
    /// methods only, so no module has to load.
    const READ_ACL: &str = "$ErrorActionPreference = 'Stop'; \
        $target = $env:TARGET; \
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; \
        if ([IO.Directory]::Exists($target)) { $acl = [IO.Directory]::GetAccessControl($target) } \
        else { $acl = [IO.File]::GetAccessControl($target) }; \
        $acl.AreAccessRulesProtected; \
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) { \
            '{0} {1} {2}' -f $rule.IdentityReference.Value, $rule.FileSystemRights, $rule.IsInherited \
        }";

    /// The user's SID, and what [`READ_ACL`] prints for `path` after it.
    fn acl(path: &Path) -> Result<(String, Vec<String>), Box<dyn std::error::Error>> {
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", READ_ACL])
            .env("TARGET", path)
            .output()?;
        if !output.status.success() {
            return Err(format!("powershell failed: {output:?}").into());
        }
        let text = String::from_utf8(output.stdout)?;
        let mut lines = text.lines().map(str::to_owned);
        let sid = lines.next().ok_or("no SID")?;
        Ok((sid, lines.collect()))
    }

    /// `BUILTIN\Users`: every other user on the machine.
    const USERS: &str = "S-1-5-32-545";

    /// SYSTEM and Administrators, which can read any path, as root can.
    const ROOT: [&str; 2] = ["S-1-5-18", "S-1-5-32-544"];

    /// Whether every entry in `rules`, after the protected line, is for
    /// `sid` or [`ROOT`] and ends `inherited`, and `sid` has full control.
    fn only_user_and_root(sid: &str, rules: &[String], inherited: &str) -> bool {
        let entry_ok = |rule: &String| {
            rule.ends_with(&format!(" {inherited}"))
                && rule
                    .split_once(' ')
                    .is_some_and(|(owner, _)| owner == sid || ROOT.contains(&owner))
        };
        rules.contains(&format!("{sid} FullControl {inherited}"))
            && rules.iter().skip(1).all(entry_ok)
    }

    /// Paths in a folder that lets Users read: a restricted folder and file
    /// inherit nothing, and only the user, SYSTEM and Administrators have
    /// an entry, as root can read a 0700 path. A file made in the folder
    /// inherits only those.
    #[test]
    fn a_restricted_path_and_what_is_made_in_it_hold_only_the_user_system_and_administrators()
    -> TestResult {
        let system_root = std::env::var_os("SystemRoot").ok_or("SystemRoot is not set")?;
        let temp = tempfile::tempdir()?;
        let shared = temp.path().join("shared");
        fs::create_dir_all(&shared)?;
        let users_read = format!("*{USERS}:(OI)(CI)R");
        let granted = Command::new(Path::new(&system_root).join("System32").join("icacls.exe"))
            .arg(&shared)
            .args(["/grant", users_read.as_str()])
            .output()?;
        if !granted.status.success() {
            return Err(format!("icacls failed: {granted:?}").into());
        }
        let folder = shared.join("private");
        fs::create_dir_all(&folder)?;
        let file = shared.join("alone.json");
        fs::write(&file, b"{}")?;
        let owner_only = OwnerOnly::icacls(Some(system_root.as_os_str()));

        let ((sid, folder_before), (_, file_before)) = (acl(&folder)?, acl(&file)?);
        owner_only.restrict(&folder, PathKind::Folder)?;
        owner_only.restrict(&file, PathKind::File)?;
        let inside = folder.join("secret.json");
        fs::write(&inside, b"{}")?;
        let (_, folder_after) = acl(&folder)?;
        let (_, file_after) = acl(&file)?;
        let (_, inside_rules) = acl(&inside)?;

        let seen = format!(
            "folder before {folder_before:?}, after {folder_after:?}; file before {file_before:?}, after {file_after:?}; inside {inside_rules:?}"
        );
        for (before, after) in [(&folder_before, &folder_after), (&file_before, &file_after)] {
            let users = format!("{USERS} ");
            assert!(before.iter().any(|rule| rule.starts_with(&users)), "{seen}");
            assert_eq!(after.first().map(String::as_str), Some("True"), "{seen}");
            assert!(only_user_and_root(&sid, after, "False"), "{seen}");
        }
        assert!(only_user_and_root(&sid, &inside_rules, "True"), "{seen}");
        Ok(())
    }
}

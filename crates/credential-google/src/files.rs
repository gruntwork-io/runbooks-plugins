//! The plugin's files: reading credentials and configuration with a size
//! limit, and writing the credential a run reads.

use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use runbooks_plugin_transport::{OwnerOnly, PathKind};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The file under `stateDir` that holds this block's credentials document.
pub(crate) const CREDENTIALS_FILE: &str = "credentials.json";

#[derive(Debug, thiserror::Error)]
pub(crate) enum ReadError {
    #[error("does not exist")]
    NotFound,
    #[error("is larger than {0} bytes")]
    TooLarge(usize),
    #[error("is not UTF-8 text")]
    NotText,
    #[error("could not be read: {0}")]
    Io(io::ErrorKind),
}

/// The file's text, if it is at most `max` bytes.
pub(crate) async fn read_text(path: &Path, max: usize) -> Result<String, ReadError> {
    let file = fs::File::open(path).await.map_err(|error| {
        let kind = error.kind();
        if kind == io::ErrorKind::NotFound {
            ReadError::NotFound
        } else {
            ReadError::Io(kind)
        }
    })?;
    let mut bytes = Vec::new();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    file.take(limit)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| ReadError::Io(error.kind()))?;
    if bytes.len() > max {
        return Err(ReadError::TooLarge(max));
    }
    String::from_utf8(bytes).map_err(|_not_utf8| ReadError::NotText)
}

/// Up to `max` names of the entries in `dir`, skipping names that aren't
/// UTF-8. A directory that can't be read has none.
pub(crate) async fn list_dir(dir: &Path, max: usize) -> Vec<String> {
    let mut names = Vec::new();
    let Ok(mut entries) = fs::read_dir(dir).await else {
        return names;
    };
    while names.len() < max {
        match entries.next_entry().await {
            Ok(Some(entry)) => {
                if let Ok(name) = entry.file_name().into_string() {
                    names.push(name);
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
    names
}

/// Creates `dir`, readable by its owner only on Unix, if it is missing.
pub(crate) async fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(dir).await
}

/// Replaces `dir/name` with `contents`: written beside it, readable by its
/// owner only before anything is written, then renamed over it, so a run
/// never reads half a file.
pub(crate) async fn write_private(
    dir: &Path,
    name: &str,
    contents: &[u8],
    owner_only: &OwnerOnly,
) -> io::Result<PathBuf> {
    static WRITES: AtomicU64 = AtomicU64::new(0);
    let target = dir.join(name);
    let temporary = dir.join(format!(
        ".{name}.{}.{}.tmp",
        process::id(),
        WRITES.fetch_add(1, Ordering::Relaxed)
    ));
    let written = async {
        let mut file = temporary_options().open(&temporary).await?;
        let (owner_only, path) = (owner_only.clone(), temporary.clone());
        tokio::task::spawn_blocking(move || owner_only.restrict(&path, PathKind::File))
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        file.write_all(contents).await?;
        file.sync_all().await?;
        drop(file);
        fs::rename(&temporary, &target).await
    };
    match written.await {
        Ok(()) => Ok(target),
        Err(error) => {
            // The temporary file may not exist; the write's error is the one to report.
            let _ignored = fs::remove_file(&temporary).await;
            Err(error)
        }
    }
}

/// Options that create a new file only its owner can use: mode 0600 on Unix.
/// On Windows no one else can open it while it is held, so no one can in
/// the moment before it is restricted.
fn temporary_options() -> fs::OpenOptions {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    #[cfg(windows)]
    options.share_mode(0);
    options
}

/// Removes `dir/name`. A file that is already gone is not an error.
pub(crate) async fn remove(dir: &Path, name: &str) -> io::Result<()> {
    match fs::remove_file(dir.join(name)).await {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        Ok(()) | Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use runbooks_plugin_transport::OwnerOnly;

    use super::{ReadError, read_text, remove, write_private};

    #[tokio::test]
    async fn a_write_replaces_the_file_and_leaves_no_temporary() -> Result<(), Box<dyn Error>> {
        let dir = tempfile::tempdir()?;
        let owner_only = if cfg!(windows) {
            OwnerOnly::icacls(std::env::var_os("SystemRoot").as_deref())
        } else {
            OwnerOnly::Mode
        };
        write_private(dir.path(), "c.json", b"first", &owner_only).await?;
        let path = write_private(dir.path(), "c.json", b"second", &owner_only).await?;
        assert_eq!(std::fs::read_to_string(&path)?, "second");
        let names: Vec<_> = std::fs::read_dir(dir.path())?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<_, _>>()?;
        assert_eq!(names, ["c.json"]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path)?.permissions().mode() & 0o777,
                0o600
            );
        }
        remove(dir.path(), "c.json").await?;
        remove(dir.path(), "c.json").await?;
        assert!(!path.exists());
        Ok(())
    }

    /// On Windows the empty file is left to its owner before the secret is
    /// written into it. Scripts stand in for `whoami.exe` and `icacls.exe`;
    /// icacls records, for each call, the file's size then and its arguments.
    #[cfg(unix)]
    #[tokio::test]
    async fn icacls_restricts_the_file_before_anything_is_written_to_it()
    -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;

        let root = tempfile::tempdir()?;
        let system32 = root.path().join("System32");
        std::fs::create_dir_all(&system32)?;
        for (name, body) in [
            ("whoami.exe", "echo 'host\\user S-1-5-21-1-2-3-1001'"),
            (
                "icacls.exe",
                r#"printf '%s %s\n' "$(wc -c < "$1" | tr -d ' ')" "$*" >> "$0.seen""#,
            ),
        ] {
            let path = system32.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n"))?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        }
        let dir = tempfile::tempdir()?;
        let owner_only = OwnerOnly::icacls(Some(root.path().as_os_str()));

        let path = write_private(dir.path(), "c.json", b"secret", &owner_only).await?;
        assert_eq!(std::fs::read_to_string(&path)?, "secret");
        let seen = std::fs::read_to_string(system32.join("icacls.exe.seen"))?;
        let restricted = seen.split(' ').nth(1).ok_or("icacls never ran")?;
        let name = Path::new(restricted)
            .file_name()
            .and_then(|name| name.to_str());
        assert_eq!(Path::new(restricted).parent(), Some(dir.path()));
        assert!(
            name.is_some_and(|name| name.starts_with(".c.json.")),
            "{seen}"
        );
        assert_eq!(
            seen,
            format!("0 {restricted} /inheritance:r /grant:r *S-1-5-21-1-2-3-1001:F\n")
        );
        Ok(())
    }

    /// On Windows no one else can open a temporary file while it is held,
    /// as they can a file opened with the default options.
    #[cfg(windows)]
    #[tokio::test]
    async fn no_one_else_can_open_a_temporary_file_while_it_is_held() -> Result<(), Box<dyn Error>>
    {
        const ERROR_SHARING_VIOLATION: i32 = 32;
        let dir = tempfile::tempdir()?;
        let (plain, temporary) = (dir.path().join("plain"), dir.path().join("temporary"));
        let _plain = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&plain)
            .await?;
        std::fs::File::open(&plain)?;
        let _held = super::temporary_options().open(&temporary).await?;
        let error = std::fs::File::open(&temporary)
            .err()
            .ok_or("opened a temporary file someone holds")?;
        assert_eq!(error.raw_os_error(), Some(ERROR_SHARING_VIOLATION));
        Ok(())
    }

    #[tokio::test]
    async fn a_read_stops_at_its_limit() -> Result<(), Box<dyn Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("big");
        std::fs::write(&path, "x".repeat(11))?;
        assert!(matches!(
            read_text(&path, 10).await,
            Err(ReadError::TooLarge(10))
        ));
        assert_eq!(read_text(&path, 11).await?, "x".repeat(11));
        let missing = dir.path().join("missing");
        assert!(matches!(
            read_text(&missing, 10).await,
            Err(ReadError::NotFound)
        ));
        Ok(())
    }
}

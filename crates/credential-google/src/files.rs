//! The plugin's files: reading credentials and configuration with a size
//! limit, and writing the credential a run reads.

use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

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
/// owner only on Unix from the moment it exists, then renamed over it, so a
/// run never reads half a file.
pub(crate) async fn write_private(dir: &Path, name: &str, contents: &[u8]) -> io::Result<PathBuf> {
    static WRITES: AtomicU64 = AtomicU64::new(0);
    let target = dir.join(name);
    let temporary = dir.join(format!(
        ".{name}.{}.{}.tmp",
        process::id(),
        WRITES.fetch_add(1, Ordering::Relaxed)
    ));
    let written = async {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary).await?;
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

    use super::{ReadError, read_text, remove, write_private};

    #[tokio::test]
    async fn a_write_replaces_the_file_and_leaves_no_temporary() -> Result<(), Box<dyn Error>> {
        let dir = tempfile::tempdir()?;
        write_private(dir.path(), "c.json", b"first").await?;
        let path = write_private(dir.path(), "c.json", b"second").await?;
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

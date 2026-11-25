//! The block's state directory: one `az` config directory per sign-in, each
//! readable by its owner only.
//!
//! `az` writes its tokens there, so a block's sign-in never changes the
//! person's own `~/.azure`, and two blocks never share one.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use runbooks_plugin_protocol::credential::ErrorKind;
use runbooks_plugin_transport::PluginError;

/// Every sign-in directory's name starts with this, so `signOut` can find
/// them all, including any an earlier process left behind.
const PREFIX: &str = "az-";

/// More leftover directories than this is a state directory in a bad way.
const MAX_ATTEMPTS: u32 = 10_000;

/// The file that lists an `az` login's accounts. A config directory
/// without it is not signed in.
const PROFILE: &str = "azureProfile.json";

/// The files of an `az` login. The rest of a config directory (logs,
/// command index, extensions) is not the login.
const LOGIN_FILES: [&str; 8] = [
    PROFILE,
    "msal_token_cache.json",
    "msal_token_cache.bin",
    "msal_http_cache.bin",
    "service_principal_entries.json",
    "service_principal_entries.bin",
    "clouds.config",
    "config",
];

/// A service principal's certificate, in its sign-in directory.
const CERTIFICATE: &str = "client-certificate.pem";

/// A PEM certificate and key larger than this is not one.
const MAX_CERTIFICATE_BYTES: u64 = 1024 * 1024;

/// A login file larger than this is not one `az` wrote.
const MAX_LOGIN_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// The block's state directory, which holds its sign-in directories.
#[derive(Clone, Debug)]
pub(crate) struct StateDir(PathBuf);

impl StateDir {
    /// The state directory at `path`.
    #[must_use]
    pub(crate) const fn new(path: PathBuf) -> Self {
        Self(path)
    }

    /// Where the state directory is.
    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// A new, empty sign-in directory.
    ///
    /// # Errors
    ///
    /// `internal` when it cannot be created, or the state directory already
    /// holds too many sign-in directories.
    pub(crate) async fn create(&self) -> Result<PathBuf, PluginError> {
        let state = self.0.clone();
        blocking(move || create_private_dir(&state)).await
    }

    /// A new sign-in directory holding a copy of the login in `from`, or
    /// `None` if `from` holds no login.
    ///
    /// # Errors
    ///
    /// `internal` when the sign-in directory cannot be created or the login
    /// cannot be copied.
    pub(crate) async fn copy_login(&self, from: &Path) -> Result<Option<PathBuf>, PluginError> {
        let (state, from) = (self.0.clone(), from.to_owned());
        blocking(move || {
            if !from.join(PROFILE).is_file() {
                return Ok(None);
            }
            let dir = create_private_dir(&state)?;
            match copy_files(&from, &dir) {
                Ok(()) => Ok(Some(dir)),
                Err(error) => {
                    // The copy failed: what is in `dir` is not a login.
                    let _partial = fs::remove_dir_all(&dir);
                    Err(PluginError::new(
                        ErrorKind::Internal,
                        format!("copying the Azure CLI login in {}: {error}", from.display()),
                    ))
                }
            }
        })
        .await
    }

    /// Copies a service principal's PEM certificate into its sign-in
    /// directory `dir`, readable by its owner only, and returns the copy.
    /// `az` reads it again whenever it needs a token, so the block keeps its
    /// own copy for as long as the sign-in lasts.
    ///
    /// # Errors
    ///
    /// `invalidParams` when the file cannot be read or is not a PEM file's
    /// size.
    pub(crate) async fn copy_certificate(
        &self,
        from: &Path,
        dir: &Path,
    ) -> Result<PathBuf, PluginError> {
        let (from, target) = (from.to_owned(), dir.join(CERTIFICATE));
        blocking(move || {
            File::open(&from)
                .and_then(|source| copy_private(source, &target, MAX_CERTIFICATE_BYTES))
                .map(|()| target)
                .map_err(|error| {
                    PluginError::new(
                        ErrorKind::InvalidParams,
                        format!(
                            "The certificate {} could not be copied ({error}). Give the path of a PEM file you can read.",
                            from.display()
                        ),
                    )
                })
        })
        .await
    }

    /// Deletes one sign-in directory. A directory already gone is not an error.
    ///
    /// # Errors
    ///
    /// `internal` when the directory cannot be deleted.
    pub(crate) async fn remove(&self, dir: &Path) -> Result<(), PluginError> {
        let dir = dir.to_owned();
        blocking(move || remove_dir(&dir)).await
    }

    /// Deletes every sign-in directory in the state directory.
    ///
    /// # Errors
    ///
    /// `internal` when the state directory cannot be read or a sign-in
    /// directory cannot be deleted.
    pub(crate) async fn remove_all(&self) -> Result<(), PluginError> {
        let state = self.0.clone();
        blocking(move || remove_sign_in_dirs(&state)).await
    }
}

fn remove_sign_in_dirs(state: &Path) -> Result<(), PluginError> {
    let entries = match fs::read_dir(state) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(state_error(state, &error)),
    };
    for entry in entries {
        let entry = entry.map_err(|error| state_error(state, &error))?;
        if entry.file_name().to_string_lossy().starts_with(PREFIX) {
            remove_dir(&entry.path())?;
        }
    }
    Ok(())
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, PluginError> + Send + 'static,
) -> Result<T, PluginError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_panicked| {
            PluginError::new(ErrorKind::Internal, "a state directory operation failed")
        })?
}

fn state_error(path: &Path, error: &io::Error) -> PluginError {
    PluginError::new(
        ErrorKind::Internal,
        format!("the state directory {}: {error}", path.display()),
    )
}

fn remove_dir(dir: &Path) -> Result<(), PluginError> {
    match fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(state_error(dir, &error)),
    }
}

/// A builder for directories only their owner can use: mode 0700 on Unix.
/// On Windows a directory inherits its parent's access list.
fn private_dir_builder() -> fs::DirBuilder {
    #[cfg(unix)]
    {
        let mut builder = fs::DirBuilder::new();
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder
    }
    #[cfg(not(unix))]
    {
        fs::DirBuilder::new()
    }
}

/// `az-1`, or the first `az-<n>` not already there. Created with mode 0700
/// on Unix; on Windows it inherits the state directory's access list.
fn create_private_dir(state: &Path) -> Result<PathBuf, PluginError> {
    let builder = private_dir_builder();
    for n in 1..=MAX_ATTEMPTS {
        let dir = state.join(format!("{PREFIX}{n}"));
        match builder.create(&dir) {
            Ok(()) => return Ok(dir),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(state_error(state, &error)),
        }
    }
    Err(PluginError::new(
        ErrorKind::Internal,
        format!(
            "the state directory {} already holds {MAX_ATTEMPTS} sign-in directories: sign out to clear them",
            state.display()
        ),
    ))
}

fn copy_files(from: &Path, to: &Path) -> io::Result<()> {
    for name in LOGIN_FILES {
        let source = match File::open(from.join(name)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        copy_private(source, &to.join(name), MAX_LOGIN_FILE_BYTES)
            .map_err(|error| io::Error::other(format!("{name}: {error}")))?;
    }
    Ok(())
}

/// Copies `source` to a new file at `target` that only its owner can read
/// (0600 on Unix), refusing more than `max` bytes.
fn copy_private(source: File, target: &Path, max: u64) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(target)?;
    let copied = io::copy(&mut source.take(max + 1), &mut file)?;
    if copied > max {
        return Err(io::Error::other(format!("it is larger than {max} bytes")));
    }
    file.flush()
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;

    use super::StateDir;

    type TestResult = Result<(), Box<dyn Error>>;

    #[tokio::test]
    async fn copies_only_the_login_files_and_leaves_the_source_alone() -> TestResult {
        let (home, state) = (tempfile::tempdir()?, tempfile::tempdir()?);
        fs::write(home.path().join("azureProfile.json"), "{}")?;
        fs::write(home.path().join("msal_token_cache.json"), "tokens")?;
        fs::write(home.path().join("commands.log"), "log")?;
        let state = StateDir::new(state.path().to_owned());

        let dir = state
            .copy_login(home.path())
            .await?
            .ok_or("no login copied")?;
        assert!(dir.starts_with(state.path()));
        assert_eq!(
            fs::read_to_string(dir.join("msal_token_cache.json"))?,
            "tokens"
        );
        assert!(!dir.join("commands.log").exists());
        assert!(home.path().join("msal_token_cache.json").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&dir)?.permissions().mode() & 0o777, 0o700);
            let file = fs::metadata(dir.join("msal_token_cache.json"))?;
            assert_eq!(file.permissions().mode() & 0o777, 0o600);
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_directory_without_a_profile_holds_no_login() -> TestResult {
        let (home, state) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let state = StateDir::new(state.path().to_owned());
        assert_eq!(state.copy_login(home.path()).await?, None);
        assert_eq!(fs::read_dir(state.path())?.count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_certificate_is_copied_into_the_sign_in_for_its_owner_only() -> TestResult {
        let (source, state) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let pem = source.path().join("sp.pem");
        fs::write(&pem, "-----BEGIN PRIVATE KEY-----")?;
        let state = StateDir::new(state.path().to_owned());
        let dir = state.create().await?;

        let copy = state.copy_certificate(&pem, &dir).await?;
        assert!(copy.starts_with(&dir));
        assert_eq!(fs::read_to_string(&copy)?, "-----BEGIN PRIVATE KEY-----");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&copy)?.permissions().mode() & 0o777, 0o600);
        }
        let missing = state
            .copy_certificate(&source.path().join("gone.pem"), &dir)
            .await
            .err()
            .ok_or("a missing certificate was copied")?;
        assert_eq!(
            missing.kind(),
            runbooks_plugin_protocol::credential::ErrorKind::InvalidParams
        );
        assert!(missing.message().contains("gone.pem"), "{missing}");
        Ok(())
    }

    /// A certificate may be 1 MiB, copied whole; one byte more is refused.
    #[tokio::test]
    async fn a_certificate_may_be_as_large_as_1_mib() -> TestResult {
        let (source, state) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let pem = source.path().join("sp.pem");
        let file = fs::File::create(&pem)?;
        file.set_len(1024 * 1024)?;
        let state = StateDir::new(state.path().to_owned());
        let dir = state.create().await?;
        let copy = state.copy_certificate(&pem, &dir).await?;
        assert_eq!(fs::metadata(&copy)?.len(), 1024 * 1024);

        fs::remove_file(&copy)?;
        file.set_len(1024 * 1024 + 1)?;
        let refused = state
            .copy_certificate(&pem, &dir)
            .await
            .err()
            .ok_or("a certificate over 1 MiB was copied")?;
        assert!(
            refused.message().contains("larger than 1048576 bytes"),
            "{refused}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn each_sign_in_gets_its_own_directory_and_remove_all_clears_them() -> TestResult {
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("engine-file"), "kept")?;
        let state = StateDir::new(temp.path().to_owned());
        let (first, second) = (state.create().await?, state.create().await?);
        assert_ne!(first, second);

        state.remove_all().await?;
        state.remove_all().await?;
        assert!(!first.exists() && !second.exists());
        assert!(temp.path().join("engine-file").exists());
        Ok(())
    }

    /// `az`'s login files may each be 64 MiB; a larger one fails the copy,
    /// which leaves nothing behind.
    #[tokio::test]
    async fn a_login_file_may_be_as_large_as_64_mib() -> TestResult {
        let (home, state) = (tempfile::tempdir()?, tempfile::tempdir()?);
        fs::write(home.path().join("azureProfile.json"), "{}")?;
        let cache = fs::File::create(home.path().join("msal_token_cache.bin"))?;
        cache.set_len(64 * 1024 * 1024)?;
        let state = StateDir::new(state.path().to_owned());
        let dir = state
            .copy_login(home.path())
            .await?
            .ok_or("no login copied")?;
        assert_eq!(
            fs::metadata(dir.join("msal_token_cache.bin"))?.len(),
            64 * 1024 * 1024
        );
        state.remove(&dir).await?;

        cache.set_len(64 * 1024 * 1024 + 1)?;
        let error = state
            .copy_login(home.path())
            .await
            .err()
            .ok_or("a login file over 64 MiB was copied")?;
        let message = error.message();
        assert!(
            message.contains("msal_token_cache.bin")
                && message.contains("larger than 67108864 bytes"),
            "{message}"
        );
        assert_eq!(fs::read_dir(state.path())?.count(), 0);
        Ok(())
    }

    /// A login file that is there but can't be opened fails the copy; only
    /// a missing one is skipped.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_login_file_that_cannot_be_opened_fails_the_copy() -> TestResult {
        let (home, state) = (tempfile::tempdir()?, tempfile::tempdir()?);
        fs::write(home.path().join("azureProfile.json"), "{}")?;
        let looped = home.path().join("msal_token_cache.json");
        std::os::unix::fs::symlink(&looped, &looped)?;
        let state = StateDir::new(state.path().to_owned());
        let error = state
            .copy_login(home.path())
            .await
            .err()
            .ok_or("a login with an unreadable file was copied")?;
        assert!(
            error
                .message()
                .starts_with("copying the Azure CLI login in"),
            "{}",
            error.message()
        );
        assert_eq!(fs::read_dir(state.path())?.count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn remove_deletes_one_sign_in_directory_and_a_missing_one_is_no_error() -> TestResult {
        let temp = tempfile::tempdir()?;
        let state = StateDir::new(temp.path().to_owned());
        let (first, second) = (state.create().await?, state.create().await?);
        state.remove(&first).await?;
        assert!(!first.exists() && second.exists());
        state.remove(&first).await?;

        let gone = StateDir::new(temp.path().join("not-there"));
        gone.remove_all().await?;
        Ok(())
    }

    /// A failure other than the directory being gone is an error: here, a
    /// state directory or a sign-in directory that is a file.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_state_or_sign_in_directory_that_is_a_file_is_an_error() -> TestResult {
        let temp = tempfile::tempdir()?;
        let file = temp.path().join("az-1");
        fs::write(&file, "not a directory")?;
        let state = StateDir::new(temp.path().to_owned());
        assert!(state.remove(&file).await.is_err());
        assert!(state.remove_all().await.is_err());
        assert!(StateDir::new(file).remove_all().await.is_err());
        Ok(())
    }

    /// A sign-in directory that can't be created for a reason other than
    /// one already being there is an error at once.
    #[tokio::test]
    async fn a_state_directory_that_is_not_there_is_an_error_at_once() -> TestResult {
        let temp = tempfile::tempdir()?;
        let state = StateDir::new(temp.path().join("not-there"));
        let error = state.create().await.err().ok_or("created")?;
        assert!(
            error.message().starts_with("the state directory")
                && !error.message().contains("already holds"),
            "{}",
            error.message()
        );
        Ok(())
    }
}

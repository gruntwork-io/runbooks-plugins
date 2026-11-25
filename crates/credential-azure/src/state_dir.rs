//! The block's state directory: one `az` config directory per sign-in, each
//! readable by its owner only. `az` writes its tokens there, so a block's
//! sign-in never changes the person's own `~/.azure`, and two blocks never
//! share one.

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

/// A login file larger than this is not one `az` wrote.
const MAX_LOGIN_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct StateDir(PathBuf);

impl StateDir {
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// A new, empty sign-in directory.
    pub async fn create(&self) -> Result<PathBuf, PluginError> {
        let state = self.0.clone();
        blocking(move || create_private_dir(&state)).await
    }

    /// A new sign-in directory holding a copy of the login in `from`, or
    /// `None` if `from` holds no login.
    pub async fn copy_login(&self, from: &Path) -> Result<Option<PathBuf>, PluginError> {
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

    /// Deletes one sign-in directory. A directory already gone is not an error.
    pub async fn remove(&self, dir: &Path) -> Result<(), PluginError> {
        let dir = dir.to_owned();
        blocking(move || remove_dir(&dir)).await
    }

    /// Deletes every sign-in directory in the state directory.
    pub async fn remove_all(&self) -> Result<(), PluginError> {
        let state = self.0.clone();
        blocking(move || {
            let entries = match fs::read_dir(&state) {
                Ok(entries) => entries,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(state_error(&state, &error)),
            };
            for entry in entries {
                let entry = entry.map_err(|error| state_error(&state, &error))?;
                if entry.file_name().to_string_lossy().starts_with(PREFIX) {
                    remove_dir(&entry.path())?;
                }
            }
            Ok(())
        })
        .await
    }
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
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut target = options.open(to.join(name))?;
        let copied = io::copy(&mut source.take(MAX_LOGIN_FILE_BYTES + 1), &mut target)?;
        if copied > MAX_LOGIN_FILE_BYTES {
            return Err(io::Error::other(format!(
                "{name} is larger than {MAX_LOGIN_FILE_BYTES} bytes"
            )));
        }
        target.flush()?;
    }
    Ok(())
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
}

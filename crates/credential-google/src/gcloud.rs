//! gcloud's files: its configuration directory, the named configurations in
//! it, and the Application Default Credentials file. The plugin reads them
//! and never runs gcloud, so the CLI need not be installed.

use std::collections::HashMap;
use std::path::PathBuf;

use runbooks_plugin_transport::PluginError;

use crate::credential::{Document, MAX_DOCUMENT_BYTES, parse_document};
use crate::files::{self, ReadError};
use crate::session::invalid_params;

/// What gcloud runs to write Application Default Credentials.
pub(crate) const ADC_LOGIN: &str = "gcloud auth application-default login";
/// The variable that names the configuration gcloud uses.
pub(crate) const CONFIGURATION_VAR: &str = "CLOUDSDK_ACTIVE_CONFIG_NAME";

/// The largest configuration file read. gcloud's are a few hundred bytes.
const MAX_CONFIGURATION_BYTES: usize = 64 * 1024;
/// The most configuration names listed in an error.
const MAX_LISTED: usize = 50;

/// gcloud's configuration directory.
#[derive(Clone, Debug)]
pub(crate) struct Root(PathBuf);

impl Root {
    /// `CLOUDSDK_CONFIG` when it is set, even to nothing, which means there
    /// is no gcloud configuration; otherwise `%APPDATA%\gcloud` on Windows and
    /// `~/.config/gcloud` elsewhere.
    pub(crate) fn resolve(env: &HashMap<String, String>) -> Option<Self> {
        let set = |name: &str| {
            env.get(name)
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
        };
        if let Some(root) = env.get("CLOUDSDK_CONFIG") {
            let root = root.trim();
            return (!root.is_empty()).then(|| Self(PathBuf::from(root)));
        }
        if cfg!(windows) {
            if let Some(app_data) = set("APPDATA") {
                return Some(Self(PathBuf::from(app_data).join("gcloud")));
            }
            let home = set("USERPROFILE")?;
            return Some(Self(
                PathBuf::from(home)
                    .join("AppData")
                    .join("Roaming")
                    .join("gcloud"),
            ));
        }
        set("HOME").map(|home| Self(PathBuf::from(home).join(".config").join("gcloud")))
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.0
    }

    pub(crate) fn adc_file(&self) -> PathBuf {
        self.0.join("application_default_credentials.json")
    }

    fn configurations(&self) -> PathBuf {
        self.0.join("configurations")
    }

    /// The configuration gcloud uses: [`CONFIGURATION_VAR`], then the
    /// `active_config` file, then `default`.
    pub(crate) async fn active_name(&self, env: &HashMap<String, String>) -> String {
        if let Some(name) = env
            .get(CONFIGURATION_VAR)
            .map(|name| name.trim())
            .filter(|name| !name.is_empty())
        {
            return name.to_owned();
        }
        match files::read_text(&self.0.join("active_config"), MAX_CONFIGURATION_BYTES).await {
            Ok(text) if !text.trim().is_empty() => text.trim().to_owned(),
            Ok(_) | Err(_) => "default".to_owned(),
        }
    }

    /// The named configuration, or `None` if it doesn't exist.
    pub(crate) async fn configuration(
        &self,
        name: &ConfigurationName,
    ) -> Result<Option<Configuration>, ReadError> {
        let path = self.configurations().join(format!("config_{}", name.0));
        match files::read_text(&path, MAX_CONFIGURATION_BYTES).await {
            Ok(text) => Ok(Some(Configuration::parse(name.clone(), &text))),
            Err(ReadError::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// The names of the configurations that exist, sorted, for an error.
    pub(crate) async fn configuration_names(&self) -> Vec<String> {
        let mut names: Vec<String> = files::list_dir(&self.configurations(), MAX_LISTED)
            .await
            .into_iter()
            .filter_map(|file| file.strip_prefix("config_").map(str::to_owned))
            .collect();
        names.sort_unstable();
        names
    }

    /// The Application Default Credentials, or `None` if the file doesn't exist.
    ///
    /// # Errors
    ///
    /// Kind `invalidParams` for a file that can't be read or used.
    pub(crate) async fn adc(&self) -> Result<Option<Document>, PluginError> {
        let path = self.adc_file();
        let text = match files::read_text(&path, MAX_DOCUMENT_BYTES).await {
            Ok(text) => text,
            Err(ReadError::NotFound) => return Ok(None),
            Err(error) => {
                return Err(invalid_params(format!(
                    "The Application Default Credentials file {}: the file {error}",
                    path.display()
                )));
            }
        };
        parse_document(text).map(Some).map_err(|error| {
            invalid_params(format!(
                "The Application Default Credentials file {} {error}. Run: {ADC_LOGIN}",
                path.display()
            ))
        })
    }
}

/// A configuration's name, checked before it becomes part of a path: gcloud
/// allows lower case letters, digits and hyphens, starting with a letter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConfigurationName(String);

impl ConfigurationName {
    /// # Errors
    ///
    /// The name back, if gcloud wouldn't accept it.
    pub(crate) fn parse(name: String) -> Result<Self, String> {
        let bytes = name.as_bytes();
        let valid = bytes.first().is_some_and(u8::is_ascii_lowercase)
            && bytes
                .iter()
                .all(|&byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if valid { Ok(Self(name)) } else { Err(name) }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The settings of a `config_<name>` file that the block uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Configuration {
    pub(crate) name: ConfigurationName,
    pub(crate) project: Option<String>,
    pub(crate) region: Option<String>,
    pub(crate) zone: Option<String>,
}

impl Configuration {
    /// Reads `core/project`, `compute/region` and `compute/zone` from the
    /// INI text. A line that isn't a section or a `key = value` is skipped,
    /// so a damaged file reads as one with fewer settings.
    fn parse(name: ConfigurationName, text: &str) -> Self {
        let mut section = "";
        let mut configuration = Self {
            name,
            project: None,
            region: None,
            zone: None,
        };
        for line in text.lines().map(str::trim) {
            if line.starts_with(['#', ';']) {
                continue;
            }
            if let Some(header) = line
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
            {
                section = header.trim();
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = Some(value.trim().to_owned()).filter(|value| !value.is_empty());
            match (section, key.trim()) {
                ("core", "project") => configuration.project = value,
                ("compute", "region") => configuration.region = value,
                ("compute", "zone") => configuration.zone = value,
                _ => {}
            }
        }
        configuration
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use super::{Configuration, ConfigurationName, Root};

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn cloudsdk_config_wins_and_set_but_empty_means_none() {
        let root = Root::resolve(&env(&[
            ("CLOUDSDK_CONFIG", "/opt/gcloud"),
            ("HOME", "/home/a"),
        ]));
        assert_eq!(root.map(|root| root.0), Some(PathBuf::from("/opt/gcloud")));
        assert!(Root::resolve(&env(&[("CLOUDSDK_CONFIG", " "), ("HOME", "/home/a")])).is_none());
    }

    #[cfg(not(windows))]
    #[test]
    fn the_default_root_is_under_home() {
        let root = Root::resolve(&env(&[("HOME", "/home/a")]));
        assert_eq!(
            root.map(|root| root.0),
            Some(PathBuf::from("/home/a/.config/gcloud"))
        );
        assert!(Root::resolve(&env(&[])).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn the_default_root_is_under_appdata() {
        let root = Root::resolve(&env(&[("APPDATA", r"C:\Users\a\AppData\Roaming")]));
        assert_eq!(
            root.map(|root| root.0),
            Some(PathBuf::from(r"C:\Users\a\AppData\Roaming\gcloud"))
        );
    }

    #[test]
    fn a_configuration_reads_its_project_region_and_zone() -> Result<(), String> {
        let text = "[core]\naccount = a@example.com\nproject = sandbox-1234\n\n# note\n[compute]\nregion=europe-west1\nzone =\nnot a setting\n";
        let name = ConfigurationName::parse("dev".to_owned())?;
        let configuration = Configuration::parse(name.clone(), text);
        assert_eq!(
            configuration,
            Configuration {
                name,
                project: Some("sandbox-1234".to_owned()),
                region: Some("europe-west1".to_owned()),
                zone: None,
            }
        );
        Ok(())
    }

    #[test]
    fn a_configuration_name_cannot_leave_the_directory() -> Result<(), String> {
        for bad in ["../x", "Dev", "a/b", "", "-x", "a b"] {
            assert!(ConfigurationName::parse(bad.to_owned()).is_err(), "{bad}");
        }
        ConfigurationName::parse("prod-2".to_owned())?;
        Ok(())
    }
}

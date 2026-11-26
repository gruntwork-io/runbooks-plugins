//! The block's settings: the region and zone a run gets.

use std::collections::HashMap;

use runbooks_plugin_transport::{PluginError, shown_name};

use crate::session::{Candidate, invalid_params};

const DEFAULT_REGION: &str = "defaultRegion";
const DEFAULT_ZONE: &str = "defaultZone";
/// Compute Engine's rule for a name, which its regions and zones follow.
const NAME_RULE: &str = "up to 63 lower case letters, digits and hyphens, starting with a letter and ending with a letter or digit";
const MAX_NAME_BYTES: usize = 63;

/// The block's `defaultRegion` and `defaultZone`.
#[derive(Clone, Debug, Default)]
pub(crate) struct Settings {
    region: Option<String>,
    zone: Option<String>,
}

impl Settings {
    /// An empty setting is no setting, as in the app.
    ///
    /// # Errors
    ///
    /// Kind `invalidParams`, naming each setting the plugin doesn't know and
    /// each value that isn't a region or zone name. It never shows a value.
    pub(crate) fn parse(mut settings: HashMap<String, String>) -> Result<Self, PluginError> {
        let region = take(&mut settings, DEFAULT_REGION, "region, such as us-central1");
        let zone = take(&mut settings, DEFAULT_ZONE, "zone, such as us-central1-a");
        let mut unknown: Vec<&str> = settings.keys().map(|name| shown_name(name)).collect();
        unknown.sort_unstable();
        match (region, zone) {
            (Ok(region), Ok(zone)) if unknown.is_empty() => Ok(Self { region, zone }),
            (region, zone) => {
                let unknown = (!unknown.is_empty()).then(|| {
                    format!(
                        "settings has no {}; this plugin's settings are {DEFAULT_REGION} and {DEFAULT_ZONE}",
                        unknown.join(", ")
                    )
                });
                let problems: Vec<String> = [unknown, region.err(), zone.err()]
                    .into_iter()
                    .flatten()
                    .collect();
                Err(invalid_params(problems.join("; ")))
            }
        }
    }

    /// The block's region and zone each win over the ones that came with the
    /// credential, as in the app.
    pub(crate) fn apply(&self, candidate: Candidate) -> Candidate {
        Candidate {
            region: self.region.clone().or(candidate.region),
            zone: self.zone.clone().or(candidate.zone),
            ..candidate
        }
    }
}

/// Removes setting `name`, which must be a Google Cloud `what`.
fn take(
    settings: &mut HashMap<String, String>,
    name: &str,
    what: &str,
) -> Result<Option<String>, String> {
    let Some(value) = settings
        .remove(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    if is_name(&value) {
        Ok(Some(value))
    } else {
        Err(format!(
            "settings.{name} must be a Google Cloud {what}: {NAME_RULE}"
        ))
    }
}

fn is_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() <= MAX_NAME_BYTES
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

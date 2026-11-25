//! The block's settings, as `configure` hands them over.

use std::collections::{BTreeSet, HashMap};

use crate::methods::DEFAULT_REGION;
use crate::region::{InvalidRegion, Region};

/// What is wrong with the settings: every problem at once. Names settings,
/// and shows a refused region only as [`InvalidRegion`] does.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.describe())]
pub(crate) struct InvalidSettings {
    /// Settings AWS does not have, each cut to 64 characters.
    pub unknown: BTreeSet<String>,
    pub region: Option<InvalidRegion>,
}

impl InvalidSettings {
    fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.unknown.is_empty() {
            let unknown: Vec<&str> = self.unknown.iter().map(String::as_str).collect();
            parts.push(format!(
                "AWS has no setting {}: its only setting is {DEFAULT_REGION}",
                unknown.join(", ")
            ));
        }
        if let Some(region) = &self.region {
            parts.push(format!("settings.{DEFAULT_REGION} is invalid: {region}"));
        }
        parts.join("; ")
    }
}

/// The run's region when the credential and the sign-in name none: the
/// `defaultRegion` setting, else us-east-1.
///
/// # Errors
///
/// [`InvalidSettings`] for a setting AWS does not have, or a `defaultRegion`
/// that is not a region name.
pub(crate) fn default_region(
    settings: &HashMap<String, String>,
) -> Result<Region, InvalidSettings> {
    let unknown: BTreeSet<String> = settings
        .keys()
        .filter(|name| name.as_str() != DEFAULT_REGION)
        .map(|name| name.chars().take(64).collect())
        .collect();
    let region = settings
        .get(DEFAULT_REGION)
        .map(|value| Region::parse(value))
        .transpose();
    match (region, unknown.is_empty()) {
        (Ok(region), true) => Ok(region.unwrap_or_else(Region::default_region)),
        (region, _) => Err(InvalidSettings {
            unknown,
            region: region.err(),
        }),
    }
}

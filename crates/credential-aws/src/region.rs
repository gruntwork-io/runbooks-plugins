use std::fmt;

/// The region a block works in when nothing names one: `defaultRegion`'s
/// documented default.
const DEFAULT_REGION: &str = "us-east-1";

/// The longest region name accepted. AWS's longest today is 14 characters.
const MAX_REGION_LEN: usize = 32;

/// An AWS region name such as `us-east-1`: lower-case letters, digits and
/// hyphens, starting with a letter and ending with a digit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Region(String);

/// The longest refused value an error shows. A longer one is more likely a
/// key pasted into the wrong input than a mistyped region, so it is hidden.
const MAX_SHOWN_LEN: usize = 20;

/// A value that is not a region name.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{} is not an AWS region name like us-east-1", self.shown())]
pub struct InvalidRegion {
    /// The value, when it is short enough to show.
    pub value: Option<String>,
    /// The value's length in characters.
    pub len: usize,
}

impl InvalidRegion {
    fn shown(&self) -> String {
        self.value.as_ref().map_or_else(
            || format!("a {}-character value", self.len),
            |value| format!("{value:?}"),
        )
    }
}

impl Region {
    /// # Errors
    ///
    /// [`InvalidRegion`] for anything but a region name.
    pub fn parse(value: &str) -> Result<Self, InvalidRegion> {
        let well_formed = value.len() <= MAX_REGION_LEN
            && value.contains('-')
            && value.starts_with(|c: char| c.is_ascii_lowercase())
            && value.ends_with(|c: char| c.is_ascii_digit())
            && value
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if well_formed {
            Ok(Self(value.to_owned()))
        } else {
            let len = value.chars().count();
            Err(InvalidRegion {
                value: (len <= MAX_SHOWN_LEN).then(|| value.to_owned()),
                len,
            })
        }
    }

    /// The region a block works in when nothing names one.
    #[must_use]
    pub fn default_region() -> Self {
        Self(DEFAULT_REGION.to_owned())
    }

    /// The region name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The region that hosts STS, IAM and the Account API for this region's
    /// partition: the partition's implicit global region. Calls go there and
    /// not to the region itself, because an opt-in region the account has
    /// not enabled refuses every call, `GetCallerIdentity` included, and a call
    /// to another partition's endpoint refuses its keys.
    ///
    /// The SDK keeps its partition table private to each service crate, so
    /// this copies `implicitGlobalRegion` from it (aws-sdk-sts 1.127.0,
    /// `endpoint_lib.rs`). A region no partition claims is commercial, as in
    /// the SDK.
    #[must_use]
    pub fn partition_home(&self) -> Self {
        const HOMES: [(&str, &str); 7] = [
            ("us-gov-", "us-gov-west-1"),
            ("us-isob-", "us-isob-east-1"),
            ("us-isof-", "us-isof-south-1"),
            ("us-iso-", "us-iso-east-1"),
            ("eu-isoe-", "eu-isoe-west-1"),
            ("eusc-", "eusc-de-east-1"),
            ("cn-", "cn-northwest-1"),
        ];
        let home = HOMES
            .iter()
            .find(|(prefix, _)| self.0.starts_with(prefix))
            .map_or(DEFAULT_REGION, |(_, home)| home);
        Self(home.to_owned())
    }
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{InvalidRegion, Region};

    #[test]
    fn region_names_parse_and_anything_else_is_refused() {
        for name in [
            "us-east-1",
            "us-gov-west-1",
            "eusc-de-east-1",
            "us-isob-east-1",
        ] {
            assert_eq!(
                Region::parse(name).map(|r| r.to_string()),
                Ok(name.to_owned())
            );
        }
        for bad in [
            "",
            "US-EAST-1",
            "us-east-",
            "useast1",
            "us_east_1",
            "us-east-1/x",
            "-us-1",
        ] {
            assert_eq!(
                Region::parse(bad),
                Err(InvalidRegion {
                    value: Some(bad.to_owned()),
                    len: bad.len(),
                }),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_long_refused_value_is_not_shown() {
        let pasted_key = "test-secret-access-key-as-long-as-a-real";
        let error = Region::parse(pasted_key).err();
        assert_eq!(
            error.map(|e| e.to_string()).as_deref(),
            Some("a 40-character value is not an AWS region name like us-east-1")
        );
    }

    #[test]
    fn each_partition_resolves_to_its_own_home_region() -> Result<(), InvalidRegion> {
        for (region, home) in [
            ("us-west-2", "us-east-1"),
            ("af-south-1", "us-east-1"),
            ("ap-southeast-7", "us-east-1"),
            ("us-gov-east-1", "us-gov-west-1"),
            ("cn-north-1", "cn-northwest-1"),
            ("eusc-de-east-1", "eusc-de-east-1"),
            ("us-iso-west-1", "us-iso-east-1"),
            ("us-isob-west-1", "us-isob-east-1"),
            ("us-isof-east-1", "us-isof-south-1"),
            ("eu-isoe-west-1", "eu-isoe-west-1"),
        ] {
            assert_eq!(
                Region::parse(region)?.partition_home().as_str(),
                home,
                "{region}"
            );
        }
        Ok(())
    }
}

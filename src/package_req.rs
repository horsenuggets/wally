use std::fmt;
use std::str::FromStr;

use anyhow::{anyhow, bail, Context};
use semver::{Version, VersionReq};
use serde::de::{Deserialize, Deserializer, Error, Visitor};
use serde::ser::{Serialize, Serializer};

use crate::package_id::PackageId;
use crate::package_name::PackageName;

/// Describes a requirement on a package, consisting of a scope, name, and valid
/// version range.
///
/// Examples of package requirements:
/// * `roblox/roact@1.4.2`
/// * `lpghatguy/asink@0.2.0-alpha.3`
/// * `foo/bar@1`
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PackageReq {
    name: PackageName,
    version_req: VersionReq,
}

impl PackageReq {
    pub fn new(name: PackageName, version_req: VersionReq) -> Self {
        PackageReq { name, version_req }
    }

    pub fn name(&self) -> &PackageName {
        &self.name
    }

    pub fn version_req(&self) -> &VersionReq {
        &self.version_req
    }

    pub fn matches_id(&self, package_id: &PackageId) -> bool {
        package_id
            .version()
            .map_or(false, |version| self.matches(package_id.name(), version))
    }

    pub fn matches(&self, name: &PackageName, version: &Version) -> bool {
        self.name() == name && self.version_req.matches(version)
    }
}

impl fmt::Display for PackageReq {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}@{}", self.name, self.version_req)
    }
}

impl FromStr for PackageReq {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> anyhow::Result<Self> {
        const BAD_FORMAT_MSG: &str = "a package requirement is of the form SCOPE/NAME@VERSION_REQ";

        let mut first_half = value.splitn(2, '/');
        let scope = first_half.next().ok_or_else(|| anyhow!(BAD_FORMAT_MSG))?;
        let name_and_version = first_half.next().ok_or_else(|| anyhow!(BAD_FORMAT_MSG))?;

        let mut second_half = name_and_version.splitn(2, '@');
        let name = second_half.next().ok_or_else(|| anyhow!(BAD_FORMAT_MSG))?;

        let version_req_source = second_half.next().ok_or_else(|| anyhow!(BAD_FORMAT_MSG))?;

        // The VersionReq type will successfully parse from an empty or
        // all-spaces string, yielding a wildcard. This is not behavior we want,
        // so let's check for that here.
        //
        // https://github.com/steveklabnik/semver-parser/issues/51
        if version_req_source.len() == 0 || version_req_source.chars().all(char::is_whitespace) {
            bail!(BAD_FORMAT_MSG);
        }

        let version_req = version_req_source
            .parse()
            .context("could not parse version requirement")?;

        let package_name = PackageName::new(scope, name).context(BAD_FORMAT_MSG)?;
        Ok(PackageReq::new(package_name, version_req))
    }
}

impl Serialize for PackageReq {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let combined_name = format!(
            "{}/{}@{}",
            self.name().scope(),
            self.name().name(),
            self.version_req()
        );
        serializer.serialize_str(&combined_name)
    }
}

impl<'de> Deserialize<'de> for PackageReq {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(PackageReqVisitor)
    }
}

struct PackageReqVisitor;

impl<'de> Visitor<'de> for PackageReqVisitor {
    type Value = PackageReq;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "a package requirement of the form SCOPE/NAME@VERSION_REQ"
        )
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
        value.parse().map_err(|err| E::custom(err))
    }
}

/// A registry requirement or a versionless, consuming-project-relative directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DependencyReq {
    Registry(PackageReq),
    Local(String),
}

pub(crate) fn is_reserved_path_component(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || (stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

/// Require one portable, normalized spelling for local paths on every platform.
pub fn validate_local_path(path: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !path.is_empty()
            && path.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && !is_reserved_path_component(part)
                    && !part.chars().any(|c| {
                        c.is_control()
                            || matches!(c, '\\' | ':' | '"' | '<' | '>' | '|' | '?' | '*')
                    })
                    && !part.ends_with('.')
                    && !part.ends_with(' ')
            }),
        "Local package paths must be normalized project-relative directories without traversal."
    );
    Ok(())
}

impl From<PackageReq> for DependencyReq {
    fn from(req: PackageReq) -> Self {
        Self::Registry(req)
    }
}

impl FromStr for DependencyReq {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> anyhow::Result<Self> {
        if let Some(path) = value.strip_prefix('^') {
            validate_local_path(path)?;
            Ok(Self::Local(path.to_owned()))
        } else {
            Ok(Self::Registry(value.parse()?))
        }
    }
}

impl fmt::Display for DependencyReq {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Registry(req) => req.fmt(formatter),
            Self::Local(path) => write!(formatter, "^{}", path),
        }
    }
}

impl Serialize for DependencyReq {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for DependencyReq {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn new() {
        let req = PackageReq::new(
            PackageName::new("foo", "bar").unwrap(),
            VersionReq::parse("1.2.3").unwrap(),
        );
        assert_eq!(req.name().scope(), "foo");
        assert_eq!(req.name().name(), "bar");
        assert_eq!(req.version_req(), &VersionReq::parse("1.2.3").unwrap());
    }

    #[test]
    fn display() {
        let req = PackageReq::new(
            PackageName::new("hello", "world").unwrap(),
            VersionReq::parse("0.2.3").unwrap(),
        );

        // The semver crate's VersionReq type stores and prints using the most
        // explicit version of a constraint. This normalization helps make
        // comparison and evaluation simpler, but make printing a little ugly.
        assert_eq!(req.to_string(), "hello/world@>=0.2.3, <0.3.0");
    }

    #[test]
    fn parse() {
        // If given a semver version, we default to the ^ operator, which means
        // "compatible with". This is a good default that Cargo also chooses.
        let default_compat: PackageReq = "hello/world@1.2.3".parse().unwrap();
        assert_eq!(default_compat.name().scope(), "hello");
        assert_eq!(default_compat.name().name(), "world");
        assert_eq!(
            default_compat.version_req(),
            &VersionReq::parse("^1.2.3").unwrap()
        );

        // Arbitrarily complex semver predicates can be chained together. This
        // range might mean "0.2.7 is really broken and I don't want it".
        let with_ops: PackageReq = "hello/world@>=0.2.0, <0.2.7".parse().unwrap();
        assert_eq!(with_ops.name().scope(), "hello");
        assert_eq!(with_ops.name().name(), "world");
        assert_eq!(
            with_ops.version_req(),
            &VersionReq::parse(">=0.2.0, <0.2.7").unwrap()
        );
    }

    #[test]
    fn parse_invalid() {
        // Package requirements require a version requirement.
        let no_version: Result<PackageReq, _> = "hello/world".parse();
        no_version.unwrap_err();
        let no_version_at: Result<PackageReq, _> = "hello/world@".parse();
        no_version_at.unwrap_err();
    }

    #[test]
    fn serialization() {
        let name = PackageName::new("lpghatguy", "asink").unwrap();
        let package_req = PackageReq::new(name, VersionReq::parse("2.3.1").unwrap());

        let serialized = serde_json::to_string(&package_req).unwrap();
        assert_eq!(serialized, "\"lpghatguy/asink@>=2.3.1, <3.0.0\"");

        let deserialized: PackageReq = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, package_req);
    }
}

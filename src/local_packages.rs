//! Source containment and derived install provenance shared by resolution and installation.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::{manifest::Realm, package_req::validate_local_path, resolution::Resolve};

pub const DESTINATIONS: [&str; 3] = ["Packages", "ServerPackages", "DevPackages"];
pub const INSTALL_LOCK_FILE: &str = ".wally-install.lock";
pub const METADATA_FILE: &str = "wally.install.json";
pub const TRANSACTION_DIR: &str = ".wally-install";

pub fn hash_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Refuse symlink aliases as well as escapes. This makes cleanup and copies independent
/// of platform-specific symlink semantics, and prevents duplicate physical identities.
pub fn source_directory(root: &Path, relative: &str) -> anyhow::Result<PathBuf> {
    validate_local_path(relative)?;
    let canonical_root = root.canonicalize()?;
    let root = canonical_root.as_path();
    let first = relative.split('/').next().unwrap();
    ensure!(
        !DESTINATIONS
            .iter()
            .any(|dir| first.eq_ignore_ascii_case(dir))
            && ![
                TRANSACTION_DIR,
                METADATA_FILE,
                INSTALL_LOCK_FILE,
                crate::lockfile::LOCKFILE_NAME
            ]
            .iter()
            .any(|name| first.eq_ignore_ascii_case(name)),
        "Local source {} overlaps an installation destination.",
        relative
    );
    let mut path = root.to_path_buf();
    for part in relative.split('/') {
        path.push(part);
        let metadata = fs_err::symlink_metadata(&path)?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "Local source contains a symlink at {}.",
            path.display()
        );
        ensure!(
            metadata.is_dir(),
            "Local source is not a directory at {}.",
            path.display()
        );
    }
    let canonical = path.canonicalize()?;
    ensure!(
        canonical.starts_with(root) && canonical != root,
        "Local source escapes the consuming project."
    );
    // A differently cased spelling can alias the same tree on case-insensitive hosts.
    ensure!(
        canonical == path,
        "Local source must use its canonical project-relative spelling."
    );
    validate_tree(&path)?;
    validate_projects(&path)?;
    Ok(path)
}

pub fn validate_tree(path: &Path) -> anyhow::Result<()> {
    for entry in WalkDir::new(path).follow_links(false) {
        let entry = entry?;
        ensure!(
            !entry.file_type().is_symlink(),
            "Refusing symbolic link at {}.",
            entry.path().display()
        );
        ensure!(
            entry.file_type().is_file() || entry.file_type().is_dir(),
            "Unsupported file type at {}.",
            entry.path().display()
        );
    }
    Ok(())
}

/// A project entrypoint must not smuggle absolute paths or external source trees into
/// an otherwise-contained package. Validate nested project mappings as well.
fn validate_projects(package: &Path) -> anyhow::Result<()> {
    fn visit(value: &serde_json::Value, base: &Path, package: &Path) -> anyhow::Result<()> {
        match value {
            serde_json::Value::Object(object) => {
                if let Some(path) = object.get("$path") {
                    let paths: Vec<&str> = if let Some(path) = path.as_str() {
                        vec![path]
                    } else if let Some(paths) = path.as_array() {
                        paths
                            .iter()
                            .map(|path| path.as_str().context("Project paths must be strings."))
                            .collect::<anyhow::Result<_>>()?
                    } else {
                        anyhow::bail!("Project paths must be strings or arrays of strings.");
                    };
                    for path in paths {
                        ensure!(
                            !path.contains('\\')
                                && !path.contains(':')
                                && !Path::new(path).is_absolute(),
                            "Local project paths must be relative to their project file."
                        );
                        let target = base.join(path).canonicalize().with_context(|| {
                            format!("Could not resolve local project path {:?}.", path)
                        })?;
                        ensure!(
                            target.starts_with(package),
                            "Local project path {:?} escapes its package source.",
                            path
                        );
                    }
                }
                for value in object.values() {
                    visit(value, base, package)?;
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    visit(value, base, package)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    for entry in WalkDir::new(package) {
        let entry = entry?;
        if entry.file_type().is_file()
            && entry
                .file_name()
                .to_str()
                .map_or(false, |name| name.ends_with(".project.json"))
        {
            let value: serde_json::Value = serde_json::from_slice(&fs_err::read(entry.path())?)
                .with_context(|| format!("Invalid local project at {}.", entry.path().display()))?;
            visit(&value, entry.path().parent().unwrap(), package)?;
        }
    }
    Ok(())
}

pub fn realm_directory(realm: Realm) -> &'static str {
    match realm {
        Realm::Shared => "Packages",
        Realm::Server => "ServerPackages",
        Realm::Dev => "DevPackages",
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstallMetadata {
    pub version: u32,
    pub manifest_hash: String,
    pub local_manifests: BTreeMap<String, String>,
    pub package_roots: Vec<PackageRoot>,
    pub generated_paths: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PackageRoot {
    pub name: String,
    pub kind: String,
    pub realm: Realm,
    pub install_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_version: Option<String>,
}

impl InstallMetadata {
    pub fn derive(
        root: &Path,
        resolved: &Resolve,
        root_id: &crate::package_id::PackageId,
    ) -> anyhow::Result<Self> {
        let mut metadata = Self {
            version: 1,
            manifest_hash: resolved
                .manifest_hashes
                .get("wally.toml")
                .context("Missing root manifest provenance.")?
                .clone(),
            local_manifests: BTreeMap::new(),
            package_roots: Vec::new(),
            generated_paths: Vec::new(),
        };
        for id in &resolved.activated {
            if id == root_id {
                continue;
            }
            if let Some(path) = id.local_path() {
                source_directory(root, path)?;
                let key = format!("{}/wally.toml", path);
                metadata.local_manifests.insert(
                    key.clone(),
                    resolved
                        .manifest_hashes
                        .get(&key)
                        .context("Missing local manifest provenance.")?
                        .clone(),
                );
            }
            for realm in resolved.metadata[id].installation_realms(id) {
                metadata.package_roots.push(PackageRoot {
                    name: id.name().to_string(),
                    kind: if id.local_path().is_some() {
                        "local"
                    } else {
                        "registry"
                    }
                    .into(),
                    realm,
                    install_path: format!(
                        "{}/_Index/{}/{}",
                        realm_directory(realm),
                        crate::installation::package_id_file_name(id),
                        id.name().name()
                    ),
                    source_path: id.local_path().map(str::to_owned),
                    package_version: id.version().map(ToString::to_string),
                });
            }
        }
        metadata
            .package_roots
            .sort_by(|a, b| a.install_path.cmp(&b.install_path));
        Ok(metadata)
    }

    pub fn verify_manifests(&self, root: &Path) -> anyhow::Result<()> {
        ensure!(
            hash_bytes(&fs_err::read(root.join("wally.toml"))?) == self.manifest_hash,
            "Root manifest changed during installation. Retry the install."
        );
        for (path, expected) in &self.local_manifests {
            let source = path
                .strip_suffix("/wally.toml")
                .context("Invalid manifest path.")?;
            let directory = source_directory(root, source)?;
            ensure!(
                hash_bytes(&fs_err::read(directory.join("wally.toml"))?) == *expected,
                "Local manifest {} changed during installation. Retry the install.",
                path
            );
        }
        Ok(())
    }

    pub fn save(&self, stage: &Path) -> anyhow::Result<()> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        fs_err::write(stage.join(METADATA_FILE), bytes)?;
        Ok(())
    }
}

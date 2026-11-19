//! Refreshes only manifest-declared local installation roots. Canonical sources are
//! never write destinations, and packaging rules remain owned by PackageContents.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use walkdir::WalkDir;

use crate::install_transaction::{fingerprint, lock_installation, sync_dir};
use crate::installation::package_id_file_name;
use crate::local_packages::{
    realm_directory, source_directory, InstallMetadata, METADATA_FILE, TRANSACTION_DIR,
};
use crate::manifest::{Manifest, Realm};
use crate::package_contents::PackageContents;
use crate::package_id::PackageId;
use crate::package_name::PackageName;
use crate::package_req::{validate_local_path, DependencyReq};
use crate::package_source::PackageSourceId;
use crate::resolution::ResolvePackageMetadata;

const SOURCE_ATTEMPTS: usize = 3;

#[derive(Debug)]
pub(crate) struct SourceChanged;

impl std::fmt::Display for SourceChanged {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output
            .write_str("Local package source changed during staging. Retry local synchronization.")
    }
}

impl std::error::Error for SourceChanged {}

fn source_read_error(error: anyhow::Error) -> anyhow::Error {
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .or_else(|| cause.downcast_ref::<walkdir::Error>()?.io_error())
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    }) {
        SourceChanged.into()
    } else {
        error
    }
}

struct Declaration {
    manifest: Manifest,
    origins: BTreeSet<Realm>,
}

struct Mirror {
    source: PathBuf,
    destination: PathBuf,
}

struct MirrorState {
    source: String,
    installed: String,
}

struct PreparedMirror {
    index: usize,
    stage: TempDir,
    state: MirrorState,
    before: Option<String>,
}

pub(crate) struct LocalSync {
    root: PathBuf,
    metadata: InstallMetadata,
    generation: Vec<u8>,
    mirrors: Vec<Mirror>,
    states: BTreeMap<usize, MirrorState>,
    _lock: File,
}

impl LocalSync {
    pub fn new(root: &Path) -> anyhow::Result<Self> {
        let root = root.canonicalize()?;
        let lock = lock_installation(&root)?;
        ensure!(
            fs_err::symlink_metadata(root.join(TRANSACTION_DIR)).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "An interrupted Wally installation must be recovered with \"wally install\" before local synchronization."
        );
        let generation = read_regular(&root.join(METADATA_FILE))
            .context("Run \"wally install\" before synchronizing local package mirrors.")?;
        let metadata: InstallMetadata = serde_json::from_slice(&generation)?;
        ensure!(
            metadata.version == 1,
            "Unsupported Wally installation metadata version."
        );
        let declarations = declarations(&root)?;
        let hashes: BTreeMap<_, _> = declarations
            .iter()
            .map(|(path, declaration)| {
                (
                    format!("{path}/wally.toml"),
                    declaration.manifest.content_hash.clone().unwrap(),
                )
            })
            .collect();
        ensure!(
            metadata.local_manifests == hashes,
            "Local package ownership is stale. Run \"wally install\"."
        );
        metadata.verify_manifests(&root)?;
        let mut represented = BTreeSet::new();
        let mut destinations = BTreeSet::new();
        let mut mirrors = Vec::new();
        for package in &metadata.package_roots {
            let name: PackageName = package.name.parse()?;
            let id = match package.kind.as_str() {
                "local" => {
                    ensure!(
                        package.package_version.is_none(),
                        "Local packages cannot claim registry versions."
                    );
                    let source = package
                        .source_path
                        .as_ref()
                        .context("Local package source is missing.")?;
                    let declaration = declarations
                        .get(source)
                        .context("Local package source is not declared by the project.")?;
                    ensure!(
                        declaration.manifest.package.name == name,
                        "Local package identity differs from its manifest."
                    );
                    let identity = ResolvePackageMetadata {
                        realm: declaration.manifest.package.realm,
                        origin_realms: declaration.origins.clone(),
                        source_registry: PackageSourceId::DefaultRegistry,
                    };
                    ensure!(
                        package.realm == identity.origin_realm(),
                        "Local installation realm differs from its declared consumers."
                    );
                    ensure!(
                        represented.insert(source.clone()),
                        "A local package has multiple installed identities."
                    );
                    PackageId::local(name.clone(), source.clone())
                }
                "registry" => {
                    ensure!(
                        package.source_path.is_none(),
                        "Registry packages cannot claim local sources."
                    );
                    PackageId::new(
                        name.clone(),
                        package
                            .package_version
                            .as_ref()
                            .context("Registry package version is missing.")?
                            .parse()?,
                    )
                }
                _ => bail!("Unknown Wally package ownership kind."),
            };
            let expected = format!(
                "{}/_Index/{}/{}",
                realm_directory(package.realm),
                package_id_file_name(&id),
                name.name()
            );
            ensure!(
                package.install_path == expected,
                "Package installation slot differs from its declared identity."
            );
            let destination = root.join(&expected);
            validate_destination(&root, &destination)?;
            ensure!(
                destinations.insert(destination.clone()),
                "Duplicate package installation slot."
            );
            if let Some(source) = &package.source_path {
                mirrors.push(Mirror {
                    source: source_directory(&root, source)?,
                    destination,
                });
            }
        }
        ensure!(
            represented == declarations.keys().cloned().collect(),
            "Declared local packages are missing from the installation."
        );
        let mut generated = BTreeSet::new();
        for path in &metadata.generated_paths {
            validate_local_path(path)?;
            ensure!(
                crate::local_packages::DESTINATIONS
                    .iter()
                    .any(|surface| Path::new(path).starts_with(surface))
                    && Path::new(path).components().count() > 1,
                "Generated Wally paths must remain inside installation surfaces."
            );
            ensure!(generated.insert(path), "Duplicate generated Wally path.");
            let path = root.join(path);
            ensure!(
                mirrors
                    .iter()
                    .all(|mirror| !path.starts_with(&mirror.destination)
                        && !mirror.destination.starts_with(&path)),
                "Generated Wally shims overlap a local package installation."
            );
        }
        Ok(Self {
            root,
            metadata,
            generation,
            mirrors,
            states: BTreeMap::new(),
            _lock: lock,
        })
    }

    fn check_generation(&self) -> anyhow::Result<()> {
        ensure!(read_regular(&self.root.join(METADATA_FILE))? == self.generation, "Wally installation ownership changed. Restart local synchronization after \"wally install\".");
        read_regular(&self.root.join("wally.toml"))?;
        self.metadata.verify_manifests(&self.root)
            .map_err(source_read_error)
            .context("Package declarations changed. Run \"wally install\" and restart local synchronization.")
    }

    pub fn refresh(&mut self) -> anyhow::Result<usize> {
        for attempt in 0..SOURCE_ATTEMPTS {
            match self.refresh_before_publication(|| Ok(())) {
                Err(error) if attempt + 1 < SOURCE_ATTEMPTS && error.is::<SourceChanged>() => {}
                result => return result,
            }
        }
        unreachable!()
    }

    fn refresh_before_publication(
        &mut self,
        before_publication: impl FnOnce() -> anyhow::Result<()>,
    ) -> anyhow::Result<usize> {
        self.check_generation()?;
        let mut prepared = Vec::new();
        for (index, mirror) in self.mirrors.iter().enumerate() {
            validate_destination(&self.root, &mirror.destination)?;
            let source = source_fingerprint(&mirror.source)?;
            let installed = fingerprint(&mirror.destination)?;
            if self.states.get(&index).is_some_and(|state| {
                state.source == source && installed.as_ref() == Some(&state.installed)
            }) {
                continue;
            }
            let contents =
                PackageContents::pack_from_path(&mirror.source).map_err(source_read_error)?;
            let stage = tempfile::tempdir()?;
            contents.unpack_into_path(stage.path())?;
            let desired = fingerprint(stage.path())?.unwrap();
            ensure!(source_fingerprint(&mirror.source)? == source, SourceChanged);
            prepared.push(PreparedMirror {
                index,
                stage,
                state: MirrorState {
                    source,
                    installed: desired,
                },
                before: installed,
            });
        }
        before_publication()?;
        self.check_generation()?;
        // Validate every staged preimage before changing any generated destination.
        for package in &prepared {
            let mirror = &self.mirrors[package.index];
            validate_destination(&self.root, &mirror.destination)?;
            ensure!(
                source_fingerprint(&mirror.source)? == package.state.source,
                SourceChanged
            );
            ensure!(
                fingerprint(&mirror.destination)? == package.before,
                "Local package installation changed during staging. Retry local synchronization."
            );
        }
        let mut refreshed = 0;
        for package in prepared {
            let mirror = &self.mirrors[package.index];
            if package.before.as_ref() != Some(&package.state.installed) {
                refresh_tree(&self.root, package.stage.path(), &mirror.destination)?;
                ensure!(fingerprint(&mirror.destination)?.as_ref() == Some(&package.state.installed), "Local package installation changed during publication. Retry local synchronization.");
                refreshed += 1;
            }
            self.states.insert(package.index, package.state);
        }
        Ok(refreshed)
    }
}

fn declarations(root: &Path) -> anyhow::Result<BTreeMap<String, Declaration>> {
    let root_manifest = Manifest::from_slice(&read_regular(&root.join("wally.toml"))?)?;
    let mut pending = VecDeque::new();
    for (realm, requirements) in [
        (Realm::Shared, &root_manifest.dependencies),
        (Realm::Server, &root_manifest.server_dependencies),
        (Realm::Dev, &root_manifest.dev_dependencies),
    ] {
        for requirement in requirements.values() {
            if let DependencyReq::Local(path) = requirement {
                pending.push_back((path.clone(), realm, realm));
            }
        }
    }
    let mut declarations: BTreeMap<String, Declaration> = BTreeMap::new();
    let mut names = BTreeMap::new();
    while let Some((path, request, origin)) = pending.pop_front() {
        if !declarations.contains_key(&path) {
            let directory = source_directory(root, &path)?;
            let manifest = Manifest::load(&directory)?;
            ensure!(
                names
                    .insert(manifest.package.name.clone(), path.clone())
                    .is_none(),
                "Different local sources claim the same package identity."
            );
            declarations.insert(
                path.clone(),
                Declaration {
                    manifest,
                    origins: BTreeSet::new(),
                },
            );
        }
        let declaration = declarations.get_mut(&path).unwrap();
        ensure!(
            Realm::is_dependency_valid(request, declaration.manifest.package.realm),
            "Local package realm is incompatible with its dependency declaration."
        );
        if !declaration.origins.insert(origin) {
            continue;
        }
        for (edge, requirements) in [
            (Realm::Shared, &declaration.manifest.dependencies),
            (Realm::Server, &declaration.manifest.server_dependencies),
        ] {
            for requirement in requirements.values() {
                if let DependencyReq::Local(path) = requirement {
                    pending.push_back((path.clone(), edge, Realm::dependency_origin(origin, edge)));
                }
            }
        }
    }
    Ok(declarations)
}

fn read_regular(path: &Path) -> anyhow::Result<Vec<u8>> {
    let metadata = fs_err::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "Expected a regular provenance file at {}.",
        path.display()
    );
    Ok(fs_err::read(path)?)
}

fn validate_destination(root: &Path, path: &Path) -> anyhow::Result<()> {
    let relative = path.strip_prefix(root)?;
    validate_local_path(
        &relative
            .to_str()
            .context("Non-Unicode package installation path.")?
            .replace('\\', "/"),
    )?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs_err::symlink_metadata(&current) {
            Ok(metadata) => ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "Unsafe local package installation directory at {}.",
                current.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn source_fingerprint(source: &Path) -> anyhow::Result<String> {
    let mut hash = Sha256::new();
    for path in PackageContents::filtered_contents(source).map_err(source_read_error)? {
        let relative = path
            .strip_prefix(source)?
            .to_str()
            .context("Non-Unicode local package path.")?
            .replace('\\', "/");
        hash.update((relative.len() as u64).to_le_bytes());
        hash.update(relative.as_bytes());
        if path.is_file() {
            let bytes = fs_err::read(path).map_err(|error| source_read_error(error.into()))?;
            hash.update(b"f");
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(&bytes);
        } else {
            hash.update(b"d");
        }
    }
    Ok(hex::encode(hash.finalize()))
}

fn refresh_tree(root: &Path, stage: &Path, destination: &Path) -> anyhow::Result<()> {
    let desired: BTreeMap<_, _> = WalkDir::new(stage)
        .min_depth(1)
        .into_iter()
        .map(|entry| {
            let entry = entry?;
            Ok((
                entry.path().strip_prefix(stage)?.to_path_buf(),
                entry.file_type().is_dir(),
            ))
        })
        .collect::<anyhow::Result<_>>()?;
    let mut old = if destination.exists() {
        WalkDir::new(destination)
            .min_depth(1)
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    old.sort_by_key(|entry| std::cmp::Reverse(entry.depth()));
    for entry in old {
        let relative = entry.path().strip_prefix(destination)?;
        if desired.get(relative) == Some(&entry.file_type().is_dir()) {
            continue;
        }
        validate_destination(root, entry.path().parent().unwrap())?;
        ensure!(
            !entry.file_type().is_symlink(),
            "Refusing a symbolic link in a local installation."
        );
        if entry.file_type().is_dir() {
            fs_err::remove_dir(entry.path())?;
        } else {
            fs_err::remove_file(entry.path())?;
        }
    }
    validate_destination(root, destination)?;
    fs_err::create_dir_all(destination)?;
    for (relative, directory) in desired {
        let target = destination.join(&relative);
        if directory {
            validate_destination(root, &target)?;
            fs_err::create_dir_all(&target)?;
            continue;
        }
        let source = stage.join(&relative);
        let bytes = fs_err::read(&source)?;
        if fs_err::read(&target).ok().as_deref() == Some(bytes.as_slice()) {
            continue;
        }
        let parent = target.parent().unwrap();
        validate_destination(root, parent)?;
        fs_err::create_dir_all(parent)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary
            .as_file()
            .set_permissions(fs_err::metadata(&source)?.permissions())?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary.persist(&target).map_err(|error| error.error)?;
        sync_dir(parent)?;
    }
    sync_dir(destination)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GlobalOptions, InstallSubcommand};
    use serde_json::{json, Value};

    fn write(root: &Path, path: &str, contents: impl AsRef<[u8]>) {
        let path = root.join(path);
        fs_err::create_dir_all(path.parent().unwrap()).unwrap();
        fs_err::write(path, contents).unwrap();
    }

    fn fixture() -> TempDir {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        write(root, "wally.toml", "[package]\nname = 'fixture/root'\nversion = '1.0.0'\nrealm = 'shared'\n[dependencies]\nShared = '^Forks/shared'\n[server-dependencies]\nServer = '^Forks/server'\nShared = '^Forks/shared'\n[dev-dependencies]\nDeveloper = '^Forks/developer'\nShared = '^Forks/shared'\n");
        for (name, realm) in [
            ("shared", "shared"),
            ("server", "server"),
            ("developer", "shared"),
        ] {
            write(root, &format!("Forks/{name}/wally.toml"), format!("[package]\nname = 'fixture/{name}'\nrealm = '{realm}'\nexclude = ['ignored.luau']\n"));
            write(
                root,
                &format!("Forks/{name}/default.project.json"),
                r#"{"name":"different-name","tree":{"$path":"src"}}"#,
            );
            write(
                root,
                &format!("Forks/{name}/src/init.luau"),
                "return 'initial'\n",
            );
            write(
                root,
                &format!("Forks/{name}/src/Removed.luau"),
                "return 'remove'\n",
            );
            write(
                root,
                &format!("Forks/{name}/ignored.luau"),
                "return 'excluded'\n",
            );
            write(
                root,
                &format!("Forks/{name}/private.luau"),
                "return 'private'\n",
            );
            write(root, &format!("Forks/{name}/.gitignore"), "private.luau\n");
            write(root, &format!("Forks/{name}/.env"), "PRIVATE=test-only\n");
        }
        InstallSubcommand {
            project_path: root.into(),
            locked: false,
        }
        .run(GlobalOptions::default())
        .unwrap();
        temporary
    }

    fn installed(root: &Path, name: &str) -> PathBuf {
        let surface = match name {
            "shared" => "Packages",
            "server" => "ServerPackages",
            "developer" => "DevPackages",
            _ => unreachable!(),
        };
        root.join(format!("{surface}/_Index/fixture_{name}@local/{name}"))
    }

    fn protected(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        WalkDir::new(root)
            .into_iter()
            .map(Result::unwrap)
            .filter(|entry| entry.file_type().is_file())
            .filter(|entry| {
                !entry.path().starts_with(root.join("Forks"))
                    && !["shared", "server", "developer"]
                        .iter()
                        .any(|name| entry.path().starts_with(installed(root, name)))
            })
            .map(|entry| {
                (
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    fs_err::read(entry.path()).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn local_mirrors_refresh_all_realms_without_registry_or_shim_writes() {
        let temporary = fixture();
        let root = temporary.path();
        write(
            root,
            "Packages/_Index/fixture_registry@1.0.0/registry/init.luau",
            "return 'registry'\n",
        );
        let preserved = protected(root);
        let mut sync = LocalSync::new(root).unwrap();
        assert_eq!(sync.refresh().unwrap(), 0);
        for name in ["shared", "server", "developer"] {
            write(
                root,
                &format!("Forks/{name}/src/init.luau"),
                format!("return '{name}-updated'\n"),
            );
            fs_err::remove_file(root.join(format!("Forks/{name}/src/Removed.luau"))).unwrap();
            write(
                root,
                &format!("Forks/{name}/src/Added.luau"),
                "return 'added'\n",
            );
            write(
                root,
                &format!("Forks/{name}/src/Nested/New.luau"),
                "return 'nested'\n",
            );
            write(root, &format!("Forks/{name}/src/Data.bin"), [0, 128, 255]);
        }
        assert_eq!(sync.refresh().unwrap(), 3);
        for name in ["shared", "server", "developer"] {
            let directory = installed(root, name);
            assert_eq!(
                fs_err::read_to_string(directory.join("src/init.luau")).unwrap(),
                format!("return '{name}-updated'\n")
            );
            assert!(!directory.join("src/Removed.luau").exists());
            assert!(directory.join("src/Added.luau").is_file());
            assert!(directory.join("src/Nested/New.luau").is_file());
            assert_eq!(
                fs_err::read(directory.join("src/Data.bin")).unwrap(),
                [0, 128, 255]
            );
            assert!(!directory.join("ignored.luau").exists());
            assert!(!directory.join("private.luau").exists());
            assert!(!directory.join(".env").exists());
            let project: Value = serde_json::from_slice(
                &fs_err::read(directory.join("default.project.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(project["name"], name);
            let original: Value = serde_json::from_slice(
                &fs_err::read(root.join(format!("Forks/{name}/default.project.json"))).unwrap(),
            )
            .unwrap();
            assert_eq!(original["name"], "different-name");
        }
        assert_eq!(protected(root), preserved);
        assert_eq!(sync.refresh().unwrap(), 0);
    }

    #[test]
    fn transient_source_traversal_errors_do_not_end_synchronization() {
        let temporary = fixture();
        let root = temporary.path();
        let traversal_error = WalkDir::new(root.join("missing"))
            .into_iter()
            .next()
            .unwrap()
            .unwrap_err();
        assert!(source_read_error(
            anyhow::Error::new(traversal_error).context("Source traversal failed.")
        )
        .is::<SourceChanged>());
        let denied = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            .context("Source access failed.");
        assert!(!source_read_error(denied).is::<SourceChanged>());

        let mut sync = LocalSync::new(root).unwrap();
        sync.refresh().unwrap();
        fs_err::rename(
            root.join("Forks/shared/src"),
            root.join("Forks/shared/parked"),
        )
        .unwrap();
        assert!(sync.refresh().unwrap_err().is::<SourceChanged>());
        fs_err::rename(
            root.join("Forks/shared/parked"),
            root.join("Forks/shared/src"),
        )
        .unwrap();
        write(root, "Forks/shared/src/init.luau", "return 'settled'\n");
        assert_eq!(sync.refresh().unwrap(), 1);
        assert_eq!(
            fs_err::read_to_string(installed(root, "shared").join("src/init.luau")).unwrap(),
            "return 'settled'\n"
        );
        write(
            root,
            "Forks/shared/wally.toml",
            "[package]\nname = 'fixture/changed'\nrealm = 'shared'\n",
        );
        assert!(!sync.refresh().unwrap_err().is::<SourceChanged>());
    }

    #[test]
    fn generated_edits_and_interrupted_refreshes_never_become_original_sources() {
        let temporary = fixture();
        let root = temporary.path();
        let original = fs_err::read(root.join("Forks/shared/src/init.luau")).unwrap();
        {
            let mut sync = LocalSync::new(root).unwrap();
            sync.refresh().unwrap();
            fs_err::write(
                installed(root, "shared").join("src/init.luau"),
                "return 'generated-only'\n",
            )
            .unwrap();
            write(
                &installed(root, "shared"),
                ".tmp-interrupted",
                "partial staged output",
            );
            assert_eq!(sync.refresh().unwrap(), 1);
            assert_eq!(
                fs_err::read(root.join("Forks/shared/src/init.luau")).unwrap(),
                original
            );
        }
        fs_err::remove_file(installed(root, "shared").join("src/init.luau")).unwrap();
        write(
            &installed(root, "shared"),
            "src/Unexpected.luau",
            "return 'unexpected'\n",
        );
        let mut restarted = LocalSync::new(root).unwrap();
        assert_eq!(restarted.refresh().unwrap(), 1);
        assert_eq!(
            fs_err::read(installed(root, "shared").join("src/init.luau")).unwrap(),
            original
        );
        assert!(!installed(root, "shared")
            .join("src/Unexpected.luau")
            .exists());
        assert!(!installed(root, "shared").join(".tmp-interrupted").exists());
    }

    #[test]
    fn renames_directory_removals_and_file_directory_replacements_converge() {
        let temporary = fixture();
        let root = temporary.path();
        let mut sync = LocalSync::new(root).unwrap();
        write(root, "Forks/shared/src/Nested/Old.luau", "return 'old'\n");
        sync.refresh().unwrap();
        fs_err::rename(
            root.join("Forks/shared/src/Removed.luau"),
            root.join("Forks/shared/src/Renamed.luau"),
        )
        .unwrap();
        fs_err::remove_dir_all(root.join("Forks/shared/src/Nested")).unwrap();
        write(root, "Forks/shared/src/Nested", "now a file");
        fs_err::remove_file(root.join("Forks/shared/src/init.luau")).unwrap();
        write(
            root,
            "Forks/shared/src/init.luau/Child.luau",
            "return 'now a directory'\n",
        );
        assert_eq!(sync.refresh().unwrap(), 1);
        let destination = installed(root, "shared");
        assert!(!destination.join("src/Removed.luau").exists());
        assert!(destination.join("src/Renamed.luau").is_file());
        assert_eq!(
            fs_err::read_to_string(destination.join("src/Nested")).unwrap(),
            "now a file"
        );
        assert!(destination.join("src/init.luau/Child.luau").is_file());
    }

    #[test]
    fn forged_or_stale_install_ownership_is_rejected_before_any_copy() {
        for change in 0..8 {
            let temporary = fixture();
            let root = temporary.path();
            let original = fingerprint(&installed(root, "shared")).unwrap();
            let path = root.join(METADATA_FILE);
            let mut metadata: Value =
                serde_json::from_slice(&fs_err::read(&path).unwrap()).unwrap();
            match change {
                0 => {
                    metadata["package_roots"][0]["install_path"] =
                        json!("Packages/_Index/fixture_registry@1.0.0/registry")
                }
                1 => metadata["package_roots"][0]["source_path"] = json!("../outside"),
                2 => metadata["package_roots"][0]["realm"] = json!("server"),
                3 => metadata["package_roots"][0]["name"] = json!("fixture/not-declared"),
                4 => metadata["local_manifests"] = json!({}),
                5 => metadata["version"] = json!(999),
                6 => {
                    let duplicate = metadata["package_roots"][0].clone();
                    metadata["package_roots"]
                        .as_array_mut()
                        .unwrap()
                        .push(duplicate);
                }
                7 => {
                    let root = metadata["package_roots"][0]["install_path"]
                        .as_str()
                        .unwrap()
                        .to_owned();
                    metadata["generated_paths"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!(format!("{root}/shim.luau")));
                }
                _ => unreachable!(),
            }
            fs_err::write(path, serde_json::to_vec(&metadata).unwrap()).unwrap();
            assert!(
                LocalSync::new(root).is_err(),
                "The ownership case \"{}\" was accepted.",
                change
            );
            assert_eq!(fingerprint(&installed(root, "shared")).unwrap(), original);
        }
    }

    #[test]
    fn staged_changes_are_checked_before_any_destination_is_modified() {
        for changed_surface in ["source", "installed", "provenance"] {
            let temporary = fixture();
            let root = temporary.path();
            let mut sync = LocalSync::new(root).unwrap();
            write(root, "Forks/shared/src/init.luau", "return 'staged'\n");
            let server_before = fingerprint(&installed(root, "server")).unwrap();
            let shared_before = fingerprint(&installed(root, "shared")).unwrap();
            let result = sync.refresh_before_publication(|| {
                match changed_surface {
                    "source" => write(
                        root,
                        "Forks/shared/src/init.luau",
                        "return 'newer source'\n",
                    ),
                    "installed" => fs_err::write(
                        installed(root, "shared").join("src/init.luau"),
                        "return 'concurrent output'\n",
                    )?,
                    "provenance" => {
                        let mut bytes = fs_err::read(root.join(METADATA_FILE))?;
                        bytes.push(b' ');
                        fs_err::write(root.join(METADATA_FILE), bytes)?;
                    }
                    _ => unreachable!(),
                }
                Ok(())
            });
            assert!(
                result.is_err(),
                "Concurrent \"{}\" changes were not rejected.",
                changed_surface
            );
            assert_eq!(
                fingerprint(&installed(root, "server")).unwrap(),
                server_before
            );
            if changed_surface != "installed" {
                assert_eq!(
                    fingerprint(&installed(root, "shared")).unwrap(),
                    shared_before
                );
            }
            if changed_surface == "source" {
                assert!(result.unwrap_err().is::<SourceChanged>());
                assert_eq!(sync.refresh().unwrap(), 1);
                assert_eq!(
                    fs_err::read_to_string(installed(root, "shared").join("src/init.luau"))
                        .unwrap(),
                    "return 'newer source'\n"
                );
            }
        }
    }

    #[test]
    fn the_existing_install_lock_excludes_parallel_installers_and_watchers() {
        let temporary = fixture();
        let sync = LocalSync::new(temporary.path()).unwrap();
        assert!(LocalSync::new(temporary.path()).is_err());
        assert!(crate::install_transaction::InstallTransaction::begin(temporary.path()).is_err());
        drop(sync);
        assert!(LocalSync::new(temporary.path()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn source_and_installation_symlinks_cannot_escape_ownership() {
        use std::os::unix::fs::symlink;
        for source_link in [false, true] {
            let temporary = fixture();
            let root = temporary.path();
            let outside = tempfile::tempdir().unwrap();
            write(outside.path(), "preserved.luau", "return 'outside'\n");
            if source_link {
                symlink(outside.path(), root.join("Forks/shared/escape")).unwrap();
            } else {
                let destination = installed(root, "shared");
                fs_err::remove_dir_all(&destination).unwrap();
                symlink(outside.path(), destination).unwrap();
            }
            assert!(LocalSync::new(root).is_err());
            assert_eq!(
                fs_err::read_to_string(outside.path().join("preserved.luau")).unwrap(),
                "return 'outside'\n"
            );
        }
    }
}

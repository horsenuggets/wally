use std::{
    collections::BTreeMap,
    fmt::Display,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::bail;
use crossterm::style::{Color, SetForegroundColor};
use fs_err as fs;
use indicatif::{ProgressBar, ProgressStyle};
use indoc::formatdoc;

use crate::{
    manifest::Realm,
    package_contents::PackageContents,
    package_id::PackageId,
    package_source::{PackageSourceMap, PackageSourceProvider},
    resolution::Resolve,
};

#[derive(Clone)]
pub struct InstallationContext {
    shared_dir: PathBuf,
    shared_index_dir: PathBuf,
    shared_path: Option<String>,
    server_dir: PathBuf,
    server_index_dir: PathBuf,
    server_path: Option<String>,
    dev_dir: PathBuf,
    dev_index_dir: PathBuf,
    type_exports: BTreeMap<PackageId, crate::link_types::ForwardedTypes>,
}

impl InstallationContext {
    /// Create a new `InstallationContext` for the given path.
    pub fn new(
        project_path: &Path,
        shared_path: Option<String>,
        server_path: Option<String>,
    ) -> Self {
        let shared_dir = project_path.join("Packages");
        let server_dir = project_path.join("ServerPackages");
        let dev_dir = project_path.join("DevPackages");

        let shared_index_dir = shared_dir.join("_Index");
        let server_index_dir = server_dir.join("_Index");
        let dev_index_dir = dev_dir.join("_Index");

        Self {
            shared_dir,
            shared_index_dir,
            shared_path,
            server_dir,
            server_index_dir,
            server_path,
            dev_dir,
            dev_index_dir,
            type_exports: BTreeMap::new(),
        }
    }

    /// Install all packages from the given `Resolve` into the package that this
    /// `InstallationContext` was built for.
    pub(crate) fn install_atomic(
        project_path: &Path,
        sources: PackageSourceMap,
        manifest: &crate::manifest::Manifest,
        resolved: Resolve,
        transaction: crate::install_transaction::InstallTransaction,
    ) -> anyhow::Result<()> {
        let root = project_path.canonicalize()?;
        let root_id = manifest.package_id();
        let mut metadata =
            crate::local_packages::InstallMetadata::derive(&root, &resolved, &root_id)?;
        let stage = transaction.stage();
        let context = Self::new(
            &stage,
            manifest.place.shared_packages.clone(),
            manifest.place.server_packages.clone(),
        );
        context.install(sources, root_id, resolved.clone())?;
        for dir in crate::local_packages::DESTINATIONS {
            let base = stage.join(dir);
            if !base.exists() {
                continue;
            }
            for entry in walkdir::WalkDir::new(&base) {
                let entry = entry?;
                if !entry.file_type().is_file() {
                    continue;
                }
                let relative = entry
                    .path()
                    .strip_prefix(&stage)?
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("Non-Unicode generated path."))?
                    .replace('\\', "/");
                if !metadata
                    .package_roots
                    .iter()
                    .any(|package| relative.starts_with(&format!("{}/", package.install_path)))
                {
                    metadata.generated_paths.push(relative);
                }
            }
        }
        metadata.generated_paths.sort();
        let lockfile = crate::lockfile::Lockfile::from_resolve(&resolved);
        lockfile.save(&stage)?;
        metadata.save(&stage)?;
        metadata.verify_manifests(&root)?;
        transaction.commit()
    }

    fn install(
        mut self,
        sources: PackageSourceMap,
        root_package_id: PackageId,
        resolved: Resolve,
    ) -> anyhow::Result<()> {
        let mut handles: Vec<tokio::task::JoinHandle<anyhow::Result<()>>> = Vec::new();
        let resolved_copy = resolved.clone();
        let bar = ProgressBar::new((resolved_copy.activated.len() - 1) as u64).with_style(
            ProgressStyle::with_template(
                "{spinner:.cyan.bold} {pos}/{len} [{wide_bar:.cyan/blue}]",
            )
            .unwrap()
            .tick_chars("⠁⠈⠐⠠⠄⠂ ")
            .progress_chars("#>-"),
        );
        bar.enable_steady_tick(Duration::from_millis(100));

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(50)
            .enable_all()
            .build()
            .unwrap();

        for package_id in resolved_copy.activated {
            log::debug!("Installing {}...", package_id);

            // The root itself is not copied into its generated package directories.
            if package_id != root_package_id {
                let metadata = resolved.metadata.get(&package_id).unwrap();
                let origin_realms = metadata.installation_realms(&package_id);

                // Install the package to all realms it's needed in
                let source_registry = resolved_copy.metadata[&package_id].source_registry.clone();
                let source_copy = sources.clone();
                let context = self.clone();
                let b = bar.clone();

                let handle = runtime.spawn_blocking(move || {
                    let contents = if let Some(path) = package_id.local_path() {
                        let source = crate::local_packages::source_directory(
                            source_copy.project_root()?,
                            path,
                        )?;
                        PackageContents::pack_from_path(&source)?
                    } else {
                        let package_source = source_copy.get(&source_registry).unwrap();
                        package_source.download_package(&package_id)?
                    };
                    b.println(format!(
                        "{} Downloaded {}{}",
                        SetForegroundColor(Color::DarkGreen),
                        SetForegroundColor(Color::Reset),
                        package_id,
                    ));
                    b.inc(1);
                    // Install to all realms where this package is needed
                    for realm in origin_realms {
                        context.write_contents(&package_id, &contents, realm)?;
                    }
                    Ok(())
                });

                handles.push(handle);
            }
        }

        let num_packages = handles.len();

        for handle in handles {
            runtime
                .block_on(handle)
                .expect("Package failed to be installed.")?;
        }

        // All entrypoints must be read from the fully unpacked staging tree. In
        // particular, local include/exclude rules and registry archives are authoritative.
        for id in &resolved.activated {
            if id == &root_package_id {
                continue;
            }
            let realms = resolved.metadata[id].installation_realms(id);
            let index = match realms.iter().next().expect("Installed package has a realm") {
                Realm::Shared => &self.shared_index_dir,
                Realm::Server => &self.server_index_dir,
                Realm::Dev => &self.dev_index_dir,
            };
            let root = index.join(package_id_file_name(id)).join(id.name().name());
            self.type_exports
                .insert(id.clone(), crate::link_types::exports(&root)?);
        }
        self.write_all_root_package_links(&root_package_id, &resolved)?;
        for id in &resolved.activated {
            if id == &root_package_id {
                continue;
            }
            for realm in resolved.metadata[id].installation_realms(id) {
                for graph in [
                    &resolved.shared_dependencies,
                    &resolved.server_dependencies,
                    &resolved.dev_dependencies,
                ] {
                    if let Some(dependencies) = graph.get(id) {
                        self.write_package_links(id, realm, dependencies, &resolved)?;
                    }
                }
            }
        }

        // Root consumers use realm aliases, while installed sources use the private
        // dependency shims in their own index bucket. Keep both configurations outside
        // physical package roots so source contents stay intact and provenance owns them.
        let mut aliases = serde_json::to_vec_pretty(&serde_json::json!({
            "aliases": { "packages": "./" }
        }))?;
        aliases.push(b'\n');
        for directory in [&self.shared_dir, &self.server_dir, &self.dev_dir] {
            if directory.is_dir() {
                fs::write(directory.join(".luaurc"), &aliases)?;
            }
        }

        for id in &resolved.activated {
            if id == &root_package_id {
                continue;
            }
            for realm in resolved.metadata[id].installation_realms(id) {
                let index = match realm {
                    Realm::Shared => &self.shared_index_dir,
                    Realm::Server => &self.server_index_dir,
                    Realm::Dev => &self.dev_index_dir,
                };
                fs::write(
                    index.join(package_id_file_name(id)).join(".luaurc"),
                    &aliases,
                )?;
            }
        }

        bar.finish_and_clear();
        eprintln!(
            "{}",
            crate::terminal_style::downloaded(
                crate::terminal_style::Style::from_env(),
                num_packages
            )
        );

        Ok(())
    }

    /// Preserve unambiguous transitive root aliases for @packages consumers, without
    /// allowing a transitive alias to overwrite a declared root dependency or leak a
    /// server/dev package into the shared realm. Ambiguous aliases remain package-local.
    fn write_all_root_package_links(
        &self,
        root: &PackageId,
        resolved: &Resolve,
    ) -> anyhow::Result<()> {
        use std::collections::BTreeMap;
        let graphs = [
            (Realm::Shared, &resolved.shared_dependencies),
            (Realm::Server, &resolved.server_dependencies),
            (Realm::Dev, &resolved.dev_dependencies),
        ];
        let mut roots: BTreeMap<Realm, BTreeMap<String, PackageId>> = BTreeMap::new();
        let mut candidates: BTreeMap<(Realm, String), Option<(String, PackageId)>> =
            BTreeMap::new();
        for (edge_realm, graph) in graphs {
            if let Some(direct) = graph.get(root) {
                roots.insert(edge_realm, direct.clone());
            }
            for (source, dependencies) in graph {
                if source == root {
                    continue;
                }
                for &origin in &resolved.metadata[source].origin_realms {
                    let realm = Realm::dependency_origin(origin, edge_realm);
                    for (alias, id) in dependencies {
                        let value = (alias.clone(), id.clone());
                        let entry = candidates
                            .entry((realm, alias.to_ascii_lowercase()))
                            .or_insert_with(|| Some(value.clone()));
                        if entry.as_ref() != Some(&value) {
                            *entry = None;
                        }
                    }
                }
            }
        }
        for ((realm, folded), value) in candidates {
            if let Some((alias, id)) = value {
                let aliases = roots.entry(realm).or_default();
                if !aliases
                    .keys()
                    .any(|alias| alias.to_ascii_lowercase() == folded)
                {
                    aliases.insert(alias, id);
                }
            }
        }
        for (realm, dependencies) in roots {
            self.write_root_package_links(realm, &dependencies, resolved)?;
        }
        Ok(())
    }

    /// Contents of a package-to-package link within the same index.
    fn link_sibling_same_index(&self, id: &PackageId) -> String {
        formatdoc! {r#"
            return require("../{full_name}/{short_name}")
            "#,
            full_name = package_id_file_name(id),
            short_name = id.name().name()
        }
    }

    /// Contents of a root-to-package link within the same index.
    fn link_root_same_index(&self, id: &PackageId) -> String {
        formatdoc! {r#"
            return require("./_Index/{full_name}/{short_name}")
            "#,
            full_name = package_id_file_name(id),
            short_name = id.name().name()
        }
    }

    /// Contents of a link into the shared index from outside the shared index.
    fn link_shared_index(&self, id: &PackageId) -> anyhow::Result<String> {
        let full_name = package_id_file_name(id);
        let short_name = id.name().name();

        let contents = match self.shared_path.as_ref() {
            Some(shared_path) => {
                // Roblox path provided - use it directly (legacy support)
                formatdoc! {r#"
                    type Package = typeof(require({packages}._Index["{full_name}"]["{short_name}"]))
                    return require({packages}._Index["{full_name}"]["{short_name}"]) :: Package
                    "#,
                    packages = shared_path,
                    full_name = full_name,
                    short_name = short_name
                }
            }
            None => {
                // No Roblox path - use require-by-string which works in both Lune and Roblox
                // Path is ../../../ because shims are at <Dir>/_Index/<package>/file.luau
                formatdoc! {r#"
                    return require("../../../Packages/_Index/{full_name}/{short_name}")
                    "#,
                    full_name = full_name,
                    short_name = short_name
                }
            }
        };

        Ok(contents)
    }

    /// Contents of a link into the server index from outside the server index.
    fn link_server_index(&self, id: &PackageId) -> anyhow::Result<String> {
        let full_name = package_id_file_name(id);
        let short_name = id.name().name();

        let contents = match self.server_path.as_ref() {
            Some(server_path) => {
                // Roblox path provided - use it directly (legacy support)
                formatdoc! {r#"
                    type Package = typeof(require({packages}._Index["{full_name}"]["{short_name}"]))
                    return require({packages}._Index["{full_name}"]["{short_name}"]) :: Package
                    "#,
                    packages = server_path,
                    full_name = full_name,
                    short_name = short_name
                }
            }
            None => {
                // No Roblox path - use require-by-string which works in both Lune and Roblox
                // Path is ../../../ because shims are at <Dir>/_Index/<package>/file.luau
                formatdoc! {r#"
                    return require("../../../ServerPackages/_Index/{full_name}/{short_name}")
                    "#,
                    full_name = full_name,
                    short_name = short_name
                }
            }
        };

        Ok(contents)
    }

    fn link_root_cross_index(&self, id: &PackageId, realm: Realm) -> anyhow::Result<String> {
        let configured = match realm {
            Realm::Shared => self.shared_path.is_some(),
            Realm::Server => self.server_path.is_some(),
            Realm::Dev => bail!("A dev dependency cannot be linked from another realm"),
        };
        if configured {
            return match realm {
                Realm::Shared => self.link_shared_index(id),
                Realm::Server => self.link_server_index(id),
                Realm::Dev => unreachable!(),
            };
        }
        Ok(formatdoc! {r#"
            return require("../{directory}/_Index/{full_name}/{short_name}")
            "#,
            directory = crate::local_packages::realm_directory(realm),
            full_name = package_id_file_name(id),
            short_name = id.name().name()
        })
    }

    fn write_root_package_links<'a, K: Display>(
        &self,
        root_realm: Realm,
        dependencies: impl IntoIterator<Item = (K, &'a PackageId)>,
        resolved: &Resolve,
    ) -> anyhow::Result<()> {
        log::debug!("Writing root package links");

        let base_path = match root_realm {
            Realm::Shared => &self.shared_dir,
            Realm::Server => &self.server_dir,
            Realm::Dev => &self.dev_dir,
        };

        log::trace!("Creating directory {}", base_path.display());
        fs::create_dir_all(base_path)?;

        for (dep_name, dep_package_id) in dependencies {
            let dep_metadata = resolved.metadata.get(dep_package_id).unwrap();
            let path = base_path.join(format!("{}.luau", dep_name));

            // If the dependency is also installed in the same realm as the root,
            // use same-index link. Otherwise, use cross-realm link to the primary realm.
            let contents = if dep_metadata
                .installation_realms(dep_package_id)
                .contains(&root_realm)
            {
                self.link_root_same_index(dep_package_id)
            } else {
                match dep_metadata.origin_realm() {
                    Realm::Server => self.link_root_cross_index(dep_package_id, Realm::Server)?,
                    Realm::Shared => self.link_root_cross_index(dep_package_id, Realm::Shared)?,
                    Realm::Dev => {
                        bail!("A dev dependency cannot be depended upon by a non-dev dependency")
                    }
                }
            };

            log::trace!("Writing {}", path.display());
            let contents = crate::link_types::forward(contents, &self.type_exports[dep_package_id]);
            fs::write(path, contents)?;
        }

        Ok(())
    }

    fn write_package_links<'a, K: std::fmt::Display>(
        &self,
        package_id: &PackageId,
        package_realm: Realm,
        dependencies: impl IntoIterator<Item = (K, &'a PackageId)>,
        resolved: &Resolve,
    ) -> anyhow::Result<()> {
        log::debug!("Writing package links for {}", package_id);

        let mut base_path = match package_realm {
            Realm::Shared => self.shared_index_dir.clone(),
            Realm::Server => self.server_index_dir.clone(),
            Realm::Dev => self.dev_index_dir.clone(),
        };

        base_path.push(package_id_file_name(package_id));

        log::trace!("Creating directory {}", base_path.display());
        fs::create_dir_all(&base_path)?;

        for (dep_name, dep_package_id) in dependencies {
            let dep_metadata = resolved.metadata.get(dep_package_id).unwrap();
            let path = base_path.join(format!("{}.luau", dep_name));

            // If the dependency is also installed in the same realm as the package,
            // use same-index link. Otherwise, use cross-realm link to the primary realm.
            let contents = if dep_metadata
                .installation_realms(dep_package_id)
                .contains(&package_realm)
            {
                self.link_sibling_same_index(dep_package_id)
            } else {
                match dep_metadata.origin_realm() {
                    Realm::Server => self.link_server_index(dep_package_id)?,
                    Realm::Shared => self.link_shared_index(dep_package_id)?,
                    Realm::Dev => {
                        bail!("A dev dependency cannot be depended upon by a non-dev dependency")
                    }
                }
            };

            log::trace!("Writing {}", path.display());
            let contents = crate::link_types::forward(contents, &self.type_exports[dep_package_id]);
            fs::write(path, contents)?;
        }

        Ok(())
    }

    fn write_contents(
        &self,
        package_id: &PackageId,
        contents: &PackageContents,
        realm: Realm,
    ) -> anyhow::Result<()> {
        let mut path = match realm {
            Realm::Shared => self.shared_index_dir.clone(),
            Realm::Server => self.server_index_dir.clone(),
            Realm::Dev => self.dev_index_dir.clone(),
        };

        path.push(package_id_file_name(package_id));
        path.push(package_id.name().name());

        fs::create_dir_all(&path)?;
        contents.unpack_into_path(&path)?;

        Ok(())
    }
}

/// Creates a suitable name for use in file paths that refer to this package.
pub fn package_id_file_name(id: &PackageId) -> String {
    format!(
        "{}_{}@{}",
        id.name().scope(),
        id.name().name(),
        id.index_version()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package_name::PackageName;
    use semver::Version;
    use std::str::FromStr;
    use tempfile::TempDir;

    fn make_package_id(name: &str, version: &str) -> PackageId {
        let package_name = PackageName::from_str(name).unwrap();
        let version = Version::parse(version).unwrap();
        PackageId::new(package_name, version)
    }

    fn make_context() -> (TempDir, InstallationContext) {
        let temp_dir = TempDir::new().unwrap();
        let context = InstallationContext::new(temp_dir.path(), None, None);
        (temp_dir, context)
    }

    fn make_context_with_paths(
        shared_path: Option<&str>,
        server_path: Option<&str>,
    ) -> (TempDir, InstallationContext) {
        let temp_dir = TempDir::new().unwrap();
        let context = InstallationContext::new(
            temp_dir.path(),
            shared_path.map(String::from),
            server_path.map(String::from),
        );
        (temp_dir, context)
    }

    #[test]
    fn link_sibling_same_index_generates_correct_path() {
        let (_temp, context) = make_context();
        let pkg = make_package_id("biff/test-pkg", "1.2.3");

        let link = context.link_sibling_same_index(&pkg);

        assert!(link.contains("require(\"../biff_test-pkg@1.2.3/test-pkg\")"));
        assert!(!link.contains(":: Package"));
        // Should NOT contain if/else conditionals
        assert!(!link.contains("if not game"));
        assert!(!link.contains("script.Parent"));
    }

    #[test]
    fn link_root_same_index_generates_correct_path() {
        let (_temp, context) = make_context();
        let pkg = make_package_id("biff/test-pkg", "1.2.3");

        let link = context.link_root_same_index(&pkg);

        assert!(link.contains("require(\"./_Index/biff_test-pkg@1.2.3/test-pkg\")"));
        assert!(!link.contains(":: Package"));
        // Should NOT contain if/else conditionals
        assert!(!link.contains("if not game"));
        assert!(!link.contains("script.Parent"));
    }

    #[test]
    fn link_shared_index_without_place_config_uses_relative_path() {
        let (_temp, context) = make_context();
        let pkg = make_package_id("biff/test-pkg", "1.2.3");

        let link = context.link_shared_index(&pkg).unwrap();

        assert!(link.contains("require(\"../../../Packages/_Index/biff_test-pkg@1.2.3/test-pkg\")"));
        assert!(!link.contains(":: Package"));
        // Should NOT contain if/else conditionals or game references
        assert!(!link.contains("if not game"));
        assert!(!link.contains("game.ReplicatedStorage"));
    }

    #[test]
    fn link_shared_index_with_place_config_uses_roblox_path() {
        let (_temp, context) =
            make_context_with_paths(Some("game.ReplicatedStorage.Packages"), None);
        let pkg = make_package_id("biff/test-pkg", "1.2.3");

        let link = context.link_shared_index(&pkg).unwrap();

        assert!(link.contains("game.ReplicatedStorage.Packages._Index"));
        assert!(link.contains(":: Package"));
        // Should use Roblox path, not require-by-string
        assert!(!link.contains("require(\"../"));
    }

    #[test]
    fn link_server_index_without_place_config_uses_relative_path() {
        let (_temp, context) = make_context();
        let pkg = make_package_id("biff/test-pkg", "1.2.3");

        let link = context.link_server_index(&pkg).unwrap();

        assert!(link
            .contains("require(\"../../../ServerPackages/_Index/biff_test-pkg@1.2.3/test-pkg\")"));
        assert!(!link.contains(":: Package"));
        // Should NOT contain if/else conditionals or game references
        assert!(!link.contains("if not game"));
        assert!(!link.contains("game.ServerScriptService"));
    }

    #[test]
    fn link_server_index_with_place_config_uses_roblox_path() {
        let (_temp, context) =
            make_context_with_paths(None, Some("game.ServerScriptService.Packages"));
        let pkg = make_package_id("biff/test-pkg", "1.2.3");

        let link = context.link_server_index(&pkg).unwrap();

        assert!(link.contains("game.ServerScriptService.Packages._Index"));
        assert!(link.contains(":: Package"));
        // Should use Roblox path, not require-by-string
        assert!(!link.contains("require(\"../"));
    }

    #[test]
    fn package_id_file_name_format() {
        let pkg = make_package_id("biff/test-pkg", "1.2.3");
        let file_name = package_id_file_name(&pkg);

        assert_eq!(file_name, "biff_test-pkg@1.2.3");
    }

    #[test]
    fn all_links_include_type_annotation() {
        let (_temp, context) = make_context();
        let pkg = make_package_id("biff/test-pkg", "1.2.3");

        let sibling = context.link_sibling_same_index(&pkg);
        let root = context.link_root_same_index(&pkg);
        let shared = context.link_shared_index(&pkg).unwrap();
        let server = context.link_server_index(&pkg).unwrap();

        // Require-by-string links should be plain returns (no type wrapper)
        assert!(sibling.contains("return require(\""));
        assert!(!sibling.contains(":: Package"));
        assert!(root.contains("return require(\""));
        assert!(!root.contains(":: Package"));
        assert!(shared.contains("return require(\""));
        assert!(!shared.contains(":: Package"));
        assert!(server.contains("return require(\""));
        assert!(!server.contains(":: Package"));
    }
}

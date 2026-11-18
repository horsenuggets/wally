use std::io::{self, BufReader, Cursor};
use std::path::{Path, PathBuf};

use anyhow::{format_err, Context};
use fs_err::File;
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde_json::json;
use walkdir::WalkDir;
use zip::{write::FileOptions, ZipArchive, ZipWriter};

use crate::manifest::Manifest;

static EXCLUDED_GLOBS: &[&str] = &[
    ".*",
    "wally.lock",
    "wally.install.json",
    "Packages",
    "ServerPackages",
    "DevPackages",
];

/// Container for the contents of a package that have been downloaded.
#[derive(Clone)]
pub struct PackageContents {
    /// Contains a zip with the contents of the package.
    data: Vec<u8>,
}

impl PackageContents {
    pub fn pack_from_path(input: &Path) -> anyhow::Result<Self> {
        let manifest = Manifest::load(input)?;
        let package_name = manifest.package.name.name();

        let mut data = Vec::new();
        let mut archive = ZipWriter::new(Cursor::new(&mut data));

        for path in Self::filtered_contents(input)? {
            let relative_path = path.strip_prefix(input).unwrap();
            let archive_name = relative_path.to_str().ok_or_else(|| {
                format_err!(
                    "Path {} contained invalid Unicode characters",
                    relative_path.display()
                )
            })?;

            // Zips embed \ from windows paths causing incorrect extraction on unix operating
            // systems; we must sanitise here. See: https://github.com/UpliftGames/wally/issues/15
            // This may be fixed in the zip crate. See: https://github.com/zip-rs/zip/issues/253
            let archive_name = str::replace(archive_name, "\\", "/");

            if path.is_dir() {
                archive.add_directory(archive_name, FileOptions::default())?;
            } else {
                archive.start_file(archive_name, FileOptions::default())?;

                if relative_path == Path::new("default.project.json") {
                    let project_file = File::open(path)?;
                    let mut project_json: serde_json::Value =
                        serde_json::from_reader(project_file)?;
                    let object = project_json
                        .as_object_mut()
                        .context("default.project.json must be an object.")?;
                    let project_name = object.get("name").and_then(|name| name.as_str());

                    if project_name != Some(package_name) {
                        log::info!(
                            "The project and package names are mismatched. The project name in \
                             `default.project.json` has been renamed to '{}' in the uploaded \
                             package to match the name provided by `wally.toml`",
                            package_name
                        );

                        object.insert("name".into(), json!(package_name));
                    }

                    serde_json::to_writer_pretty(&mut archive, &project_json)?;
                } else {
                    let mut file = BufReader::new(File::open(path)?);
                    io::copy(&mut file, &mut archive)?;
                }
            }
        }

        archive.finish()?;
        drop(archive);

        Ok(PackageContents { data })
    }

    /// Unpack the package into the given path on the filesystem.
    pub fn unpack_into_path(&self, output: &Path) -> anyhow::Result<()> {
        let mut archive = ZipArchive::new(Cursor::new(self.data.as_slice()))?;
        archive.extract(output)?;
        Ok(())
    }

    pub fn filtered_contents(input: &Path) -> anyhow::Result<Vec<PathBuf>> {
        let manifest = Manifest::load(input)?;
        let includes = manifest.package.include;
        let mut excludes = manifest.package.exclude;

        let mut gitignore = ignore::gitignore::GitignoreBuilder::new(input);
        if includes.is_empty() && input.join(".gitignore").exists() {
            if let Some(error) = gitignore.add(input.join(".gitignore")) {
                return Err(error.into());
            }
        }
        let gitignore = gitignore.build()?;

        EXCLUDED_GLOBS
            .iter()
            .map(|pattern| pattern.to_string())
            .for_each(|pattern| excludes.push(pattern));

        let include = build_glob_set(&includes)?;
        let exclude = build_glob_set(&excludes)?;

        let entries = WalkDir::new(input)
            .min_depth(1)
            .into_iter()
            .filter_entry(|entry| {
                let relative = entry.path().strip_prefix(input).unwrap();
                relative == Path::new("wally.toml")
                    || (!includes.is_empty() && include.is_match(relative))
                    || (exclude.matches(relative).is_empty()
                        && !gitignore
                            .matched(entry.path(), entry.file_type().is_dir())
                            .is_ignore())
            });
        collect_contents(input, &include, !includes.is_empty(), entries)
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Create a new PackageContents object from a buffer.
    pub fn from_buffer(data: Vec<u8>) -> PackageContents {
        PackageContents { data }
    }
}

fn collect_contents(
    input: &Path,
    include: &GlobSet,
    restrict_includes: bool,
    entries: impl IntoIterator<Item = Result<walkdir::DirEntry, walkdir::Error>>,
) -> anyhow::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry?;
        anyhow::ensure!(
            !entry.file_type().is_symlink(),
            "Package contents cannot contain symbolic links at {}.",
            entry.path().display()
        );
        let relative = entry.path().strip_prefix(input)?;
        if relative == Path::new("wally.toml")
            || !restrict_includes
            || entry.file_type().is_dir()
            || include.is_match(relative)
        {
            paths.push(entry.into_path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn build_glob_set(patterns: &[String]) -> anyhow::Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();

    for pattern in patterns {
        let anchored = pattern.starts_with('/');
        let pattern = pattern.trim_start_matches('/').trim_end_matches('/');
        if pattern.is_empty() {
            continue;
        }
        builder.add(Glob::new(pattern)?);
        builder.add(Glob::new(&format!("{}/**", pattern))?);
        if !anchored && !pattern.contains('/') {
            builder.add(Glob::new(&format!("**/{}", pattern))?);
            builder.add(Glob::new(&format!("**/{}/**", pattern))?);
        }
    }

    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_manifest_is_packaged_despite_include_exclude_and_ignore_rules() {
        for version in ["version = \"1.0.0\"\n", ""] {
            for filtering in ["include = [\"/src\"]\n", "exclude = [\"wally.toml\"]\n", ""] {
                let temporary = tempfile::tempdir().unwrap();
                let root = temporary.path();
                let manifest = format!(
                    "[package]\nname = \"fixture/contents\"\n{version}realm = \"shared\"\n{filtering}"
                );
                fs_err::write(root.join("wally.toml"), &manifest).unwrap();
                fs_err::write(root.join(".gitignore"), "wally.toml\nother.luau\n").unwrap();
                fs_err::create_dir(root.join("src")).unwrap();
                fs_err::write(root.join("src/init.luau"), "return 1\n").unwrap();
                fs_err::write(root.join("other.luau"), "return 2\n").unwrap();
                let paths = PackageContents::filtered_contents(root).unwrap();
                assert_eq!(
                    paths
                        .iter()
                        .filter(|path| *path == &root.join("wally.toml"))
                        .count(),
                    1
                );
                assert!(!paths.contains(&root.join("other.luau")));

                let package = PackageContents::pack_from_path(root).unwrap();
                let mut archive = ZipArchive::new(Cursor::new(package.data())).unwrap();
                let mut actual = String::new();
                std::io::Read::read_to_string(
                    &mut archive.by_name("wally.toml").unwrap(),
                    &mut actual,
                )
                .unwrap();
                assert_eq!(actual, manifest);
                assert!(archive.by_name("src/init.luau").is_ok());
            }
        }
    }

    #[test]
    fn walk_errors_are_propagated_instead_of_flattened_away() {
        let temporary = tempfile::tempdir().unwrap();
        let missing = temporary.path().join("missing");
        let include = build_glob_set(&[]).unwrap();
        // Exercise a genuine WalkDir error independently of manifest loading, which
        // would otherwise fail first and mask a regression in the traversal collector.
        assert!(collect_contents(&missing, &include, false, WalkDir::new(&missing)).is_err());
    }
}

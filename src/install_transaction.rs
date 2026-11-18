//! Durable, guarded replacement of the fixed generated install surfaces.
//!
//! A prepared journal always rolls back. The committed marker is written only after
//! every destination is durable. Recovery validates every fingerprint before changing
//! anything, retaining unexpected edits for manual inspection instead of deleting them.
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::local_packages::{validate_tree, INSTALL_LOCK_FILE, TRANSACTION_DIR};

const SURFACES: [&str; 5] = [
    "Packages",
    "ServerPackages",
    "DevPackages",
    "wally.lock",
    "wally.install.json",
];
const MARKER: &[u8] = b"Wally install transaction version 1\n";

pub(crate) struct InstallTransaction {
    root: PathBuf,
    directory: PathBuf,
    _lock: File,
    originals: BTreeMap<String, Option<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Journal {
    version: u32,
    entries: BTreeMap<String, Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    old: Option<String>,
    new: Option<String>,
}

impl InstallTransaction {
    pub fn begin(root: &Path) -> anyhow::Result<Self> {
        let lock_path = root.join(INSTALL_LOCK_FILE);
        if let Ok(metadata) = fs_err::symlink_metadata(&lock_path) {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "Unsafe install lock path."
            );
        }
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(lock_path)?;
        lock.try_lock_exclusive()
            .context("Another Wally installation is running for this project.")?;
        let mut transaction = Self {
            root: root.into(),
            directory: root.join(TRANSACTION_DIR),
            _lock: lock,
            originals: BTreeMap::new(),
        };
        if transaction.directory.exists()
            || fs_err::symlink_metadata(&transaction.directory).is_ok()
        {
            transaction.recover()?;
        }
        // Inspect all old surfaces before creating any staging output.
        for name in SURFACES {
            transaction
                .originals
                .insert(name.into(), fingerprint(&root.join(name))?);
        }
        fs_err::create_dir(&transaction.directory)?;
        durable_write(&transaction.directory.join("owner"), MARKER)?;
        fs_err::create_dir(transaction.stage())?;
        fs_err::create_dir(transaction.directory.join("backup"))?;
        sync_dir(&transaction.directory)?;
        sync_dir(root)?;
        Ok(transaction)
    }

    pub fn stage(&self) -> PathBuf {
        self.directory.join("stage")
    }

    pub fn commit(self) -> anyhow::Result<()> {
        let mut journal = Journal {
            version: 1,
            entries: BTreeMap::new(),
        };
        for name in SURFACES {
            journal.entries.insert(
                name.into(),
                Entry {
                    old: self.originals[name].clone(),
                    new: fingerprint(&self.stage().join(name))?,
                },
            );
        }
        sync_tree(&self.stage())?;
        for name in SURFACES {
            ensure!(
                fingerprint(&self.root.join(name))? == journal.entries[name].old,
                "Install destination {} changed during staging.",
                name
            );
        }
        durable_write(
            &self.directory.join("journal.pending"),
            &serde_json::to_vec(&journal)?,
        )?;
        fs_err::rename(
            self.directory.join("journal.pending"),
            self.directory.join("journal.json"),
        )?;
        sync_dir(&self.directory)?;
        // Invalidate provenance before any tree changes. Publish new provenance last,
        // so a consumer can never mistake a mixed generation for a successful install.
        let metadata_name = "wally.install.json";
        if journal.entries[metadata_name].old.is_some() {
            fs_err::rename(
                self.root.join(metadata_name),
                self.directory.join("backup").join(metadata_name),
            )?;
            sync_dir(&self.root)?;
            sync_dir(&self.directory.join("backup"))?;
        }
        // Every operation below can be recovered using the durable journal and backups.
        for name in SURFACES {
            let entry = &journal.entries[name];
            ensure!(
                fingerprint(&self.root.join(name))?
                    == if name == metadata_name {
                        None
                    } else {
                        entry.old.clone()
                    },
                "Install destination {} changed during staging.",
                name
            );
            if name != metadata_name && entry.old.is_some() {
                fs_err::rename(
                    self.root.join(name),
                    self.directory.join("backup").join(name),
                )?;
                sync_dir(&self.root)?;
                sync_dir(&self.directory.join("backup"))?;
            }
            if entry.new.is_some() {
                fs_err::rename(self.stage().join(name), self.root.join(name))?;
                sync_dir(&self.root)?;
                sync_dir(&self.stage())?;
            }
        }
        durable_write(&self.directory.join("commit.pending"), MARKER)?;
        fs_err::rename(
            self.directory.join("commit.pending"),
            self.directory.join("committed"),
        )?;
        sync_dir(&self.directory)?;
        self.recover()
    }

    fn recover(&self) -> anyhow::Result<()> {
        validate_tree(&self.directory)?;
        let owner = self.directory.join("owner");
        match fs_err::read(&owner) {
            Ok(contents) if contents == MARKER => {}
            Ok(contents) if MARKER.starts_with(&contents) => {
                // A crash during the first marker write cannot have changed live
                // output. Only remove the partial marker if nothing else is present.
                ensure!(
                    fs_err::read_dir(&self.directory)?
                        .all(|entry| entry.map_or(false, |entry| entry.path() == owner)),
                    "Incomplete transaction owner with unexpected files. No files were removed."
                );
                fs_err::remove_file(owner)?;
                fs_err::remove_dir(&self.directory)?;
                sync_dir(&self.root)?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // The only marker-free state we own is an empty directory, before
                // initialization or after the last cleanup operation.
                fs_err::remove_dir(&self.directory)
                    .context("Unrecognized Wally transaction directory. No files were removed.")?;
                sync_dir(&self.root)?;
                return Ok(());
            }
            _ => anyhow::bail!("Unrecognized Wally transaction directory. No files were removed."),
        }
        let journal_path = self.directory.join("journal.json");
        if !journal_path.exists() {
            // Before the journal is durable, no live destination has been modified.
            self.cleanup()?;
            return Ok(());
        }
        let journal: Journal = serde_json::from_slice(&fs_err::read(journal_path)?)?;
        ensure!(
            journal.version == 1
                && journal.entries.len() == SURFACES.len()
                && SURFACES
                    .iter()
                    .all(|name| journal.entries.contains_key(*name)),
            "Invalid Wally transaction journal. No files were removed."
        );
        let committed = self.directory.join("committed").exists();
        if committed {
            ensure!(
                fs_err::read(self.directory.join("committed"))? == MARKER,
                "Invalid commit marker."
            );
        }
        // Preflight the entire recovery, including retained staging and backup trees.
        for name in SURFACES {
            let entry = &journal.entries[name];
            let current = fingerprint(&self.root.join(name))?;
            let backup = fingerprint(&self.directory.join("backup").join(name))?;
            let staged = fingerprint(&self.stage().join(name))?;
            ensure!(
                backup.is_none() || backup == entry.old,
                "Recovery backup {} changed. No files were removed.",
                name
            );
            ensure!(
                staged.is_none() || staged == entry.new,
                "Recovery staging {} changed. No files were removed.",
                name
            );
            if committed {
                ensure!(
                    current == entry.new,
                    "Committed destination {} changed. No files were removed.",
                    name
                );
            } else if backup.is_some() {
                ensure!(
                    current.is_none() || current == entry.new,
                    "Interrupted destination {} changed. No files were removed.",
                    name
                );
            } else if entry.old.is_some() {
                ensure!(
                    current == entry.old,
                    "Missing original {} during recovery. No files were removed.",
                    name
                );
            } else {
                ensure!(
                    current.is_none() || (current == entry.new && staged.is_none()),
                    "Unexpected destination {} during recovery. No files were removed.",
                    name
                );
            }
        }
        if !committed {
            if self.directory.join("backup/wally.install.json").exists()
                || journal.entries["wally.install.json"].old.is_none()
            {
                remove_surface(&self.root.join("wally.install.json"))?;
                sync_dir(&self.root)?;
            }
            for name in SURFACES {
                let entry = &journal.entries[name];
                let destination = self.root.join(name);
                let backup = self.directory.join("backup").join(name);
                if backup.exists() {
                    remove_surface(&destination)?;
                    fs_err::rename(&backup, &destination)?;
                    sync_dir(&self.root)?;
                    sync_dir(&self.directory.join("backup"))?;
                } else if entry.old.is_none() {
                    remove_surface(&destination)?;
                    sync_dir(&self.root)?;
                }
            }
        }
        // Mark rollback complete before deleting the journal. A crash during cleanup
        // must not reinterpret a partially deleted backup as a missing original.
        fs_err::remove_file(self.directory.join("journal.json"))?;
        sync_dir(&self.directory)?;
        self.cleanup()
    }

    fn cleanup(&self) -> anyhow::Result<()> {
        // Keep the durable ownership marker until every other entry is gone, so
        // cleanup itself is restartable even if deleting a large backup is interrupted.
        for entry in fs_err::read_dir(&self.directory)? {
            let entry = entry?;
            if entry.file_name() != "owner" {
                remove_surface(&entry.path())?;
            }
        }
        sync_dir(&self.directory)?;
        fs_err::remove_file(self.directory.join("owner"))?;
        sync_dir(&self.directory)?;
        fs_err::remove_dir(&self.directory)?;
        sync_dir(&self.root)?;
        Ok(())
    }
}

fn remove_surface(path: &Path) -> anyhow::Result<()> {
    match fs_err::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs_err::remove_dir_all(path)?,
        Ok(_) => fs_err::remove_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn fingerprint(path: &Path) -> anyhow::Result<Option<String>> {
    match fs_err::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    validate_tree(path)?;
    let mut entries = WalkDir::new(path)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by(|a, b| a.path().cmp(b.path()));
    let mut hash = Sha256::new();
    for entry in entries {
        let relative = entry
            .path()
            .strip_prefix(path)?
            .to_str()
            .context("Non-Unicode install path.")?
            .replace('\\', "/");
        hash.update((relative.len() as u64).to_le_bytes());
        hash.update(relative.as_bytes());
        hash.update(if entry.file_type().is_dir() {
            b"d"
        } else {
            b"f"
        });
        if entry.file_type().is_file() {
            let bytes = fs_err::read(entry.path())?;
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(&bytes);
        }
    }
    Ok(Some(hex::encode(hash.finalize())))
}

fn durable_write(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn sync_tree(root: &Path) -> anyhow::Result<()> {
    for entry in WalkDir::new(root).contents_first(true) {
        let entry = entry?;
        if entry.file_type().is_file() {
            File::open(entry.path())?.sync_all()?;
        } else {
            sync_dir(entry.path())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn surface(root: &Path, name: &str, contents: &str) {
        if name.ends_with(".json") || name.ends_with(".lock") {
            fs_err::write(root.join(name), contents).unwrap();
        } else {
            fs_err::create_dir_all(root.join(name)).unwrap();
            fs_err::write(root.join(name).join("init.luau"), contents).unwrap();
        }
    }

    fn prepare_journal(transaction: &InstallTransaction) -> Journal {
        let journal = Journal {
            version: 1,
            entries: SURFACES
                .iter()
                .map(|&name| {
                    (
                        name.into(),
                        Entry {
                            old: transaction.originals[name].clone(),
                            new: fingerprint(&transaction.stage().join(name)).unwrap(),
                        },
                    )
                })
                .collect(),
        };
        durable_write(
            &transaction.directory.join("journal.json"),
            &serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        journal
    }

    #[test]
    fn restart_rolls_back_every_interrupted_rename_and_finishes_committed_generations() {
        for (old_mask, new_mask) in [(31, 31), (0, 31), (31, 0), (21, 10)] {
            for cut in 0..=12 {
                let temporary = TempDir::new().unwrap();
                let root = temporary.path().canonicalize().unwrap();
                fs_err::create_dir(root.join("Source")).unwrap();
                fs_err::write(root.join("Source/original"), "authoritative").unwrap();
                for (index, name) in SURFACES.iter().enumerate() {
                    if old_mask & (1 << index) != 0 {
                        surface(&root, name, "old");
                    }
                }
                let transaction = InstallTransaction::begin(&root).unwrap();
                for (index, name) in SURFACES.iter().enumerate() {
                    if new_mask & (1 << index) != 0 {
                        surface(&transaction.stage(), name, "new");
                    }
                }
                let journal = prepare_journal(&transaction);
                let mut operations = Vec::new();
                if journal.entries["wally.install.json"].old.is_some() {
                    operations.push((
                        root.join("wally.install.json"),
                        transaction.directory.join("backup/wally.install.json"),
                    ));
                }
                for name in SURFACES {
                    if name != "wally.install.json" && journal.entries[name].old.is_some() {
                        operations.push((
                            root.join(name),
                            transaction.directory.join("backup").join(name),
                        ));
                    }
                    if journal.entries[name].new.is_some() {
                        operations.push((transaction.stage().join(name), root.join(name)));
                    }
                }
                for (from, to) in operations.iter().take(cut) {
                    fs_err::rename(from, to).unwrap();
                }
                let committed = cut > operations.len();
                if committed {
                    durable_write(&transaction.directory.join("committed"), MARKER).unwrap();
                }
                if cut > 0 && cut < operations.len() {
                    assert!(
                        !root.join("wally.install.json").exists(),
                        "Provenance must not expose a mixed generation."
                    );
                }
                drop(transaction);
                let recovered = InstallTransaction::begin(&root).unwrap();
                for name in SURFACES {
                    let expected = if committed {
                        &journal.entries[name].new
                    } else {
                        &journal.entries[name].old
                    };
                    assert_eq!(
                        &fingerprint(&root.join(name)).unwrap(),
                        expected,
                        "{name}, cut {cut}, masks {old_mask}/{new_mask}"
                    );
                }
                assert_eq!(
                    fs_err::read_to_string(root.join("Source/original")).unwrap(),
                    "authoritative"
                );
                drop(recovered);
            }
        }
    }

    #[test]
    fn staging_and_recovery_guards_preserve_unexpected_edits() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path();
        surface(root, "Packages", "old");
        let transaction = InstallTransaction::begin(root).unwrap();
        surface(&transaction.stage(), "Packages", "new");
        surface(root, "Packages", "edited while staging");
        assert!(transaction.commit().is_err());
        assert_eq!(
            fs_err::read_to_string(root.join("Packages/init.luau")).unwrap(),
            "edited while staging"
        );
        let transaction = InstallTransaction::begin(root).unwrap();
        surface(&transaction.stage(), "Packages", "new");
        prepare_journal(&transaction);
        fs_err::rename(
            root.join("Packages"),
            transaction.directory.join("backup/Packages"),
        )
        .unwrap();
        fs_err::rename(transaction.stage().join("Packages"), root.join("Packages")).unwrap();
        surface(root, "Packages", "edited after interruption");
        drop(transaction);
        assert!(InstallTransaction::begin(root).is_err());
        assert_eq!(
            fs_err::read_to_string(root.join("Packages/init.luau")).unwrap(),
            "edited after interruption"
        );
        assert!(root
            .join(".wally-install/backup/Packages/init.luau")
            .exists());
    }

    #[test]
    fn malformed_journal_cannot_redirect_cleanup_and_concurrent_installs_fail() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path();
        fs_err::write(root.join("keep"), "untouched").unwrap();
        let transaction = InstallTransaction::begin(root).unwrap();
        assert!(InstallTransaction::begin(root).is_err());
        let mut journal = prepare_journal(&transaction);
        journal.entries.insert(
            "../keep".into(),
            Entry {
                old: None,
                new: None,
            },
        );
        fs_err::write(
            transaction.directory.join("journal.json"),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        drop(transaction);
        assert!(InstallTransaction::begin(root).is_err());
        assert_eq!(
            fs_err::read_to_string(root.join("keep")).unwrap(),
            "untouched"
        );
    }

    #[test]
    fn interrupted_initialization_and_final_cleanup_are_restartable() {
        for length in 0..MARKER.len() {
            let temporary = TempDir::new().unwrap();
            let root = temporary.path();
            fs_err::create_dir(root.join(TRANSACTION_DIR)).unwrap();
            fs_err::write(root.join(TRANSACTION_DIR).join("owner"), &MARKER[..length]).unwrap();
            let transaction = InstallTransaction::begin(root).unwrap();
            assert!(transaction.stage().is_dir());
        }
        let temporary = TempDir::new().unwrap();
        let root = temporary.path();
        fs_err::create_dir(root.join(TRANSACTION_DIR)).unwrap();
        assert!(InstallTransaction::begin(root).is_ok());
    }

    #[test]
    fn unowned_transaction_files_and_partial_markers_never_authorize_recursive_cleanup() {
        for marker in [
            None,
            Some(b"Wally".as_slice()),
            Some(b"not Wally".as_slice()),
        ] {
            let temporary = TempDir::new().unwrap();
            let directory = temporary.path().join(TRANSACTION_DIR);
            fs_err::create_dir(&directory).unwrap();
            fs_err::write(directory.join("keep"), "untouched").unwrap();
            if let Some(marker) = marker {
                fs_err::write(directory.join("owner"), marker).unwrap();
            }
            assert!(InstallTransaction::begin(temporary.path()).is_err());
            assert_eq!(
                fs_err::read_to_string(directory.join("keep")).unwrap(),
                "untouched"
            );
        }
    }

    #[test]
    fn incomplete_journal_staging_is_discarded_without_touching_live_surfaces() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path();
        surface(root, "Packages", "old");
        let transaction = InstallTransaction::begin(root).unwrap();
        surface(&transaction.stage(), "Packages", "partial output");
        fs_err::write(transaction.directory.join("journal.pending"), b"{partial").unwrap();
        drop(transaction);
        let recovered = InstallTransaction::begin(root).unwrap();
        assert_eq!(
            fs_err::read_to_string(root.join("Packages/init.luau")).unwrap(),
            "old"
        );
        assert!(!recovered.stage().join("Packages").exists());
    }
}

fn sync_dir(path: &Path) -> anyhow::Result<()> {
    // Windows does not support opening directories with ordinary File::open.
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

use super::temp_project::TempProject;
use libwally::{
    local_packages::{hash_bytes, InstallMetadata},
    lockfile::{LockPackage, Lockfile},
    manifest::{Manifest, Realm},
    package_contents::PackageContents,
    package_id::PackageId,
    package_req::{DependencyReq, PackageReq},
    package_source::{InMemoryRegistry, PackageSourceMap},
    resolution::resolve,
    test_package::PackageBuilder,
    GlobalOptions, InstallSubcommand, PublishSubcommand, UpdateSubcommand,
};
use std::{collections::BTreeSet, path::Path};

fn write(root: &Path, relative: &str, contents: impl AsRef<[u8]>) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn root_manifest(root: &Path, deps: &str) {
    write(
        root,
        "wally.toml",
        format!("[package]\nname = 'fixture/root'\nversion = '1.0.0'\nrealm = 'shared'\n{deps}\n"),
    );
}

fn local(root: &Path, directory: &str, name: &str, realm: &str, deps: &str) {
    write(
        root,
        &format!("{directory}/wally.toml"),
        format!("[package]\nname = 'fixture/{name}'\nrealm = '{realm}'\n{deps}\n"),
    );
    write(
        root,
        &format!("{directory}/default.project.json"),
        format!(r#"{{"name":"{name}","tree":{{"$path":"Source/Module"}}}}"#),
    );
    write(
        root,
        &format!("{directory}/init.luau"),
        "return require(\"@self/Source/Module\")\n",
    );
    write(
        root,
        &format!("{directory}/Source/Module/init.luau"),
        "return {}\n",
    );
}

fn install(root: &Path, locked: bool) -> anyhow::Result<()> {
    InstallSubcommand {
        project_path: root.into(),
        locked,
    }
    .run(GlobalOptions {
        test_registry: true,
        ..Default::default()
    })
}

fn metadata(root: &Path) -> InstallMetadata {
    serde_json::from_slice(&std::fs::read(root.join("wally.install.json")).unwrap()).unwrap()
}

struct LocalWatcher(std::process::Child);

impl Drop for LocalWatcher {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for_mirror(watcher: &mut LocalWatcher, path: &Path, expected: &[u8]) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::fs::read(path).ok().as_deref() != Some(expected) {
        assert!(
            watcher.0.try_wait().unwrap().is_none(),
            "Local watcher exited before refreshing its mirror."
        );
        assert!(
            std::time::Instant::now() < deadline,
            "Local mirror refresh timed out."
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn local_mirror_watch_updates_dev_only_outputs_and_stops_on_owned_stdin_eof() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let project = TempProject::empty().unwrap();
    let root = project.path();
    root_manifest(root, "[dev-dependencies]\nDeveloper = '^Forks/developer'");
    local(root, "Forks/developer", "developer", "shared", "");
    install(root, false).unwrap();
    let mirror =
        root.join("DevPackages/_Index/fixture_developer@local/developer/Source/Module/init.luau");
    std::fs::write(&mirror, "return 'generated-only'\n").unwrap();
    let provenance = std::fs::read(root.join("wally.install.json")).unwrap();
    let mut watcher = LocalWatcher(
        Command::new(env!("CARGO_BIN_EXE_wally"))
            .arg("sync-local")
            .arg("--project-path")
            .arg(root)
            .arg("--watch")
            .arg("--shutdown-on-stdin-eof")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    wait_for_mirror(&mut watcher, &mirror, b"return {}\n");
    write(
        root,
        "Forks/developer/Source/Module/init.luau",
        "return 'new-source'\n",
    );
    wait_for_mirror(&mut watcher, &mirror, b"return 'new-source'\n");
    let mut input = watcher.0.stdin.take().unwrap();
    input.write_all(b"The owner is still alive.\n").unwrap();
    input.flush().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(watcher.0.try_wait().unwrap().is_none());
    drop(input);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if let Some(status) = watcher.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "Owned watcher did not stop after stdin closed."
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(
        std::fs::read(root.join("wally.install.json")).unwrap(),
        provenance
    );
    assert!(!root
        .join("Packages/_Index/fixture_developer@local")
        .exists());
    assert!(!root
        .join("ServerPackages/_Index/fixture_developer@local")
        .exists());
}

#[test]
fn local_mirror_watch_recovers_initial_source_loss_and_can_stop_before_readiness() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;

    for recover in [false, true] {
        let project = TempProject::empty().unwrap();
        let root = project.path();
        root_manifest(root, "[dependencies]\nCode = '^Forks/code'");
        local(root, "Forks/code", "code", "shared", "");
        install(root, false).unwrap();
        std::fs::rename(
            root.join("Forks/code/Source"),
            root.join("Forks/code/parked"),
        )
        .unwrap();
        let mut watcher = LocalWatcher(
            Command::new(env!("CARGO_BIN_EXE_wally"))
                .arg("sync-local")
                .arg("--project-path")
                .arg(root)
                .arg("--watch")
                .arg("--shutdown-on-stdin-eof")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let output = watcher.0.stdout.take().unwrap();
        let (lines, receiver) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                if lines.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        assert!(matches!(
            receiver.recv_timeout(Duration::from_millis(500)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(watcher.0.try_wait().unwrap().is_none());
        if recover {
            std::fs::rename(
                root.join("Forks/code/parked"),
                root.join("Forks/code/Source"),
            )
            .unwrap();
            assert_eq!(
                receiver.recv_timeout(Duration::from_secs(20)).unwrap(),
                "Local package mirrors are synchronized."
            );
        }
        drop(watcher.0.stdin.take());
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = watcher.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "Owned watcher did not stop."
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        reader.join().unwrap();
        assert!(receiver.try_iter().next().is_none());
    }
}

#[test]
fn local_mirror_watch_ignores_closed_stdin_without_the_ownership_flag() {
    use std::process::{Command, Stdio};

    let project = TempProject::empty().unwrap();
    let root = project.path();
    root_manifest(root, "[dependencies]\nCode = '^Forks/code'");
    local(root, "Forks/code", "code", "shared", "");
    install(root, false).unwrap();
    let mirror = root.join("Packages/_Index/fixture_code@local/code/Source/Module/init.luau");
    std::fs::write(&mirror, "return 'generated-only'\n").unwrap();
    let mut watcher = LocalWatcher(
        Command::new(env!("CARGO_BIN_EXE_wally"))
            .arg("sync-local")
            .arg("--project-path")
            .arg(root)
            .arg("--watch")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    wait_for_mirror(&mut watcher, &mirror, b"return {}\n");
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(watcher.0.try_wait().unwrap().is_none());
}

#[test]
fn local_mirror_stdin_ownership_requires_watch_mode_before_touching_the_project() {
    let project = TempProject::empty().unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_wally"))
        .arg("sync-local")
        .arg("--project-path")
        .arg(project.path())
        .arg("--shutdown-on-stdin-eof")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--watch"));
    assert!(!project.path().join(".wally-install.lock").exists());
}

#[test]
fn caret_parsing_is_distinct_from_registry_semver_in_all_sections() {
    let manifest = Manifest::from_slice(
        br#"
[package]
name = "fixture/root"
realm = "shared"
[dependencies]
Foo = "^Source/Forks/foo"
Registry = "fixture/foo@^1.2.3"
[server-dependencies]
Bar = "^Source/Forks/bar"
[dev-dependencies]
Baz = "^Source/Forks/baz"
"#,
    )
    .unwrap();
    assert!(manifest.package.version.is_none());
    assert!(
        matches!(&manifest.dependencies["Foo"], DependencyReq::Local(path) if path == "Source/Forks/foo")
    );
    assert!(matches!(
        manifest.dependencies["Registry"],
        DependencyReq::Registry(_)
    ));
    assert!(matches!(
        manifest.server_dependencies["Bar"],
        DependencyReq::Local(_)
    ));
    assert!(matches!(
        manifest.dev_dependencies["Baz"],
        DependencyReq::Local(_)
    ));
    let encoded = toml::to_string(&manifest).unwrap();
    assert!(!encoded.contains("version ="));
    assert!(encoded.contains("^Source/Forks/foo"));
    for invalid in [
        "^",
        "^/tmp/foo",
        "^../foo",
        "^foo/../bar",
        "^foo/./bar",
        "^foo//bar",
        "^foo/",
        "^C:/foo",
        "^foo\\bar",
        "^foo\nbar",
        "^Forks/CON",
        "^Forks/nul.txt",
    ] {
        assert!(invalid.parse::<DependencyReq>().is_err(), "{}", invalid);
    }
    assert!("fixture/foo@^1.2".parse::<PackageReq>().is_ok());
}

#[test]
fn local_sources_keep_one_identity_across_shared_server_and_dev_consumers() {
    let project = TempProject::empty().unwrap();
    let root = project.path();
    root_manifest(root, "[dependencies]\nHelpers = '^Forks/helpers'\n[server-dependencies]\nService = '^Forks/service'\n[dev-dependencies]\nDeveloper = '^Forks/developer'");
    local(root, "Forks/helpers", "helpers", "shared", "");
    local(
        root,
        "Forks/service",
        "service",
        "server",
        "[dependencies]\nHelpers = '^Forks/helpers'",
    );
    local(
        root,
        "Forks/developer",
        "developer",
        "shared",
        "[dependencies]\nHelpers = '^Forks/helpers'",
    );
    install(root, false).unwrap();
    let installed = metadata(root);
    let helpers: Vec<_> = installed
        .package_roots
        .iter()
        .filter(|package| package.name == "fixture/helpers")
        .collect();
    assert_eq!(helpers.len(), 1);
    assert_eq!(helpers[0].realm, Realm::Shared);
    assert!(root
        .join("Packages/_Index/fixture_helpers@local/helpers/Source/Module/init.luau")
        .is_file());
    for realm in ["ServerPackages", "DevPackages"] {
        assert!(!root
            .join(realm)
            .join("_Index/fixture_helpers@local/helpers")
            .exists());
        let alias = std::fs::read_to_string(root.join(realm).join("Helpers.luau")).unwrap();
        assert!(alias.contains("require(\"../Packages/_Index/fixture_helpers@local/helpers\")"));
    }
    for (realm, consumer) in [("ServerPackages", "service"), ("DevPackages", "developer")] {
        let alias = std::fs::read_to_string(root.join(format!(
            "{realm}/_Index/fixture_{consumer}@local/Helpers.luau"
        )))
        .unwrap();
        assert!(
            alias.contains("require(\"../../../Packages/_Index/fixture_helpers@local/helpers\")")
        );
    }
}

#[test]
fn origin_realm_truth_table_preserves_dev_isolation_and_server_edges() {
    let realms = [Realm::Shared, Realm::Server, Realm::Dev];
    let expected = [
        [Realm::Shared, Realm::Server, Realm::Dev],
        [Realm::Server, Realm::Server, Realm::Dev],
        [Realm::Dev, Realm::Dev, Realm::Dev],
    ];
    for (row, &origin) in realms.iter().enumerate() {
        for (column, &edge) in realms.iter().enumerate() {
            assert_eq!(
                Realm::dependency_origin(origin, edge),
                expected[row][column]
            );
        }
    }
}

#[test]
fn provenance_hashes_use_standard_sha256_without_newline_normalization() {
    assert_eq!(
        hash_bytes(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_ne!(hash_bytes(b"abc\n"), hash_bytes(b"abc\r\n"));
}

#[test]
fn local_identity_is_versionless_and_never_satisfies_registry_requirements() {
    let local: PackageId = "fixture/foo@local:Source/Forks/foo".parse().unwrap();
    let registry: PackageId = "fixture/foo@1.0.0".parse().unwrap();
    assert!(local.version().is_none());
    assert_ne!(local, registry);
    assert!(!"fixture/foo@*"
        .parse::<PackageReq>()
        .unwrap()
        .matches_id(&local));
    let encoded = serde_json::to_string(&local).unwrap();
    assert_eq!(serde_json::from_str::<PackageId>(&encoded).unwrap(), local);
    assert!("fixture/foo@local:../outside".parse::<PackageId>().is_err());
}

#[test]
fn versionless_and_local_dependencies_are_not_publishable() {
    for section in ["dependencies", "server-dependencies", "dev-dependencies"] {
        let project = TempProject::empty().unwrap();
        root_manifest(project.path(), &format!("[{section}]\nFoo = '^Forks/foo'"));
        let error = PublishSubcommand {
            project_path: project.path().into(),
            token: None,
        }
        .run(GlobalOptions::default())
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("Cannot publish local dependencies"));
    }
    let manifest =
        Manifest::from_slice(b"[package]\nname='fixture/local'\nrealm='server'\n").unwrap();
    assert!(manifest
        .validate_publish()
        .unwrap_err()
        .to_string()
        .contains("version"));
}

#[test]
fn install_root_relative_transitives_all_realms_and_reinstall_preserves_sources() {
    let project = TempProject::empty().unwrap();
    let root = project.path();
    root_manifest(root, "[dependencies]\nShared = '^Forks/a'\n[server-dependencies]\nServer = '^Forks/server'\n[dev-dependencies]\nDev = '^Forks/dev'");
    local(
        root,
        "Forks/a",
        "a",
        "shared",
        "[dependencies]\nNested = '^Forks/b'",
    );
    local(
        root,
        "Forks/b",
        "b",
        "shared",
        "[dependencies]\nLeaf = '^Forks/leaf'",
    );
    local(root, "Forks/leaf", "leaf", "shared", "");
    local(
        root,
        "Forks/server",
        "server",
        "server",
        "[dependencies]\nNested = '^Forks/b'",
    );
    local(
        root,
        "Forks/dev",
        "dev",
        "shared",
        "[dependencies]\nNested = '^Forks/b'\n[dev-dependencies]\nIgnored = '^does-not-exist'",
    );
    install(root, false).unwrap();
    let first = std::fs::read(root.join("wally.install.json")).unwrap();
    assert_eq!(first.last(), Some(&b'\n'));
    let info = metadata(root);
    assert_eq!(info.version, 1);
    assert_eq!(
        info.manifest_hash,
        hash_bytes(&std::fs::read(root.join("wally.toml")).unwrap())
    );
    assert_eq!(info.local_manifests.len(), 5);
    assert_eq!(info.package_roots.len(), 5);
    for package in &info.package_roots {
        assert_eq!(package.kind, "local");
        assert!(package.package_version.is_none());
        assert!(package.install_path.contains("@local/"));
        assert!(root
            .join(&package.install_path)
            .join("Source/Module/init.luau")
            .is_file());
        assert!(root
            .join(package.source_path.as_ref().unwrap())
            .join("wally.toml")
            .is_file());
        assert!(!package.install_path.starts_with('/'));
        assert!(!package.install_path.contains('\\'));
    }
    for realm in ["Packages", "ServerPackages", "DevPackages"] {
        assert!(root.join(realm).join("Leaf.luau").is_file());
        let configuration: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join(realm).join(".luaurc")).unwrap())
                .unwrap();
        let alias = configuration["aliases"]["packages"].as_str().unwrap();
        assert_eq!(
            root.join(realm).join(alias).canonicalize().unwrap(),
            root.join(realm).canonicalize().unwrap()
        );
        assert!(info.generated_paths.contains(&format!("{realm}/.luaurc")));
    }
    for source in info.local_manifests.keys() {
        let package = source.strip_suffix("/wally.toml").unwrap();
        assert!(!root.join(package).join(".luaurc").exists());
    }
    assert!(root
        .join("Packages/_Index/fixture_leaf@local/leaf/Source/Module/init.luau")
        .is_file());
    assert!(!root
        .join("ServerPackages/_Index/fixture_leaf@local")
        .exists());
    assert!(!root.join("DevPackages/_Index/fixture_leaf@local").exists());
    assert!(!root.join("Packages/_Index/fixture_server@local").exists());
    assert!(info
        .generated_paths
        .contains(&"Packages/Shared.luau".to_owned()));
    assert!(info
        .generated_paths
        .contains(&"Packages/_Index/fixture_a@local/Nested.luau".to_owned()));
    assert!(!info
        .generated_paths
        .iter()
        .any(|path| path.contains("/Source/")));
    info.verify_manifests(root).unwrap();
    let lock = Lockfile::load(root).unwrap().unwrap();
    assert!(
        lock.packages
            .iter()
            .filter(|p| matches!(p, LockPackage::Local(_)))
            .count()
            == 5
    );
    write(
        root,
        "Forks/leaf/Source/Module/init.luau",
        "return { Edited = true }\n",
    );
    info.verify_manifests(root).unwrap();
    install(root, true).unwrap();
    assert_eq!(
        std::fs::read(root.join("wally.install.json")).unwrap(),
        first
    );
    assert_eq!(
        std::fs::read_to_string(root.join("Forks/leaf/Source/Module/init.luau")).unwrap(),
        "return { Edited = true }\n"
    );
    assert_eq!(
        std::fs::read_to_string(
            root.join("Packages/_Index/fixture_leaf@local/leaf/Source/Module/init.luau")
        )
        .unwrap(),
        "return { Edited = true }\n"
    );
    UpdateSubcommand {
        project_path: root.into(),
        package_specs: vec!["fixture/leaf".parse().unwrap()],
    }
    .run(GlobalOptions {
        test_registry: true,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        std::fs::read(root.join("wally.install.json")).unwrap(),
        first
    );
}

#[test]
fn mixed_registry_local_graph_has_distinct_identities_and_roundtrips_lock() {
    let project = TempProject::empty().unwrap();
    root_manifest(
        project.path(),
        "[dependencies]\nLocal = '^Forks/foo'\nRegistry = 'fixture/foo@1'",
    );
    local(
        project.path(),
        "Forks/foo",
        "foo",
        "shared",
        "[dependencies]\nRemote = 'fixture/remote@1'",
    );
    let registry = InMemoryRegistry::new();
    registry
        .publish(PackageBuilder::new("fixture/foo@1.0.0").with_dep("Remote", "fixture/remote@1"));
    registry.publish(PackageBuilder::new("fixture/remote@1.0.0"));
    let sources = PackageSourceMap::new(Box::new(registry.source()))
        .with_project_root(project.path())
        .unwrap();
    let manifest = Manifest::load(project.path()).unwrap();
    let graph = resolve(&manifest, &Default::default(), &sources).unwrap();
    assert_eq!(graph.activated.len(), 4);
    assert_eq!(
        graph
            .activated
            .iter()
            .filter(|id| id.name().name() == "foo")
            .count(),
        2
    );
    let lock = Lockfile::from_resolve(&graph);
    lock.save(project.path()).unwrap();
    assert_eq!(Lockfile::load(project.path()).unwrap().unwrap(), lock);
    let again = resolve(&manifest, &lock.as_ids().collect(), &sources).unwrap();
    assert_eq!(Lockfile::from_resolve(&again), lock);
}

#[test]
fn mixed_graph_installs_registry_contents_and_contract_metadata() {
    let project = TempProject::empty().unwrap();
    let root = project.path();
    let registry_path = root.join("Registry");
    let remote = PackageBuilder::new("fixture/remote@1.2.3").with_file("init.luau", "return {}\n");
    write(
        root,
        "Registry/index/fixture/remote",
        format!("{}\n", serde_json::to_string(remote.manifest()).unwrap()),
    );
    write(
        root,
        "Registry/contents/fixture/remote/1.2.3.zip",
        remote.contents().data(),
    );
    write(
        root,
        "Registry/index/config.json",
        r#"{"api":"https://example.invalid/","fallback_registries":[]}"#,
    );
    write(root, "wally.toml", format!("[package]\nname='fixture/root'\nrealm='shared'\nregistry={}\n[server-dependencies]\nLocal='^Forks/local'\n", toml::Value::String(registry_path.to_str().unwrap().into())));
    local(
        root,
        "Forks/local",
        "local",
        "server",
        "[dependencies]\nRemote='fixture/remote@1'",
    );
    install(root, false).unwrap();
    let info = metadata(root);
    let remote = info
        .package_roots
        .iter()
        .find(|p| p.kind == "registry")
        .unwrap();
    assert_eq!(remote.realm, Realm::Server);
    assert_eq!(remote.package_version.as_deref(), Some("1.2.3"));
    assert!(remote.source_path.is_none());
    assert_eq!(
        remote.install_path,
        "ServerPackages/_Index/fixture_remote@1.2.3/remote"
    );
    assert!(root.join(&remote.install_path).join("init.luau").is_file());
    assert!(!root.join("Packages").exists());
    install(root, true).unwrap();
}

#[test]
fn changed_local_graph_invalidates_locked_install_even_when_node_set_is_unchanged() {
    let project = TempProject::empty().unwrap();
    let root = project.path();
    root_manifest(root, "[dependencies]\nFoo='^Forks/foo'\nBar='^Forks/bar'");
    local(
        root,
        "Forks/foo",
        "foo",
        "shared",
        "[dependencies]\nOld='^Forks/bar'",
    );
    local(root, "Forks/bar", "bar", "shared", "");
    install(root, false).unwrap();
    let old_lock = std::fs::read(root.join("wally.lock")).unwrap();
    let old_metadata = std::fs::read(root.join("wally.install.json")).unwrap();
    write(
        root,
        "Forks/foo/wally.toml",
        "[package]\nname='fixture/foo'\nrealm='shared'\n[dependencies]\nNew='^Forks/bar'\n",
    );
    assert!(metadata(root).verify_manifests(root).is_err());
    assert!(install(root, true).is_err());
    assert_eq!(std::fs::read(root.join("wally.lock")).unwrap(), old_lock);
    assert_eq!(
        std::fs::read(root.join("wally.install.json")).unwrap(),
        old_metadata
    );
    assert!(root
        .join("Packages/_Index/fixture_foo@local/Old.luau")
        .exists());
    install(root, false).unwrap();
    assert!(!root
        .join("Packages/_Index/fixture_foo@local/Old.luau")
        .exists());
    assert!(root
        .join("Packages/_Index/fixture_foo@local/New.luau")
        .exists());
}

#[test]
fn locked_local_graph_records_edge_realms_even_when_all_nodes_and_origins_match() {
    let project = TempProject::empty().unwrap();
    let root = project.path();
    root_manifest(root, "[dependencies]\nFoo='^Forks/a'\nBar='^Forks/b'\n[dev-dependencies]\nFoo='^Forks/b'\nBar='^Forks/a'");
    local(root, "Forks/a", "a", "shared", "");
    local(root, "Forks/b", "b", "shared", "");
    install(root, false).unwrap();
    let lock = std::fs::read(root.join("wally.lock")).unwrap();
    root_manifest(root, "[dependencies]\nFoo='^Forks/b'\nBar='^Forks/a'\n[dev-dependencies]\nFoo='^Forks/a'\nBar='^Forks/b'");
    assert!(install(root, true).is_err());
    assert_eq!(std::fs::read(root.join("wally.lock")).unwrap(), lock);
}

#[test]
fn registry_lock_comparison_accepts_legacy_checksums_and_ordering_and_escapes_registry_strings() {
    let registry = InMemoryRegistry::new();
    registry.publish(PackageBuilder::new("fixture/a@1.0.0"));
    registry.publish(PackageBuilder::new("fixture/b@1.0.0"));
    let manifest = PackageBuilder::new("fixture/root@1.0.0")
        .with_dep("A", "fixture/a@1")
        .with_dep("B", "fixture/b@1")
        .into_manifest();
    let graph = resolve(
        &manifest,
        &Default::default(),
        &PackageSourceMap::new(Box::new(registry.source())),
    )
    .unwrap();
    let mut lock = Lockfile::from_resolve(&graph);
    lock.packages.reverse();
    for package in &mut lock.packages {
        if let LockPackage::Registry(package) = package {
            package.checksum = Some("legacy checksum".into());
            package.dependencies.reverse();
        }
    }
    assert!(lock.graph_matches(&graph));
    lock.registry = "registry \"quoted\" with \\ characters".into();
    let project = TempProject::empty().unwrap();
    lock.save(project.path()).unwrap();
    assert_eq!(Lockfile::load(project.path()).unwrap().unwrap(), lock);
}

#[test]
fn ambiguous_local_names_aliases_and_cycles_fail_before_replacing_installation() {
    for (deps, a_deps, other_name) in [
        ("[dependencies]\nA='^Forks/a'\nB='^Forks/b'", "", "a"),
        ("[dependencies]\nFoo='^Forks/a'\nfoo='^Forks/b'", "", "b"),
        (
            "[dependencies]\nA='^Forks/a'",
            "[dependencies]\nB='^Forks/b'",
            "b",
        ),
    ] {
        let project = TempProject::empty().unwrap();
        let root = project.path();
        root_manifest(root, deps);
        local(root, "Forks/a", "a", "shared", a_deps);
        local(
            root,
            "Forks/b",
            other_name,
            "shared",
            "[dependencies]\nA='^Forks/a'",
        );
        write(root, "Packages/Keep.luau", "original\n");
        assert!(install(root, false).is_err());
        assert_eq!(
            std::fs::read_to_string(root.join("Packages/Keep.luau")).unwrap(),
            "original\n"
        );
        assert!(!root.join("wally.lock").exists());
        assert!(!root.join("wally.install.json").exists());
    }
}

#[test]
fn reused_active_server_node_is_rejected_on_a_shared_edge() {
    let project = TempProject::empty().unwrap();
    root_manifest(
        project.path(),
        "[dependencies]\nA='^Forks/a'\n[dev-dependencies]\nServer='^Forks/server'",
    );
    local(
        project.path(),
        "Forks/a",
        "a",
        "shared",
        "[dependencies]\nServer='^Forks/server'",
    );
    local(project.path(), "Forks/server", "server", "server", "");
    let error = install(project.path(), false).unwrap_err().to_string();
    assert!(
        error.contains("No packages were found that matched (Shared)"),
        "{}",
        error
    );
    assert!(error.contains("^Forks/server"), "{}", error);
    assert!(!project.path().join("wally.lock").exists());
    assert!(!project.path().join("wally.install.json").exists());
}

#[test]
fn server_edges_under_shared_packages_never_replicate_server_contents() {
    let project = TempProject::empty().unwrap();
    root_manifest(project.path(), "[dependencies]\nShared='^Forks/a'");
    local(
        project.path(),
        "Forks/a",
        "a",
        "shared",
        "[server-dependencies]\nSecret='^Forks/secret'",
    );
    local(project.path(), "Forks/secret", "secret", "server", "");
    install(project.path(), false).unwrap();
    let info = metadata(project.path());
    assert_eq!(
        info.package_roots
            .iter()
            .find(|p| p.name == "fixture/secret")
            .unwrap()
            .realm,
        Realm::Server
    );
    assert!(!project
        .path()
        .join("Packages/_Index/fixture_secret@local")
        .exists());
}

#[test]
fn package_ignore_rules_use_package_root_and_traversal_errors_are_not_hidden() {
    let project = TempProject::empty().unwrap();
    let root = project.path();
    local(root, "Forks/pkg", "pkg", "shared", "");
    write(
        root,
        "Forks/pkg/.gitignore",
        "/Ignored/\n*.tmp\n!keep.tmp\n",
    );
    write(root, "Forks/pkg/Source/Module/Ignored/kept.luau", "kept\n");
    write(root, "Forks/pkg/Source/Module/keep.tmp", "kept\n");
    write(root, "Forks/pkg/Ignored/secret.luau", "secret\n");
    write(root, "Forks/pkg/Source/Module/temp.tmp", "ignored\n");
    let package = root.join("Forks/pkg");
    let paths = PackageContents::filtered_contents(&package).unwrap();
    assert!(!paths
        .iter()
        .any(|p| p.ends_with("secret.luau") || p.ends_with("temp.tmp")));
    assert!(paths.iter().any(|p| p.ends_with("Source/Module/init.luau")));
    assert!(paths
        .iter()
        .any(|p| p.ends_with("Source/Module/Ignored/kept.luau")));
    assert!(paths.iter().any(|p| p.ends_with("keep.tmp")));
    assert!(PackageContents::filtered_contents(&root.join("missing")).is_err());
}

#[test]
fn package_includes_preserve_explicit_hidden_files_and_nested_projects_are_not_renamed() {
    let project = TempProject::empty().unwrap();
    let root = project.path();
    local(root, "Forks/pkg", "pkg", "shared", "");
    write(root, "Forks/pkg/wally.toml", "[package]\nname='fixture/pkg'\nrealm='shared'\ninclude=['/Source', '.luaurc', '/default.project.json', '/wally.toml']\n");
    write(root, "Forks/pkg/.luaurc", "{}\n");
    write(root, "Forks/pkg/junk.luau", "not included\n");
    write(
        root,
        "Forks/pkg/default.project.json",
        r#"{"tree":{"$path":"Source/Module"}}"#,
    );
    let nested_project = r#"{"name":"Nested","tree":{"$path":"init.luau"}}"#;
    write(
        root,
        "Forks/pkg/Source/Module/default.project.json",
        nested_project,
    );
    let contents = PackageContents::pack_from_path(&root.join("Forks/pkg")).unwrap();
    let output = TempProject::empty().unwrap();
    contents.unpack_into_path(output.path()).unwrap();
    assert!(output.path().join(".luaurc").is_file());
    assert!(!output.path().join("junk.luau").exists());
    assert_eq!(
        std::fs::read_to_string(output.path().join("Source/Module/default.project.json")).unwrap(),
        nested_project
    );
    let entry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.path().join("default.project.json")).unwrap())
            .unwrap();
    assert_eq!(entry["name"], "pkg");
}

#[cfg(unix)]
#[test]
fn source_aliases_escapes_and_destination_symlinks_are_refused_without_mutation() {
    use std::os::unix::fs::symlink;
    for mode in ["source-root", "source-child", "destination"] {
        let project = TempProject::empty().unwrap();
        let outside = TempProject::empty().unwrap();
        root_manifest(project.path(), "[dependencies]\nPkg='^Forks/pkg'");
        local(project.path(), "Forks/pkg", "pkg", "shared", "");
        write(outside.path(), "Keep.luau", "untouched\n");
        match mode {
            "source-root" => {
                std::fs::rename(
                    project.path().join("Forks/pkg"),
                    project.path().join("Forks/original"),
                )
                .unwrap();
                symlink(
                    project.path().join("Forks/original"),
                    project.path().join("Forks/pkg"),
                )
                .unwrap();
            }
            "source-child" => {
                symlink(outside.path(), project.path().join("Forks/pkg/Escape")).unwrap()
            }
            _ => symlink(outside.path(), project.path().join("Packages")).unwrap(),
        }
        assert!(install(project.path(), false).is_err(), "{}", mode);
        assert_eq!(
            std::fs::read_to_string(outside.path().join("Keep.luau")).unwrap(),
            "untouched\n"
        );
    }
}

#[test]
fn local_destination_overlap_is_rejected() {
    for destination in [
        "Packages",
        "ServerPackages",
        "DevPackages",
        "wally.lock",
        "wally.install.json",
        ".wally-install",
        ".wally-install.lock",
    ] {
        let project = TempProject::empty().unwrap();
        let directory = format!("{destination}/pkg");
        root_manifest(
            project.path(),
            &format!("[dependencies]\nPkg='^{directory}'"),
        );
        local(project.path(), &directory, "pkg", "shared", "");
        assert!(install(project.path(), false).is_err(), "{}", destination);
        assert!(project
            .path()
            .join(&directory)
            .join("Source/Module/init.luau")
            .is_file());
    }
}

#[test]
fn cli_binary_installs_and_updates_from_an_unrelated_working_directory() {
    let project = TempProject::empty().unwrap();
    let unrelated = TempProject::empty().unwrap();
    let root = project.path();
    root_manifest(
        root,
        "[server-dependencies]\nProfileStore='^Source/ForkedPackages/profile-store'",
    );
    local(
        root,
        "Source/ForkedPackages/profile-store",
        "profile-store",
        "server",
        "",
    );
    for command in ["install", "update", "install"] {
        let mut cli = std::process::Command::new(env!("CARGO_BIN_EXE_wally"));
        cli.current_dir(unrelated.path())
            .arg(command)
            .arg("--project-path")
            .arg(root);
        if command == "install" && root.join("wally.lock").exists() {
            cli.arg("--locked");
        }
        let output = cli.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let info = metadata(root);
    assert_eq!(
        info.package_roots[0].install_path,
        "ServerPackages/_Index/fixture_profile-store@local/profile-store"
    );
    assert_eq!(
        info.package_roots[0].source_path.as_deref(),
        Some("Source/ForkedPackages/profile-store")
    );
    assert!(!root.join("Packages").exists());
    assert!(!unrelated.path().join("wally.install.json").exists());
}

#[test]
fn failed_staged_download_retains_old_trees_lock_and_provenance_then_recovers() {
    let project = TempProject::empty().unwrap();
    let root = project.path();
    root_manifest(root, "[dependencies]\nLocal='^Forks/local'");
    local(root, "Forks/local", "local", "shared", "");
    install(root, false).unwrap();
    let old_metadata = std::fs::read(root.join("wally.install.json")).unwrap();
    let old_lock = std::fs::read(root.join("wally.lock")).unwrap();
    let registry_path = root.join("Registry");
    let remote = PackageBuilder::new("fixture/remote@1.0.0").with_file("init.luau", "return {}\n");
    write(
        root,
        "Registry/index/fixture/remote",
        format!("{}\n", serde_json::to_string(remote.manifest()).unwrap()),
    );
    write(
        root,
        "Registry/contents/fixture/remote/1.0.0.zip",
        "not a ZIP archive",
    );
    write(
        root,
        "Registry/index/config.json",
        r#"{"api":"https://example.invalid/","fallback_registries":[]}"#,
    );
    write(root, "wally.toml", format!("[package]\nname='fixture/root'\nrealm='shared'\nregistry={}\n[dependencies]\nLocal='^Forks/local'\nRemote='fixture/remote@1'\n", toml::Value::String(registry_path.to_str().unwrap().into())));
    assert!(install(root, false).is_err());
    assert_eq!(
        std::fs::read(root.join("wally.install.json")).unwrap(),
        old_metadata
    );
    assert_eq!(std::fs::read(root.join("wally.lock")).unwrap(), old_lock);
    assert!(root.join("Packages/Local.luau").is_file());
    assert!(root.join("Forks/local/Source/Module/init.luau").is_file());
    write(
        root,
        "Registry/contents/fixture/remote/1.0.0.zip",
        remote.contents().data(),
    );
    install(root, false).unwrap();
    assert!(root.join("Packages/Remote.luau").is_file());
    assert!(!root.join(".wally-install").exists());
}

#[test]
fn project_mapping_escapes_and_unsafe_aliases_are_preflight_errors() {
    for alias in [
        "../Escape",
        "_Index",
        "Bad/Name",
        "Bad\\Name",
        "CON",
        "LPT1",
    ] {
        let project = TempProject::empty().unwrap();
        root_manifest(
            project.path(),
            &format!("[dependencies]\n'{alias}'='^Forks/pkg'"),
        );
        local(project.path(), "Forks/pkg", "pkg", "shared", "");
        assert!(install(project.path(), false).is_err());
        assert!(!project.path().join("Packages").exists());
    }
    let project = TempProject::empty().unwrap();
    root_manifest(project.path(), "[dependencies]\nPkg='^Forks/pkg'");
    local(project.path(), "Forks/pkg", "pkg", "shared", "");
    write(project.path(), "External/init.luau", "return {}\n");
    write(
        project.path(),
        "Forks/pkg/default.project.json",
        r#"{"name":"pkg","tree":{"$path":"../../External"}}"#,
    );
    assert!(install(project.path(), false)
        .unwrap_err()
        .to_string()
        .contains("escapes its package"));
    assert!(!project.path().join("Packages").exists());
}

#[test]
fn aliases_in_separate_root_realms_are_independent_and_transitive_aliases_cannot_overwrite_them() {
    let project = TempProject::empty().unwrap();
    let root = project.path();
    root_manifest(
        root,
        "[dependencies]\nFoo='^Forks/a'\nOther='^Forks/b'\n[dev-dependencies]\nFoo='^Forks/c'",
    );
    local(root, "Forks/a", "a", "shared", "");
    local(
        root,
        "Forks/b",
        "b",
        "shared",
        "[dependencies]\nFoo='^Forks/c'",
    );
    local(root, "Forks/c", "c", "shared", "");
    install(root, false).unwrap();
    assert!(std::fs::read_to_string(root.join("Packages/Foo.luau"))
        .unwrap()
        .contains("fixture_a@local/a"));
    assert!(std::fs::read_to_string(root.join("DevPackages/Foo.luau"))
        .unwrap()
        .contains("fixture_c@local/c"));
    assert!(
        std::fs::read_to_string(root.join("Packages/_Index/fixture_b@local/Foo.luau"))
            .unwrap()
            .contains("fixture_c@local/c")
    );
}

#[test]
fn ambiguous_transitive_root_aliases_stay_isolated_in_package_shims() {
    let project = TempProject::empty().unwrap();
    let root = project.path();
    root_manifest(root, "[dependencies]\nA='^Forks/a'\nB='^Forks/b'");
    local(
        root,
        "Forks/a",
        "a",
        "shared",
        "[dependencies]\nUtil='^Forks/x'",
    );
    local(
        root,
        "Forks/b",
        "b",
        "shared",
        "[dependencies]\nUtil='^Forks/y'",
    );
    local(root, "Forks/x", "x", "shared", "");
    local(root, "Forks/y", "y", "shared", "");
    install(root, false).unwrap();
    assert!(!root.join("Packages/Util.luau").exists());
    assert!(
        std::fs::read_to_string(root.join("Packages/_Index/fixture_a@local/Util.luau"))
            .unwrap()
            .contains("fixture_x@local/x")
    );
    assert!(
        std::fs::read_to_string(root.join("Packages/_Index/fixture_b@local/Util.luau"))
            .unwrap()
            .contains("fixture_y@local/y")
    );
}

#[test]
fn installed_packages_resolve_private_aliases_in_their_own_index_buckets() {
    fn alias_directory(source: &Path) -> std::path::PathBuf {
        for directory in source.parent().unwrap().ancestors() {
            let config = directory.join(".luaurc");
            if config.is_file() {
                let config: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(config).unwrap()).unwrap();
                if let Some(alias) = config["aliases"]["packages"].as_str() {
                    return directory.join(alias).canonicalize().unwrap();
                }
            }
        }
        panic!("No packages alias found for {}", source.display());
    }

    fn source_bytes(root: &Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
        walkdir::WalkDir::new(root)
            .into_iter()
            .map(Result::unwrap)
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| {
                (
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    std::fs::read(entry.path()).unwrap(),
                )
            })
            .collect()
    }

    for registry_source in [false, true] {
        for (section, realm) in [
            ("dependencies", "Packages"),
            ("server-dependencies", "ServerPackages"),
            ("dev-dependencies", "DevPackages"),
        ] {
            for root_util in [false, true] {
                let project = TempProject::empty().unwrap();
                let root = project.path();
                let requirement = |name: &str| {
                    if registry_source {
                        format!("fixture/{name}@1")
                    } else {
                        format!("^Forks/{name}")
                    }
                };
                for (name, dependency) in [
                    ("a", Some("x")),
                    ("b", Some("y")),
                    ("x", None),
                    ("y", None),
                    ("z", None),
                ] {
                    let source = if dependency.is_some() {
                        "return require(\"@packages/Util\")\n".to_owned()
                    } else {
                        format!("return {{ Identity = \"{name}\" }}\n")
                    };
                    if registry_source {
                        let mut package = PackageBuilder::new(format!("fixture/{name}@1.0.0"))
                            .with_file("init.luau", "return require(\"@self/Source/Module\")\n")
                            .with_file(
                                "default.project.json",
                                r#"{"tree":{"$path":"Source/Module"}}"#,
                            )
                            .with_file("Source/Module/init.luau", source);
                        if let Some(dependency) = dependency {
                            package = package.with_dep("Util", requirement(dependency));
                        }
                        write(
                            root,
                            &format!("Registry/index/fixture/{name}"),
                            format!("{}\n", serde_json::to_string(package.manifest()).unwrap()),
                        );
                        write(
                            root,
                            &format!("Registry/contents/fixture/{name}/1.0.0.zip"),
                            package.contents().data(),
                        );
                    } else {
                        let deps = dependency
                            .map(|name| format!("[dependencies]\nUtil='{}'", requirement(name)))
                            .unwrap_or_default();
                        local(root, &format!("Forks/{name}"), name, "shared", &deps);
                        write(
                            root,
                            &format!("Forks/{name}/Source/Module/init.luau"),
                            source,
                        );
                    }
                }
                let registry = if registry_source {
                    write(
                        root,
                        "Registry/index/config.json",
                        r#"{"api":"https://example.invalid/","fallback_registries":[]}"#,
                    );
                    format!(
                        "registry={}\n",
                        toml::Value::String(root.join("Registry").to_str().unwrap().into())
                    )
                } else {
                    String::new()
                };
                // Give x a shared installation too, exercising cross-index local shims
                // and multiple registry installations when the consumers are server/dev.
                let shared = format!("[dependencies]\nSharedTarget='{}'\n", requirement("x"));
                let direct = format!(
                    "A='{}'\nB='{}'\n{}",
                    requirement("a"),
                    requirement("b"),
                    if root_util {
                        format!("Util='{}'\n", requirement("z"))
                    } else {
                        String::new()
                    }
                );
                let deps = if section == "dependencies" {
                    format!("{shared}{direct}")
                } else {
                    format!("{shared}[{section}]\n{direct}")
                };
                write(
                    root,
                    "wally.toml",
                    format!("[package]\nname='fixture/root'\nrealm='shared'\n{registry}{deps}"),
                );
                let source_root = root.join(if registry_source { "Registry" } else { "Forks" });
                let before = source_bytes(&source_root);
                install(root, false).unwrap();
                assert_eq!(source_bytes(&source_root), before);
                let info = metadata(root);

                for package in &info.package_roots {
                    let physical_root = root.join(&package.install_path);
                    let bucket = physical_root.parent().unwrap();
                    let config = bucket.join(".luaurc");
                    let contents = std::fs::read(&config).unwrap();
                    assert_eq!(contents.last(), Some(&b'\n'));
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&contents).unwrap(),
                        serde_json::json!({"aliases": {"packages": "./"}})
                    );
                    let relative = config
                        .strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace('\\', "/");
                    assert!(info.generated_paths.contains(&relative));
                    assert!(!info.package_roots.iter().any(|package| {
                        relative.starts_with(&format!("{}/", package.install_path))
                    }));
                    assert!(!physical_root.join(".luaurc").exists());
                }

                for (consumer, target) in [("a", "x"), ("b", "y")] {
                    let package = info
                        .package_roots
                        .iter()
                        .find(|package| package.name == format!("fixture/{consumer}"))
                        .unwrap();
                    let physical_root = root.join(&package.install_path);
                    let source = physical_root.join("Source/Module/init.luau");
                    assert_eq!(
                        std::fs::read_to_string(&source).unwrap(),
                        "return require(\"@packages/Util\")\n"
                    );
                    let directory = alias_directory(&source);
                    assert_eq!(
                        directory,
                        physical_root.parent().unwrap().canonicalize().unwrap()
                    );
                    assert_ne!(directory, root.join(realm).canonicalize().unwrap());
                    let shim = directory.join("Util.luau");
                    let link = std::fs::read_to_string(&shim).unwrap();
                    let require = link
                        .trim()
                        .strip_prefix("return require(\"")
                        .unwrap()
                        .strip_suffix("\")")
                        .unwrap();
                    let destination = directory.join(require).canonicalize().unwrap();
                    let target_package = info
                        .package_roots
                        .iter()
                        .find(|package| {
                            package.name == format!("fixture/{target}")
                                && root.join(&package.install_path).canonicalize().unwrap()
                                    == destination
                        })
                        .unwrap();
                    assert_eq!(
                        std::fs::read_to_string(
                            root.join(&target_package.install_path)
                                .join("Source/Module/init.luau")
                        )
                        .unwrap(),
                        format!("return {{ Identity = \"{target}\" }}\n")
                    );
                    let relative = shim
                        .strip_prefix(root.canonicalize().unwrap())
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace('\\', "/");
                    assert!(info.generated_paths.contains(&relative));
                }
                for directory in ["Packages", "ServerPackages", "DevPackages"] {
                    let util = root.join(directory).join("Util.luau");
                    if directory == realm && root_util {
                        assert!(std::fs::read_to_string(util)
                            .unwrap()
                            .contains("fixture_z@"));
                    } else {
                        assert!(!util.exists());
                    }
                    if root.join(directory).is_dir() {
                        assert_eq!(
                            alias_directory(&root.join(directory).join("Consumer.luau")),
                            root.join(directory).canonicalize().unwrap()
                        );
                        assert!(info
                            .generated_paths
                            .contains(&format!("{directory}/.luaurc")));
                    }
                }
            }
        }
    }
}

#[test]
fn origin_realms_propagate_through_previously_activated_registry_subgraphs() {
    let registry = InMemoryRegistry::new();
    for name in ["a", "b", "c"] {
        registry.publish(
            PackageBuilder::new(format!("fixture/{name}@1.0.0")).with_dep("Util", "fixture/util@1"),
        );
    }
    registry.publish(PackageBuilder::new("fixture/util@1.0.0").with_dep("Leaf", "fixture/leaf@1"));
    registry.publish(PackageBuilder::new("fixture/leaf@1.0.0"));
    let manifest = PackageBuilder::new("fixture/root@1.0.0")
        .with_dep("A", "fixture/a@1")
        .with_server_dep("B", "fixture/b@1")
        .with_dev_dep("C", "fixture/c@1")
        .into_manifest();
    let graph = resolve(
        &manifest,
        &Default::default(),
        &PackageSourceMap::new(Box::new(registry.source())),
    )
    .unwrap();
    let leaf = graph
        .activated
        .iter()
        .find(|id| id.name().name() == "leaf")
        .unwrap();
    assert_eq!(
        graph.metadata[leaf].origin_realms,
        BTreeSet::from([Realm::Shared, Realm::Server, Realm::Dev])
    );
}

#[test]
fn named_types_follow_staged_entrypoints_for_all_realms_sources_and_link_forms() {
    const TYPES: &str = r#"
-- export type Comment = string
local text = [[export type Fake = string]]
local Leaf = require("../../Leaf")
local Types = require(script.Types)
type Fusion = Types.Fusion
type Private = string
export type Scope<Constructors = Fusion> = Types.Scope<Constructors>
export type Connection = Leaf.Connection
export type Maid = { Clean: () -> () }
export type Replica<T = string, U = T, P... = (number, string)> = { Data: T, Callback: (U, P...) -> () }
return { Text = text }
"#;
    const IMPORTED_TYPES: &str = r#"
export type Task = () -> ()
export type Scope<C = unknown> = {Task} & C
type ValueConstructor = <T>(Scope<unknown>, T) -> T
export type Fusion = { Value: ValueConstructor, Next: Fusion? }
type Unreachable = typeof(runtime)
return nil
"#;
    for registry_source in [false, true] {
        for configured in [false, true] {
            let project = TempProject::empty().unwrap();
            let root = project.path();
            let requirement = |name: &str| {
                if registry_source {
                    format!("fixture/{name}@1")
                } else {
                    format!("^Forks/{name}")
                }
            };
            let deps = format!("[dependencies]\nShared='{}'\n", requirement("shared"));
            let server_deps = format!(
                "{deps}[server-dependencies]\nServer='{}'\n",
                requirement("server")
            );
            let dev_deps = format!(
                "{server_deps}[dev-dependencies]\nDev='{}'\n",
                requirement("dev")
            );
            for (name, realm, dependencies) in [
                ("shared-consumer", "shared", deps.as_str()),
                ("server-consumer", "server", server_deps.as_str()),
                ("dev-consumer", "shared", dev_deps.as_str()),
            ] {
                local(root, &format!("Forks/{name}"), name, realm, dependencies);
            }
            for (name, realm) in [
                ("shared", Realm::Shared),
                ("server", Realm::Server),
                ("dev", Realm::Shared),
            ] {
                if registry_source {
                    let package = PackageBuilder::new(format!("fixture/{name}@1.0.0"))
                        .with_realm(realm)
                        .with_dep("Leaf", "fixture/leaf@1")
                        .with_file("init.luau", "export type Wrong = string\nreturn {}\n")
                        .with_file(
                            "default.project.json",
                            r#"{"name":"entry","tree":{"$path":"Source/Module"}}"#,
                        )
                        .with_file("Source/Module/init.luau", TYPES)
                        .with_file("Source/Module/Types.luau", IMPORTED_TYPES);
                    write(
                        root,
                        &format!("Registry/index/fixture/{name}"),
                        format!("{}\n", serde_json::to_string(package.manifest()).unwrap()),
                    );
                    write(
                        root,
                        &format!("Registry/contents/fixture/{name}/1.0.0.zip"),
                        package.contents().data(),
                    );
                } else {
                    let realm = if realm == Realm::Server {
                        "server"
                    } else {
                        "shared"
                    };
                    local(
                        root,
                        &format!("Forks/{name}"),
                        name,
                        realm,
                        "[dependencies]\nLeaf='^Forks/leaf'",
                    );
                    write(
                        root,
                        &format!("Forks/{name}/init.luau"),
                        "export type Wrong = string\nreturn {}\n",
                    );
                    write(
                        root,
                        &format!("Forks/{name}/Source/Module/init.luau"),
                        TYPES,
                    );
                    write(
                        root,
                        &format!("Forks/{name}/Source/Module/Types.luau"),
                        IMPORTED_TYPES,
                    );
                }
            }
            let leaf_source = "export type Connection = { Disconnect: () -> () }\nreturn {}\n";
            if registry_source {
                let leaf =
                    PackageBuilder::new("fixture/leaf@1.0.0").with_file("init.lua", leaf_source);
                write(
                    root,
                    "Registry/index/fixture/leaf",
                    format!("{}\n", serde_json::to_string(leaf.manifest()).unwrap()),
                );
                write(
                    root,
                    "Registry/contents/fixture/leaf/1.0.0.zip",
                    leaf.contents().data(),
                );
                write(
                    root,
                    "Registry/index/config.json",
                    r#"{"api":"https://example.invalid/","fallback_registries":[]}"#,
                );
            } else {
                local(root, "Forks/leaf", "leaf", "shared", "");
                write(root, "Forks/leaf/Source/Module/init.luau", leaf_source);
            }
            let registry = if registry_source {
                format!(
                    "registry={}\n",
                    toml::Value::String(root.join("Registry").to_str().unwrap().into())
                )
            } else {
                String::new()
            };
            let place = if configured {
                "[place]\nshared-packages='game.ReplicatedStorage.Packages'\nserver-packages='game.ServerScriptService.Packages'\n"
            } else {
                ""
            };
            write(root, "wally.toml", format!("[package]\nname='fixture/root'\nrealm='shared'\n{registry}{place}[dependencies]\nSharedConsumer='^Forks/shared-consumer'\n[server-dependencies]\nServerConsumer='^Forks/server-consumer'\n[dev-dependencies]\nDevConsumer='^Forks/dev-consumer'\n"));
            install(root, false).unwrap();
            let info = metadata(root);
            let mut typed_links = 0;
            let mut leaf_links = 0;
            for path in &info.generated_paths {
                if !path.ends_with(".luau") {
                    continue;
                }
                let link = std::fs::read_to_string(root.join(path)).unwrap();
                if ["Shared.luau", "Server.luau", "Dev.luau"]
                    .iter()
                    .any(|name| path.ends_with(name))
                {
                    typed_links += 1;
                    assert_eq!(link.matches("require(").count(), 1, "{}", path);
                    assert_eq!(link.matches("export type ").count(), 4, "{}", path);
                    assert!(link.contains("export type Scope< Constructors = __WallyType0 >"));
                    assert!(link.contains("type __WallyType0 = __WallyType1"));
                    assert!(!link.contains("Types ."));
                    assert!(!link.contains("typeof"));
                    assert!(!link.contains("Unreachable"));
                    for name in ["Connection", "Maid", "Replica", "Scope"] {
                        assert!(link.contains(&format!("export type {name}")), "{}", path);
                    }
                    assert!(link.ends_with("return __WallyPackage\n"));
                    assert!(!link.contains("Wrong"));
                    full_moon::parse(&link).unwrap();
                } else if path.ends_with("Leaf.luau") {
                    leaf_links += 1;
                    assert!(link.contains("export type Connection = __WallyPackage.Connection"));
                }
            }
            assert!(typed_links >= 9, "{}", typed_links);
            assert!(leaf_links >= 4, "{}", leaf_links);
            for package in &info.package_roots {
                if ["fixture/shared", "fixture/server", "fixture/dev"]
                    .contains(&package.name.as_str())
                {
                    assert_eq!(
                        std::fs::read_to_string(
                            root.join(&package.install_path)
                                .join("Source/Module/init.luau")
                        )
                        .unwrap(),
                        TYPES
                    );
                    assert_eq!(
                        std::fs::read_to_string(
                            root.join(&package.install_path)
                                .join("Source/Module/Types.luau")
                        )
                        .unwrap(),
                        IMPORTED_TYPES
                    );
                }
            }
            if !registry_source {
                assert_eq!(
                    std::fs::read_to_string(root.join("Forks/shared/Source/Module/init.luau"))
                        .unwrap(),
                    TYPES
                );
            }
        }
    }
}

#[test]
fn imported_default_failures_abort_install_and_valid_transitive_types_recover() {
    let project = TempProject::empty().unwrap();
    let root = project.path();
    root_manifest(root, "[dependencies]\nPkg='^Forks/pkg'");
    local(root, "Forks/pkg", "pkg", "shared", "");
    write(root, "Forks/pkg/Source/Module/init.luau", "local Types = require(script.Types)\ntype Fusion = Types.Fusion\nexport type Scope<Constructors = Fusion> = Types.Scope<Constructors>\nreturn {}\n");
    const VALID: &str = "local Inner = require(script.Parent.Inner)\nexport type Scope<C = unknown> = {Inner.Task} & C\nexport type Fusion = { Scope: Scope<unknown>, Next: Fusion? }\nreturn nil\n";
    write(root, "Forks/pkg/Source/Module/Types.luau", VALID);
    write(
        root,
        "Forks/pkg/Source/Module/Inner.luau",
        "export type Task = () -> ()\nreturn nil\n",
    );
    install(root, false).unwrap();
    let link = std::fs::read(root.join("Packages/Pkg.luau")).unwrap();
    let provenance = std::fs::read(root.join("wally.install.json")).unwrap();
    for invalid in [
        "local Inner = require(runtime)\nexport type Fusion = Inner.Value\nreturn nil\n",
        "export type Fusion = typeof(runtime)\nreturn nil\n",
        "local Inner = require(script.Parent.Parent.Escape)\nexport type Fusion = Inner.Value\nreturn nil\n",
        "type function Build() return types.number end\nexport type Fusion = Build<>\nreturn nil\n",
    ] {
        write(root, "Forks/pkg/Source/Module/Types.luau", invalid);
        assert!(install(root, false).is_err(), "{}", invalid);
        assert_eq!(std::fs::read(root.join("Packages/Pkg.luau")).unwrap(), link);
        assert_eq!(std::fs::read(root.join("wally.install.json")).unwrap(), provenance);
        write(root, "Forks/pkg/Source/Module/Types.luau", VALID);
        install(root, false).unwrap();
        assert_eq!(std::fs::read(root.join("Packages/Pkg.luau")).unwrap(), link);
        assert!(!root.join(".wally-install").exists());
    }
    let link = String::from_utf8(link).unwrap();
    assert_eq!(link.matches("require(").count(), 1);
    assert_eq!(link.matches("export type ").count(), 1);
    assert!(link.contains("Constructors = __WallyType0"));
    full_moon::parse(&link).unwrap();
}

#[test]
fn invalid_type_entrypoint_aborts_staged_install_without_replacing_previous_links() {
    let project = TempProject::empty().unwrap();
    let root = project.path();
    root_manifest(root, "[dependencies]\nPkg='^Forks/pkg'");
    local(root, "Forks/pkg", "pkg", "shared", "");
    write(
        root,
        "Forks/pkg/Source/Module/init.luau",
        "export type Existing = string\nreturn {}\n",
    );
    install(root, false).unwrap();
    let link = std::fs::read(root.join("Packages/Pkg.luau")).unwrap();
    let provenance = std::fs::read(root.join("wally.install.json")).unwrap();
    write(
        root,
        "Forks/pkg/Source/Module/init.luau",
        "export type Broken< = {}\nreturn {}\n",
    );
    let error = format!("{:#}", install(root, false).unwrap_err());
    assert!(error.contains("Invalid Luau entrypoint"), "{}", error);
    assert_eq!(std::fs::read(root.join("Packages/Pkg.luau")).unwrap(), link);
    assert_eq!(
        std::fs::read(root.join("wally.install.json")).unwrap(),
        provenance
    );
    // Failed staging is retained by the transaction until the next guarded recovery.
    write(
        root,
        "Forks/pkg/Source/Module/init.luau",
        "export type Existing = string\nreturn {}\n",
    );
    install(root, false).unwrap();
    assert_eq!(std::fs::read(root.join("Packages/Pkg.luau")).unwrap(), link);
    assert!(!root.join(".wally-install").exists());
}

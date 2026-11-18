mod in_memory;
mod registry;
mod test_registry;

pub use self::in_memory::InMemoryRegistry;
use self::in_memory::InMemoryRegistrySource;
pub use self::registry::Registry;
pub use self::test_registry::TestRegistry;

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Serialize;

use crate::manifest::Manifest;
use crate::package_contents::PackageContents;
use crate::package_id::PackageId;
use crate::package_req::PackageReq;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum PackageSourceId {
    DefaultRegistry,
    Git(String),
    Local(String),
    Path(PathBuf),
}

#[derive(Clone)]
pub struct PackageSourceMap {
    sources: HashMap<PackageSourceId, Box<PackageSource>>,
    source_order: Vec<PackageSourceId>,
    project_root: Option<PathBuf>,
}

impl PackageSourceMap {
    pub fn new(default_registry: Box<PackageSource>) -> Self {
        let mut sources = HashMap::new();
        sources.insert(PackageSourceId::DefaultRegistry, default_registry);

        Self {
            sources,
            source_order: vec![PackageSourceId::DefaultRegistry],
            project_root: None,
        }
    }

    pub fn with_project_root(mut self, root: &std::path::Path) -> anyhow::Result<Self> {
        self.project_root = Some(root.canonicalize()?);
        Ok(self)
    }

    /// Discover local manifests without contacting the network. Only initialize registry
    /// fallbacks if a reachable registry requirement actually needs them.
    pub fn prepare(&mut self, manifest: &Manifest) -> anyhow::Result<()> {
        crate::resolution::validate_aliases(manifest, true)?;
        let mut queue = vec![manifest.clone()];
        let mut visited = std::collections::BTreeSet::new();
        let mut needs_registry = false;
        while let Some(package) = queue.pop() {
            for req in package
                .dependencies
                .values()
                .chain(package.server_dependencies.values())
                .chain(package.dev_dependencies.values())
            {
                match req {
                    crate::package_req::DependencyReq::Registry(_) => needs_registry = true,
                    crate::package_req::DependencyReq::Local(path)
                        if visited.insert(path.clone()) =>
                    {
                        let directory =
                            crate::local_packages::source_directory(self.project_root()?, path)?;
                        let mut local = Manifest::load(&directory)?;
                        crate::resolution::validate_aliases(&local, false)?;
                        // Development requirements are only activated at the consuming root.
                        local.dev_dependencies.clear();
                        queue.push(local);
                    }
                    _ => {}
                }
            }
        }
        if needs_registry {
            anyhow::ensure!(
                !manifest.package.registry.is_empty(),
                "Registry dependencies require a registry in the consuming root manifest."
            );
            self.add_fallbacks()?;
        }
        Ok(())
    }

    pub fn project_root(&self) -> anyhow::Result<&std::path::Path> {
        self.project_root
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Local dependencies require a consuming project root."))
    }

    pub fn get(&self, id: &PackageSourceId) -> Option<&PackageSource> {
        self.sources.get(id).map(|source| source.as_ref())
    }

    pub fn source_order(&self) -> &Vec<PackageSourceId> {
        &self.source_order
    }

    /// Searches the current list of sources for fallbacks and adds any not yet in the list, producing
    /// a complete tree of reachable sources for packages.
    /// Sources are searched breadth-first to ensure correct fallback priority.
    pub fn add_fallbacks(&mut self) -> anyhow::Result<()> {
        let mut source_index = 0;

        while source_index < self.source_order.len() {
            let registry = self.sources.get(&self.source_order[source_index]).unwrap();

            for fallback in registry.fallback_sources()? {
                // Prevent circular references by only adding new sources
                if !self.source_order.contains(&fallback) {
                    let source: Box<PackageSource> = match &fallback {
                        PackageSourceId::Git(url) => {
                            Box::new(PackageSource::Registry(Registry::from_registry_spec(url)?))
                        }
                        PackageSourceId::Path(path) => {
                            Box::new(PackageSource::TestRegistry(TestRegistry::new(path.clone())))
                        }
                        PackageSourceId::Local(_) => {
                            anyhow::bail!("Local packages cannot be registry fallback sources.")
                        }
                        PackageSourceId::DefaultRegistry => {
                            panic!("Default registry should never be added as a fallback source!")
                        }
                    };

                    self.sources.insert(fallback.clone(), source);
                    self.source_order.push(fallback);
                }
            }

            source_index += 1;
        }

        Ok(())
    }
}

pub trait PackageSourceProvider: Sync + Send + Clone {
    /// Update this package source, if it has state that needs to be updated.
    fn update(&self) -> anyhow::Result<()>;

    /// Query this package source for all of the packages that match this
    /// `PackageReq`.
    fn query(&self, package_req: &PackageReq) -> anyhow::Result<Vec<Manifest>>;

    /// Downloads the contents of a package given its fully-qualified
    /// `PackageId`.
    fn download_package(&self, package_id: &PackageId) -> anyhow::Result<PackageContents>;

    /// Provide a list of fallback sources to search if this source can't provide a package
    fn fallback_sources(&self) -> anyhow::Result<Vec<PackageSourceId>>;
}

#[derive(Clone)]
pub enum PackageSource {
    InMemory(InMemoryRegistrySource),
    Registry(Registry),
    TestRegistry(TestRegistry),
}

impl PackageSourceProvider for PackageSource {
    fn update(&self) -> anyhow::Result<()> {
        match self {
            PackageSource::InMemory(source) => source.update(),
            PackageSource::Registry(source) => source.update(),
            PackageSource::TestRegistry(source) => source.update(),
        }
    }

    fn query(&self, package_req: &PackageReq) -> anyhow::Result<Vec<Manifest>> {
        match self {
            PackageSource::InMemory(source) => source.query(package_req),
            PackageSource::Registry(source) => source.query(package_req),
            PackageSource::TestRegistry(source) => source.query(package_req),
        }
    }

    fn download_package(&self, package_id: &PackageId) -> anyhow::Result<PackageContents> {
        match self {
            PackageSource::InMemory(source) => source.download_package(package_id),
            PackageSource::Registry(source) => source.download_package(package_id),
            PackageSource::TestRegistry(source) => source.download_package(package_id),
        }
    }

    fn fallback_sources(&self) -> anyhow::Result<Vec<PackageSourceId>> {
        match self {
            PackageSource::InMemory(source) => source.fallback_sources(),
            PackageSource::Registry(source) => source.fallback_sources(),
            PackageSource::TestRegistry(source) => source.fallback_sources(),
        }
    }
}

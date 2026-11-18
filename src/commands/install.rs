use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::style::{Attribute, Color, SetAttribute, SetForegroundColor};
use indicatif::{ProgressBar, ProgressStyle};

use structopt::StructOpt;

use crate::installation::InstallationContext;
use crate::lockfile::Lockfile;
use crate::manifest::Manifest;
use crate::package_source::{PackageSource, PackageSourceMap, Registry, TestRegistry};
use crate::resolution::resolve;

use super::utils::{generate_dependency_changes, render_update_difference};
use super::GlobalOptions;

/// Install all of the dependencies of this project.
#[derive(Debug, StructOpt)]
pub struct InstallSubcommand {
    /// Path to the project to install dependencies for.
    #[structopt(long = "project-path", default_value = ".")]
    pub project_path: PathBuf,

    /// Flag to error if the lockfile does not match with the latest dependencies.
    #[structopt(long = "locked")]
    pub locked: bool,
}

impl InstallSubcommand {
    pub fn run(self, global: GlobalOptions) -> anyhow::Result<()> {
        let root = self.project_path.canonicalize()?;
        let transaction = crate::install_transaction::InstallTransaction::begin(&root)?;
        let manifest = Manifest::load(&root)?;

        let default_registry: Box<PackageSource> = if manifest.package.registry.is_empty() {
            Box::new(crate::package_source::InMemoryRegistry::new().source())
        } else if global.test_registry {
            Box::new(PackageSource::TestRegistry(TestRegistry::new(
                &manifest.package.registry,
            )))
        } else {
            Box::new(PackageSource::Registry(Registry::from_registry_spec(
                &manifest.package.registry,
            )?))
        };

        let mut package_sources =
            PackageSourceMap::new(default_registry).with_project_root(&root)?;
        package_sources.prepare(&manifest)?;
        let lockfile = Lockfile::load(&root)?.unwrap_or_else(|| Lockfile::from_manifest(&manifest));

        let try_to_use = lockfile.as_ids().collect();

        let progress = ProgressBar::new(0).with_style(
            ProgressStyle::with_template("{spinner:.cyan}{wide_msg}")?.tick_chars("⠁⠈⠐⠠⠄⠂ "),
        );

        progress.enable_steady_tick(Duration::from_millis(100));

        let resolved = resolve(&manifest, &try_to_use, &package_sources)?;
        if self.locked {
            progress.println(format!(
                "{} Verifying {}lockfile is up-to-date...",
                SetForegroundColor(Color::DarkGreen),
                SetForegroundColor(Color::Reset)
            ));

            let latest_graph = resolve(&manifest, &Default::default(), &package_sources)?;
            if !lockfile.graph_matches(&latest_graph) {
                progress.finish_and_clear();

                let old_dependencies = &try_to_use;

                let changes =
                    generate_dependency_changes(old_dependencies, &latest_graph.activated);
                let mut error_output = Vec::new();

                writeln!(
                    error_output,
                    "{} The Lockfile is out of date and wasn't changed due to --locked{}",
                    SetForegroundColor(Color::Yellow),
                    SetForegroundColor(Color::Reset)
                )?;

                render_update_difference(&changes, &mut error_output)?;

                writeln!(
                    error_output,
                    "{}{} Suggestion{}{} try running wally update",
                    SetAttribute(Attribute::Bold),
                    SetForegroundColor(Color::DarkGreen),
                    SetForegroundColor(Color::Reset),
                    SetAttribute(Attribute::Reset)
                )?;

                anyhow::bail!(String::from_utf8(error_output)
                    .expect("output from render_update_difference should always be utf-8"));
            }

            progress.println(format!(
                "{}   Verified {}lockfile is up-to-date...{}",
                SetForegroundColor(Color::DarkGreen),
                SetForegroundColor(Color::Green),
                SetForegroundColor(Color::Reset)
            ));
        }

        progress.println(format!(
            "{} Resolving {}packages...",
            SetForegroundColor(Color::DarkGreen),
            SetForegroundColor(Color::Reset)
        ));

        progress.println(format!(
            "{}   Resolved {}{} dependencies",
            SetForegroundColor(Color::DarkGreen),
            SetForegroundColor(Color::Reset),
            resolved.activated.len() - 1
        ));

        progress.finish_and_clear();
        InstallationContext::install_atomic(
            &root,
            package_sources,
            &manifest,
            resolved,
            transaction,
        )?;

        Ok(())
    }
}

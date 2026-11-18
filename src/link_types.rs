//! Named-type forwarding for generated links. Read the staged runtime module, never a
//! manifest guess or the unstaged local source. Runtime requires stay unchanged.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

use anyhow::{bail, Context};
use fs_err as fs;
use full_moon::{
    ast::{luau::TypeInfo, Stmt},
    node::Node,
    visitors::{Visit, Visitor},
};

#[derive(Clone, Default)]
pub(crate) struct ForwardedTypes {
    namespace: String,
    aliases: Vec<String>,
}

/// A directory without an entrypoint can be an asset-only package. Preserve its old
/// link, but never silently accept a broken explicit project mapping.
pub(crate) fn exports(root: &Path) -> anyhow::Result<ForwardedTypes> {
    let root = root.canonicalize()?;
    let entry = resolve_path(&root, &root, &mut BTreeSet::new())
        .with_context(|| format!("Cannot resolve package entrypoint in {}", root.display()))?;
    match entry {
        Some(entry) => declarations(&fs::read_to_string(&entry)?)
            .with_context(|| format!("Cannot forward named types from {}", entry.display())),
        None => Ok(ForwardedTypes::default()),
    }
}

fn resolve_path(
    root: &Path,
    path: &Path,
    visiting: &mut BTreeSet<PathBuf>,
) -> anyhow::Result<Option<PathBuf>> {
    let path = path
        .canonicalize()
        .with_context(|| format!("Entrypoint path does not exist, {}", path.display()))?;
    if !path.starts_with(root) {
        bail!(
            "Entrypoint escapes the staged package root, {}",
            path.display()
        );
    }
    if !visiting.insert(path.clone()) {
        bail!("Cyclic entrypoint project mapping at {}", path.display());
    }
    let result = if path.is_dir() {
        let project = path.join("default.project.json");
        if project.is_file() {
            resolve_path(root, &project, visiting)?
        } else {
            if path.join("default.project.jsonc").is_file() {
                bail!(
                    "JSONC entrypoint projects are unsupported, {}",
                    path.display()
                );
            }
            check_metadata(&path.join("init.meta.json"))?;
            let candidates: Vec<_> = [
                "init.luau",
                "init.lua",
                "init.server.luau",
                "init.server.lua",
                "init.client.luau",
                "init.client.lua",
                "init.legacy.luau",
                "init.legacy.lua",
                "init.local.luau",
                "init.local.lua",
                "init.plugin.luau",
                "init.plugin.lua",
                "init.csv",
            ]
            .iter()
            .map(|name| path.join(name))
            .filter(|path| path.is_file())
            .collect();
            match candidates.as_slice() {
                [] => None,
                [entry] => resolve_path(root, entry, visiting)?,
                _ => bail!("Ambiguous entrypoint scripts in {}", path.display()),
            }
        }
    } else if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".project.json"))
    {
        let project: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)
            .with_context(|| format!("Invalid Rojo project {}", path.display()))?;
        for option in ["syncRules", "globIgnorePaths"] {
            if project
                .get(option)
                .is_some_and(|value| !matches!(value.as_array(), Some(items) if items.is_empty()))
            {
                bail!(
                    "Custom Rojo {option} can change the entrypoint mapping and are unsupported."
                );
            }
        }
        let tree = project
            .get("tree")
            .and_then(|tree| tree.as_object())
            .context("Rojo project must have an object tree.")?;
        if !tree.contains_key("$path")
            && tree.get("$className").and_then(|value| value.as_str()) != Some("ModuleScript")
            && tree
                .get("$properties")
                .and_then(|properties| properties.get("Source"))
                .is_none()
        {
            // An inline asset tree has no root ModuleScript exports. Its filesystem
            // wrapper is not the runtime entrypoint, even if one exists beside it.
            visiting.remove(&path);
            return Ok(None);
        }
        if tree.contains_key("$className") {
            // Rojo only permits a class override when $path resolves to a Folder.
            // A module source plus an explicit class is not a valid mapping.
            bail!("Explicit entrypoint $className with $path is unsupported; map a ModuleScript source directly.");
        }
        if tree
            .get("$properties")
            .and_then(|p| p.get("Source"))
            .is_some()
        {
            bail!("Inline Source entrypoints are unsupported.");
        }
        let target = tree.get("$path").and_then(|value| value.as_str())
            .context("Entrypoint project requires a single string $path; merged or inline mappings are unsupported.")?;
        let target = Path::new(target);
        if target.is_absolute()
            || target
                .components()
                .any(|c| matches!(c, Component::Prefix(_)))
        {
            bail!("Entrypoint $path must be package-relative.");
        }
        resolve_path(root, &path.parent().unwrap().join(target), visiting)?
    } else {
        let name = path.file_name().unwrap().to_string_lossy();
        if !(name.ends_with(".luau") || name.ends_with(".lua"))
            || name.ends_with(".server.luau")
            || name.ends_with(".server.lua")
            || name.ends_with(".client.luau")
            || name.ends_with(".client.lua")
            || name.ends_with(".legacy.luau")
            || name.ends_with(".legacy.lua")
            || name.ends_with(".local.luau")
            || name.ends_with(".local.lua")
            || name.ends_with(".plugin.luau")
            || name.ends_with(".plugin.lua")
        {
            bail!("Unsupported non-ModuleScript entrypoint {}", path.display());
        }
        check_metadata(&path.with_extension("meta.json"))?;
        Some(path.clone())
    };
    visiting.remove(&path);
    Ok(result)
}

fn check_metadata(path: &Path) -> anyhow::Result<()> {
    if path.with_extension("jsonc").exists() {
        bail!(
            "JSONC entrypoint metadata is unsupported, {}",
            path.display()
        );
    }
    if path.exists() {
        let metadata: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
        if metadata.get("className").is_some()
            || metadata
                .get("properties")
                .and_then(|properties| properties.get("Source"))
                .is_some()
        {
            bail!(
                "Entrypoint metadata overrides its class or Source, {}",
                path.display()
            );
        }
    }
    Ok(())
}

/// Drop trivia through the parser, not text substitutions. In particular, comments
/// around generic parameters must not consume the generated equals sign or body.
fn syntax(node: &impl Node) -> String {
    let mut tokens: Vec<_> = node.tokens().collect();
    // ContainedSpan stores both delimiters together, so Node::tokens is not
    // necessarily in source order (for example, the closing generic arrow).
    tokens.sort_by_key(|token| token.token().start_position().bytes());
    tokens
        .iter()
        .map(|token| token.token().to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn declarations(source: &str) -> anyhow::Result<ForwardedTypes> {
    let ast = full_moon::parse(source)
        .map_err(|errors| anyhow::anyhow!("Invalid Luau entrypoint, {errors:?}"))?;
    let mut private = BTreeSet::new();
    let mut private_declarations = BTreeMap::new();
    let mut required_private = BTreeSet::new();
    let mut exported = BTreeSet::new();
    for statement in ast.nodes().stmts() {
        match statement {
            Stmt::TypeDeclaration(declaration) => {
                let name = syntax(declaration.type_name());
                private.insert(name.clone());
                private_declarations.insert(name, declaration);
            }
            Stmt::TypeFunction(function) => {
                private.insert(syntax(function.function_name()));
            }
            Stmt::ExportedTypeDeclaration(declaration) => {
                let name = syntax(declaration.type_declaration().type_name());
                if !exported.insert(name) {
                    bail!("Duplicate exported type declaration.");
                }
            }
            Stmt::ExportedTypeFunction(_) => {
                bail!("Exported type functions cannot be forwarded by a type alias.")
            }
            _ => {}
        }
    }
    // Avoid collisions with both exported names and generic parameter names. No new
    // exported names are introduced; this is only a local runtime namespace.
    let tokens: BTreeSet<_> = ast
        .nodes()
        .tokens()
        .map(|t| t.token().to_string())
        .collect();
    let mut namespace = "__WallyPackage".to_owned();
    while tokens.contains(&namespace) {
        namespace.push('_');
    }
    let mut result = Vec::new();
    for statement in ast.nodes().stmts() {
        if let Stmt::ExportedTypeDeclaration(export) = statement {
            let declaration = export.type_declaration();
            let name = syntax(declaration.type_name());
            let mut parameters = String::new();
            let mut arguments = String::new();
            if let Some(generics) = declaration.generics() {
                let bound = generic_names(Some(generics));
                for parameter in generics.generics().iter() {
                    if let Some(default) = parameter.default_type() {
                        let mut validator = DefaultValidator {
                            private: &private,
                            bound: &bound,
                            nested: Vec::new(),
                            required: &mut required_private,
                            error: None,
                        };
                        default.visit(&mut validator);
                        if let Some(error) = validator.error {
                            bail!("Cannot forward default for exported type {name}, {error}");
                        }
                    }
                }
                parameters = syntax(generics);
                arguments = format!(
                    "<{}>",
                    generics
                        .generics()
                        .iter()
                        .map(|p| syntax(p.parameter()))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            result.push((
                declaration.start_position().unwrap().bytes(),
                format!("export type {name}{parameters} = {namespace}.{name}{arguments}\n"),
            ));
        }
    }
    // Defaults can use closed private aliases. Carry only their reachable type
    // declarations, never runtime locals or additional exported names. Forward
    // references retain the source aliases' recursion and declaration order semantics.
    let mut copied = BTreeSet::new();
    let mut helpers = Vec::new();
    while let Some(name) = required_private.difference(&copied).next().cloned() {
        let declaration = private_declarations.get(&name).with_context(|| {
            format!("Cannot forward default using private type function {name}.")
        })?;
        let bound = generic_names(declaration.generics());
        let mut validator = DefaultValidator {
            private: &private,
            bound: &bound,
            nested: Vec::new(),
            required: &mut required_private,
            error: None,
        };
        declaration.visit(&mut validator);
        if let Some(error) = validator.error {
            bail!("Cannot forward private default type {name}, {error}");
        }
        helpers.push((
            declaration.start_position().unwrap().bytes(),
            format!("{}\n", syntax(*declaration)),
        ));
        copied.insert(name);
    }
    helpers.extend(result);
    helpers.sort_by_key(|(position, _)| *position);
    Ok(ForwardedTypes {
        namespace,
        aliases: helpers
            .into_iter()
            .map(|(_, declaration)| declaration)
            .collect(),
    })
}

fn generic_names(generics: Option<&full_moon::ast::luau::GenericDeclaration>) -> BTreeSet<String> {
    generics
        .into_iter()
        .flat_map(|g| g.generics().iter())
        .map(|parameter| {
            // The AST separates the parameter name from a pack's ellipsis.
            parameter
                .parameter()
                .tokens()
                .next()
                .unwrap()
                .token()
                .to_string()
        })
        .collect()
}

/// Defaults are evaluated in the link's type scope. Collect reachable private
/// aliases, accounting for nested callback generic scopes. Module imports and typeof
/// expressions cannot be copied without replaying runtime code, so refuse them.
struct DefaultValidator<'a> {
    private: &'a BTreeSet<String>,
    bound: &'a BTreeSet<String>,
    nested: Vec<BTreeSet<String>>,
    required: &'a mut BTreeSet<String>,
    error: Option<String>,
}

impl Visitor for DefaultValidator<'_> {
    fn visit_type_info(&mut self, info: &TypeInfo) {
        if let TypeInfo::Callback { generics, .. } = info {
            self.nested.push(generic_names(generics.as_ref()));
        }
        let name = match info {
            TypeInfo::Basic(name) | TypeInfo::Generic { base: name, .. } => Some(syntax(name)),
            TypeInfo::Module { .. } | TypeInfo::Typeof { .. } => {
                self.error = Some("module-scoped or typeof defaults are unsupported.".into());
                None
            }
            _ => None,
        };
        if let Some(name) = name {
            if self.private.contains(&name)
                && !self.bound.contains(&name)
                && !self.nested.iter().any(|bound| bound.contains(&name))
            {
                self.required.insert(name);
            }
        }
    }

    fn visit_type_info_end(&mut self, info: &TypeInfo) {
        if matches!(info, TypeInfo::Callback { .. }) {
            self.nested.pop();
        }
    }
}

/// Add forwarding around the existing require expression. The empty case is byte
/// compatible, including legacy configured Roblox-path links and their casts.
pub(crate) fn forward(link: String, exports: &ForwardedTypes) -> String {
    if exports.aliases.is_empty() {
        return link;
    }
    let namespace = &exports.namespace;
    let expression = link.strip_prefix("return ").unwrap_or_else(|| {
        // Legacy links contain a typeof alias followed by a casted return. The
        // cast isn't needed when the actual module is bound directly below.
        link.lines()
            .find_map(|line| line.strip_prefix("return "))
            .unwrap()
    });
    let expression = expression
        .trim_end()
        .strip_suffix(" :: Package")
        .unwrap_or(expression.trim_end());
    format!(
        "local {namespace} = {expression}\n{}return {namespace}\n",
        exports.aliases.concat()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write(root: &Path, path: &str, contents: &str) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn forwards_only_top_level_exports_and_preserves_generic_defaults_and_packs() {
        let source = r#"
-- export type Comment = string
local text = [[export type String = number]]
type Private = number
export type Value = { Name: string }
export type Box<T = Value, U = T, P... = (string, number)> = (T, U, P...) -> ()
export type Collision<__WallyPackage> = __WallyPackage
do type Nested = string end
return { text = text }
"#;
        let output = forward(
            "return require(\"./target\")\n".into(),
            &declarations(source).unwrap(),
        );
        assert!(output.contains("local __WallyPackage_ = require(\"./target\")"));
        assert!(output.contains("export type Box< T = Value , U = T , P ... = ( string , number ) > = __WallyPackage_.Box<T, U, P ...>"), "{}", output);
        assert!(output.contains("export type Value = __WallyPackage_.Value"));
        assert_eq!(output.matches("export type ").count(), 3);
        assert!(full_moon::parse(&output).is_ok(), "{}", output);
    }

    #[test]
    fn comments_in_parameters_are_not_copied_and_nonexports_keep_old_links() {
        let declarations =
            declarations("export type Box<T -- a comment\n, P...> = (T, P...) -> ()\nreturn {} ")
                .unwrap();
        let output = forward("return require(\"./target\")\n".into(), &declarations);
        assert!(!output.contains("comment"));
        assert!(full_moon::parse(&output).is_ok(), "{}", output);
        let old = "type Package = typeof(require(game.Packages.Foo))\nreturn require(game.Packages.Foo) :: Package\n";
        assert_eq!(forward(old.into(), &ForwardedTypes::default()), old);
        assert!(super::declarations("type Private = string\nreturn {}")
            .unwrap()
            .aliases
            .is_empty());
    }

    #[test]
    fn rejects_defaults_that_would_change_scope_and_invalid_syntax() {
        for source in [
            "type Hidden = Imported.Value\nexport type Box<T = Hidden> = T\nreturn {}",
            "export type Box<T = Imported.Value> = T\nreturn {}",
            "local value = {}\nexport type Box<T = typeof(value)> = T\nreturn {}",
            "export type Broken< = {}",
        ] {
            assert!(declarations(source).is_err(), "{}", source);
        }
    }

    #[test]
    fn defaults_carry_reachable_private_aliases_without_exporting_them() {
        let source = "type Unused = Imported.NotAvailable\ntype Inner = string\ntype Hidden<T = Inner> = { Value: T, Next: Hidden<T>? }\nexport type Box<T = Hidden<Inner>, P... = ...number> = (T, P...) -> ()\nexport type Callback<T = <Unused>(Unused) -> Unused> = T\nreturn {}";
        let output = forward(
            "return require(\"./target\")\n".into(),
            &declarations(source).unwrap(),
        );
        assert!(output.contains("type Inner = string\n"));
        assert!(output.contains("type Hidden < T = Inner >"));
        assert!(!output.contains("Imported"));
        assert_eq!(output.matches("export type ").count(), 2);
        assert!(full_moon::parse(&output).is_ok(), "{}", output);
    }

    #[test]
    fn projects_override_root_wrappers_and_follow_nested_redirects() {
        let temp = TempDir::new().unwrap();
        write(
            temp.path(),
            "init.luau",
            "export type Wrong = string\nreturn {}",
        );
        write(
            temp.path(),
            "default.project.json",
            r#"{"tree":{"$path":"Source"}}"#,
        );
        write(
            temp.path(),
            "Source/default.project.json",
            r#"{"tree":{"$path":"Module.luau"}}"#,
        );
        write(
            temp.path(),
            "Source/Module.luau",
            "export type Actual = string\nreturn {}",
        );
        let result = exports(temp.path()).unwrap().aliases.concat();
        assert!(result.contains("Actual"));
        assert!(!result.contains("Wrong"));
    }

    #[test]
    fn inline_asset_projects_do_not_forward_filesystem_wrapper_types() {
        for class in ["", r#""$className":"Folder","#, r#""$className":"Model","#] {
            let temp = TempDir::new().unwrap();
            write(
                temp.path(),
                "init.luau",
                "export type FilesystemOnly = string\nreturn {}",
            );
            write(
                temp.path(),
                "default.project.json",
                &format!(
                    r#"{{"tree":{{{class}"Source":{{"$className":"Folder","$path":"Source"}}}}}}"#
                ),
            );
            write(
                temp.path(),
                "Source/init.luau",
                "export type ChildOnly = number\nreturn {}",
            );
            let types = exports(temp.path()).unwrap();
            assert!(types.aliases.is_empty());
            let link = "return require(\"./asset-package\")\n";
            assert_eq!(forward(link.into(), &types), link);
        }
        let temp = TempDir::new().unwrap();
        write(
            temp.path(),
            "init.luau",
            "export type FilesystemOnly = string\nreturn {}",
        );
        write(
            temp.path(),
            "default.project.json",
            r#"{"tree":{"$path":"Assets"}}"#,
        );
        write(temp.path(), "Assets/info.txt", "asset");
        assert!(exports(temp.path()).unwrap().aliases.is_empty());
    }

    #[test]
    fn refuses_invalid_ambiguous_and_unsupported_entrypoints() {
        for project in [
            r#"{"tree":{"$path":"missing"}}"#,
            r#"{"tree":{"$path":["a","b"]}}"#,
            r#"{"tree":{"$path":".","$className":"ModuleScript"}}"#,
            r#"{"tree":{"$path":"init.luau","$className":"Folder"}}"#,
            r#"{"tree":{"$path":"init.luau","$className":"ModuleScript"}}"#,
            r#"{"syncRules":[{}],"tree":{"$path":"init.luau"}}"#,
            r#"{"globIgnorePaths":["**/*.luau"],"tree":{"$path":"init.luau"}}"#,
            r#"{"tree":{"$path":"init.luau","$properties":{"Source":"return {}"}}}"#,
            r#"{"tree":{"$path":"../outside.luau"}}"#,
            "invalid json",
        ] {
            let temp = TempDir::new().unwrap();
            write(temp.path(), "default.project.json", project);
            write(temp.path(), "init.luau", "return {}");
            assert!(exports(temp.path()).is_err(), "{}", project);
        }
        let temp = TempDir::new().unwrap();
        write(temp.path(), "init.lua", "return {}");
        write(temp.path(), "init.luau", "return {}");
        assert!(exports(temp.path()).is_err());
        for name in [
            "init.server.luau",
            "init.local.lua",
            "init.legacy.luau",
            "init.plugin.lua",
            "init.csv",
            "default.project.jsonc",
        ] {
            let temp = TempDir::new().unwrap();
            write(temp.path(), name, "return {}");
            assert!(exports(temp.path()).is_err(), "{}", name);
        }
        let temp = TempDir::new().unwrap();
        write(temp.path(), "init.luau", "return {}");
        write(
            temp.path(),
            "init.meta.json",
            r#"{"properties":{"Source":"return {}"}}"#,
        );
        assert!(exports(temp.path()).is_err());
    }
}

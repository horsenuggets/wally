//! Named-type forwarding for generated links. Read the staged runtime module, never a
//! manifest guess or the unstaged local source. Runtime requires stay unchanged.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

use anyhow::{bail, Context};
use fs_err as fs;
use full_moon::{
    ast::{
        luau::{
            GenericDeclarationParameter, GenericParameterInfo, IndexedTypeInfo, TypeDeclaration,
            TypeInfo,
        },
        punctuated::{Pair, Punctuated},
        span::ContainedSpan,
        Call, Expression, FunctionArgs, Index, Prefix, Stmt, Suffix, Var,
    },
    node::Node,
    tokenizer::{Token, TokenReference, TokenType},
    visitors::{Visit, VisitMut, Visitor, VisitorMut},
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
        Some(entry) => declarations(&root, &entry)
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
            let candidates: Vec<_> = module_candidates(&path, "init")
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

fn module_candidates<'a>(directory: &'a Path, name: &'a str) -> impl Iterator<Item = PathBuf> + 'a {
    [
        ".luau",
        ".lua",
        ".server.luau",
        ".server.lua",
        ".client.luau",
        ".client.lua",
        ".legacy.luau",
        ".legacy.lua",
        ".local.luau",
        ".local.lua",
        ".plugin.luau",
        ".plugin.lua",
        ".csv",
    ]
    .iter()
    .map(move |suffix| directory.join(format!("{name}{suffix}")))
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

// Module identities are paths in the staged instance tree, not just source files.
// Redirects can mount the same file at different instance paths.
type ModuleId = Vec<String>;
type AliasId = (ModuleId, String);

#[derive(Clone)]
struct TypeModule {
    aliases: BTreeMap<String, TypeDeclaration>,
    exported: BTreeSet<String>,
    functions: BTreeSet<String>,
    bindings: BTreeMap<String, (usize, Option<Expression>)>,
    ambiguous: BTreeSet<String>,
    tokens: BTreeSet<String>,
}

impl TypeModule {
    fn parse(source: &str) -> anyhow::Result<Self> {
        let ast = full_moon::parse(source)
            .map_err(|errors| anyhow::anyhow!("Invalid Luau entrypoint, {errors:?}"))?;
        let mut module = Self {
            aliases: BTreeMap::new(),
            exported: BTreeSet::new(),
            functions: BTreeSet::new(),
            bindings: BTreeMap::new(),
            ambiguous: BTreeSet::new(),
            tokens: ast
                .nodes()
                .tokens()
                .map(|t| t.token().to_string())
                .collect(),
        };
        for statement in ast.nodes().stmts() {
            let declaration = match statement {
                Stmt::TypeDeclaration(declaration) => Some(declaration.as_ref()),
                Stmt::ExportedTypeDeclaration(export) => {
                    module
                        .exported
                        .insert(syntax(export.type_declaration().type_name()));
                    Some(export.type_declaration())
                }
                Stmt::TypeFunction(function) => {
                    module.functions.insert(syntax(function.function_name()));
                    None
                }
                Stmt::ExportedTypeFunction(function) => {
                    let name = syntax(function.type_function().function_name());
                    module.exported.insert(name.clone());
                    module.functions.insert(name);
                    None
                }
                Stmt::LocalAssignment(assignment) => {
                    module.bind(assignment.names().iter(), assignment.expressions().iter());
                    None
                }
                Stmt::ConstAssignment(assignment) => {
                    module.bind(assignment.names().iter(), assignment.expressions().iter());
                    None
                }
                Stmt::LocalFunction(function) => {
                    module.bind(std::iter::once(function.name()), std::iter::empty());
                    None
                }
                _ => None,
            };
            if let Some(declaration) = declaration {
                let name = syntax(declaration.type_name());
                if module.aliases.insert(name, declaration.clone()).is_some() {
                    bail!("Duplicate type declaration is ambiguous.");
                }
            }
        }
        // Refuse writes to top-level bindings, including captures, but not writes
        // to unrelated locals that happen to use the same spelling.
        let mut writes = BindingWrites::default();
        ast.nodes().visit(&mut writes);
        module.ambiguous.extend(writes.names);
        if module
            .functions
            .iter()
            .any(|name| module.aliases.contains_key(name))
        {
            bail!("Ambiguous type alias and type function declarations.");
        }
        Ok(module)
    }

    fn bind<'a>(
        &mut self,
        names: impl Iterator<Item = &'a TokenReference>,
        mut expressions: impl Iterator<Item = &'a Expression>,
    ) {
        for token in names {
            let name = syntax(token);
            let binding = (
                token.start_position().unwrap().bytes(),
                expressions.next().cloned(),
            );
            if self.bindings.insert(name.clone(), binding).is_some() {
                self.ambiguous.insert(name);
            }
        }
    }
}

/// Resolve writes in source order. Body binders are attached to the actual AST
/// block, so function parameters and loop variables do not hide outer bindings
/// while visiting annotations, initializers, or iterator expressions.
#[derive(Default)]
struct BindingWrites {
    names: BTreeSet<String>,
    scopes: Vec<BTreeSet<String>>,
    body_bindings: BTreeMap<*const full_moon::ast::Block, BTreeSet<String>>,
    repeat_blocks: BTreeSet<*const full_moon::ast::Block>,
}

impl BindingWrites {
    fn write(&mut self, token: &TokenReference) {
        let name = syntax(token);
        match self.scopes.iter().rposition(|scope| scope.contains(&name)) {
            Some(0) => {
                self.names.insert(name);
            }
            // These unbound globals are also part of static import resolution.
            None if name == "require" || name == "script" => {
                self.names.insert(name);
            }
            _ => {}
        }
    }

    fn declare<'a>(&mut self, names: impl Iterator<Item = &'a TokenReference>) {
        self.scopes.last_mut().unwrap().extend(names.map(syntax));
    }

    fn body<'a>(
        &mut self,
        block: &full_moon::ast::Block,
        names: impl Iterator<Item = &'a TokenReference>,
    ) {
        // Visit borrows the original AST without cloning or moving its blocks.
        self.body_bindings
            .entry(std::ptr::from_ref(block))
            .or_default()
            .extend(names.map(syntax));
    }
}

impl Visitor for BindingWrites {
    fn visit_block(&mut self, block: &full_moon::ast::Block) {
        self.scopes.push(
            self.body_bindings
                .remove(&std::ptr::from_ref(block))
                .unwrap_or_default(),
        );
    }

    fn visit_block_end(&mut self, block: &full_moon::ast::Block) {
        // A repeat body's locals remain visible in its until condition.
        if !self.repeat_blocks.remove(&std::ptr::from_ref(block)) {
            self.scopes.pop();
        }
    }

    fn visit_repeat(&mut self, repeat: &full_moon::ast::Repeat) {
        self.repeat_blocks
            .insert(std::ptr::from_ref(repeat.block()));
    }

    fn visit_repeat_end(&mut self, _: &full_moon::ast::Repeat) {
        self.scopes.pop();
    }

    fn visit_function_body(&mut self, function: &full_moon::ast::FunctionBody) {
        self.body(
            function.block(),
            function
                .parameters()
                .iter()
                .filter_map(|parameter| match parameter {
                    full_moon::ast::Parameter::Name(name) => Some(name),
                    _ => None,
                }),
        );
    }

    fn visit_numeric_for(&mut self, loop_: &full_moon::ast::NumericFor) {
        self.body(loop_.block(), std::iter::once(loop_.index_variable()));
    }

    fn visit_generic_for(&mut self, loop_: &full_moon::ast::GenericFor) {
        self.body(loop_.block(), loop_.names().iter());
    }

    fn visit_local_assignment_end(&mut self, assignment: &full_moon::ast::LocalAssignment) {
        self.declare(assignment.names().iter());
    }

    fn visit_const_assignment_end(&mut self, assignment: &full_moon::ast::luau::ConstAssignment) {
        self.declare(assignment.names().iter());
    }

    fn visit_local_function(&mut self, function: &full_moon::ast::LocalFunction) {
        // Unlike assignment initializers, local functions can refer to themselves.
        self.declare(std::iter::once(function.name()));
    }

    fn visit_assignment(&mut self, assignment: &full_moon::ast::Assignment) {
        for variable in assignment.variables() {
            if let Var::Name(name) = variable {
                self.write(name);
            }
        }
    }

    fn visit_compound_assignment(&mut self, assignment: &full_moon::ast::CompoundAssignment) {
        if let Var::Name(name) = assignment.lhs() {
            self.write(name);
        }
    }

    fn visit_function_declaration(&mut self, function: &full_moon::ast::FunctionDeclaration) {
        if function.name().method_name().is_some() {
            self.body_bindings
                .entry(std::ptr::from_ref(function.body().block()))
                .or_default()
                .insert("self".to_owned());
        } else if function.name().names().len() == 1 {
            self.write(function.name().names().iter().next().unwrap());
        }
    }
}

// Source positions distinguish applications even when their text or binders match.
type ApplicationId = (ModuleId, usize);
type Captures = BTreeSet<(bool, String)>;

struct DefaultTypes<'a> {
    root: &'a Path,
    modules: BTreeMap<ModuleId, TypeModule>,
    required: BTreeSet<AliasId>,
    defaults: BTreeSet<AliasId>,
    applications: BTreeMap<ApplicationId, Captures>,
    application_bodies: BTreeMap<ApplicationId, TypeInfo>,
}

struct DefaultNames {
    aliases: BTreeMap<AliasId, String>,
    defaults: BTreeMap<AliasId, String>,
    applications: BTreeMap<ApplicationId, String>,
}

impl DefaultTypes<'_> {
    fn module(&mut self, id: &ModuleId) -> anyhow::Result<TypeModule> {
        if !self.modules.contains_key(id) {
            let path = import_path(self.root, id)?;
            let entry = resolve_path(self.root, &path, &mut BTreeSet::new())?
                .context("Imported type module has no ModuleScript entrypoint.")?;
            let module = TypeModule::parse(&fs::read_to_string(&entry)?)
                .with_context(|| format!("Cannot read imported types from {}", entry.display()))?;
            self.modules.insert(id.clone(), module);
        }
        Ok(self.modules[id].clone())
    }

    fn imported_alias(
        &mut self,
        id: &ModuleId,
        module: &TypeModule,
        binding: &str,
        name: &str,
        position: usize,
    ) -> anyhow::Result<AliasId> {
        if module.ambiguous.contains(binding)
            || module.bindings.contains_key("require")
            || module.ambiguous.contains("require")
            || module.bindings.contains_key("script")
            || module.ambiguous.contains("script")
        {
            bail!("Ambiguous or shadowed static import binding {binding}.");
        }
        let expression = module
            .bindings
            .get(binding)
            .filter(|(declared, _)| *declared < position)
            .and_then(|(_, expression)| expression.as_ref())
            .with_context(|| {
                format!("Unsupported dynamic, out-of-scope, or runtime import binding {binding}.")
            })?;
        let imported = import_id(self.root, id, expression)?;
        let target = self.module(&imported)?;
        if target.functions.contains(name) {
            bail!("Imported type function {binding}.{name} cannot be forwarded.");
        }
        if !target.exported.contains(name) {
            bail!("Imported type {binding}.{name} is not an exported alias.");
        }
        Ok((imported, name.to_owned()))
    }

    fn rewrite<T: VisitMut>(
        &mut self,
        id: &ModuleId,
        module: &TypeModule,
        node: T,
        names: Option<&DefaultNames>,
    ) -> anyhow::Result<T> {
        let mut validator = DefaultValidator {
            types: self,
            id,
            module,
            scopes: vec![GenericBindings::default()],
            default_depth: 0,
            applications: Vec::new(),
            names,
            error: None,
        };
        let node = node.visit_mut(&mut validator);
        if let Some(error) = validator.error {
            return Err(error);
        }
        Ok(node)
    }
}

/// Resolve children using the same staged entrypoint rules as exports. Never infer
/// script children from a wrapper beside a project redirect or from a plain source
/// file's siblings. Merged inline children are rejected rather than guessed.
fn import_child(root: &Path, path: &Path, child: &str) -> anyhow::Result<PathBuf> {
    resolve_path(root, path, &mut BTreeSet::new())?;
    if path.is_dir() && path.join("default.project.json").is_file() {
        return import_child(root, &path.join("default.project.json"), child);
    }
    if path.to_string_lossy().ends_with(".project.json") {
        let project: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
        let tree = &project["tree"];
        if tree.get(child).is_some() {
            bail!("Ambiguous or unsupported merged inline import mapping for {child}.");
        }
        let target = tree["$path"]
            .as_str()
            .context("Unsupported inline import mapping.")?;
        return import_child(root, &path.parent().unwrap().join(target), child);
    }
    if !path.is_dir() {
        bail!("Source file has no filesystem import child {child}.");
    }
    let directory = path;
    let candidates: Vec<_> = std::iter::once(directory.join(child))
        .chain(module_candidates(directory, child))
        .filter(|path| path.exists())
        .collect();
    match candidates.as_slice() {
        [path] => {
            resolve_path(root, path, &mut BTreeSet::new())?;
            Ok(path.clone())
        }
        [] => bail!("Static import child {child} does not exist in the staged module layout."),
        _ => bail!("Ambiguous static import child {child}."),
    }
}

fn import_path(root: &Path, id: &ModuleId) -> anyhow::Result<PathBuf> {
    let mut path = root.to_path_buf();
    let mut ancestors = BTreeSet::new();
    for child in id {
        let entry =
            resolve_path(root, &path, &mut BTreeSet::new())?.unwrap_or(path.canonicalize()?);
        if !ancestors.insert(entry) {
            bail!("Cyclic static import module layout.");
        }
        path = import_child(root, &path, child)?;
    }
    let entry = resolve_path(root, &path, &mut BTreeSet::new())?.unwrap_or(path.canonicalize()?);
    if ancestors.contains(&entry) {
        bail!("Cyclic static import module layout.");
    }
    Ok(path)
}

fn import_id(root: &Path, id: &ModuleId, expression: &Expression) -> anyhow::Result<ModuleId> {
    let Expression::FunctionCall(call) = expression else {
        bail!("Unsupported dynamic import; expected a static require.");
    };
    if !matches!(call.prefix(), Prefix::Name(name) if syntax(name) == "require") {
        bail!("Unsupported dynamic import; expected a static require.");
    }
    let suffixes: Vec<_> = call.suffixes().collect();
    let [Suffix::Call(Call::AnonymousCall(arguments))] = suffixes.as_slice() else {
        bail!("Unsupported dynamic import call.");
    };
    let argument = match arguments.as_ref() {
        FunctionArgs::Parentheses { arguments, .. } if arguments.len() == 1 => {
            arguments.iter().next().unwrap()
        }
        _ => bail!("Unsupported dynamic import arguments."),
    };
    let mut target = id.clone();
    match argument {
        Expression::Var(Var::Expression(variable)) if matches!(variable.prefix(), Prefix::Name(name) if syntax(name) == "script") =>
        {
            for suffix in variable.suffixes() {
                let Suffix::Index(Index::Dot { name, .. }) = suffix else {
                    bail!("Unsupported dynamic script import path.");
                };
                let child = syntax(name);
                if child == "Parent" {
                    target
                        .pop()
                        .context("Static import escapes the staged package root.")?;
                } else {
                    target.push(child);
                    // Each instance lookup must exist, even when followed by Parent.
                    import_path(root, &target)?;
                }
            }
        }
        Expression::String(token) => {
            let TokenType::StringLiteral { literal, .. } = token.token().token_type() else {
                unreachable!()
            };
            let path = literal.to_string();
            if path.contains('\\') || path.contains('\n') {
                bail!("Escaped static import strings are unsupported.");
            }
            let relative = if let Some(relative) = path.strip_prefix("@self/") {
                relative
            } else if path.starts_with("./") || path.starts_with("../") {
                target
                    .pop()
                    .context("Static import escapes the staged package root.")?;
                path.as_str()
            } else {
                bail!("Unsupported static import path; imports must stay in the staged package.");
            };
            for part in relative.split('/') {
                match part {
                    "." => {}
                    ".." => {
                        target
                            .pop()
                            .context("Static import escapes the staged package root.")?;
                    }
                    "" => bail!("Unsupported empty static import path component."),
                    part => target.push(part.to_owned()),
                }
            }
        }
        _ => bail!("Unsupported dynamic import path."),
    }
    Ok(target)
}

fn declarations(root: &Path, entry: &Path) -> anyhow::Result<ForwardedTypes> {
    let entry_id = Vec::new();
    let entry = TypeModule::parse(&fs::read_to_string(entry)?)?;
    if entry
        .exported
        .iter()
        .any(|name| entry.functions.contains(name))
    {
        bail!("Exported type functions cannot be forwarded by a type alias.");
    }
    let mut types = DefaultTypes {
        root,
        modules: BTreeMap::from([(entry_id.clone(), entry.clone())]),
        required: BTreeSet::new(),
        defaults: BTreeSet::new(),
        applications: BTreeMap::new(),
        application_bodies: BTreeMap::new(),
    };
    // Discover the entire reachable closure before choosing names. Imported aliases
    // can recurse, including across modules; each module/alias pair is visited once.
    for name in &entry.exported {
        let declaration = &entry.aliases[name];
        if let Some(generics) = declaration.generics() {
            types.rewrite(&entry_id, &entry, generics.clone(), None)?;
        }
    }
    let mut copied = BTreeSet::new();
    while let Some(key) = types.required.difference(&copied).next().cloned() {
        let module = types.module(&key.0)?;
        let declaration = &module.aliases[&key.1];
        types
            .rewrite(&key.0, &module, declaration.clone(), None)
            .with_context(|| format!("Cannot forward default dependency {}.", key.1))?;
        copied.insert(key);
    }
    let mut tokens: BTreeSet<_> = types
        .modules
        .values()
        .flat_map(|module| module.tokens.iter().cloned())
        .collect();
    let namespace = fresh_name("__WallyPackage", &mut tokens);
    let names = DefaultNames {
        aliases: copied
            .iter()
            .enumerate()
            .map(|(index, key)| {
                (
                    key.clone(),
                    fresh_name(&format!("__WallyType{index}"), &mut tokens),
                )
            })
            .collect(),
        defaults: types
            .defaults
            .iter()
            .enumerate()
            .map(|(index, key)| {
                (
                    key.clone(),
                    fresh_name(&format!("__WallyDefault{index}"), &mut tokens),
                )
            })
            .collect(),
        applications: types
            .applications
            .keys()
            .enumerate()
            .map(|(index, key)| {
                (
                    key.clone(),
                    fresh_name(
                        &format!("__WallyDefault{}", types.defaults.len() + index),
                        &mut tokens,
                    ),
                )
            })
            .collect(),
    };
    let mut aliases = Vec::new();
    let mut helpers: Vec<_> = copied.iter().collect();
    helpers.sort_by_key(|key| {
        (
            key.0.clone(),
            types.modules[&key.0].aliases[&key.1]
                .start_position()
                .unwrap()
                .bytes(),
        )
    });
    for key in helpers {
        let module = types.module(&key.0)?;
        let declaration = &module.aliases[&key.1];
        let rewritten = types.rewrite(&key.0, &module, declaration.clone(), Some(&names))?;
        let rewritten = rewritten.with_type_name(identifier(&names.aliases[key]));
        aliases.push(format!("{}\n", clean_syntax(rewritten)));
    }
    // Keep public declarations in source order. Only defaults need the copied
    // closure; their actual bodies continue to refer to the runtime namespace.
    let mut exports: Vec<_> = entry.exported.iter().collect();
    exports.sort_by_key(|name| entry.aliases[*name].start_position().unwrap().bytes());
    let mut public_aliases = Vec::new();
    for name in exports {
        let declaration = &entry.aliases[name];
        let mut parameters = String::new();
        let mut arguments = String::new();
        if let Some(generics) = declaration.generics() {
            parameters =
                clean_syntax(types.rewrite(&entry_id, &entry, generics.clone(), Some(&names))?);
            arguments = format!(
                "<{}>",
                generics
                    .generics()
                    .iter()
                    .map(|parameter| syntax(parameter.parameter()))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        public_aliases.push(format!(
            "export type {name}{parameters} = {namespace}.{name}{arguments}\n"
        ));
    }
    // Luau prototypes defaults before checking bodies. Defer instantiation of
    // copied generics, including entire explicit applications, into alias bodies.
    for (key, name) in &names.defaults {
        aliases.push(format!("type {name} = {}\n", names.aliases[key]));
    }
    for (key, name) in &names.applications {
        let parameters = types.applications[key]
            .iter()
            .map(|(pack, name)| format!("{name}{}", if *pack { "..." } else { "" }))
            .collect::<Vec<_>>();
        let parameters = if parameters.is_empty() {
            String::new()
        } else {
            format!("<{}>", parameters.join(", "))
        };
        let body = types
            .application_bodies
            .remove(key)
            .context("Missing deferred default application body.")?;
        aliases.push(format!(
            "type {name}{parameters} = {}\n",
            clean_syntax(body)
        ));
    }
    aliases.extend(public_aliases);
    Ok(ForwardedTypes { namespace, aliases })
}

fn fresh_name(base: &str, tokens: &mut BTreeSet<String>) -> String {
    let mut name = base.to_owned();
    while !tokens.insert(name.clone()) {
        name.push('_');
    }
    name
}

fn identifier(name: &str) -> TokenReference {
    TokenReference::new(
        Vec::new(),
        Token::new(TokenType::Identifier {
            identifier: name.into(),
        }),
        Vec::new(),
    )
}

// AST display preserves delimiter order after replacing nodes. Strip trivia by
// visiting tokens, since replacement tokens have no original source positions.
fn clean_syntax<T: VisitMut + std::fmt::Display>(node: T) -> String {
    struct Trivia;
    impl VisitorMut for Trivia {
        fn visit_token_reference(&mut self, token: TokenReference) -> TokenReference {
            TokenReference::new(
                Vec::new(),
                token.token().clone(),
                vec![Token::new(TokenType::spaces(1))],
            )
        }
    }
    node.visit_mut(&mut Trivia).to_string().trim().to_owned()
}

#[derive(Default)]
struct GenericBindings {
    types: BTreeSet<String>,
    packs: BTreeSet<String>,
}

impl GenericBindings {
    fn declare(&mut self, parameter: &GenericParameterInfo) {
        match parameter {
            GenericParameterInfo::Name(name) => {
                self.types.insert(syntax(name));
            }
            GenericParameterInfo::Variadic { name, .. } => {
                self.packs.insert(syntax(name));
            }
            _ => {}
        }
    }
}

/// Collect and then rewrite only type-reference nodes. Field names, string types,
/// declaration binders, and callback/pack binders are never textually substituted.
struct DefaultValidator<'a, 'root> {
    types: &'a mut DefaultTypes<'root>,
    id: &'a ModuleId,
    module: &'a TypeModule,
    scopes: Vec<GenericBindings>,
    default_depth: usize,
    applications: Vec<Option<(ApplicationId, AliasId)>>,
    names: Option<&'a DefaultNames>,
    error: Option<anyhow::Error>,
}

impl DefaultValidator<'_, '_> {
    fn bound(&self, name: &str, pack: bool) -> bool {
        self.scopes.iter().any(|scope| {
            if pack {
                scope.packs.contains(name)
            } else {
                scope.types.contains(name)
            }
        })
    }

    fn reference(&mut self, key: AliasId, bare: bool) -> Option<TokenReference> {
        self.types.required.insert(key.clone());
        let defaulted = bare
            && self.types.modules[&key.0].aliases[&key.1]
                .generics()
                .is_some();
        if defaulted {
            self.types.defaults.insert(key.clone());
        }
        self.names.map(|names| {
            identifier(if defaulted {
                &names.defaults[&key]
            } else {
                &names.aliases[&key]
            })
        })
    }

    fn rewrite_info(&mut self, mut info: TypeInfo) -> anyhow::Result<(TypeInfo, Option<AliasId>)> {
        let mut dependency = None;
        let pack = matches!(info, TypeInfo::GenericPack { .. });
        let bare = matches!(info, TypeInfo::Basic(_));
        match &mut info {
            TypeInfo::Basic(token)
            | TypeInfo::Generic { base: token, .. }
            | TypeInfo::GenericPack { name: token, .. } => {
                let name = syntax(token);
                if !self.bound(&name, pack) {
                    if self.module.functions.contains(&name) {
                        bail!("Type function {name} cannot be forwarded.");
                    }
                    if self.module.aliases.contains_key(&name) {
                        // Entry exports already have public forwarding aliases. Their
                        // bodies need not be closed or copied just to name a default.
                        if !(self.id.is_empty() && self.module.exported.contains(&name)) {
                            let key = (self.id.clone(), name);
                            if let Some(replacement) = self.reference(key.clone(), bare) {
                                *token = replacement;
                            }
                            dependency = Some(key);
                        }
                    } else if !self.id.is_empty()
                        && self.types.modules[&ModuleId::new()]
                            .exported
                            .contains(&name)
                    {
                        bail!("Free imported type {name} would be captured by entrypoint export {name}; rename the entrypoint export or bind the type explicitly in its source module.");
                    }
                }
            }
            TypeInfo::Module {
                module, type_info, ..
            } => {
                let binding = syntax(module);
                let name = match type_info.as_ref() {
                    IndexedTypeInfo::Basic(name) | IndexedTypeInfo::Generic { base: name, .. } => {
                        syntax(name)
                    }
                    _ => bail!("Unsupported imported type reference."),
                };
                let key = self.types.imported_alias(
                    self.id,
                    self.module,
                    &binding,
                    &name,
                    module.start_position().unwrap().bytes(),
                )?;
                if let Some(replacement) = self.reference(
                    key.clone(),
                    matches!(type_info.as_ref(), IndexedTypeInfo::Basic(_)),
                ) {
                    info = match *type_info.clone() {
                        IndexedTypeInfo::Basic(_) => TypeInfo::Basic(replacement),
                        IndexedTypeInfo::Generic {
                            arrows, generics, ..
                        } => TypeInfo::Generic {
                            base: replacement,
                            arrows,
                            generics,
                        },
                        _ => unreachable!(),
                    };
                }
                dependency = Some(key);
            }
            TypeInfo::Typeof { .. } => {
                bail!("typeof defaults depend on runtime code and cannot be forwarded.")
            }
            _ => {}
        }
        Ok((info, dependency))
    }

    fn defer_application(
        &mut self,
        key: ApplicationId,
        target: AliasId,
        mut info: TypeInfo,
    ) -> anyhow::Result<TypeInfo> {
        // Validate pack grouping during discovery, before generating any output.
        normalize_application(&mut info, &self.types.modules[&target.0].aliases[&target.1])?;
        let Some(names) = self.names else {
            let mut captures = CaptureReferences {
                available: self
                    .scopes
                    .iter()
                    .flat_map(|scope| {
                        scope
                            .types
                            .iter()
                            .map(|name| (false, name.clone()))
                            .chain(scope.packs.iter().map(|name| (true, name.clone())))
                    })
                    .collect(),
                scopes: vec![GenericBindings::default()],
                used: BTreeSet::new(),
            };
            info.visit(&mut captures);
            for (pack, name) in &captures.used {
                if captures.used.contains(&(!pack, name.clone())) {
                    bail!("Cannot defer generic default application capturing both type {name} and pack {name}...; use distinct type and pack binder names in the source.");
                }
                if self.scopes.iter().skip(1).any(|scope| {
                    if *pack {
                        scope.packs.contains(name)
                    } else {
                        scope.types.contains(name)
                    }
                }) {
                    bail!("Cannot defer generic default application capturing callback-local generic {name}; move the application outside the generic callback or into a named source alias. The legacy analyzer cannot instantiate this helper inside a generic callback default.");
                }
            }
            self.types.applications.insert(key, captures.used);
            return Ok(info);
        };
        // Introduce fresh helper binders with the original spellings. The legacy
        // analyzer requires matching names when instantiating these in defaults;
        // alpha-renaming them incorrectly reports recursive type instantiation.
        let name = &names.applications[&key];
        let arguments = self.types.applications[&key]
            .iter()
            .map(|(pack, name)| {
                if *pack {
                    TypeInfo::GenericPack {
                        name: identifier(name),
                        ellipsis: TokenReference::symbol("...").unwrap(),
                    }
                } else {
                    TypeInfo::Basic(identifier(name))
                }
            })
            .collect::<Vec<_>>();
        self.types.application_bodies.insert(key, info);
        Ok(if arguments.is_empty() {
            TypeInfo::Basic(identifier(name))
        } else {
            TypeInfo::Generic {
                base: identifier(name),
                arrows: delimiters("<", ">"),
                generics: punctuated(arguments),
            }
        })
    }
}

impl VisitorMut for DefaultValidator<'_, '_> {
    fn visit_generic_declaration_parameter(
        &mut self,
        parameter: GenericDeclarationParameter,
    ) -> GenericDeclarationParameter {
        if parameter.default_type().is_some() {
            self.default_depth += 1;
        }
        parameter
    }

    fn visit_generic_declaration_parameter_end(
        &mut self,
        parameter: GenericDeclarationParameter,
    ) -> GenericDeclarationParameter {
        if parameter.default_type().is_some() {
            self.default_depth -= 1;
        }
        // Luau resolves a default before introducing its own binder. Visiting in
        // AST order also leaves later parameters out of scope until their turn.
        self.scopes
            .last_mut()
            .unwrap()
            .declare(parameter.parameter());
        parameter
    }

    fn visit_type_info(&mut self, info: TypeInfo) -> TypeInfo {
        if matches!(info, TypeInfo::Callback { .. }) {
            self.scopes.push(GenericBindings::default());
        }
        let explicit = matches!(&info, TypeInfo::Generic { .. })
            || matches!(&info, TypeInfo::Module { type_info, .. }
                if matches!(type_info.as_ref(), IndexedTypeInfo::Generic { .. }));
        match self.rewrite_info(info.clone()) {
            Ok((rewritten, dependency)) => {
                let application = dependency
                    .filter(|_| explicit && self.default_depth > 0)
                    .map(|target| {
                        (
                            (self.id.clone(), info.start_position().unwrap().bytes()),
                            target,
                        )
                    });
                self.applications.push(application);
                rewritten
            }
            Err(error) => {
                self.applications.push(None);
                if self.error.is_none() {
                    self.error = Some(error);
                }
                info
            }
        }
    }

    fn visit_type_info_end(&mut self, mut info: TypeInfo) -> TypeInfo {
        if let Some((key, target)) = self.applications.pop().unwrap() {
            match self.defer_application(key, target, info.clone()) {
                Ok(rewritten) => info = rewritten,
                Err(error) => {
                    if self.error.is_none() {
                        self.error = Some(error);
                    }
                }
            }
        }
        if matches!(info, TypeInfo::Callback { .. }) {
            self.scopes.pop();
        }
        info
    }
}

fn delimiters(open: &str, close: &str) -> ContainedSpan {
    ContainedSpan::new(
        TokenReference::symbol(open).unwrap(),
        TokenReference::symbol(close).unwrap(),
    )
}

fn punctuated(items: Vec<TypeInfo>) -> Punctuated<TypeInfo> {
    let len = items.len();
    items
        .into_iter()
        .enumerate()
        .map(|(index, item)| {
            Pair::new(
                item,
                (index + 1 < len).then(|| TokenReference::symbol(",").unwrap()),
            )
        })
        .collect()
}

/// Only the sole trailing target pack has an unambiguous flattening rule. A tuple
/// supplies that pack as one argument to the legacy analyzer in a helper body.
fn normalize_application(info: &mut TypeInfo, target: &TypeDeclaration) -> anyhow::Result<()> {
    let arguments = match info {
        TypeInfo::Generic { generics, .. } => generics,
        TypeInfo::Module { type_info, .. } => match type_info.as_mut() {
            IndexedTypeInfo::Generic { generics, .. } => generics,
            _ => return Ok(()),
        },
        _ => return Ok(()),
    };
    let Some(parameters) = target.generics() else {
        return Ok(());
    };
    let parameters: Vec<_> = parameters.generics().iter().collect();
    let fixed = parameters
        .iter()
        .take_while(|parameter| matches!(parameter.parameter(), GenericParameterInfo::Name(_)))
        .count();
    let packs = parameters.len() - fixed;
    if packs == 0 || arguments.len() <= fixed {
        return Ok(());
    }
    let mut items: Vec<_> = arguments.iter().cloned().collect();
    let is_pack = |info: &TypeInfo| {
        matches!(
            info,
            TypeInfo::GenericPack { .. }
                | TypeInfo::Tuple { .. }
                | TypeInfo::Variadic { .. }
                | TypeInfo::VariadicPack { .. }
        )
    };
    let tail = &items[fixed..];
    if items[..fixed].iter().any(is_pack)
        || (packs > 1 && (tail.len() > packs || tail.iter().any(|info| !is_pack(info))))
        || (packs == 1 && tail[..tail.len() - 1].iter().any(is_pack))
    {
        bail!("Cannot defer generic default application of {} with ambiguous type-pack arguments; use one explicit tuple per target pack, or a named source alias for the application.", syntax(target.type_name()));
    }
    if packs == 1 && tail.len() > 1 {
        let tail = items.split_off(fixed);
        items.push(TypeInfo::Tuple {
            parentheses: delimiters("(", ")"),
            types: punctuated(tail),
        });
        *arguments = punctuated(items);
    }
    Ok(())
}

/// Find only free references to binders visible at an application. Traversing
/// callback declarations in order also handles same-name nested scopes.
struct CaptureReferences {
    available: Captures,
    scopes: Vec<GenericBindings>,
    used: Captures,
}

impl Visitor for CaptureReferences {
    fn visit_generic_declaration_parameter_end(&mut self, parameter: &GenericDeclarationParameter) {
        self.scopes
            .last_mut()
            .unwrap()
            .declare(parameter.parameter());
    }

    fn visit_type_info(&mut self, info: &TypeInfo) {
        if matches!(info, TypeInfo::Callback { .. }) {
            self.scopes.push(GenericBindings::default());
        }
        let pack = matches!(info, TypeInfo::GenericPack { .. });
        let token = match info {
            TypeInfo::Basic(token)
            | TypeInfo::Generic { base: token, .. }
            | TypeInfo::VariadicPack { name: token, .. }
            | TypeInfo::GenericPack { name: token, .. } => token,
            _ => return,
        };
        let name = syntax(token);
        let key = (pack, name.clone());
        let local = self.scopes.iter().any(|scope| {
            if pack {
                scope.packs.contains(&name)
            } else {
                scope.types.contains(&name)
            }
        });
        if !local && self.available.contains(&key) {
            self.used.insert(key);
        }
    }

    fn visit_type_info_end(&mut self, info: &TypeInfo) {
        if matches!(info, TypeInfo::Callback { .. }) {
            self.scopes.pop();
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

    fn declarations(source: &str) -> anyhow::Result<ForwardedTypes> {
        let temp = TempDir::new().unwrap();
        write(temp.path(), "init.luau", source);
        exports(temp.path())
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
        let types =
            declarations("export type Box<T -- a comment\n, P...> = (T, P...) -> ()\nreturn {} ")
                .unwrap();
        let output = forward("return require(\"./target\")\n".into(), &types);
        assert!(!output.contains("comment"));
        assert!(full_moon::parse(&output).is_ok(), "{}", output);
        let old = "type Package = typeof(require(game.Packages.Foo))\nreturn require(game.Packages.Foo) :: Package\n";
        assert_eq!(forward(old.into(), &ForwardedTypes::default()), old);
        assert!(declarations("type Private = string\nreturn {}")
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
        assert!(
            output.contains("type __WallyType1 = string\n"),
            "{}",
            output
        );
        assert!(
            output.contains("type __WallyType0 < T = __WallyType1 >"),
            "{}",
            output
        );
        assert!(!output.contains("Imported"));
        assert_eq!(output.matches("export type ").count(), 2);
        assert!(full_moon::parse(&output).is_ok(), "{}", output);
    }

    fn generated(root: &Path) -> String {
        let output = forward(
            "return require(\"./target\")\n".into(),
            &exports(root).unwrap(),
        );
        full_moon::parse(&output).unwrap();
        assert_eq!(output.matches("require(").count(), 1, "{}", output);
        output
    }

    #[test]
    fn entry_export_defaults_keep_existing_public_aliases_without_copying_runtime_bodies() {
        let output = forward("return require(\"./target\")\n".into(), &declarations(
            "local value = {}\nexport type Value = typeof(value)\ntype Private = Value\nexport type Box<T = Value, U = Private> = { Value: T, Other: U }\nreturn {}"
        ).unwrap());
        assert!(
            output.contains("export type Box< T = Value , U = __WallyType0 >"),
            "{}",
            output
        );
        assert!(output.contains("type __WallyType0 = Value"), "{}", output);
        assert!(!output.contains("typeof"), "{}", output);
        full_moon::parse(&output).unwrap();
    }

    #[test]
    fn imported_generic_arguments_and_callback_pack_binders_are_rewritten_structurally() {
        let temp = TempDir::new().unwrap();
        write(temp.path(), "init.luau", "local Types = require(script.Types)\nexport type Box<T = Types.Value<Types.Leaf>, P... = ...Types.Leaf> = (T, P...) -> ()\nreturn {}");
        write(temp.path(), "Types.luau", "type P = typeof(runtime)\nexport type Leaf = string\nexport type Value<T, __WallyPackage = T> = { Value: T, Call: <P...>(P...) -> P..., Literal: \"Leaf\" }\nreturn nil");
        let output = generated(temp.path());
        assert!(
            output.contains("local __WallyPackage_ = require"),
            "{}",
            output
        );
        assert!(
            output.contains("T = __WallyDefault0 , P ... = ... __WallyType0"),
            "{}",
            output
        );
        assert!(
            output.contains("Call : < P ... > ( P ... ) -> P ..."),
            "{}",
            output
        );
        assert!(output.contains("Literal : \"Leaf\""), "{}", output);
        assert!(!output.contains("typeof"), "{}", output);
    }

    #[test]
    fn generic_defaults_resolve_self_and_later_names_before_binding_them() {
        let output = forward(
            "return require(\"./target\")\n".into(),
            &declarations("type T = string\ntype U = number\nexport type Box<T = T, U = U, V = T> = { First: T, Second: U, Third: V }\nreturn {}").unwrap(),
        );
        assert!(output.contains("type __WallyType0 = string"), "{}", output);
        assert!(output.contains("type __WallyType1 = number"), "{}", output);
        assert!(
            output.contains("export type Box< T = __WallyType0 , U = __WallyType1 , V = T >"),
            "{}",
            output
        );

        let temp = TempDir::new().unwrap();
        write(temp.path(), "init.luau", "local Types = require(\"@self/Types\")\nexport type T = boolean\nexport type Box<U = Types.Value> = U\nreturn {}");
        write(
            temp.path(),
            "Types.luau",
            "type T = string\nexport type Value<T = T> = { Value: T }\nreturn nil",
        );
        let output = generated(temp.path());
        assert!(output.contains("type __WallyType0 = string"), "{}", output);
        assert!(
            output.contains("type __WallyType1 < T = __WallyType0 > = { Value : T }"),
            "{}",
            output
        );

        write(temp.path(), "Types.luau", "type Later = number\nexport type Value<T = Later, Later = T> = { First: T, Second: Later }\nreturn nil");
        let output = generated(temp.path());
        assert!(output.contains("type __WallyType0 = number"), "{}", output);
        assert!(output.contains("type __WallyType1 < T = __WallyType0 , Later = T > = { First : T , Second : Later }"), "{}", output);
        assert!(
            output.contains("type __WallyDefault0 = __WallyType1"),
            "{}",
            output
        );
        assert!(
            output.contains("export type Box< U = __WallyDefault0 >"),
            "{}",
            output
        );
    }

    #[test]
    fn omitted_and_explicit_generic_defaults_use_distinct_fresh_deferred_aliases() {
        let temp = TempDir::new().unwrap();
        write(temp.path(), "init.luau", "local Types = require(script.Types)\nexport type Box<T = Types.Value, U = Types.Value<string>, __WallyDefault0 = Types.Value> = { First: T, Second: U }\nreturn {}");
        write(
            temp.path(),
            "Types.luau",
            "export type Value<T = number> = { Value: T }\nreturn nil",
        );
        let output = generated(temp.path());
        assert!(
            output.contains("type __WallyType0 < T = number > = { Value : T }"),
            "{}",
            output
        );
        assert!(
            output.contains("type __WallyDefault0_ = __WallyType0"),
            "{}",
            output
        );
        assert!(
            output.contains("type __WallyDefault1 = __WallyType0 < string >"),
            "{}",
            output
        );
        assert!(
            output.contains(
                "T = __WallyDefault0_ , U = __WallyDefault1 , __WallyDefault0 = __WallyDefault0_"
            ),
            "{}",
            output
        );
        assert_eq!(
            output.matches("type __WallyDefault").count(),
            2,
            "{}",
            output
        );
        assert_eq!(generated(temp.path()), output);
    }

    fn application_output(entry: &str, imported: &str) -> String {
        let temp = TempDir::new().unwrap();
        write(
            temp.path(),
            "init.luau",
            &format!("local Types = require(script.Types)\n{entry}\nreturn {{}}"),
        );
        write(
            temp.path(),
            "Types.luau",
            &format!("{imported}\nreturn nil"),
        );
        let output = generated(temp.path());
        assert_eq!(generated(temp.path()), output);
        output
    }

    #[test]
    fn closed_explicit_default_defers_the_entire_application() {
        let output = application_output(
            "export type Box<T = Types.Value<string>> = T",
            "export type Value<T> = { Value: T }",
        );
        assert!(
            output.contains("type __WallyDefault0 = __WallyType0 < string >"),
            "{}",
            output
        );
        assert!(
            output.contains("export type Box< T = __WallyDefault0 >"),
            "{}",
            output
        );
    }

    #[test]
    fn compound_earlier_type_capture_is_a_generic_helper_not_a_global() {
        let output = application_output(
            "export type Box<T = string, U = Types.Value<{ Inner: T }>> = U",
            "export type Value<T> = { Value: T }",
        );
        assert!(
            output.contains("type __WallyDefault0<T> = __WallyType0 < { Inner : T } >"),
            "{}",
            output
        );
        assert!(
            output.contains("T = string , U = __WallyDefault0 < T >"),
            "{}",
            output
        );
    }

    #[test]
    fn mixed_earlier_pack_capture_groups_the_sole_target_pack() {
        let output = application_output(
            "export type Box<P... = (string, number), Q... = (Types.Value<boolean, P...>)> = (Q...) -> Q...",
            "export type Value<P...> = (P...) -> P...",
        );
        assert!(
            output.contains("type __WallyDefault0<P...> = __WallyType0 < ( boolean , P ... ) >"),
            "{}",
            output
        );
        assert!(
            output.contains("Q ... = ( __WallyDefault0 < P ... > )"),
            "{}",
            output
        );
        let output = application_output(
            "export type Box<T = string, P... = (number), Q... = (Types.Value<T, boolean, P...>)> = (Q...) -> ()",
            "export type Value<T, P...> = { Item: T, Call: (P...) -> () }",
        );
        assert!(
            output.contains("__WallyType0 < T , ( boolean , P ... ) >"),
            "{}",
            output
        );
        assert!(
            output.contains("Q ... = ( __WallyDefault0 < T , P ... > )"),
            "{}",
            output
        );
    }

    #[test]
    fn nested_applications_defer_children_before_building_the_parent_body() {
        let output = application_output(
            "export type Box<T = string, U = Types.Value<Types.Value<{ Inner: T }>>> = U",
            "export type Value<T> = { Value: T }",
        );
        assert!(
            output.contains("type __WallyDefault0<T> = __WallyType0 < __WallyDefault1 < T > >"),
            "{}",
            output
        );
        assert!(
            output.contains("type __WallyDefault1<T> = __WallyType0 < { Inner : T } >"),
            "{}",
            output
        );
        assert!(output.contains("U = __WallyDefault0 < T >"), "{}", output);
    }

    #[test]
    fn application_captures_avoid_tokens_and_preserve_callback_shadowing() {
        let output = application_output(
            "type __WallyDefault0 = string\nexport type Box<T = string, U = Types.Value<{ Outer: T, Call: <T>(T) -> T, Pack: <T...>(T, T...) -> T }>> = U",
            "type __WallyDefault0_ = number\nexport type Value<T> = { Value: T }",
        );
        assert!(output.contains("type __WallyDefault0__<T>"), "{}", output);
        assert!(
            output.contains(
                "Outer : T , Call : < T > ( T ) -> T , Pack : < T ... > ( T , T ... ) -> T"
            ),
            "{}",
            output
        );
        assert!(output.contains("U = __WallyDefault0__ < T >"), "{}", output);
        let output = application_output(
            "export type Box<T = <T>(Types.Value<string>, <T>(Types.Value<number>) -> T) -> T> = T",
            "export type Value<T> = { Value: T }",
        );
        assert!(
            output.contains("< T > ( __WallyDefault0 , < T > ( __WallyDefault1 ) -> T ) -> T"),
            "{}",
            output
        );
        assert_eq!(output.matches("type __WallyDefault").count(), 2);
        let output = application_output(
            "export type Box<T = string, U = <P...>(Types.Value<T>, P...) -> T> = U",
            "export type Value<T> = { Value: T }",
        );
        assert!(
            output.contains("type __WallyDefault0<T> = __WallyType0 < T >"),
            "{}",
            output
        );
        assert!(
            output.contains("< P ... > ( __WallyDefault0 < T > , P ... ) -> T"),
            "{}",
            output
        );
    }

    #[test]
    fn application_captures_keep_type_and_pack_namespaces_separate() {
        let output = application_output(
            "export type Box<T = string, P... = (number), Q... = (Types.Value<T, P...>)> = (Q...) -> ()",
            "export type Value<T, P...> = { Item: T, Call: (P...) -> () }",
        );
        assert!(
            output.contains("type __WallyDefault0<T, P...> = __WallyType0 < T , P ... >"),
            "{}",
            output
        );
        assert!(
            output.contains("Q ... = ( __WallyDefault0 < T , P ... > )"),
            "{}",
            output
        );
    }

    #[test]
    fn explicit_deferral_preserves_recursive_bodies_and_real_multiple_packs() {
        let output = application_output(
            "export type Box<T = Types.Value<string>> = T",
            "type Inner<T> = { Item: T }\nexport type Value<T, U = Inner<T>> = { Item: T, Other: U, Next: Value<T, U>? }",
        );
        assert!(output.contains("U = __WallyDefault1 < T >"), "{}", output);
        assert!(
            output.contains("Next : __WallyType1 < T , U > ?"),
            "{}",
            output
        );
        assert_eq!(output.matches("type __WallyDefault").count(), 2);
        let output = application_output(
            "export type Box<T = Types.Value<(string), (number)>> = T",
            "export type Value<P..., Q...> = { First: (P...) -> (), Second: (Q...) -> () }",
        );
        assert!(
            output.contains("type __WallyDefault0 = __WallyType0 < ( string ) , ( number ) >"),
            "{}",
            output
        );
        let output = application_output(
            "export type Box<T = Types.Value<(string)>> = T",
            "export type Value<P..., Q... = (number)> = { First: (P...) -> (), Second: (Q...) -> () }",
        );
        assert!(output.contains("Q ... = ( number )"), "{}", output);
        assert!(
            output.contains("type __WallyDefault0 = __WallyType0 < ( string ) >"),
            "{}",
            output
        );
    }

    #[test]
    fn rejects_captures_the_legacy_analyzer_cannot_instantiate_safely() {
        for (entry, message) in [
            (
                "export type Box<T = <T>(Types.Value<T>) -> T> = T",
                "capturing callback-local generic T",
            ),
            (
                "export type Box<T = string, U = <P...>(Types.Fixed<T, P...>) -> T> = U",
                "capturing callback-local generic P",
            ),
            (
                "export type Box<T = string, U = <T...>(Types.Fixed<T, T...>) -> T> = U",
                "use distinct type and pack binder names",
            ),
            (
                "export type Box<T = <T>(<T>(Types.Value<T>) -> T) -> T> = T",
                "capturing callback-local generic T",
            ),
        ] {
            let temp = TempDir::new().unwrap();
            write(
                temp.path(),
                "init.luau",
                &format!("local Types = require(script.Types)\n{entry}\nreturn {{}}"),
            );
            write(temp.path(), "Types.luau", "export type Value<T> = { Value: T }\nexport type Fixed<T, P...> = { Item: T, Call: (P...) -> () }\nreturn nil");
            let error = format!("{:#}", exports(temp.path()).err().expect(entry));
            assert!(error.contains(message), "{}", error);
        }
    }

    #[test]
    fn rejects_ambiguous_pack_shapes_in_deferred_applications() {
        for (entry, imported) in [
            (
                "export type Box<P..., Q... = (Types.Value<P..., P...>)> = (Q...) -> ()",
                "export type Value<P...> = (P...) -> ()",
            ),
            (
                "export type Box<T = Types.Value<string, number, boolean>> = T",
                "export type Value<P..., Q...> = { First: (P...) -> (), Second: (Q...) -> () }",
            ),
        ] {
            let temp = TempDir::new().unwrap();
            write(
                temp.path(),
                "init.luau",
                &format!("local Types = require(script.Types)\n{entry}\nreturn {{}}"),
            );
            write(
                temp.path(),
                "Types.luau",
                &format!("{imported}\nreturn nil"),
            );
            let error = format!("{:#}", exports(temp.path()).err().expect(entry));
            assert!(error.contains("ambiguous type-pack arguments"), "{}", error);
            assert!(
                error.contains("one explicit tuple per target pack"),
                "{}",
                error
            );
        }
    }

    #[test]
    fn pack_binders_do_not_hide_type_aliases_or_outer_type_parameters() {
        let temp = TempDir::new().unwrap();
        write(temp.path(), "init.luau", "local Types = require(script.Types)\nexport type Box<T = Types.Value<number>> = T\nreturn {}");
        write(temp.path(), "Types.luau", "type P = string\nexport type Value<T, P... = (P)> = { Bare: P, Bound: T, Call: (P...) -> T, Nested: <T...>(T, T...) -> (P, T...) }\nreturn nil");
        let output = generated(temp.path());
        assert!(output.contains("type __WallyType0 = string"), "{}", output);
        assert!(
            output.contains("type __WallyType1 < T , P ... = ( __WallyType0 ) >"),
            "{}",
            output
        );
        assert!(
            output.contains("Bare : __WallyType0 , Bound : T , Call : ( P ... ) -> T"),
            "{}",
            output
        );
        assert!(
            output.contains("Nested : < T ... > ( T , T ... ) -> ( __WallyType0 , T ... )"),
            "{}",
            output
        );
    }

    #[test]
    fn nested_callback_bindings_are_separate_and_do_not_escape_their_scope() {
        let temp = TempDir::new().unwrap();
        write(
            temp.path(),
            "init.luau",
            "local Types = require(script.Types)\nexport type Box<T = Types.Value> = T\nreturn {}",
        );
        write(temp.path(), "Types.luau", "type P = number\ntype T = string\nexport type Value = { Call: <T>(T, <P...>(P, T, P...) -> T) -> T, After: T, Other: <P...>(P, P...) -> P }\nreturn nil");
        let output = generated(temp.path());
        assert!(output.contains("type __WallyType0 = number"), "{}", output);
        assert!(output.contains("type __WallyType1 = string"), "{}", output);
        assert!(
            output
                .contains("Call : < T > ( T , < P ... > ( __WallyType0 , T , P ... ) -> T ) -> T"),
            "{}",
            output
        );
        assert!(
            output.contains(
                "After : __WallyType1 , Other : < P ... > ( __WallyType0 , P ... ) -> __WallyType0"
            ),
            "{}",
            output
        );
    }

    #[test]
    fn rejects_free_imported_types_captured_by_entrypoint_exports() {
        for declaration in [
            "export type Value = Vector3",
            "local Vector3 = {}\nexport type Value = { Value: Vector3 }",
            "export type Value<Vector3 = Vector3> = Vector3",
            "export type Value<T = Vector3, Vector3 = T> = T",
            "export type Value = <Vector3...>(Vector3, Vector3...) -> ()",
            "export type Value = <T>(T, <Vector3...>(Vector3) -> T) -> T",
            "export type Value = Vector3<number>",
        ] {
            let temp = TempDir::new().unwrap();
            write(temp.path(), "init.luau", "local Types = require(script.Types)\nexport type Vector3 = string\nexport type Box<T = Types.Value> = T\nreturn {}");
            write(
                temp.path(),
                "Types.luau",
                &format!("{declaration}\nreturn nil"),
            );
            let error = format!("{:#}", exports(temp.path()).err().expect(declaration));
            assert!(
                error.contains(
                    "Free imported type Vector3 would be captured by entrypoint export Vector3"
                ),
                "{}\n{}",
                declaration,
                error
            );
            assert!(error.contains("rename the entrypoint export"), "{}", error);
        }
    }

    #[test]
    fn imported_aliases_and_bound_generics_precede_global_capture_checks() {
        for declaration in [
            "type Vector3 = number\nexport type Value = Vector3",
            "export type Vector3 = number\nexport type Value = Vector3",
            "export type Value<Vector3 = number, T = Vector3> = { Value: Vector3, Other: T }",
            "export type Value = <Vector3>(Vector3) -> Vector3",
            "export type Value<Vector3...> = (Vector3...) -> Vector3...",
            "export type Value = <Vector3...>(Vector3...) -> Vector3...",
            "type Vector3 = number\nexport type Value<Vector3 = Vector3> = Vector3",
            "type Unreachable = Vector3\nexport type Value = number",
        ] {
            let temp = TempDir::new().unwrap();
            write(temp.path(), "init.luau", "local Types = require(script.Types)\nexport type Vector3 = string\nexport type Box<T = Types.Value> = T\nreturn {}");
            write(
                temp.path(),
                "Types.luau",
                &format!("{declaration}\nreturn nil"),
            );
            generated(temp.path());
        }
        let temp = TempDir::new().unwrap();
        write(temp.path(), "init.luau", "local Types = require(script.Types)\ntype Vector3 = string\nexport type Box<T = Types.Value> = T\nreturn {}");
        write(
            temp.path(),
            "Types.luau",
            "export type Value = Vector3\nreturn nil",
        );
        let output = generated(temp.path());
        assert!(output.contains("type __WallyType0 = Vector3"), "{}", output);
        assert!(!output.contains("= string"), "{}", output);
    }

    #[test]
    fn generic_type_binders_do_not_shadow_qualified_value_import_namespaces() {
        for parameter in [
            "Types, T = Types.Value",
            "T = <Types>(Types.Value, Types) -> Types",
            "T = <Types...>(Types.Value, Types...) -> Types...",
        ] {
            let temp = TempDir::new().unwrap();
            write(temp.path(), "init.luau", &format!("local Types = require(script.Types)\nexport type Box<{parameter}> = T\nreturn {{}}"));
            write(temp.path(), "Types.luau", "local Inner = require(\"./Inner\")\nexport type Value<Inner = number, T = Inner.Value> = { Value: T, Other: Inner }\nreturn nil");
            write(
                temp.path(),
                "Inner.luau",
                "export type Value = string\nreturn nil",
            );
            let output = generated(temp.path());
            assert!(output.contains("type __WallyType0 = string"), "{}", output);
            assert!(
                output.contains("type __WallyType1 < Inner = number , T = __WallyType0 >"),
                "{}",
                output
            );
        }
        for binding in [
            "local Types = runtime",
            "local Types = require(script.Types)\nTypes = {}",
            "local Types = require(\"../outside\")",
            "do local Types = require(script.Types) end",
            "",
        ] {
            let temp = TempDir::new().unwrap();
            write(
                temp.path(),
                "init.luau",
                &format!("{binding}\nexport type Box<Types, T = Types.Value> = T\nreturn {{}}"),
            );
            write(
                temp.path(),
                "Types.luau",
                "export type Value = string\nreturn nil",
            );
            assert!(exports(temp.path()).is_err(), "{}", binding);
        }
        let temp = TempDir::new().unwrap();
        write(temp.path(), "init.luau", "export type Box<Types, T = Types.Value> = T\nlocal Types = require(script.Types)\nreturn {}");
        write(
            temp.path(),
            "Types.luau",
            "export type Value = string\nreturn nil",
        );
        assert!(exports(temp.path()).is_err());
    }

    #[test]
    fn fusion_like_imported_default_carries_the_exact_recursive_type_closure() {
        let temp = TempDir::new().unwrap();
        write(temp.path(), "init.luau", "local Types = require(script.Types)\ntype Fusion = Types.Fusion\nexport type Scope<Constructors = Fusion> = Types.Scope<Constructors>\nreturn {}");
        write(temp.path(), "Types.luau", "type Task = () -> ()\nexport type Scope<Constructors = any> = {Task} & Constructors\ntype Constructor = <T>(Scope<unknown>, T) -> T\nexport type Fusion = { Value: Constructor, Next: Fusion? }\ntype Unreachable = typeof(runtime)\nreturn nil");
        let output = generated(temp.path());
        assert!(
            output.contains("export type Scope< Constructors = __WallyType0 >"),
            "{}",
            output
        );
        assert!(
            output.contains("type __WallyType0 = __WallyType2"),
            "{}",
            output
        );
        assert!(
            output.contains("type __WallyType2 = { Value : __WallyType1 , Next : __WallyType2 ? }"),
            "{}",
            output
        );
        assert!(
            output.contains(
                "type __WallyType3 < Constructors = any > = { __WallyType4 } & Constructors"
            ),
            "{}",
            output
        );
        assert!(
            output.contains("type __WallyType4 = ( ) -> ( )"),
            "{}",
            output
        );
        assert_eq!(output.matches("export type ").count(), 1);
        // Preserve the source's one explicit any default; introduce no widening.
        assert_eq!(output.matches("any").count(), 1, "{}", output);
        for forbidden in ["Types .", "typeof", "Unreachable"] {
            assert!(!output.contains(forbidden), "{}", output);
        }
        assert_eq!(generated(temp.path()), output);
    }

    #[test]
    fn imported_aliases_recurse_across_modules_and_preserve_defaults_and_packs() {
        let temp = TempDir::new().unwrap();
        write(temp.path(), "init.luau", "const A = require(script.A)\nexport type Box<T = A.Node, P... = (A.Node, string)> = (T, P...) -> ()\nreturn {}");
        write(temp.path(), "A.luau", "local B = require(\"./B\")\ntype Leaf = number\nexport type Node<T = Leaf, P... = ...Leaf> = { Value: T, Next: B.Node<T, P...>?, Call: (P...) -> T }\nreturn nil");
        write(temp.path(), "B.luau", "local A = require(script.Parent.A)\nexport type Node<T, P...> = { Next: A.Node<T, P...>? }\nreturn nil");
        let output = generated(temp.path());
        assert!(output.contains("type __WallyType0 = number"), "{}", output);
        assert!(
            output.contains("type __WallyType1 < T = __WallyType0 , P ... = ... __WallyType0 >"),
            "{}",
            output
        );
        assert!(
            output.contains("Next : __WallyType2 < T , P ... > ?"),
            "{}",
            output
        );
        assert!(
            output.contains("Next : __WallyType1 < T , P ... > ?"),
            "{}",
            output
        );
        assert!(
            output.contains("P ... = ( __WallyDefault0 , string )"),
            "{}",
            output
        );
        assert_eq!(output.matches("type __WallyType").count(), 3);
    }

    #[test]
    fn private_names_do_not_capture_fields_literals_or_nested_callback_and_pack_binders() {
        let temp = TempDir::new().unwrap();
        write(temp.path(), "init.luau", "local Types = require(script.Types)\ntype Hidden = Types.Hidden\nexport type Box<Hidden, T = Types.Hidden, __WallyType0 = <Hidden, P...>(Hidden, P...) -> (Hidden, P...)> = T\nreturn {}");
        write(temp.path(), "Types.luau", "type Hidden = string\nexport type Outer = number\nexport type Hidden = { Hidden: \"Hidden\", Global: Outer, Call: <Outer, P...>(Outer, P...) -> (Outer, P...), Nested: <T>(T, <Outer>(Outer) -> T) -> Outer }\nreturn nil");
        // Distinct local and exported aliases with one spelling are ambiguous, even
        // if an earlier parser accepted the syntax.
        assert!(exports(temp.path()).is_err());
        write(temp.path(), "Types.luau", "export type Outer = number\nexport type Hidden = { Hidden: \"Hidden\", Global: Outer, Call: <Outer, P...>(Outer, P...) -> (Outer, P...), Nested: <T>(T, <Outer>(Outer) -> T) -> Outer }\nreturn nil");
        let output = generated(temp.path());
        assert!(
            output.contains("type __WallyType0_ = { Hidden : \"Hidden\" , Global : __WallyType1"),
            "{}",
            output
        );
        assert!(
            output.contains("Call : < Outer , P ... > ( Outer , P ... ) -> ( Outer , P ... )"),
            "{}",
            output
        );
        assert!(
            output.contains("Nested : < T > ( T , < Outer > ( Outer ) -> T ) -> __WallyType1"),
            "{}",
            output
        );
        assert!(
            output.contains(
                "export type Box< Hidden , T = __WallyType0_ , __WallyType0 = < Hidden , P ... >"
            ),
            "{}",
            output
        );
        assert!(!output.contains("type Hidden ="), "{}", output);
    }

    #[test]
    fn imports_follow_actual_root_and_child_project_redirects() {
        let temp = TempDir::new().unwrap();
        write(
            temp.path(),
            "default.project.json",
            r#"{"tree":{"$path":"Source"}}"#,
        );
        write(temp.path(), "init.luau", "return {}");
        write(
            temp.path(),
            "Types.luau",
            "export type Value = boolean\nreturn nil",
        );
        write(temp.path(), "Source/init.luau", "local Types = require(\"@self/Types\")\nexport type Box<T = Types.Value> = T\nreturn {}");
        write(
            temp.path(),
            "Source/Types/default.project.json",
            r#"{"tree":{"$path":"Impl"}}"#,
        );
        write(
            temp.path(),
            "Source/Types/init.luau",
            "export type Value = boolean\nreturn nil",
        );
        write(
            temp.path(),
            "Source/Types/Impl/init.luau",
            "local Child = require(script.Child)\nexport type Value = Child.Value\nreturn nil",
        );
        write(
            temp.path(),
            "Source/Types/Impl/Child.lua",
            "export type Value = string\nreturn nil",
        );
        let output = generated(temp.path());
        assert!(output.contains("type __WallyType1 = string"), "{}", output);
        assert!(!output.contains("boolean"), "{}", output);
    }

    #[test]
    fn shadowed_writes_do_not_invalidate_static_imports() {
        for statement in [
            "local function f(Types) Types = {} end",
            "local function f(Types) Types += runtime end",
            "local function f(Types) function Types() end end",
            "local f = function(Types, ...) Types = {} end",
            "function f(Types) local function g() Types = {} end end",
            "do local Types = {} Types = {} end",
            "do local Types = {} Types += runtime end",
            "do local Types = {} function Types() end end",
            "do const Types = {} local function f() Types = {} end end",
            "do local function Types() Types = {} end end",
            "do local function Types() end function Types() end end",
            "do local Types = {} local Types = (function() Types = {} end)() end",
            "for Types = 1, 2 do Types = 3 end",
            "for Types = 1, 2 do Types += runtime end",
            "for Types = 1, 2 do function Types() end end",
            "for _, Types in iterator() do Types = {} end",
            "for Types, _ in iterator() do Types += runtime end",
            "for Types in iterator() do local function f() Types = {} end end",
            "if runtime then local Types = {} Types = {} else local Types = {} function Types() end end",
            "while runtime do local Types = {} Types = {} end",
            "repeat local Types = {} until (function() Types = {} return true end)()",
            "do local Types = {} repeat until (function() Types = {} return true end)() end",
            "local function f() do local Types = {} Types = {} end end",
            "function Types.method() end function Types:method() end",
        ] {
            let temp = TempDir::new().unwrap();
            write(
                temp.path(),
                "init.luau",
                &format!("local Types = require(script.Types)\n{statement}\nexport type Box<T = Types.Value> = T\nreturn {{}}"),
            );
            write(temp.path(), "Types.luau", "export type Value = string\nreturn nil");
            let types =
                exports(temp.path()).unwrap_or_else(|error| panic!("{}\n{:#}", statement, error));
            let output = forward("return require(\"./target\")\n".into(), &types);
            assert!(output.contains("type __WallyType0 = string"), "{}\n{}", statement, output);
            full_moon::parse(&output).unwrap();
        }
    }

    #[test]
    fn captured_writes_including_initializers_and_iterators_invalidate_imports() {
        for statement in [
            "local function f() Types = {} end",
            "local function f() Types += runtime end",
            "local function f() function Types() end end",
            "local function f() local function g() Types = {} end end",
            "local function f() Types = {} local Types = {} end",
            "local function f() Types += runtime const Types = {} end",
            "local function f() function Types() end local function Types() end end",
            "do Types = {} local Types = {} end",
            "do Types = {} end",
            "do local Types = {} end Types = {}",
            "if runtime then local Types = {} else Types = {} end",
            "repeat local Types = {} until true Types = {}",
            "repeat until (function() Types = {} return true end)()",
            "do local Types = (function() Types = {} end)() end",
            "do const Types = (function() Types = {} end)() end",
            "do local Other, Types = (function() Types = {} end)(), {} end",
            "local function f() local Types = function() Types = {} end end",
            "for Types = (function() Types = {} return 1 end)(), 2 do end",
            "for Types = 1, (function() Types = {} return 2 end)() do end",
            "for Types = 1, 2, (function() Types = {} return 1 end)() do end",
            "for Types in iterator(function() Types = {} end) do end",
            "for _, Types in (function() Types = {} return iterator() end)() do end",
            "for Other in iterator() do Types = {} end",
            "for Types = 1, 2 do end Types = {}",
        ] {
            let temp = TempDir::new().unwrap();
            write(
                temp.path(),
                "init.luau",
                &format!("local Types = require(script.Types)\n{statement}\nexport type Box<T = Types.Value> = T\nreturn {{}}"),
            );
            write(
                temp.path(),
                "Types.luau",
                "export type Value = string\nreturn nil",
            );
            let error = format!("{:#}", exports(temp.path()).err().expect(statement));
            assert!(
                error.contains("Ambiguous or shadowed static import binding Types"),
                "{}\n{}",
                statement,
                error
            );
        }
    }

    #[test]
    fn writes_resolve_declaration_order_and_implicit_method_parameters() {
        let module = TypeModule::parse(
            "Types = {}\nlocal function before() Types = {} end\nlocal Types = require(script.Types)\nlocal self = require(script.Types)\nfunction object:method() self = {} end\nlocal function f() local Types = {} Types = {} end",
        ).unwrap();
        assert!(module.ambiguous.is_empty(), "{:?}", module.ambiguous);
        let module = TypeModule::parse(
            "local Types = require(script.Types)\nlocal Types = (function() Types = {} end)()",
        )
        .unwrap();
        assert!(module.ambiguous.contains("Types"));
        for name in ["require", "script"] {
            for statement in [
                format!("local function f({name}) {name} = runtime end"),
                format!("do local {name} = runtime {name} += runtime end"),
                format!("for {name} in iterator() do function {name}() end end"),
            ] {
                let module = TypeModule::parse(&statement).unwrap();
                assert!(!module.ambiguous.contains(name), "{}", statement);
            }
            let module =
                TypeModule::parse(&format!("local function f() {name} = runtime end")).unwrap();
            assert!(module.ambiguous.contains(name));
        }
    }

    #[test]
    fn unqualified_type_defaults_ignore_same_named_value_bindings() {
        for (name, value) in [
            ("string", "string"),
            ("Vector3", "Vector3"),
            ("Runtime", "{}"),
        ] {
            let output = forward(
                "return require(\"./target\")\n".into(),
                &declarations(&format!(
                    "local {name} = {value}\nexport type Box<T = {name}> = T\nreturn {{}}"
                ))
                .unwrap(),
            );
            assert!(
                output.contains(&format!("export type Box< T = {name} >")),
                "{}",
                output
            );
            full_moon::parse(&output).unwrap();

            let temp = TempDir::new().unwrap();
            write(temp.path(), "init.luau", "local Types = require(script.Types)\nexport type Box<T = Types.Value> = T\nreturn {}");
            write(
                temp.path(),
                "Types.luau",
                &format!(
                    "local {name} = {value}\nexport type Value = {{ Value: {name} }}\nreturn nil"
                ),
            );
            let output = generated(temp.path());
            assert!(
                output.contains(&format!("type __WallyType0 = {{ Value : {name} }}")),
                "{}",
                output
            );
        }
    }

    #[test]
    fn type_alias_and_generic_scopes_still_precede_unqualified_global_types() {
        let output = forward(
            "return require(\"./target\")\n".into(),
            &declarations("local string = string\ntype string = number\nexport type Box<T = string> = T\nexport type Generic<string, T = string> = T\nexport type Callback<T = <string>(string) -> string> = T\nreturn {}").unwrap(),
        );
        assert!(output.contains("type __WallyType0 = number"), "{}", output);
        assert!(
            output.contains("export type Box< T = __WallyType0 >"),
            "{}",
            output
        );
        assert!(
            output.contains("export type Generic< string , T = string >"),
            "{}",
            output
        );
        assert!(
            output.contains("< string > ( string ) -> string"),
            "{}",
            output
        );
        full_moon::parse(&output).unwrap();
        for source in [
            "local string = string\nexport type Box<T = typeof(string)> = T\nreturn {}",
            "local Compute = {}\ntype function Compute() return types.string end\nexport type Box<T = Compute<>> = T\nreturn {}",
        ] {
            assert!(declarations(source).is_err(), "{}", source);
        }
    }

    #[test]
    fn rejects_unsupported_reachable_imports_without_replaying_runtime_code() {
        for binding in [
            "local Types = require(path)",
            "local Types = require(script:WaitForChild(\"Types\"))",
            "local Types = require(script[\"Types\"])",
            "local Types = require(script.Types, script.Other)",
            "local Types = require(script.Types).Nested",
            "local Types = runtime",
            "local Types = require(\"other-package\")",
            "local Types = require(\"../outside\")",
            "local Types = require(script.Parent.Outside)",
            "local Types = require(script.Missing.Parent.Types)",
            "local Types = require(script.Types)\nfunction Types() end",
            "local Types = require(script.Types)\nTypes += runtime",
            "local Types = require(script.Types)\nTypes = require(script.Other)",
            "local Types = require(script.Types)\nlocal Types = require(script.Types)",
            "local require = runtime\nlocal Types = require(script.Types)",
            "local script = runtime\nlocal Types = require(script.Types)",
            "local Types\nif runtime then Types = require(script.Types) end",
        ] {
            let temp = TempDir::new().unwrap();
            write(
                temp.path(),
                "init.luau",
                &format!("{binding}\nexport type Box<T = Types.Value> = T\nreturn {{}}"),
            );
            write(
                temp.path(),
                "Types.luau",
                "export type Value = string\nreturn nil",
            );
            let error = format!("{:#}", exports(temp.path()).err().expect(binding));
            assert!(error.contains("import"), "{}\n{}", binding, error);
        }
        for source in [
            "export type Value = typeof(runtime)\nreturn nil",
            "type function Compute() return types.number end\nexport type Value = Compute<>\nreturn nil",
            "export type function Value() return types.number end\nreturn nil",
            "type Value = string\nreturn nil",
            "local Nested = require(path)\nexport type Value = Nested.Value\nreturn nil",
        ] {
            let temp = TempDir::new().unwrap();
            write(temp.path(), "init.luau", "local Types = require(script.Types)\nexport type Box<T = Types.Value> = T\nreturn {}");
            write(temp.path(), "Types.luau", source);
            assert!(exports(temp.path()).is_err(), "{}", source);
        }
        let temp = TempDir::new().unwrap();
        write(
            temp.path(),
            "init.luau",
            "export type Box<T = Types.Value> = T\nlocal Types = require(script.Types)\nreturn {}",
        );
        write(
            temp.path(),
            "Types.luau",
            "export type Value = string\nreturn nil",
        );
        assert!(exports(temp.path()).is_err());
    }

    #[test]
    fn imported_modules_reuse_entrypoint_validation_and_reject_ambiguous_layouts() {
        for file in ["Types.lua", "Types/init.luau", "Types.server.luau"] {
            let temp = TempDir::new().unwrap();
            write(temp.path(), "init.luau", "local Types = require(script.Types)\nexport type Box<T = Types.Value> = T\nreturn {}");
            write(
                temp.path(),
                "Types.luau",
                "export type Value = string\nreturn nil",
            );
            write(temp.path(), file, "export type Value = number\nreturn nil");
            assert!(exports(temp.path()).is_err(), "{}", file);
        }
        for (path, content) in [
            ("Types.meta.json", r#"{"className":"Script"}"#),
            ("Types.meta.jsonc", "{}"),
            ("default.project.json", r#"{"tree":{"$path":"init.luau"}}"#),
            (
                "default.project.json",
                r#"{"tree":{"$path":"init.luau","Types":{"$path":"Other.luau"}}}"#,
            ),
        ] {
            let temp = TempDir::new().unwrap();
            write(temp.path(), "init.luau", "local Types = require(script.Types)\nexport type Box<T = Types.Value> = T\nreturn {}");
            write(
                temp.path(),
                "Types.luau",
                "export type Value = string\nreturn nil",
            );
            write(temp.path(), path, content);
            assert!(exports(temp.path()).is_err(), "{}", path);
        }
    }

    #[test]
    fn imported_project_redirects_cannot_escape_or_recursively_mount_an_ancestor() {
        for target in ["../../Outside.luau", "..", "."] {
            let temp = TempDir::new().unwrap();
            write(temp.path(), "Package/init.luau", "local Types = require(script.Types)\nexport type Box<T = Types.Value> = T\nreturn {}");
            write(
                temp.path(),
                "Outside.luau",
                "export type Value = string\nreturn nil",
            );
            write(
                temp.path(),
                "Package/Types/default.project.json",
                &format!(r#"{{"tree":{{"$path":"{target}"}}}}"#),
            );
            let error = format!("{:#}", exports(&temp.path().join("Package")).err().unwrap());
            assert!(
                error.contains("escapes") || error.contains("Cyclic"),
                "{}",
                error
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn imported_symlinks_cannot_escape_the_staged_package() {
        let temp = TempDir::new().unwrap();
        write(
            temp.path(),
            "Package/init.luau",
            "local Types = require(script.Types)\nexport type Box<T = Types.Value> = T\nreturn {}",
        );
        write(
            temp.path(),
            "Outside.luau",
            "export type Value = string\nreturn nil",
        );
        std::os::unix::fs::symlink(
            temp.path().join("Outside.luau"),
            temp.path().join("Package/Types.luau"),
        )
        .unwrap();
        let error = format!("{:#}", exports(&temp.path().join("Package")).err().unwrap());
        assert!(
            error.contains("escapes the staged package root"),
            "{}",
            error
        );
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

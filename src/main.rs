#![forbid(unsafe_code)]
#![allow(clippy::chunks_exact_to_as_chunks)]

//! `omniex` command-line interface.

use std::collections::HashSet;
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use omniex::extract;
use omniex::json::{encoding_name, hash_document, role_name};
use omniex::registry;
use omniex::{FieldRole, HashValue, Mode, ParseOptions, RenderOptions, Tool};
use serde_json::{Value, json};

mod ui;

#[derive(Parser)]
#[command(
    name = "omniex",
    version,
    about = "The extractor for everything.",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse hash strings and render them again.
    Parse(ParseArgs),
    /// List the hash types that parse an input.
    Identify(IdentifyArgs),
    /// Extract hashes from an artifact.
    Extract(ExtractArgs),
    /// List the hash types available in this build.
    Types(TypesArgs),
    /// Show the descriptor for one hash type.
    Show(ShowArgs),
}

#[derive(Args)]
struct InputArgs {
    /// Hash string to read.
    hash: Option<String>,

    /// Read one hash per line from a file.
    #[arg(long, value_name = "FILE", conflicts_with = "hash")]
    file: Option<PathBuf>,
}

#[derive(Args)]
struct ParseArgs {
    #[command(flatten)]
    input: InputArgs,

    /// Hash type slug.
    #[arg(long = "type", value_name = "SLUG")]
    type_slug: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value = "human")]
    format: OutputFormat,

    /// Serialization target. Defaults to hashcat when available, otherwise John.
    #[arg(long, value_enum)]
    tool: Option<ToolArg>,

    /// Show complete field values instead of truncating long parameters.
    #[arg(long)]
    full: bool,
}

#[derive(Args)]
struct IdentifyArgs {
    #[command(flatten)]
    input: InputArgs,

    /// Print one JSON array of matches.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct TypesArgs {
    /// Print a JSON array instead of a table.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct ShowArgs {
    /// Hash type slug.
    slug: String,

    /// Print one JSON object.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct ExtractArgs {
    /// Artifact to extract from.
    artifact: PathBuf,

    /// Hash type slug.
    #[arg(long = "type", value_name = "SLUG", conflicts_with = "all")]
    type_slug: Option<String>,

    /// Extract every hash type that confidently matches.
    #[arg(long, conflicts_with = "type_slug")]
    all: bool,

    /// Output format.
    #[arg(long, value_enum, default_value = "hash")]
    format: OutputFormat,

    /// Serialization target. Defaults to hashcat when available, otherwise John.
    #[arg(long, value_enum)]
    tool: Option<ToolArg>,

    /// Extractor option, as NAME or NAME=VALUE. May be repeated; `show` lists them.
    #[arg(long = "opt", value_name = "NAME[=VALUE]")]
    options: Vec<String>,

    /// Named companion file, as NAME=PATH. May be repeated; `show` lists them.
    #[arg(long = "companion", value_name = "NAME=PATH")]
    companion: Vec<String>,

    /// Show complete field values instead of truncating long parameters.
    #[arg(long)]
    full: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum ToolArg {
    Hashcat,
    John,
    Json,
}

impl ToolArg {
    fn tool(self) -> Option<Tool> {
        match self {
            Self::Hashcat => Some(Tool::Hashcat),
            Self::John => Some(Tool::John),
            Self::Json => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Hashcat => "hashcat",
            Self::John => "john",
            Self::Json => "json",
        }
    }
}

impl From<ToolArg> for Tool {
    fn from(value: ToolArg) -> Self {
        value
            .tool()
            .expect("JSON output is handled by render_value")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Human,
    Hash,
    Json,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Input(String),
    #[error("{0}")]
    Usage(String),
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Input(_) => 1,
            Self::Usage(_) => 2,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("omniex: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Parse(args) => run_parse(args),
        Command::Identify(args) => run_identify(args),
        Command::Extract(args) => run_extract(args),
        Command::Types(args) => run_types(args),
        Command::Show(args) => run_show(args),
    }
}

fn run_show(args: ShowArgs) -> Result<(), CliError> {
    let descriptor = registry::by_slug(&args.slug)
        .ok_or_else(|| CliError::Usage(format!("unknown hash type `{}`", args.slug)))?;

    if args.json {
        return write_stdout(&format!(
            "{}\n",
            serde_json::to_string_pretty(&descriptor_json(descriptor))
                .expect("JSON values serialize")
        ));
    }

    let context = human_context()?;
    let (hashcat, john) = mode_columns(descriptor.all_modes);
    let mut block = ui::title(
        &context,
        &format!("{} ({})", descriptor.name, descriptor.slug),
    );
    block.push('\n');
    block.push_str(&ui::modes(&context, &hashcat, &john));
    block.push('\n');
    block.push('\n');

    let rows = descriptor
        .fields
        .iter()
        .map(|field| {
            vec![
                field.name.to_owned(),
                role_name(field.role).to_owned(),
                encoding_name(field.encoding).to_owned(),
                field.ty.to_owned(),
                field.description.to_owned(),
            ]
        })
        .collect::<Vec<_>>();
    block.push_str(&ui::table(
        &context,
        &["Name", "Role", "Encoding", "Type", "Description"],
        &rows,
    ));

    if let Some(extractor) = extract::by_slug(descriptor.slug) {
        let specs = extractor.options();
        if !specs.is_empty() {
            block.push('\n');
            block.push('\n');
            let rows = specs
                .iter()
                .map(|spec| {
                    vec![
                        spec.name.to_owned(),
                        if spec.takes_value {
                            "value".to_owned()
                        } else {
                            "flag".to_owned()
                        },
                        spec.help.to_owned(),
                    ]
                })
                .collect::<Vec<_>>();
            block.push_str(&ui::table(
                &context,
                &["Option", "Argument", "Description"],
                &rows,
            ));
        }

        let specs = extractor.companions();
        if !specs.is_empty() {
            block.push('\n');
            block.push('\n');
            let rows = specs
                .iter()
                .map(|spec| {
                    vec![
                        spec.name.to_owned(),
                        if spec.required {
                            "required".to_owned()
                        } else {
                            "optional".to_owned()
                        },
                        spec.help.to_owned(),
                    ]
                })
                .collect::<Vec<_>>();
            block.push_str(&ui::table(
                &context,
                &["Companion", "Required", "Description"],
                &rows,
            ));
        }
    }

    write_stdout(&format!("{block}\n"))
}

fn run_types(args: TypesArgs) -> Result<(), CliError> {
    if args.json {
        let entries = registry::all()
            .iter()
            .map(|descriptor| descriptor_json(descriptor))
            .collect::<Vec<_>>();
        return print_json(&Value::Array(entries));
    }

    let context = human_context()?;
    let rows = registry::all()
        .iter()
        .map(|descriptor| table_row(descriptor, descriptor.all_modes))
        .collect::<Vec<_>>();
    let title = format!("Hash types ({})", rows.len());

    write_stdout(&format!(
        "{}\n",
        ui::titled_table(
            &context,
            &title,
            &["Slug", "Name", "Hashcat", "John"],
            &rows
        )
    ))
}

fn run_parse(args: ParseArgs) -> Result<(), CliError> {
    if args.full && args.format != OutputFormat::Human {
        return Err(CliError::Usage("--full requires --format human".to_owned()));
    }
    let tool = args.tool;
    let parse_opts = ParseOptions::default();
    let selected = select_type(args.type_slug.as_deref())?;
    let lines = args.input.read()?;
    let total = lines.len();
    let context = if args.format == OutputFormat::Human {
        Some(human_context()?)
    } else {
        None
    };

    let mut output = Vec::with_capacity(total);
    let mut json_output = Vec::with_capacity(total);
    let mut used_tools = Vec::new();

    for (line, text) in &lines {
        let document = serde_json::from_str::<Value>(text)
            .ok()
            .filter(Value::is_object);
        let (descriptor, value) = if let Some(document) = document {
            let slug = document
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| CliError::Input(format!("line {line}: JSON hash has no type")))?;
            let descriptor = match selected {
                Some(descriptor) if descriptor.slug == slug => descriptor,
                Some(descriptor) => {
                    return Err(CliError::Input(format!(
                        "line {line}: JSON hash type `{slug}` does not match `{}`",
                        descriptor.slug
                    )));
                }
                None => registry::by_slug(slug).ok_or_else(|| {
                    CliError::Input(format!("line {line}: unknown JSON hash type `{slug}`"))
                })?,
            };
            let value = (descriptor.parse_json)(text)
                .map_err(|error| line_error(*line, total, error.to_string()))?;
            (descriptor, value)
        } else {
            match selected {
                Some(descriptor) => (
                    descriptor,
                    registry::parse(descriptor, text, &parse_opts)
                        .map_err(|error| line_error(*line, total, error.to_string()))?,
                ),
                None => {
                    let mut matches = matches(text, &parse_opts);
                    match matches.len() {
                        0 => {
                            return Err(CliError::Input(format!(
                                "line {line}: no hash type matched `{text}`"
                            )));
                        }
                        1 => matches.pop().expect("one match"),
                        _ => {
                            let candidates = matches
                                .iter()
                                .map(|(descriptor, _)| descriptor.slug)
                                .collect::<Vec<_>>()
                                .join(", ");
                            return Err(CliError::Input(format!(
                                "line {line}: ambiguous hash type (candidates: {candidates}); use --type"
                            )));
                        }
                    }
                }
            }
        };

        match args.format {
            OutputFormat::Json => {
                let (used, hash) = render_value(tool, descriptor, value.as_ref())
                    .map_err(|error| line_error(*line, total, error))?;
                used_tools.push(used);
                json_output.push(json!({
                    "line": line,
                    "type": descriptor.slug,
                    "tool": used.name(),
                    "input": text,
                    "hash": hash,
                }));
            }
            OutputFormat::Human => {
                output.push(verbose_value(
                    &context.expect("human context"),
                    descriptor,
                    value.as_ref(),
                    Some(("Input", text)),
                    args.full,
                    ("Line", *line, total),
                ));
            }
            OutputFormat::Hash => {
                let (_, hash) = render_value(tool, descriptor, value.as_ref())
                    .map_err(|error| line_error(*line, total, error))?;
                output.push(match hash {
                    Value::String(hash) => hash,
                    other => serde_json::to_string(&other).expect("JSON values always serialize"),
                });
            }
        }
    }

    if args.format == OutputFormat::Json {
        print_json(&json!({
            "omniex_version": env!("CARGO_PKG_VERSION"),
            "command": "parse",
            "tool": report_tool(tool, &used_tools),
            "results": json_output,
        }))
    } else {
        print_lines(&output)
    }
}

fn run_identify(args: IdentifyArgs) -> Result<(), CliError> {
    let opts = ParseOptions::default();
    let lines = args.input.read()?;
    let total = lines.len();
    let context = if args.json {
        None
    } else {
        Some(human_context()?)
    };

    let mut blocks = Vec::with_capacity(total);
    let mut json_output = Vec::new();

    for (line, text) in &lines {
        let matches = matches(text, &opts);
        if matches.is_empty() {
            return Err(CliError::Input(format!(
                "line {line}: no hash type matched `{text}`"
            )));
        }

        let ambiguous = matches.len() > 1;
        let count = matches.len();
        if args.json {
            for (descriptor, value) in &matches {
                json_output.push(identify_json(
                    descriptor,
                    value.as_ref(),
                    *line,
                    text,
                    ambiguous,
                ));
            }
            continue;
        }

        let context = context.expect("human context");
        let rows = matches
            .into_iter()
            .map(|(descriptor, value)| table_row(descriptor, &value.modes()))
            .collect::<Vec<_>>();
        let mut block = ui::title(&context, &format!("Input: {text}"));
        block.push('\n');
        block.push_str(&ui::table(
            &context,
            &["Slug", "Name", "Hashcat", "John"],
            &rows,
        ));
        if ambiguous {
            block.push('\n');
            block.push_str(&format!(
                "{count} hash types match this input; use --type <slug> to select one."
            ));
        }
        blocks.push(block);
    }

    if args.json {
        print_json(&Value::Array(json_output))
    } else {
        write_stdout(&format!("{}\n", blocks.join("\n\n")))
    }
}

fn run_extract(args: ExtractArgs) -> Result<(), CliError> {
    if args.full && args.format != OutputFormat::Human {
        return Err(CliError::Usage("--full requires --format human".to_owned()));
    }
    let tool = args.tool;
    let selected = select_type(args.type_slug.as_deref())?;
    let extractor = selected
        .map(|descriptor| {
            extract::by_slug(descriptor.slug)
                .ok_or_else(|| {
                    CliError::Input(format!(
                        "no extractor is registered for `{}`",
                        descriptor.slug
                    ))
                })
                .map(|extractor| (descriptor, extractor))
        })
        .transpose()?;
    let options = parse_options(&args.options)?;
    let mut artifact = extract::Artifact::from_file(&args.artifact)
        .map_err(|error| {
            CliError::Input(format!("cannot read {}: {error}", args.artifact.display()))
        })?
        .with_options(options.clone());
    for companion in &args.companion {
        let (name, path) = companion.split_once('=').ok_or_else(|| {
            CliError::Input(format!("companion must be NAME=PATH, got `{companion}`"))
        })?;
        let source = extract::FileSource::open(std::path::Path::new(path))
            .map_err(|error| CliError::Input(format!("cannot read companion {path}: {error}")))?;
        artifact = artifact.with_member(name.to_owned(), source);
    }

    let extractors = match extractor {
        Some((descriptor, extractor)) => vec![(descriptor.slug, extractor)],
        None => match extract::select(extract::EXTRACTORS, &artifact) {
            extract::Selection::Unique(extractor) => vec![(extractor.slug(), extractor)],
            extract::Selection::Ambiguous(candidates) if args.all => candidates
                .into_iter()
                .map(|candidate| (candidate.extractor.slug(), candidate.extractor))
                .collect(),
            extract::Selection::Ambiguous(candidates) => {
                return Err(CliError::Input(format!(
                    "ambiguous artifact; extractor candidates: {}; use --type or --all",
                    format_candidates(&candidates)
                )));
            }
            extract::Selection::Unconfirmed(candidates) => {
                return Err(CliError::Input(format!(
                    "artifact may match an extractor but has no reliable signature: {}; use --type",
                    format_candidates(&candidates)
                )));
            }
            extract::Selection::None => {
                return Err(CliError::Input(format!(
                    "no extractor recognized {}; use --type to choose a hash type",
                    args.artifact.display()
                )));
            }
        },
    };

    validate_options(&options, &extractors)?;

    let mut outputs = Vec::new();
    let mut seen = HashSet::new();
    for (slug, extractor) in extractors {
        let hashes = extractor.extract(&artifact).map_err(|error| {
            CliError::Input(format!(
                "cannot extract `{slug}` from {}: {error}",
                args.artifact.display()
            ))
        })?;
        for value in hashes {
            let key = serde_json::to_string(&json_fields(value.as_ref()))
                .expect("JSON values always serialize");
            if seen.insert((slug, key)) {
                outputs.push((slug, value));
            }
        }
    }

    match args.format {
        OutputFormat::Json => {
            ensure_compiled(&outputs)?;
            let mut used_tools = Vec::with_capacity(outputs.len());
            let entries = outputs
                .iter()
                .map(|(slug, value)| {
                    let descriptor = registry::by_slug(slug).ok_or_else(|| {
                        CliError::Input(format!("no descriptor registered for `{slug}`"))
                    })?;
                    let (used, hash) =
                        render_value(tool, descriptor, value.as_ref()).map_err(|error| {
                            CliError::Input(format!(
                                "cannot render extracted `{slug}` hash: {error}"
                            ))
                        })?;
                    used_tools.push(used);
                    Ok(json!({
                        "type": slug,
                        "tool": used.name(),
                        "hash": hash,
                        "fields": json_fields(value.as_ref()),
                    }))
                })
                .collect::<Result<Vec<_>, CliError>>()?;
            print_json(&json!({
                "omniex_version": env!("CARGO_PKG_VERSION"),
                "command": "extract",
                "tool": report_tool(tool, &used_tools),
                "artifact": args.artifact.display().to_string(),
                "results": entries,
            }))
        }
        OutputFormat::Hash => write_hashes(&outputs, tool),
        OutputFormat::Human => {
            ensure_compiled(&outputs)?;
            let context = human_context()?;
            let mut blocks = Vec::with_capacity(outputs.len());
            for (index, (slug, value)) in outputs.iter().enumerate() {
                let descriptor = registry::by_slug(slug).ok_or_else(|| {
                    CliError::Input(format!("no descriptor registered for `{slug}`"))
                })?;
                let rendered = render_hash(None, value.as_ref()).ok();
                let serialized = rendered.as_ref().map(|(_, hash)| ("Hash", hash.as_str()));
                blocks.push(verbose_value(
                    &context,
                    descriptor,
                    value.as_ref(),
                    serialized,
                    args.full,
                    ("Index", index + 1, outputs.len()),
                ));
            }
            write_stdout(&format!(
                "{}\n\n{}\n",
                context.bold(&format!("Artifact: {}", args.artifact.display())),
                blocks.join("\n\n")
            ))
        }
    }
}

fn format_candidates(candidates: &[extract::Candidate]) -> String {
    candidates
        .iter()
        .map(|candidate| format!("{} ({})", candidate.extractor.slug(), candidate.reason))
        .collect::<Vec<_>>()
        .join(", ")
}

fn select_type(
    slug: Option<&str>,
) -> Result<Option<&'static omniex::HashTypeDescriptor>, CliError> {
    slug.map(|slug| {
        registry::by_slug(slug)
            .ok_or_else(|| CliError::Usage(format!("unknown hash type `{slug}`")))
    })
    .transpose()
}

fn matches(
    input: &str,
    opts: &ParseOptions,
) -> Vec<(&'static omniex::HashTypeDescriptor, Box<dyn HashValue>)> {
    registry::all()
        .iter()
        .filter_map(|descriptor| {
            registry::parse(descriptor, input, opts)
                .ok()
                .map(|value| (*descriptor, value))
        })
        .collect()
}

fn line_error(line: usize, total: usize, message: String) -> CliError {
    if total == 1 {
        CliError::Input(message)
    } else {
        CliError::Input(format!("line {line}: {message}"))
    }
}

impl InputArgs {
    fn read(&self) -> Result<Vec<(usize, String)>, CliError> {
        if let Some(hash) = &self.hash {
            return Ok(vec![(1, hash.clone())]);
        }

        let implicit_stdin = self.file.is_none();
        let text = if let Some(path) = &self.file {
            std::fs::read_to_string(path).map_err(|error| {
                CliError::Input(format!("cannot read {}: {error}", path.display()))
            })?
        } else if std::io::stdin().is_terminal() {
            return Err(CliError::Usage(
                "provide a hash, --file <FILE>, or pipe hashes on standard input".to_owned(),
            ));
        } else {
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .map_err(|error| CliError::Input(format!("cannot read stdin: {error}")))?;
            text
        };

        let lines = text
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty())
            .map(|(index, line)| (index + 1, line.to_owned()))
            .collect::<Vec<_>>();

        if lines.is_empty() {
            if implicit_stdin {
                return Err(CliError::Usage(
                    "provide a hash, --file <FILE>, or pipe hashes on standard input".to_owned(),
                ));
            }
            return Err(CliError::Input("no hashes found".to_owned()));
        }

        Ok(lines)
    }
}

fn human_context() -> Result<ui::Context, CliError> {
    ui::Context::detect().map_err(|error| CliError::Input(error.to_string()))
}

fn print_lines(lines: &[String]) -> Result<(), CliError> {
    let mut text = lines.join("\n");
    text.push('\n');
    write_stdout(&text)
}

fn print_json(value: &Value) -> Result<(), CliError> {
    let text = format!(
        "{}\n",
        serde_json::to_string_pretty(value).expect("JSON values serialize")
    );
    write_stdout(&text)
}

fn write_stdout(text: &str) -> Result<(), CliError> {
    let mut stdout = std::io::stdout().lock();
    if let Err(error) = stdout.write_all(text.as_bytes()) {
        if error.kind() == std::io::ErrorKind::BrokenPipe {
            return Ok(());
        }
        return Err(CliError::Input(format!("cannot write output: {error}")));
    }
    if let Err(error) = stdout.flush() {
        if error.kind() == std::io::ErrorKind::BrokenPipe {
            return Ok(());
        }
        return Err(CliError::Input(format!("cannot write output: {error}")));
    }
    Ok(())
}

fn split_modes(modes: &[Mode]) -> (Vec<u32>, Vec<&'static str>) {
    let mut hashcat = Vec::new();
    let mut john = Vec::new();

    for mode in modes {
        match mode {
            Mode::Hashcat(value) => hashcat.push(*value),
            Mode::John(format) => john.push(*format),
        }
    }

    (hashcat, john)
}

fn mode_columns(modes: &[Mode]) -> (String, String) {
    let (hashcat, john) = split_modes(modes);
    (join_numbers(hashcat), join_labels(john))
}

fn join_numbers(values: Vec<u32>) -> String {
    if values.is_empty() {
        "-".to_owned()
    } else {
        values
            .into_iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn join_labels(values: Vec<&str>) -> String {
    if values.is_empty() {
        "-".to_owned()
    } else {
        values.join(", ")
    }
}

fn table_row(descriptor: &omniex::HashTypeDescriptor, modes: &[Mode]) -> Vec<String> {
    let (hashcat, john) = mode_columns(modes);
    vec![
        descriptor.slug.to_owned(),
        descriptor.name.to_owned(),
        hashcat,
        john,
    ]
}

fn descriptor_json(descriptor: &omniex::HashTypeDescriptor) -> Value {
    let (hashcat, john) = split_modes(descriptor.all_modes);
    let fields = descriptor
        .fields
        .iter()
        .map(|field| {
            json!({
                "name": field.name,
                "role": role_name(field.role),
                "encoding": encoding_name(field.encoding),
                "description": field.description,
                "ty": field.ty,
            })
        })
        .collect::<Vec<_>>();

    let options = extract::by_slug(descriptor.slug)
        .map(|extractor| {
            extractor
                .options()
                .iter()
                .map(|spec| {
                    json!({
                        "name": spec.name,
                        "takes_value": spec.takes_value,
                        "help": spec.help,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let companions = extract::by_slug(descriptor.slug)
        .map(|extractor| {
            extractor
                .companions()
                .iter()
                .map(|spec| {
                    json!({
                        "name": spec.name,
                        "required": spec.required,
                        "help": spec.help,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    json!({
        "slug": descriptor.slug,
        "name": descriptor.name,
        "hashcat": hashcat,
        "john": john,
        "fields": fields,
        "options": options,
        "companions": companions,
    })
}

fn identify_json(
    descriptor: &omniex::HashTypeDescriptor,
    value: &dyn HashValue,
    line: usize,
    input: &str,
    ambiguous: bool,
) -> Value {
    let (hashcat, john) = split_modes(&value.modes());
    json!({
        "line": line,
        "input": input,
        "slug": descriptor.slug,
        "name": descriptor.name,
        "hashcat": hashcat,
        "john": john,
        "ambiguous": ambiguous,
    })
}

fn parse_options(raw: &[String]) -> Result<extract::ExtractOptions, CliError> {
    let mut options = extract::ExtractOptions::new();
    for entry in raw {
        let (name, value) = match entry.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (entry.as_str(), None),
        };
        if name.is_empty() {
            return Err(CliError::Usage(format!(
                "option must be NAME or NAME=VALUE, got `{entry}`"
            )));
        }
        if !options.set(name, value) {
            return Err(CliError::Usage(format!("duplicate option `{name}`")));
        }
    }
    Ok(options)
}

fn validate_options(
    options: &extract::ExtractOptions,
    extractors: &[(&'static str, &'static dyn extract::Extractor)],
) -> Result<(), CliError> {
    if options.is_empty() {
        return Ok(());
    }

    let mut supported: Vec<&'static str> = Vec::new();
    for (_, extractor) in extractors {
        for spec in extractor.options() {
            if !supported.contains(&spec.name) {
                supported.push(spec.name);
            }
        }
    }

    for (name, value) in options.iter() {
        let spec = extractors
            .iter()
            .flat_map(|(_, extractor)| extractor.options())
            .find(|spec| spec.name == name);
        let Some(spec) = spec else {
            let slugs = extractors
                .iter()
                .map(|(slug, _)| *slug)
                .collect::<Vec<_>>()
                .join(", ");
            let hint = if supported.is_empty() {
                "it takes no options".to_owned()
            } else {
                format!("supported options: {}", supported.join(", "))
            };
            return Err(CliError::Usage(format!(
                "{slugs} does not accept `--opt {name}`; {hint}"
            )));
        };
        if spec.takes_value && value.is_none() {
            return Err(CliError::Usage(format!(
                "`--opt {name}` requires a value: --opt {name}=VALUE"
            )));
        }
        if !spec.takes_value && value.is_some() {
            return Err(CliError::Usage(format!(
                "`--opt {name}` does not take a value"
            )));
        }
    }
    Ok(())
}

fn ensure_compiled(outputs: &[(&'static str, Box<dyn HashValue>)]) -> Result<(), CliError> {
    if let Some((slug, _)) = outputs.iter().find(|(_, value)| value.streams()) {
        return Err(CliError::Usage(format!(
            "extracted `{slug}` hash streams its payload; use `--format hash`"
        )));
    }
    Ok(())
}

fn write_result(result: std::io::Result<()>) -> Result<(), CliError> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(CliError::Input(format!("cannot write output: {error}"))),
    }
}

fn write_hashes(
    outputs: &[(&'static str, Box<dyn HashValue>)],
    tool: Option<ToolArg>,
) -> Result<(), CliError> {
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for (slug, value) in outputs {
        if tool == Some(ToolArg::Json) {
            if value.streams() {
                return Err(CliError::Usage(format!(
                    "extracted `{slug}` hash streams its payload and cannot be written as a JSON document"
                )));
            }
            let descriptor = registry::by_slug(slug)
                .ok_or_else(|| CliError::Input(format!("no descriptor registered for `{slug}`")))?;
            let (_, hash) = render_value(tool, descriptor, value.as_ref()).map_err(|error| {
                CliError::Input(format!("cannot render extracted `{slug}` hash: {error}"))
            })?;
            let text = match hash {
                Value::String(hash) => hash,
                other => serde_json::to_string(&other).expect("JSON values always serialize"),
            };
            write_result(
                out.write_all(text.as_bytes())
                    .and_then(|()| out.write_all(b"\n")),
            )?;
        } else if value.streams() {
            let tool = preferred_tool(tool, value.as_ref()).map_err(|error| {
                CliError::Input(format!("cannot render extracted `{slug}` hash: {error}"))
            })?;
            let options = RenderOptions {
                tool: tool.into(),
                ..RenderOptions::default()
            };
            value.render_to(&options, &mut out).map_err(|error| {
                CliError::Input(format!("cannot write extracted `{slug}` hash: {error}"))
            })?;
            write_result(out.write_all(b"\n"))?;
        } else {
            let (_, hash) = render_hash(tool, value.as_ref()).map_err(|error| {
                CliError::Input(format!("cannot render extracted `{slug}` hash: {error}"))
            })?;
            write_result(
                out.write_all(hash.as_bytes())
                    .and_then(|()| out.write_all(b"\n")),
            )?;
        }
    }
    write_result(out.flush())
}

fn preferred_tool(requested: Option<ToolArg>, value: &dyn HashValue) -> Result<ToolArg, String> {
    if let Some(tool) = requested {
        return Ok(tool);
    }
    let modes = value.modes();
    if value.streams() && modes.iter().any(|mode| matches!(mode, Mode::John(_))) {
        return Ok(ToolArg::John);
    }
    if modes.iter().any(|mode| matches!(mode, Mode::Hashcat(_))) {
        Ok(ToolArg::Hashcat)
    } else if modes.iter().any(|mode| matches!(mode, Mode::John(_))) {
        Ok(ToolArg::John)
    } else {
        Err("no compatible hashcat or John serialization".to_owned())
    }
}

fn render_hash(
    requested: Option<ToolArg>,
    value: &dyn HashValue,
) -> Result<(ToolArg, String), String> {
    if let Some(tool) = requested {
        return value
            .render(&RenderOptions {
                tool: tool.into(),
                ..RenderOptions::default()
            })
            .map(|hash| (tool, hash))
            .map_err(|error| error.to_string());
    }

    let modes = value.modes();
    let preferred = if modes.iter().any(|mode| matches!(mode, Mode::Hashcat(_))) {
        ToolArg::Hashcat
    } else if modes.iter().any(|mode| matches!(mode, Mode::John(_))) {
        ToolArg::John
    } else {
        return Err("no compatible hashcat or John serialization".to_owned());
    };
    value
        .render(&RenderOptions {
            tool: preferred.into(),
            ..RenderOptions::default()
        })
        .map(|hash| (preferred, hash))
        .map_err(|error| error.to_string())
}

fn render_value(
    requested: Option<ToolArg>,
    descriptor: &omniex::HashTypeDescriptor,
    value: &dyn HashValue,
) -> Result<(ToolArg, Value), String> {
    if requested == Some(ToolArg::Json) {
        return Ok((ToolArg::Json, hash_document(descriptor, value)));
    }
    render_hash(requested, value).map(|(tool, hash)| (tool, Value::String(hash)))
}

fn report_tool(requested: Option<ToolArg>, used: &[ToolArg]) -> &'static str {
    if let Some(tool) = requested {
        return tool.name();
    }
    match used {
        [first, rest @ ..] if rest.iter().all(|tool| tool == first) => first.name(),
        [] => "auto",
        _ => "auto",
    }
}

fn json_fields(value: &dyn HashValue) -> Value {
    Value::Array(
        value
            .describe()
            .into_iter()
            .map(|entry| {
                json!({
                    "name": entry.field.name,
                    "role": role_name(entry.field.role),
                    "encoding": encoding_name(entry.field.encoding),
                    "value": entry.value,
                })
            })
            .collect(),
    )
}

fn verbose_value(
    context: &ui::Context,
    descriptor: &omniex::HashTypeDescriptor,
    value: &dyn HashValue,
    serialized: Option<(&str, &str)>,
    full: bool,
    count: (&str, usize, usize),
) -> String {
    let (count_label, line, total) = count;
    let (hashcat, john) = mode_columns(&value.modes());
    let mut block = ui::title(
        context,
        &format!("{} ({})", descriptor.name, descriptor.slug),
    );
    block.push('\n');

    let fields = value.describe();
    let mut pairs = Vec::new();
    if total > 1 {
        pairs.push((count_label, line.to_string()));
    }
    pairs.push(("Hashcat", hashcat));
    pairs.push(("John", john));
    let label_width = pairs
        .iter()
        .map(|(label, _)| label.len())
        .max()
        .unwrap_or(0)
        .max(serialized.map_or(0, |(label, _)| label.len()))
        .max(5);
    if let Some((label, input)) = serialized {
        let (spans, _) = field_spans(&fields, input);
        block.push_str(&ui::key_value_accented(
            context,
            label,
            input,
            &spans,
            label_width,
            full,
        ));
        block.push('\n');
    }
    block.push_str(&ui::key_values(context, &pairs));
    block.push('\n');
    block.push_str(&context.bold("Fields"));
    block.push('\n');

    let (_, accents) = field_spans(&fields, serialized.map_or("", |(_, value)| value));
    let rows = fields
        .iter()
        .map(|entry| {
            vec![
                entry.field.name.to_owned(),
                role_name(entry.field.role).to_owned(),
                encoding_name(entry.field.encoding).to_owned(),
                entry.value.clone(),
                entry.field.description.to_owned(),
            ]
        })
        .collect::<Vec<_>>();
    block.push_str(&ui::table_with_accents(
        context,
        &["Name", "Role", "Encoding", "Value", "Description"],
        &rows,
        &accents,
        &[0, 3],
        if full {
            None
        } else {
            Some((3, ui::detail_width(context)))
        },
    ));

    block
}

fn field_spans(
    fields: &[omniex::FieldValue],
    input: &str,
) -> (Vec<ui::AccentSpan>, Vec<Option<ui::Accent>>) {
    let mut spans = Vec::new();
    let mut accents = vec![None; fields.len()];
    let mut cursor = 0;
    for (index, entry) in fields.iter().enumerate() {
        let value = entry.value.as_str();
        if value.is_empty() {
            continue;
        }
        let mut search = cursor;
        let mut found = None;
        while let Some(relative) = input.get(search..).and_then(|rest| rest.find(value)) {
            let start = search + relative;
            let end = start + value.len();
            if is_field_boundary(input, start, end) {
                found = Some((start, end));
                break;
            }
            search = start + 1;
        }
        let Some((start, end)) = found else {
            continue;
        };
        let accent = accent_for(entry.field.role);
        accents[index] = accent;
        spans.push(ui::AccentSpan { start, end, accent });
        cursor = end;
    }
    (spans, accents)
}

fn is_field_boundary(input: &str, start: usize, end: usize) -> bool {
    let separator = |byte: u8| matches!(byte, b'$' | b':' | b'*' | b',');
    let before = start == 0
        || input
            .as_bytes()
            .get(start - 1)
            .is_some_and(|byte| separator(*byte));
    let after = end == input.len()
        || input
            .as_bytes()
            .get(end)
            .is_some_and(|byte| separator(*byte));
    before && after
}

fn accent_for(role: FieldRole) -> Option<ui::Accent> {
    match role {
        FieldRole::Salt => Some(ui::Accent::Red),
        FieldRole::Key => Some(ui::Accent::Magenta),
        FieldRole::Digest => Some(ui::Accent::Blue),
        FieldRole::Iv => Some(ui::Accent::Cyan),
        FieldRole::Ciphertext => Some(ui::Accent::Yellow),
        FieldRole::Iterations => Some(ui::Accent::Green),
        FieldRole::Username => Some(ui::Accent::White),
        FieldRole::Other => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniex::{Encoding, FieldValue};

    static FIELDS: [omniex::Field; 2] = [
        omniex::Field {
            name: "digest",
            description: "Digest",
            ty: "[u8; 16]",
            role: FieldRole::Digest,
            encoding: Encoding::Hex,
        },
        omniex::Field {
            name: "salt",
            description: "Salt",
            ty: "String",
            role: FieldRole::Salt,
            encoding: Encoding::Ascii,
        },
    ];

    #[test]
    fn accent_spans_follow_field_order() {
        let fields = [
            FieldValue {
                field: &FIELDS[0],
                value: "abcd".to_owned(),
            },
            FieldValue {
                field: &FIELDS[1],
                value: "12".to_owned(),
            },
        ];
        let (spans, accents) = field_spans(&fields, "abcd:12");
        assert_eq!(spans.len(), 2);
        assert_eq!(accents, vec![Some(ui::Accent::Blue), Some(ui::Accent::Red)]);
        assert_eq!(spans[0].start, 0);
        assert_eq!(spans[0].end, 4);
        assert_eq!(spans[0].accent, Some(ui::Accent::Blue));
        assert_eq!(spans[1].start, 5);
        assert_eq!(spans[1].end, 7);
        assert_eq!(spans[1].accent, Some(ui::Accent::Red));
    }
}

//! `omniex` command-line interface.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use omniex::extract;
use omniex::registry;
use omniex::{Encoding, FieldRole, HashValue, Mode, ParseOptions, RenderOptions, Tool};
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

    /// Read one hash per line from standard input.
    #[arg(long, conflicts_with_all = ["hash", "file"])]
    stdin: bool,
}

#[derive(Args)]
struct ParseArgs {
    #[command(flatten)]
    input: InputArgs,

    /// Hash type slug.
    #[arg(long = "type", value_name = "SLUG")]
    type_slug: Option<String>,

    /// Output serialization.
    #[arg(long, value_enum, default_value = "hashcat")]
    format: FormatArg,

    /// Print the descriptor and field values.
    #[arg(long, conflicts_with = "json")]
    verbose: bool,

    /// Print one JSON array containing every input.
    #[arg(long, conflicts_with = "verbose")]
    json: bool,
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

    /// Print one JSON array containing every extracted hash.
    #[arg(long)]
    json: bool,

    /// Output serialization.
    #[arg(long, value_enum, default_value = "hashcat")]
    format: FormatArg,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FormatArg {
    Hashcat,
    John,
}

impl From<FormatArg> for Tool {
    fn from(value: FormatArg) -> Self {
        match value {
            FormatArg::Hashcat => Self::Hashcat,
            FormatArg::John => Self::John,
        }
    }
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
    let tool = Tool::from(args.format);
    let parse_opts = ParseOptions {
        tool,
        ..ParseOptions::default()
    };
    let render_opts = RenderOptions {
        tool,
        ..RenderOptions::default()
    };
    let selected = select_type(args.type_slug.as_deref())?;
    let lines = args.input.read()?;
    let total = lines.len();
    let context = if args.verbose {
        Some(human_context()?)
    } else {
        None
    };

    let mut output = Vec::with_capacity(total);
    let mut json_output = Vec::with_capacity(total);

    for (line, text) in &lines {
        let (descriptor, value) = match selected {
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
        };

        if args.json {
            json_output.push(json_value(descriptor, value.as_ref(), *line, text));
        } else if args.verbose {
            output.push(verbose_value(
                &context.expect("verbose context"),
                descriptor,
                value.as_ref(),
                *line,
                total,
                text,
            ));
        } else {
            output.push(
                value
                    .render(&render_opts)
                    .map_err(|error| line_error(*line, total, error.to_string()))?,
            );
        }
    }

    if args.json {
        print_json(&Value::Array(json_output))
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

        if args.json {
            for (descriptor, value) in &matches {
                json_output.push(identify_json(descriptor, value.as_ref(), *line, text));
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
        blocks.push(block);
    }

    if args.json {
        print_json(&Value::Array(json_output))
    } else {
        write_stdout(&format!("{}\n", blocks.join("\n\n")))
    }
}

fn run_extract(args: ExtractArgs) -> Result<(), CliError> {
    let tool = Tool::from(args.format);
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
    let artifact = extract::Artifact::from_file(&args.artifact).map_err(|error| {
        CliError::Input(format!("cannot read {}: {error}", args.artifact.display()))
    })?;

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
            let rendered = value
                .render(&RenderOptions {
                    tool,
                    ..RenderOptions::default()
                })
                .map_err(|error| {
                    CliError::Input(format!("cannot render extracted `{slug}` hash: {error}"))
                })?;
            if seen.insert((slug, rendered.clone())) {
                let fields = value
                    .describe()
                    .into_iter()
                    .map(|entry| {
                        json!({
                            "name": entry.field.name,
                            "value": entry.value,
                        })
                    })
                    .collect::<Vec<_>>();
                outputs.push((slug, rendered, fields));
            }
        }
    }

    if args.json {
        let entries = outputs
            .iter()
            .map(|(slug, hash, fields)| json!({"type": slug, "hash": hash, "fields": fields}))
            .collect::<Vec<_>>();
        return print_json(&Value::Array(entries));
    }

    write_stdout(&format!(
        "{}\n",
        outputs
            .iter()
            .map(|(_, hash, _)| hash.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    ))
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

        let text = if let Some(path) = &self.file {
            std::fs::read_to_string(path).map_err(|error| {
                CliError::Input(format!("cannot read {}: {error}", path.display()))
            })?
        } else if self.stdin {
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .map_err(|error| CliError::Input(format!("cannot read stdin: {error}")))?;
            text
        } else {
            return Err(CliError::Usage(
                "provide a hash, --file <FILE>, or --stdin".to_owned(),
            ));
        };

        let lines = text
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty())
            .map(|(index, line)| (index + 1, line.to_owned()))
            .collect::<Vec<_>>();

        if lines.is_empty() {
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

    json!({
        "slug": descriptor.slug,
        "name": descriptor.name,
        "hashcat": hashcat,
        "john": john,
        "fields": fields,
    })
}

fn identify_json(
    descriptor: &omniex::HashTypeDescriptor,
    value: &dyn HashValue,
    line: usize,
    input: &str,
) -> Value {
    let (hashcat, john) = split_modes(&value.modes());
    json!({
        "line": line,
        "input": input,
        "slug": descriptor.slug,
        "name": descriptor.name,
        "hashcat": hashcat,
        "john": john,
    })
}

fn json_value(
    descriptor: &omniex::HashTypeDescriptor,
    value: &dyn HashValue,
    line: usize,
    input: &str,
) -> Value {
    let (hashcat, john) = split_modes(&value.modes());
    let fields = value
        .describe()
        .into_iter()
        .map(|entry| {
            json!({
                "name": entry.field.name,
                "role": role_name(entry.field.role),
                "encoding": encoding_name(entry.field.encoding),
                "description": entry.field.description,
                "value": entry.value,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "line": line,
        "input": input,
        "slug": descriptor.slug,
        "name": descriptor.name,
        "hashcat": hashcat,
        "john": john,
        "fields": fields,
    })
}

fn verbose_value(
    context: &ui::Context,
    descriptor: &omniex::HashTypeDescriptor,
    value: &dyn HashValue,
    line: usize,
    total: usize,
    input: &str,
) -> String {
    let (hashcat, john) = mode_columns(&value.modes());
    let mut block = ui::title(
        context,
        &format!("{} ({})", descriptor.name, descriptor.slug),
    );
    block.push('\n');

    let mut pairs = Vec::new();
    if total > 1 {
        pairs.push(("Line", line.to_string()));
    }
    pairs.push(("Input", input.to_owned()));
    pairs.push(("Hashcat", hashcat));
    pairs.push(("John", john));
    block.push_str(&ui::key_values(context, &pairs));
    block.push('\n');
    block.push_str(&context.bold("Fields"));
    block.push('\n');

    let rows = value
        .describe()
        .into_iter()
        .map(|entry| {
            vec![
                entry.field.name.to_owned(),
                role_name(entry.field.role).to_owned(),
                encoding_name(entry.field.encoding).to_owned(),
                entry.value,
                entry.field.description.to_owned(),
            ]
        })
        .collect::<Vec<_>>();
    block.push_str(&ui::table(
        context,
        &["Name", "Role", "Encoding", "Value", "Description"],
        &rows,
    ));

    block
}

fn role_name(role: FieldRole) -> &'static str {
    match role {
        FieldRole::Salt => "salt",
        FieldRole::Key => "key",
        FieldRole::Digest => "digest",
        FieldRole::Iv => "iv",
        FieldRole::Ciphertext => "ciphertext",
        FieldRole::Iterations => "iterations",
        FieldRole::Username => "username",
        FieldRole::Other => "other",
    }
}

fn encoding_name(encoding: Encoding) -> &'static str {
    match encoding {
        Encoding::Raw => "raw",
        Encoding::Hex => "hex",
        Encoding::Base64 => "base64",
        Encoding::Decimal => "decimal",
        Encoding::Ascii => "ascii",
    }
}

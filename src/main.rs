//! `omniex` command-line interface.

use std::fmt;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use omniex::registry;
use omniex::{
    Encoding, Family, FieldRole, HashValue, HashcatVersion, Mode, ParseOptions, ReleaseVersion,
    RenderOptions, Tool,
};
use serde_json::{Value, json};

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

    /// Hashcat release used for parsing and rendering.
    #[arg(long, value_name = "RELEASE", default_value = "8.0.0", value_parser = parse_hc_version)]
    hc_version: HashcatVersion,

    /// Print the descriptor and field values.
    #[arg(long, conflicts_with = "json")]
    verbose: bool,

    /// Print one JSON object per input.
    #[arg(long, conflicts_with = "verbose")]
    json: bool,
}

#[derive(Args)]
struct IdentifyArgs {
    #[command(flatten)]
    input: InputArgs,
}

#[derive(Args)]
struct ExtractArgs {
    /// Artifact to extract from.
    artifact: PathBuf,

    /// Hash type slug.
    #[arg(long = "type", value_name = "SLUG")]
    type_slug: Option<String>,

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

#[derive(Debug)]
enum CliError {
    Input(String),
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

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(message) | Self::Usage(message) => f.write_str(message),
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
    }
}

fn run_parse(args: ParseArgs) -> Result<(), CliError> {
    let tool = Tool::from(args.format);
    let parse_opts = ParseOptions {
        tool,
        hc_version: args.hc_version,
    };
    let render_opts = RenderOptions {
        tool,
        hc_version: args.hc_version,
    };
    let selected = select_type(args.type_slug.as_deref())?;
    let lines = args.input.read()?;
    let total = lines.len();

    let mut output = Vec::with_capacity(total);
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
            output.push(
                serde_json::to_string(&json_value(descriptor, value.as_ref()))
                    .expect("JSON value serializes"),
            );
        } else if args.verbose {
            output.push(verbose_value(descriptor, value.as_ref()));
        } else {
            output.push(value.render(&render_opts));
        }
    }

    print_lines(&output);
    Ok(())
}

fn run_identify(args: IdentifyArgs) -> Result<(), CliError> {
    let opts = ParseOptions::default();
    let lines = args.input.read()?;
    let total = lines.len();
    let mut output = Vec::with_capacity(total);

    for (line, text) in &lines {
        let matches = matches(text, &opts);
        if matches.is_empty() {
            return Err(CliError::Input(format!(
                "line {line}: no hash type matched `{text}`"
            )));
        }
        for (descriptor, _) in matches {
            output.push(format!("{}\t{}", descriptor.slug, descriptor.name));
        }
    }

    print_lines(&output);
    Ok(())
}

fn run_extract(args: ExtractArgs) -> Result<(), CliError> {
    let _tool = Tool::from(args.format);
    let selected = select_type(args.type_slug.as_deref())?;
    let artifact = args.artifact.display();

    match selected {
        Some(descriptor) => Err(CliError::Input(format!(
            "no extractor is registered for `{}`; cannot extract from {artifact}",
            descriptor.slug
        ))),
        None => Err(CliError::Input(format!(
            "no extractor is registered; cannot extract from {artifact}"
        ))),
    }
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

fn print_lines(lines: &[String]) {
    for line in lines {
        println!("{line}");
    }
}

fn json_value(descriptor: &omniex::HashTypeDescriptor, value: &dyn HashValue) -> Value {
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
        "name": descriptor.name,
        "slug": descriptor.slug,
        "family": descriptor.family.map(family_name),
        "modes": value.modes().into_iter().map(mode_value).collect::<Vec<_>>(),
        "fields": fields,
    })
}

fn verbose_value(descriptor: &omniex::HashTypeDescriptor, value: &dyn HashValue) -> String {
    let modes = value
        .modes()
        .into_iter()
        .map(mode_name)
        .collect::<Vec<_>>()
        .join(", ");
    let family = descriptor.family.map(family_name).unwrap_or("none");

    let mut lines = vec![
        format!("{} [{}]", descriptor.name, descriptor.slug),
        format!("family: {family}"),
        format!("modes: {modes}"),
    ];

    for entry in value.describe() {
        lines.push(format!(
            "field {} [{}, {}]: {}",
            entry.field.name,
            role_name(entry.field.role),
            encoding_name(entry.field.encoding),
            entry.value
        ));
        lines.push(format!("  {}", entry.field.description));
    }

    lines.join("\n")
}

fn mode_value(mode: Mode) -> Value {
    match mode {
        Mode::Hashcat(mode) => json!({"tool": "hashcat", "mode": mode}),
        Mode::John(format) => json!({"tool": "john", "format": format}),
    }
}

fn mode_name(mode: Mode) -> String {
    match mode {
        Mode::Hashcat(mode) => format!("hashcat:{mode}"),
        Mode::John(format) => format!("john:{format}"),
    }
}

fn family_name(family: Family) -> &'static str {
    match family {
        Family::Md5 => "md5",
        Family::Sha1 => "sha1",
        Family::Sha2 => "sha2",
        Family::Sha3 => "sha3",
        Family::Blake2 => "blake2",
        Family::Ripemd => "ripemd",
        Family::Whirlpool => "whirlpool",
        Family::Ntlm => "ntlm",
        Family::Lm => "lm",
        Family::Des => "des",
        Family::Aes => "aes",
        Family::Other => "other",
    }
}

fn role_name(role: FieldRole) -> &'static str {
    match role {
        FieldRole::Salt => "salt",
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

fn parse_hc_version(value: &str) -> Result<HashcatVersion, String> {
    let mut parts = value.split('.');
    let major = next_version_part(&mut parts, value)?;
    let minor = next_version_part(&mut parts, value)?;
    let patch = next_version_part(&mut parts, value)?;

    if parts.next().is_some() {
        return Err(format!(
            "invalid release `{value}`; expected MAJOR.MINOR.PATCH"
        ));
    }

    Ok(HashcatVersion::Release(ReleaseVersion::new(
        major, minor, patch,
    )))
}

fn next_version_part<'a>(
    parts: &mut impl Iterator<Item = &'a str>,
    value: &str,
) -> Result<u16, String> {
    parts
        .next()
        .ok_or_else(|| format!("invalid release `{value}`; expected MAJOR.MINOR.PATCH"))?
        .parse()
        .map_err(|_| format!("invalid release `{value}`; expected MAJOR.MINOR.PATCH"))
}

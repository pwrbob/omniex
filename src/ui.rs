//! Human-readable terminal layout.
//!
//! No table or record uses tab stops. Human output is aligned with spaces, uses
//! bold only on a terminal, and has exactly one horizontal rule below each
//! title.

use std::env;
use std::io::{self, IsTerminal};

use comfy_table::presets::NOTHING;
use comfy_table::{Attribute, Cell, ContentArrangement, Table};
use textwrap::{Options, WordSeparator, WordSplitter};
use unicode_width::UnicodeWidthStr;

/// Smallest terminal this UI will render into.
pub const MIN_WIDTH: usize = 40;
/// Smallest terminal height this UI will render into.
pub const MIN_HEIGHT: usize = 10;

const GAP: usize = 2;

/// A terminal sizing or styling failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UiError {
    /// The terminal is smaller than the supported minimum.
    #[error("terminal is too small ({width}x{height}); need at least {MIN_WIDTH}x{MIN_HEIGHT}")]
    TooSmall { width: usize, height: usize },
}

/// Resolved terminal context for one invocation.
#[derive(Debug, Clone, Copy)]
pub struct Context {
    width: usize,
    #[allow(dead_code)]
    height: usize,
    bold: bool,
}

impl Context {
    /// Detects the current terminal.
    pub fn detect() -> Result<Self, UiError> {
        let terminal = io::stdout().is_terminal();
        let measured = terminal_size::terminal_size();

        let width = env_usize("COLUMNS")
            .or_else(|| measured.map(|(width, _)| usize::from(width.0)))
            .unwrap_or(80);
        let height = env_usize("LINES")
            .or_else(|| measured.map(|(_, height)| usize::from(height.0)))
            .unwrap_or(24);
        let bold = terminal && env::var_os("NO_COLOR").is_none();

        Self::from_parts(width, height, terminal, bold)
    }

    /// Builds a context from explicit values. Used by tests.
    pub fn from_parts(
        width: usize,
        height: usize,
        terminal: bool,
        bold: bool,
    ) -> Result<Self, UiError> {
        if terminal && (width < MIN_WIDTH || height < MIN_HEIGHT) {
            return Err(UiError::TooSmall { width, height });
        }

        Ok(Self {
            width: width.max(1),
            height,
            bold,
        })
    }

    /// Styles text as bold when the terminal supports it.
    #[must_use]
    pub fn bold(&self, text: &str) -> String {
        if self.bold {
            format!("\x1b[1m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }
}

/// Renders a title, its single rule, and a table.
#[must_use]
pub fn titled_table(
    context: &Context,
    title: &str,
    headers: &[&str],
    rows: &[Vec<String>],
) -> String {
    let title_lines = wrap_text(title, context.width);
    let rule_width = title_lines
        .iter()
        .map(|line| line.width())
        .max()
        .unwrap_or(1)
        .min(context.width)
        .max(1);

    let mut output = Vec::new();
    for line in &title_lines {
        output.push(context.bold(line));
    }
    output.push("─".repeat(rule_width));
    output.push(table(context, headers, rows));
    output.join("\n")
}

/// Renders a title and its single rule.
#[must_use]
pub fn title(context: &Context, title: &str) -> String {
    let title_lines = wrap_text(title, context.width);
    let rule_width = title_lines
        .iter()
        .map(|line| line.width())
        .max()
        .unwrap_or(1)
        .min(context.width)
        .max(1);

    let mut output = Vec::new();
    for line in &title_lines {
        output.push(context.bold(line));
    }
    output.push("─".repeat(rule_width));
    output.join("\n")
}

/// Renders a table with a bold header row. It never draws a rule.
#[must_use]
pub fn table(context: &Context, headers: &[&str], rows: &[Vec<String>]) -> String {
    if headers.is_empty() {
        return String::new();
    }

    let mut table = Table::new();
    table.load_preset(NOTHING);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_width(u16::try_from(context.width).unwrap_or(u16::MAX));
    if context.bold {
        table.enforce_styling();
    }

    let mut header_cells = Vec::with_capacity(headers.len());
    for header in headers {
        let mut cell = Cell::new(header);
        if context.bold {
            cell = cell.add_attribute(Attribute::Bold);
        }
        header_cells.push(cell);
    }
    table.set_header(header_cells);

    for index in 0..headers.len() {
        if let Some(column) = table.column_mut(index) {
            column.set_padding((0, GAP as u16));
        }
    }

    for row in rows {
        let cells = headers
            .iter()
            .enumerate()
            .map(|(index, _)| Cell::new(cell_or_dash(row.get(index).map_or("", String::as_str))))
            .collect::<Vec<_>>();
        table.add_row(cells);
    }

    table
        .to_string()
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Renders aligned key/value rows.
#[must_use]
pub fn key_values(context: &Context, pairs: &[(&str, String)]) -> String {
    let label_width = pairs
        .iter()
        .map(|(label, _)| label.width())
        .max()
        .unwrap_or(0);
    let value_width = context.width.saturating_sub(label_width + GAP).max(1);
    let mut output = Vec::new();

    for (label, value) in pairs {
        for (index, line) in wrap_text(value, value_width).into_iter().enumerate() {
            if index == 0 {
                let padding = " ".repeat(label_width - label.width());
                output.push(format!(
                    "{}{padding}{}{line}",
                    context.bold(label),
                    " ".repeat(GAP)
                ));
            } else {
                output.push(format!("{}{line}", " ".repeat(label_width + GAP)));
            }
        }
    }

    output.join("\n")
}

/// Renders the hashcat and John modes for one type on one line.
#[must_use]
pub fn modes(context: &Context, hashcat: &str, john: &str) -> String {
    let line = format!("Hashcat: {hashcat} / John: {john}");
    wrap_text(&line, context.width)
        .into_iter()
        .map(|line| {
            line.replace("Hashcat:", &context.bold("Hashcat:"))
                .replace("John:", &context.bold("John:"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Wraps text to `width` characters, breaking at whitespace first.
#[must_use]
pub fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let options = Options::new(width)
        .break_words(true)
        .word_separator(WordSeparator::AsciiSpace)
        .word_splitter(WordSplitter::NoHyphenation);
    let lines = textwrap::wrap(text, options)
        .into_iter()
        .map(|line| line.into_owned())
        .collect::<Vec<_>>();

    if lines.is_empty() {
        vec![String::new()]
    } else {
        lines
    }
}

fn cell_or_dash(cell: &str) -> &str {
    if cell.is_empty() { "-" } else { cell }
}

fn env_usize(name: &str) -> Option<usize> {
    env::var(name).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_at_words_and_hard_splits_long_words() {
        assert_eq!(wrap_text("one two three", 7), vec!["one two", "three"]);
        assert_eq!(wrap_text("abcdefgh", 3), vec!["abc", "def", "gh"]);
    }

    #[test]
    fn table_fits_the_requested_width() {
        let context = Context::from_parts(40, 20, false, false).unwrap();
        let output = table(
            &context,
            &["Slug", "Name", "Hashcat"],
            &[vec![
                "salted-md5".to_owned(),
                "Salted MD5".to_owned(),
                "10, 11, 12, 20, 21, 23, 24, 30, 40, 2611, 2630, 2711, 2811, 3800".to_owned(),
            ]],
        );

        assert!(output.lines().all(|line| line.width() <= 40));
    }

    #[test]
    fn modes_share_one_line() {
        let context = Context::from_parts(80, 20, false, false).unwrap();
        assert_eq!(
            modes(&context, "0, 70", "Raw-MD5, Raw-MD5u"),
            "Hashcat: 0, 70 / John: Raw-MD5, Raw-MD5u"
        );
    }

    #[test]
    fn titled_table_has_exactly_one_rule() {
        let context = Context::from_parts(80, 20, false, false).unwrap();
        let output = titled_table(
            &context,
            "Hash types (2)",
            &["Slug", "Name"],
            &[
                vec!["md4".to_owned(), "MD4".to_owned()],
                vec!["md5".to_owned(), "MD5".to_owned()],
            ],
        );

        assert_eq!(
            output.lines().filter(|line| line.starts_with('─')).count(),
            1
        );
    }

    #[test]
    fn bold_is_terminal_only() {
        let plain = Context::from_parts(80, 20, false, false).unwrap();
        let bold = Context::from_parts(80, 20, false, true).unwrap();
        assert_eq!(plain.bold("x"), "x");
        assert_eq!(bold.bold("x"), "\u{1b}[1mx\u{1b}[0m");
    }

    #[test]
    fn table_bolds_the_header_only_when_requested() {
        let plain = Context::from_parts(80, 20, false, false).unwrap();
        let bold = Context::from_parts(80, 20, false, true).unwrap();
        let rows = [vec!["md5".to_owned(), "MD5".to_owned()]];

        let plain_output = table(&plain, &["Slug", "Name"], &rows);
        let bold_output = table(&bold, &["Slug", "Name"], &rows);

        assert!(!plain_output.contains('\u{1b}'));
        assert!(bold_output.contains("\u{1b}[1mSlug"));
    }

    #[test]
    fn minimum_terminal_size_is_enforced() {
        assert!(matches!(
            Context::from_parts(20, 5, true, false),
            Err(UiError::TooSmall { .. })
        ));
        assert!(Context::from_parts(20, 5, false, false).is_ok());
    }

    #[test]
    fn wide_characters_count_toward_display_width() {
        let context = Context::from_parts(20, 20, false, false).unwrap();
        let output = table(
            &context,
            &["Slug", "Name"],
            &[vec![
                "md5".to_owned(),
                "\u{1f600}\u{1f600}\u{1f600}".repeat(10),
            ]],
        );
        assert!(output.lines().all(|line| line.width() <= 20));
    }

    #[test]
    fn empty_cells_render_as_dash() {
        let context = Context::from_parts(80, 20, false, false).unwrap();
        let output = table(
            &context,
            &["Slug", "John"],
            &[vec!["md5".to_owned(), String::new()]],
        );
        assert!(output.contains("-"));
    }
}

//! Human-readable terminal layout.
//!
//! No table or record uses tab stops. Human output is aligned with spaces, uses
//! bold only on a terminal, and has exactly one horizontal rule below each
//! title.

use std::env;
use std::fmt;
use std::io::{self, IsTerminal};

/// Smallest terminal this UI will render into.
pub const MIN_WIDTH: usize = 40;
/// Smallest terminal height this UI will render into.
pub const MIN_HEIGHT: usize = 10;

const GAP: usize = 2;

/// A terminal sizing or styling failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiError {
    /// The terminal is smaller than the supported minimum.
    TooSmall { width: usize, height: usize },
}

impl fmt::Display for UiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall { width, height } => write!(
                f,
                "terminal is too small ({width}x{height}); need at least {MIN_WIDTH}x{MIN_HEIGHT}"
            ),
        }
    }
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
        .map(|line| line.chars().count())
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
        .map(|line| line.chars().count())
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

    let columns = headers.len();
    let mut widths = vec![0usize; columns];

    for (index, header) in headers.iter().enumerate() {
        widths[index] = header.chars().count();
    }
    for row in rows {
        for (index, cell) in row.iter().enumerate().take(columns) {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }

    let minimums = headers
        .iter()
        .map(|header| {
            header
                .split_whitespace()
                .map(|word| word.chars().count())
                .max()
                .unwrap_or(1)
                .max(1)
        })
        .collect::<Vec<_>>();

    let total = |widths: &[usize]| widths.iter().sum::<usize>() + GAP * columns.saturating_sub(1);
    while total(&widths) > context.width {
        let Some((index, _)) = widths
            .iter()
            .enumerate()
            .filter(|(index, width)| **width > minimums[*index])
            .max_by_key(|(_, width)| **width)
        else {
            break;
        };
        widths[index] -= 1;
    }

    while total(&widths) > context.width {
        let Some((index, _)) = widths.iter().enumerate().max_by_key(|(_, width)| **width) else {
            break;
        };
        if widths[index] <= 1 {
            break;
        }
        widths[index] -= 1;
    }

    let mut output = Vec::new();
    output.extend(render_row(context, headers, &widths, true));

    for row in rows {
        let cells = row
            .iter()
            .enumerate()
            .map(|(index, cell)| wrap_text(cell_or_dash(cell), widths[index]))
            .collect::<Vec<_>>();
        output.extend(render_cells(context, &cells, &widths, false));
    }

    output.join("\n")
}

/// Renders aligned key/value rows.
#[must_use]
pub fn key_values(context: &Context, pairs: &[(&str, String)]) -> String {
    let label_width = pairs
        .iter()
        .map(|(label, _)| label.chars().count())
        .max()
        .unwrap_or(0);
    let value_width = context.width.saturating_sub(label_width + GAP).max(1);
    let mut output = Vec::new();

    for (label, value) in pairs {
        for (index, line) in wrap_text(value, value_width).into_iter().enumerate() {
            if index == 0 {
                let padding = " ".repeat(label_width - label.chars().count());
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

/// Wraps text to `width` characters, breaking at whitespace first.
#[must_use]
pub fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        if word.chars().count() > width {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }

            let mut chunk = String::new();
            for character in word.chars() {
                chunk.push(character);
                if chunk.chars().count() == width {
                    lines.push(std::mem::take(&mut chunk));
                }
            }
            current = chunk;
            continue;
        }

        let candidate =
            current.chars().count() + usize::from(!current.is_empty()) + word.chars().count();
        if candidate <= width {
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}

fn render_row(context: &Context, cells: &[&str], widths: &[usize], bold: bool) -> Vec<String> {
    let wrapped = cells
        .iter()
        .enumerate()
        .map(|(index, cell)| wrap_text(cell, widths[index]))
        .collect::<Vec<_>>();

    render_cells(context, &wrapped, widths, bold)
}

fn render_cells(
    context: &Context,
    cells: &[Vec<String>],
    widths: &[usize],
    bold: bool,
) -> Vec<String> {
    let height = cells.iter().map(Vec::len).max().unwrap_or(0);
    let mut output = Vec::new();

    for line in 0..height {
        let mut parts = Vec::new();
        for (index, cell) in cells.iter().enumerate() {
            let text = cell.get(line).map_or("", String::as_str);
            let padding = " ".repeat(widths[index].saturating_sub(text.chars().count()));
            if bold {
                parts.push(format!("{}{padding}", context.bold(text)));
            } else {
                parts.push(format!("{text}{padding}"));
            }
        }
        output.push(parts.join(&" ".repeat(GAP)).trim_end().to_owned());
    }

    output
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

        assert!(output.lines().all(|line| line.chars().count() <= 40));
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
    fn minimum_terminal_size_is_enforced() {
        assert!(matches!(
            Context::from_parts(20, 5, true, false),
            Err(UiError::TooSmall { .. })
        ));
        assert!(Context::from_parts(20, 5, false, false).is_ok());
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

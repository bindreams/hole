//! Reads the code of a Rust source well enough to tell which functions it calls however it spells them: the full path,
//! a name imported by `use` (in a group, a glob, or under another name), a turbofish, a method.
//!
//! The guards in the parent module are scans of source text, and a scan of substrings sees one spelling. This one
//! sees what the `use` declarations of the file say a name stands for, comments and string literals aside.

use std::collections::{BTreeSet, HashMap};

// Code without comments and strings -----------------------------------------------------------------------------------

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn blank(c: char) -> char {
    if c == '\n' {
        '\n'
    } else {
        ' '
    }
}

/// `text` with every comment blanked and, unless `keep_strings`, the inside of every string literal too. The result
/// has the same characters in the same places (a blank is a space; line breaks stay), so an offset or a line number
/// found in it holds in `text`.
fn code(text: &str, keep_strings: bool) -> Vec<char> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::with_capacity(chars.len());
    let mut i = 0;
    let text_char = |c: char| if keep_strings { c } else { blank(c) };
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                out.push(' ');
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out.extend([' ', ' ']);
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out.extend([' ', ' ']);
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(blank(chars[i]));
                    i += 1;
                }
            }
        } else if let Some((opener, hashes)) = raw_string_start(&chars, i) {
            // `r#"` ... `"#`: no escapes inside.
            let open = i + opener;
            out.extend(chars[i..open].iter().copied());
            i = open;
            while i < chars.len() {
                let closes =
                    chars[i] == '"' && chars[i + 1..].iter().take(hashes).filter(|c| **c == '#').count() == hashes;
                if closes {
                    break;
                }
                out.push(text_char(chars[i]));
                i += 1;
            }
            let close = (i + 1 + hashes).min(chars.len());
            out.extend(chars[i..close].iter().copied());
            i = close;
        } else if c == '"' {
            out.push('"');
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    out.push(text_char(chars[i]));
                    i += 1;
                }
                out.push(text_char(chars[i]));
                i += 1;
            }
            if i < chars.len() {
                out.push('"');
                i += 1;
            }
        } else if c == '\'' {
            // A character literal (`'"'`, `'\n'`) is kept whole so that its quote does not open a string; anything
            // else is a lifetime.
            let literal = match (next, chars.get(i + 2)) {
                (Some('\\'), _) => chars
                    .get(i + 3..)
                    .and_then(|rest| rest.iter().position(|c| *c == '\''))
                    .map(|at| at + 4),
                (Some(_), Some('\'')) => Some(3),
                _ => None,
            };
            let length = literal.unwrap_or(1);
            out.extend(chars[i..i + length].iter().copied());
            i += length;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// The length of the opening and the number of `#` of a raw string literal (`r"`, `r#"`, `br#"`) that starts at `at`.
fn raw_string_start(chars: &[char], at: usize) -> Option<(usize, usize)> {
    if at > 0 && is_ident(chars[at - 1]) {
        return None;
    }
    let start = match (chars[at], chars.get(at + 1)) {
        ('r', _) => at,
        ('b', Some('r')) => at + 1,
        _ => return None,
    };
    let hashes = chars[start + 1..].iter().take_while(|c| **c == '#').count();
    (chars.get(start + 1 + hashes) == Some(&'"')).then_some((start + 2 + hashes - at, hashes))
}

// Imports -------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Name(String),
    Colons,
    Open,
    Close,
    Comma,
    Star,
}

fn tokens(chars: &[char]) -> Vec<Token> {
    let mut found = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            c if is_ident(c) => {
                let end = chars[i..]
                    .iter()
                    .position(|c| !is_ident(*c))
                    .map_or(chars.len(), |n| i + n);
                found.push(Token::Name(chars[i..end].iter().collect()));
                i = end;
                continue;
            }
            ':' if chars.get(i + 1) == Some(&':') => {
                found.push(Token::Colons);
                i += 1;
            }
            '{' => found.push(Token::Open),
            '}' => found.push(Token::Close),
            ',' => found.push(Token::Comma),
            '*' => found.push(Token::Star),
            _ => {}
        }
        i += 1;
    }
    found
}

/// What the `use` declarations of a file make a name stand for.
#[derive(Debug, Default)]
struct Imports {
    /// A name the file imported, and the path it stands for.
    names: HashMap<String, Vec<String>>,
    /// The prefixes of `use prefix::*`.
    globs: Vec<Vec<String>>,
}

impl Imports {
    fn of(code: &[char]) -> Imports {
        let mut imports = Imports::default();
        let mut i = 0;
        while i < code.len() {
            let at_word = (i == 0 || !is_ident(code[i - 1])) && code[i..].starts_with(&['u', 's', 'e']);
            let word_ends = code.get(i + 3).is_none_or(|c| !is_ident(*c));
            if !(at_word && word_ends) {
                i += 1;
                continue;
            }
            let end = code[i..].iter().position(|c| *c == ';').map_or(code.len(), |n| i + n);
            let declaration = tokens(&code[i + 3..end]);
            imports.add_tree(&declaration, &mut 0, Vec::new());
            i = end;
        }
        imports
    }

    /// One tree of a `use` declaration, below `prefix`: `a::b`, `a::{b, c as d}`, `a::*`.
    fn add_tree(&mut self, declaration: &[Token], at: &mut usize, prefix: Vec<String>) {
        let mut path = prefix;
        loop {
            match declaration.get(*at) {
                Some(Token::Colons) => *at += 1,
                Some(Token::Open) => {
                    *at += 1;
                    while declaration.get(*at).is_some_and(|token| *token != Token::Close) {
                        self.add_tree(declaration, at, path.clone());
                        if declaration.get(*at) == Some(&Token::Comma) {
                            *at += 1;
                        }
                    }
                    *at += 1;
                    return;
                }
                Some(Token::Star) => {
                    *at += 1;
                    self.globs.push(path);
                    return;
                }
                Some(Token::Name(name)) => {
                    *at += 1;
                    path.push(name.clone());
                    if declaration.get(*at) == Some(&Token::Colons) {
                        continue;
                    }
                    if name == "self" {
                        path.pop();
                    }
                    let mut local = path.last().cloned();
                    if matches!(declaration.get(*at), Some(Token::Name(word)) if word == "as") {
                        local = match declaration.get(*at + 1) {
                            Some(Token::Name(alias)) => Some(alias.clone()),
                            _ => None,
                        };
                        *at += 2;
                    }
                    if let Some(local) = local.filter(|local| local != "_") {
                        self.names.insert(local, path);
                    }
                    return;
                }
                // The end of the declaration, or a `,` or `}` for the group around this tree.
                _ => return,
            }
        }
    }

    /// Every path `written` can stand for: as written, with its first segment replaced by what the file imported under
    /// that name, and below each glob import.
    fn resolve(&self, written: &[String]) -> Vec<Vec<String>> {
        let mut found = vec![written.to_vec()];
        if let Some(path) = written.first().and_then(|first| self.names.get(first)) {
            found.push(path.iter().chain(&written[1..]).cloned().collect());
        }
        for glob in &self.globs {
            found.push(glob.iter().chain(written).cloned().collect());
        }
        found
    }
}

// Calls ---------------------------------------------------------------------------------------------------------------

/// One call in a source.
#[derive(Debug)]
pub(super) struct Call {
    /// The line of the call, from 1.
    pub line: usize,
    /// Whether it is `.name(..)` on a value.
    method: bool,
    /// Every path the callee can stand for (see [`Imports::resolve`]).
    paths: Vec<Vec<String>>,
}

impl Call {
    /// Whether the callee is `pattern`: a path whose last segments are the pattern's (`fs::read` is `std::fs::read`
    /// and `tokio::fs::read`), or `.name` for a method. A last segment ending in `*` is a prefix.
    pub fn is(&self, pattern: &str) -> bool {
        let (method, pattern) = match pattern.strip_prefix('.') {
            Some(name) => (true, name),
            None => (false, pattern),
        };
        if method != self.method {
            return false;
        }
        let wanted: Vec<&str> = pattern.split("::").collect();
        self.paths.iter().any(|path| {
            path.len() >= wanted.len()
                && path[path.len() - wanted.len()..]
                    .iter()
                    .zip(&wanted)
                    .enumerate()
                    .all(
                        |(n, (have, want))| match (n + 1 == wanted.len(), want.strip_suffix('*')) {
                            (true, Some(prefix)) => have.starts_with(prefix),
                            _ => have == want,
                        },
                    )
        })
    }

    /// The first path the callee was written as, for a message.
    pub fn written(&self) -> String {
        let shown = if self.method { ".".to_owned() } else { String::new() };
        shown + &self.paths[0].join("::")
    }
}

/// The word before `at`, if it is one.
fn word_before(code: &[char], at: usize) -> String {
    let end = code[..at].iter().rposition(|c| !c.is_whitespace()).map_or(0, |n| n + 1);
    let start = code[..end].iter().rposition(|c| !is_ident(*c)).map_or(0, |n| n + 1);
    code[start..end].iter().collect()
}

/// Past the balanced `<..>` that starts at `at`.
fn after_angles(code: &[char], at: usize) -> usize {
    let mut depth = 0;
    for (n, c) in code[at..].iter().enumerate() {
        match c {
            '<' => depth += 1,
            '>' if !follows_dash(code, at + n) => {
                depth -= 1;
                if depth == 0 {
                    return at + n + 1;
                }
            }
            _ => {}
        }
    }
    code.len()
}

/// Whether the character before `at` is `-`: a `>` there is the arrow `->`, not the end of generics.
fn follows_dash(code: &[char], at: usize) -> bool {
    at > 0 && code[at - 1] == '-'
}

fn skip_space(code: &[char], mut at: usize) -> usize {
    while code.get(at).is_some_and(|c| c.is_whitespace()) {
        at += 1;
    }
    at
}

/// Every call in `text`, resolved through the file's own imports. A function the file defines (`fn read`) is not a
/// call, nor is a macro.
pub(super) fn calls(text: &str) -> Vec<Call> {
    let code = code(text, false);
    let imports = Imports::of(&code);
    let mut found = Vec::new();
    let mut line = 1;
    let mut i = 0;
    while i < code.len() {
        let c = code[i];
        if c == '\n' {
            line += 1;
            i += 1;
            continue;
        }
        if !(c.is_alphabetic() || c == '_') || (i > 0 && is_ident(code[i - 1])) {
            i += 1;
            continue;
        }
        let word = word_before(&code, i);
        let before = code[..i].iter().rposition(|c| !c.is_whitespace());
        let method = before.is_some_and(|b| code[b] == '.' && (b == 0 || code[b - 1] != '.'));
        let mut segments = Vec::new();
        let mut end = i;
        loop {
            let name_end = code[end..]
                .iter()
                .position(|c| !is_ident(*c))
                .map_or(code.len(), |n| end + n);
            segments.push(code[end..name_end].iter().collect::<String>());
            end = name_end;
            let mut next = skip_space(&code, end);
            if !(code[next..].starts_with(&[':', ':'])) {
                break;
            }
            next = skip_space(&code, next + 2);
            if code.get(next) == Some(&'<') {
                end = after_angles(&code, next);
                let after = skip_space(&code, end);
                if !code[after..].starts_with(&[':', ':']) {
                    break;
                }
                next = skip_space(&code, after + 2);
            }
            if !code.get(next).is_some_and(|c| c.is_alphabetic() || *c == '_') {
                break;
            }
            end = next;
        }
        let paren = skip_space(&code, end);
        let is_call = code.get(paren) == Some(&'(') && word != "fn";
        if is_call {
            found.push(Call {
                line,
                method,
                paths: if method {
                    vec![segments.clone()]
                } else {
                    imports.resolve(&segments)
                },
            });
        }
        line += code[i..end].iter().filter(|c| **c == '\n').count();
        i = end.max(i + 1);
    }
    found
}

// Logged paths --------------------------------------------------------------------------------------------------------

/// The macros whose arguments become text: a log line, a message, a panic.
const FORMATTING_MACROS: &[&str] = &[
    "warn",
    "info",
    "debug",
    "error",
    "trace",
    "event",
    "span",
    "format",
    "format_args",
    "print",
    "println",
    "eprint",
    "eprintln",
    "write",
    "writeln",
    "panic",
    "unreachable",
    "todo",
    "unimplemented",
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "bail",
    "anyhow",
];

/// The calls that give a path as text.
const PATH_AS_TEXT: &[&str] = &[".display", ".to_string_lossy"];

/// What, in a `let` binding, makes the binding a path.
const MAKES_A_PATH: &[&str] = &["Path::new(", "PathBuf", ".join(", ".to_path_buf(", ".parent("];

fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + word.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

/// The text of `code` from `at` to the first of `stops` at depth 0 of brackets and angles.
fn until(code: &[char], at: usize, stops: &[char]) -> String {
    let mut depth = 0i32;
    let mut text = String::new();
    for (n, c) in code[at..].iter().enumerate() {
        match c {
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            '>' if !follows_dash(code, at + n) => depth -= 1,
            _ => {}
        }
        if depth < 0 || (depth == 0 && stops.contains(c)) {
            break;
        }
        text.push(*c);
    }
    text
}

/// The names the file declares with a path for a type, or binds to an expression that makes one: `dir: &Path`,
/// `files: Vec<PathBuf>`, `let target = dir.join(NAME)`.
fn path_bindings(code: &[char]) -> Vec<String> {
    let mut found = Vec::new();
    for (i, c) in code.iter().enumerate() {
        let single_colon = *c == ':' && code.get(i + 1) != Some(&':') && (i == 0 || code[i - 1] != ':');
        if single_colon {
            let name_end = code[..i].iter().rposition(|c| !c.is_whitespace()).map_or(0, |n| n + 1);
            let name_start = code[..name_end]
                .iter()
                .rposition(|c| !is_ident(*c))
                .map_or(0, |n| n + 1);
            let name: String = code[name_start..name_end].iter().collect();
            let declared = until(code, i + 1, &[',', ')', '=', ';', '{', '}']);
            if !name.is_empty() && (has_word(&declared, "Path") || has_word(&declared, "PathBuf")) {
                found.push(name);
            }
        }
        if code[i..].starts_with(&['l', 'e', 't', ' ']) && (i == 0 || !is_ident(code[i - 1])) {
            let head = until(code, i + 4, &['=', ';']);
            let name: String = head
                .trim_start()
                .trim_start_matches("mut ")
                .chars()
                .take_while(|c| is_ident(*c))
                .collect();
            let equals = i + 4 + head.chars().count();
            if code.get(equals) == Some(&'=') && !name.is_empty() {
                let value = until(code, equals + 1, &[';']);
                if MAKES_A_PATH.iter().any(|part| value.contains(part)) {
                    found.push(name);
                }
            }
        }
    }
    found
}

/// The lines of `text` where a path becomes text: `.display()` or `.to_string_lossy()` anywhere, and a binding the
/// file declares or builds as a path (see [`path_bindings`]) inside a formatting macro, as an argument, a tracing field
/// (`?dir`, `dir = %dir`) or an inline placeholder (`{dir:?}`). Each as `line: text`, once per line.
///
/// A binding whose type the file does not write (a closure parameter, a pattern) is not known to be a path; a path
/// that reaches a log through one of those is not seen.
pub(super) fn logged_paths(text: &str) -> Vec<String> {
    let blanked = code(text, false);
    let with_strings = code(text, true);
    let bindings = path_bindings(&blanked);
    let mut lines = BTreeSet::new();
    let line_of = |at: usize| blanked[..at].iter().filter(|c| **c == '\n').count() + 1;

    for call in calls(text) {
        if PATH_AS_TEXT.iter().any(|name| call.is(name)) {
            lines.insert(call.line);
        }
    }
    let mut i = 0;
    while i < blanked.len() {
        let starts_a_name = (blanked[i].is_alphabetic() || blanked[i] == '_') && (i == 0 || !is_ident(blanked[i - 1]));
        if !starts_a_name {
            i += 1;
            continue;
        }
        let end = blanked[i..]
            .iter()
            .position(|c| !is_ident(*c))
            .map_or(blanked.len(), |n| i + n);
        let name: String = blanked[i..end].iter().collect();
        let open = skip_space(&blanked, end + 1);
        let is_macro = blanked.get(end) == Some(&'!') && matches!(blanked.get(open), Some('(' | '[' | '{'));
        if !(is_macro && FORMATTING_MACROS.contains(&name.as_str())) {
            i = end;
            continue;
        }
        let mut depth = 0;
        let close = blanked[open..]
            .iter()
            .position(|c| {
                match c {
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' => depth -= 1,
                    _ => {}
                }
                depth == 0
            })
            .map_or(blanked.len(), |n| open + n);
        for at in open..close {
            let in_string = blanked[at] != with_strings[at];
            let placeholder = in_string
                && with_strings[at] == '{'
                && with_strings.get(at + 1) != Some(&'{')
                && (at == 0 || with_strings[at - 1] != '{');
            if placeholder {
                let inline: String = with_strings[at + 1..close]
                    .iter()
                    .take_while(|c| is_ident(**c))
                    .collect();
                if bindings.contains(&inline) {
                    lines.insert(line_of(at));
                }
                continue;
            }
            let starts_here = (blanked[at].is_alphabetic() || blanked[at] == '_') && !is_ident(blanked[at - 1]);
            if !starts_here || blanked[at - 1] == ':' || blanked[at - 1] == '\'' {
                continue;
            }
            let word_end = blanked[at..]
                .iter()
                .position(|c| !is_ident(*c))
                .map_or(blanked.len(), |n| at + n);
            let word: String = blanked[at..word_end].iter().collect();
            let after = skip_space(&blanked, word_end);
            let is_field_name = blanked.get(after) == Some(&'=') && !matches!(blanked.get(after + 1), Some('=' | '>'));
            if bindings.contains(&word) && !is_field_name {
                lines.insert(line_of(at));
            }
        }
        i = end;
    }
    let source: Vec<&str> = text.lines().collect();
    lines
        .into_iter()
        .map(|line| format!("{line}: {}", source.get(line - 1).map_or("", |text| text.trim())))
        .collect()
}

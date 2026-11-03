//! F-026 — integer literals mean what their host language says they mean.
//!
//! A port of the TS reference (packages/runar-compiler/src/passes/int-literal.ts,
//! user decision R15). Every hand-written tokenizer scans a number token over
//! every `[0-9A-Za-z_]` character glued to its first digit and validates the
//! whole token against the surface's host-language grammar. The table every
//! tier must reproduce is conformance/negatives/int-literal-cases.json.
//!
//! A lowercase `0x` on .runar.sol / .runar.move / .runar.rs is a Rúnar
//! ByteString literal, handled by those tokenizers before a number is scanned;
//! on every other surface `0x` is a hexadecimal integer.

use num_bigint::BigInt;
use num_traits::One;

/// A validated literal. `neg_only` marks a literal valid only as the operand
/// of a unary minus (Java `2147483648`, Rust `128i8`); `value` is then the
/// positive magnitude.
#[derive(Debug, Clone)]
pub struct IntLiteral {
    pub value: BigInt,
    pub neg_only: bool,
}

fn language(surface: &str) -> &'static str {
    match surface {
        "ts" => "TypeScript",
        "sol" => "Solidity",
        "move" => "Move",
        "go" => "Go",
        "rs" => "Rust",
        "py" => "Python",
        "zig" => "Zig",
        "rb" => "Ruby",
        "java" => "Java",
        _ => "unknown",
    }
}

/// The TS reference's `invalidIntegerLiteral()`.
pub fn invalid_integer_literal(surface: &str, text: &str) -> String {
    format!("invalid {} integer literal '{}'", language(surface), text)
}

/// A character that continues a number token.
pub fn is_number_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

/// End (exclusive) of the number token whose first digit is at `pos`.
pub fn scan_number_end(chars: &[char], pos: usize) -> usize {
    let mut i = pos + 1;
    while i < chars.len() && is_number_continue(chars[i]) {
        i += 1;
    }
    i
}

/// Where `_` may appear in a digit run.
#[derive(Clone, Copy)]
enum Sep {
    /// `d(_?d)*`: single separators, strictly between digits.
    Single,
    /// `(_?d)+`: as Single, plus one separator before the first digit.
    LeadSingle,
    /// `d([d_]*d)?`: repeatable separators between digits (Java).
    Java,
    /// `[d_]*d`: any separators, a digit last (Java octal after its `0`).
    LastDigit,
    /// `[d_]*` with at least one digit (Rust).
    Loose,
}

fn digits_ok(s: &str, radix: u32, sep: Sep) -> bool {
    let cs: Vec<char> = s.chars().collect();
    if cs.is_empty() || !cs.iter().all(|&c| c == '_' || c.is_digit(radix)) || !cs.iter().any(|&c| c != '_') {
        return false;
    }
    let first_digit = cs[0] != '_';
    let last_digit = *cs.last().unwrap() != '_';
    let no_double = !s.contains("__");
    match sep {
        Sep::Single => first_digit && last_digit && no_double,
        Sep::LeadSingle => last_digit && no_double,
        Sep::Java => first_digit && last_digit,
        Sep::LastDigit => last_digit,
        Sep::Loose => true,
    }
}

fn value(s: &str, radix: u32) -> BigInt {
    let clean: String = s.chars().filter(|&c| c != '_').collect();
    BigInt::parse_bytes(clean.as_bytes(), radix).unwrap_or_default()
}

fn pow2(n: u32) -> BigInt {
    BigInt::one() << n
}

fn ok(v: BigInt) -> Option<IntLiteral> {
    Some(IntLiteral { value: v, neg_only: false })
}

/// `0<p>digits` with the prefix letter(s) in `prefixes`; the digit run obeys `sep`.
fn prefixed(text: &str, prefixes: &str, radix: u32, sep: Sep) -> Option<IntLiteral> {
    let b: Vec<char> = text.chars().collect();
    if b.len() >= 2 && b[0] == '0' && prefixes.contains(b[1]) {
        let rest = &text[2..];
        if digits_ok(rest, radix, sep) {
            return ok(value(rest, radix));
        }
    }
    None
}

/// `0 | [1-9](_?d)*`
fn plain_decimal(text: &str) -> bool {
    text == "0" || (text.starts_with(|c: char| ('1'..='9').contains(&c)) && digits_ok(text, 10, Sep::Single))
}

fn parse_ts(text: &str) -> Option<IntLiteral> {
    let body = text.strip_suffix('n').unwrap_or(text);
    if plain_decimal(body) {
        return ok(value(body, 10));
    }
    prefixed(body, "xX", 16, Sep::Single)
        .or_else(|| prefixed(body, "oO", 8, Sep::Single))
        .or_else(|| prefixed(body, "bB", 2, Sep::Single))
}

fn parse_move(text: &str) -> Option<IntLiteral> {
    let mut body = text;
    let mut bits = 256;
    for (s, b) in [("u256", 256), ("u128", 128), ("u64", 64), ("u32", 32), ("u16", 16), ("u8", 8)] {
        if let Some(stripped) = text.strip_suffix(s) {
            body = stripped;
            bits = b;
            break;
        }
    }
    if !body.starts_with(|c: char| c.is_ascii_digit()) || !body.chars().all(|c| c.is_ascii_digit() || c == '_') {
        return None;
    }
    let v = value(body, 10);
    if v < pow2(bits) {
        ok(v)
    } else {
        None
    }
}

fn parse_go(text: &str) -> Option<IntLiteral> {
    if plain_decimal(text) {
        return ok(value(text, 10));
    }
    if text.len() > 1 && text.starts_with('0') && digits_ok(&text[1..], 8, Sep::LeadSingle) {
        return ok(value(&text[1..], 8));
    }
    prefixed(text, "xX", 16, Sep::LeadSingle)
        .or_else(|| prefixed(text, "oO", 8, Sep::LeadSingle))
        .or_else(|| prefixed(text, "bB", 2, Sep::LeadSingle))
}

const RUST_SUFFIXES: [(&str, u32, bool); 12] = [
    ("i128", 128, true), ("isize", 64, true), ("i16", 16, true), ("i32", 32, true), ("i64", 64, true), ("i8", 8, true),
    ("u128", 128, false), ("usize", 64, false), ("u16", 16, false), ("u32", 32, false), ("u64", 64, false), ("u8", 8, false),
];

fn rust_body(body: &str) -> Option<BigInt> {
    let (digits, radix) = if let Some(d) = body.strip_prefix("0x") {
        (d, 16)
    } else if let Some(d) = body.strip_prefix("0o") {
        (d, 8)
    } else if let Some(d) = body.strip_prefix("0b") {
        (d, 2)
    } else {
        if !body.starts_with(|c: char| c.is_ascii_digit()) {
            return None;
        }
        (body, 10)
    };
    if digits_ok(digits, radix, Sep::Loose) {
        Some(value(digits, radix))
    } else {
        None
    }
}

fn parse_rust(text: &str) -> Option<IntLiteral> {
    // Unsuffixed values are unbounded: rustc stops at u128::MAX, but Rúnar's
    // Int is a bigint and the corpus spells 256-bit constants this way.
    if let Some(v) = rust_body(text) {
        return ok(v);
    }
    for (suffix, bits, signed) in RUST_SUFFIXES {
        if let Some(body) = text.strip_suffix(suffix) {
            let v = rust_body(body)?;
            if !signed {
                return if v < pow2(bits) { ok(v) } else { None };
            }
            let min = pow2(bits - 1);
            if v < min {
                return ok(v);
            }
            return if v == min { Some(IntLiteral { value: v, neg_only: true }) } else { None };
        }
    }
    None
}

fn parse_py(text: &str) -> Option<IntLiteral> {
    let zeros = text.starts_with('0') && text.chars().all(|c| c == '0' || c == '_') && digits_ok(text, 10, Sep::Single);
    if zeros || (text.starts_with(|c: char| ('1'..='9').contains(&c)) && digits_ok(text, 10, Sep::Single)) {
        return ok(value(text, 10));
    }
    prefixed(text, "xX", 16, Sep::LeadSingle)
        .or_else(|| prefixed(text, "oO", 8, Sep::LeadSingle))
        .or_else(|| prefixed(text, "bB", 2, Sep::LeadSingle))
}

fn parse_zig(text: &str) -> Option<IntLiteral> {
    if plain_decimal(text) {
        return ok(value(text, 10));
    }
    prefixed(text, "x", 16, Sep::Single)
        .or_else(|| prefixed(text, "o", 8, Sep::Single))
        .or_else(|| prefixed(text, "b", 2, Sep::Single))
}

fn parse_rb(text: &str) -> Option<IntLiteral> {
    if plain_decimal(text) {
        return ok(value(text, 10));
    }
    if text.len() > 1 && text.starts_with('0') && digits_ok(&text[1..], 8, Sep::LeadSingle) {
        return ok(value(&text[1..], 8));
    }
    prefixed(text, "dD", 10, Sep::Single)
        .or_else(|| prefixed(text, "xX", 16, Sep::Single))
        .or_else(|| prefixed(text, "oO", 8, Sep::Single))
        .or_else(|| prefixed(text, "bB", 2, Sep::Single))
}

fn parse_java(text: &str) -> Option<IntLiteral> {
    let (body, bits) = match text.strip_suffix(['L', 'l']) {
        Some(b) => (b, 64u32),
        None => (text, 32u32),
    };
    if body == "0" || (body.starts_with(|c: char| ('1'..='9').contains(&c)) && digits_ok(body, 10, Sep::Java)) {
        let v = value(body, 10);
        let min = pow2(bits - 1);
        if v < min {
            return ok(v);
        }
        return if v == min { Some(IntLiteral { value: v, neg_only: true }) } else { None };
    }
    let b: Vec<char> = body.chars().collect();
    let v = if b.len() >= 2 && b[0] == '0' && "xX".contains(b[1]) && digits_ok(&body[2..], 16, Sep::Java) {
        value(&body[2..], 16)
    } else if b.len() >= 2 && b[0] == '0' && "bB".contains(b[1]) && digits_ok(&body[2..], 2, Sep::Java) {
        value(&body[2..], 2)
    } else if b.len() >= 2 && b[0] == '0' && digits_ok(&body[1..], 8, Sep::LastDigit) {
        value(&body[1..], 8)
    } else {
        return None;
    };
    if v >= pow2(bits) {
        return None;
    }
    if v >= pow2(bits - 1) {
        return ok(v - pow2(bits));
    }
    ok(v)
}

/// The value of the integer literal `text` (the whole number token) on
/// `surface`, or None when the host language rejects it.
pub fn parse_int_literal(surface: &str, text: &str) -> Option<IntLiteral> {
    match surface {
        "ts" => parse_ts(text),
        "sol" => {
            if plain_decimal(text) {
                ok(value(text, 10))
            } else {
                None
            }
        }
        "move" => parse_move(text),
        "go" => parse_go(text),
        "rs" => parse_rust(text),
        "py" => parse_py(text),
        "zig" => parse_zig(text),
        "rb" => parse_rb(text),
        "java" => parse_java(text),
        _ => None,
    }
}

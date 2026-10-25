//! Python parser for Rúnar contracts (.runar.py).
//!
//! Parses Python-style contract definitions using a hand-written tokenizer
//! with INDENT/DEDENT tokens and recursive descent parser.
//! Produces the same AST as the TypeScript parser.
//!
//! ## Expected format
//!
//! ```python
//! from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig
//!
//! class P2PKH(SmartContract):
//!     pub_key_hash: Addr
//!
//!     def __init__(self, pub_key_hash: Addr):
//!         super().__init__(pub_key_hash)
//!         self.pub_key_hash = pub_key_hash
//!
//!     @public
//!     def unlock(self, sig: Sig, pub_key: PubKey):
//!         assert_(hash160(pub_key) == self.pub_key_hash)
//!         assert_(check_sig(sig, pub_key))
//! ```
//!
//! Key mappings:
//! - `class Foo(SmartContract):` -> contract
//! - `@public` decorator -> Visibility::Public
//! - `self.prop` -> PropertyAccess (like `this.prop`)
//! - `assert_(expr)` or `assert expr` -> assert(expr)
//! - `//` integer division -> Div in AST (OP_DIV)
//! - `and`/`or`/`not` -> And/Or/Not operators
//! - `==`/`!=` -> StrictEq/StrictNe
//! - `Readonly[T]` -> readonly property
//! - `for i in range(n):` -> ForStatement
//! - snake_case identifiers -> camelCase in AST

use num_bigint::BigInt;
use num_traits::ToPrimitive;
use super::ast::{
    BinaryOp, ContractNode, Expression, MethodNode, ParamNode, PrimitiveTypeName, PropertyNode,
    SourceLocation, Statement, TypeNode, UnaryOp, Visibility,
};
use super::diagnostic::{
    invalid_escape_sequence_message, lex_error, static_method_message,
    unexpected_class_body_token_message, unexpected_token_after_class_message, unknown_return_type_message, unsupported_statement_message, Diagnostic, PY_BYTES_NON_ASCII, PY_STATEMENT_LINE_BREAK,
    UNTERMINATED_STRING_LITERAL,
};
use super::int_literal::{invalid_integer_literal, parse_int_literal, scan_number_end};
use super::sighash_directive::{lost_directive_message, resolve_native_sighash};
use super::identifier_collision::DeclaredIdents;
use super::input_limits::{enforce_ast_nesting, nesting_refusal, DepthTracker, NestingCounter};
use super::parser::ParseResult;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a Python-format Rúnar contract source.
pub fn parse_python(source: &str, file_name: Option<&str>) -> ParseResult {
    // DoS-bound size guard, enforced at every exported parser entry, not
    // just parse_source. N-136.
    if let Some(sse) = super::input_limits::assert_source_bytes_under_limit(source) {
        return ParseResult {
            contract: None,
            errors: vec![Diagnostic::error(sse.to_string(), None)],
            source_size_err: Some(sse),
        };
    }
    // F-213: the parse runs on its own stack segment, so its bounded
    // recursion fits whatever stack the caller runs on (a 2 MiB thread,
    // a debug build).
    super::input_limits::run_on_parse_stack(|| parse_python_on_parse_stack(source, file_name))
}

/// The body of [`parse_python`], on the parse stack segment.
fn parse_python_on_parse_stack(source: &str, file_name: Option<&str>) -> ParseResult {
    let file = file_name.unwrap_or("contract.runar.py");
    let mut errors: Vec<Diagnostic> = Vec::new();

    let (tokens, positions) = tokenize(source, file, &mut errors);
    let mut parser = PyParser::new(tokens, positions, file, &mut errors);

    let contract = parser.parse_contract();
    // F-213 measure (A), then measure (B) on the finished tree.
    if parser.nest.exceeded() {
        return nesting_refusal(None);
    }
    let collision = parser.idents.collision_diagnostic();
    if contract.is_some() {
        errors.extend(collision);
    }

    enforce_ast_nesting(ParseResult { contract, errors, source_size_err: None })
}

// ---------------------------------------------------------------------------
// Name conversion helpers
// ---------------------------------------------------------------------------

/// Convert snake_case to camelCase. Single words pass through unchanged.
/// Strips trailing underscore (e.g. `sum_` -> `sum`, `assert_` -> `assert`).
/// Emitted for a `range` step the unrolled loop model cannot represent.
///
/// Shared verbatim with the other six tiers.
const RANGE_STEP_DIAGNOSTIC: &str = concat!(
    "range() step must be 1 or -1. The unrolled loop carries only a start value ",
    "and a unit step, so any other step -- range(0, 10, 2), say -- cannot be ",
    "represented and would be discarded."
);

/// The integer value of a literal expression, or `None` when it is not one.
///
/// A negative literal arrives as a unary minus over a positive one, so both
/// shapes have to be walked — the same walk `extract_big_int_value` does in
/// ANF lowering, for the same reason (N-138).
fn literal_int_value(expr: &Expression) -> Option<BigInt> {
    match expr {
        Expression::BigIntLiteral { value } => Some(value.clone()),
        Expression::UnaryExpr { op, operand } if *op == UnaryOp::Neg => {
            literal_int_value(operand).map(|v| -v)
        }
        _ => None,
    }
}

/// N-404: the AST name of a contract METHOD (declaration and `self.<m>(...)`
/// call). Generic snake->camel, except `require_output_p2pkh`, which keeps the
/// intrinsic's spelling like every other tier, so a method of that name hits
/// the `requireOutputP2PKH` refusal instead of being accepted as
/// `requireOutputP2pkh`.
fn method_ast_name(name: &str) -> String {
    if name == "require_output_p2pkh" {
        "requireOutputP2PKH".to_string()
    } else {
        snake_to_camel(name)
    }
}

fn snake_to_camel(name: &str) -> String {
    // Preserve dunder names (__init__, __foo__) unchanged
    if name.len() >= 4 && name.starts_with("__") && name.ends_with("__") {
        return name.to_string();
    }

    // Strip trailing underscore (e.g. assert_ -> assert)
    let mut n: &str = if name.ends_with('_') && name != "_" {
        &name[..name.len() - 1]
    } else {
        name
    };

    // Strip leading single underscore for private methods (Python convention:
    // _helper -> helper). Matches Go/Python/Zig/Ruby parser behavior.
    if n.starts_with('_') && !n.starts_with("__") {
        n = &n[1..];
    }

    let mut result = String::new();
    let mut capitalize_next = false;

    for ch in n.chars() {
        if ch == '_' {
            capitalize_next = true;
        } else if capitalize_next {
            result.push(ch.to_ascii_uppercase());
            capitalize_next = false;
        } else {
            result.push(ch);
        }
    }

    result
}

/// Map Python builtin function names to Rúnar AST callee names.
fn map_builtin_name(name: &str) -> String {
    // Exact-match special cases (names that don't follow simple snake_case -> camelCase)
    match name {
        "assert_" => return "assert".to_string(),
        "verify_wots" => return "verifyWOTS".to_string(),
        "verify_slh_dsa_sha2_128s" => return "verifySLHDSA_SHA2_128s".to_string(),
        "verify_slh_dsa_sha2_128f" => return "verifySLHDSA_SHA2_128f".to_string(),
        "verify_slh_dsa_sha2_192s" => return "verifySLHDSA_SHA2_192s".to_string(),
        "verify_slh_dsa_sha2_192f" => return "verifySLHDSA_SHA2_192f".to_string(),
        "verify_slh_dsa_sha2_256s" => return "verifySLHDSA_SHA2_256s".to_string(),
        "verify_slh_dsa_sha2_256f" => return "verifySLHDSA_SHA2_256f".to_string(),
        "verify_rabin_sig" => return "verifyRabinSig".to_string(),
        "check_sig" => return "checkSig".to_string(),
        "check_multi_sig" => return "checkMultiSig".to_string(),
        "check_preimage" => return "checkPreimage".to_string(),
        "hash160" => return "hash160".to_string(),
        "hash256" => return "hash256".to_string(),
        "sha256" => return "sha256".to_string(),
        "ripemd160" => return "ripemd160".to_string(),
        "num2bin" => return "num2bin".to_string(),
        "reverse_bytes" => return "reverseBytes".to_string(),
        "extract_locktime" => return "extractLocktime".to_string(),
        "extract_output_hash" => return "extractOutputHash".to_string(),
        "extract_amount" => return "extractAmount".to_string(),
        "extract_version" => return "extractVersion".to_string(),
        "extract_sequence" => return "extractSequence".to_string(),
        "ec_add" => return "ecAdd".to_string(),
        "ec_mul" => return "ecMul".to_string(),
        "ec_mul_gen" => return "ecMulGen".to_string(),
        "ec_negate" => return "ecNegate".to_string(),
        "ec_on_curve" => return "ecOnCurve".to_string(),
        "ec_mod_reduce" => return "ecModReduce".to_string(),
        "ec_encode_compressed" => return "ecEncodeCompressed".to_string(),
        "ec_make_point" => return "ecMakePoint".to_string(),
        "ec_point_x" => return "ecPointX".to_string(),
        "ec_point_y" => return "ecPointY".to_string(),
        "mul_div" => return "mulDiv".to_string(),
        "percent_of" => return "percentOf".to_string(),
        // Names the mechanical snake -> camel rule cannot produce: a digit
        // ('to' -> '2') or an all-lowercase builtin with no interior capital.
        "int_to_str" => return "int2str".to_string(),
        "safe_div" => return "safediv".to_string(),
        "safe_mod" => return "safemod".to_string(),
        "div_mod" => return "divmod".to_string(),
        // The all-caps PKH token does not survive snake -> camel either
        // (it would come back as `requireOutputP2pkh`).
        "require_output_p2pkh" => return "requireOutputP2PKH".to_string(),
        "add_output" => return "addOutput".to_string(),
        "add_raw_output" => return "addRawOutput".to_string(),
        "add_data_output" => return "addDataOutput".to_string(),
        "get_state_script" => return "getStateScript".to_string(),
        "p256_add" => return "p256Add".to_string(),
        "p256_mul" => return "p256Mul".to_string(),
        "p256_mul_gen" => return "p256MulGen".to_string(),
        "p256_negate" => return "p256Negate".to_string(),
        "p256_on_curve" => return "p256OnCurve".to_string(),
        "p256_encode_compressed" => return "p256EncodeCompressed".to_string(),
        "verify_ecdsa_p256" => return "verifyECDSA_P256".to_string(),
        "p384_add" => return "p384Add".to_string(),
        "p384_mul" => return "p384Mul".to_string(),
        "p384_mul_gen" => return "p384MulGen".to_string(),
        "p384_negate" => return "p384Negate".to_string(),
        "p384_on_curve" => return "p384OnCurve".to_string(),
        "p384_encode_compressed" => return "p384EncodeCompressed".to_string(),
        "verify_ecdsa_p384" => return "verifyECDSA_P384".to_string(),
        _ => {}
    }

    // Names that pass through unchanged
    match name {
        "bool" | "abs" | "min" | "max" | "len" | "pow" | "cat" | "within" | "safediv"
        | "safemod" | "clamp" | "sign" | "sqrt" | "gcd" | "divmod" | "log2" | "substr" => {
            return name.to_string();
        }
        _ => {}
    }

    // Default: snake_case -> camelCase
    snake_to_camel(name)
}

/// Map Python type names to Rúnar AST types.
fn map_py_type(name: &str) -> &str {
    match name {
        "Bigint" | "int" | "Int" => "bigint",
        "bool" | "Bool" => "boolean",
        "ByteString" | "bytes" => "ByteString",
        "PubKey" => "PubKey",
        "Sig" => "Sig",
        "Addr" => "Addr",
        "Sha256" => "Sha256",
        "Sha256Digest" => "Sha256",
        "Ripemd160" => "Ripemd160",
        "SigHashPreimage" => "SigHashPreimage",
        "RabinSig" => "RabinSig",
        "RabinPubKey" => "RabinPubKey",
        "Point" => "Point",
        "P256Point" => "P256Point",
        "P384Point" => "P384Point",
        _ => name,
    }
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    // Keywords
    Class,
    Def,
    If,
    Elif,
    Else,
    For,
    In,
    Range,
    Return,
    Pass,
    TrueLit,
    FalseLit,
    NoneLit,
    And,
    Or,
    Not,
    SelfKw,
    Super,
    From,
    Import,
    Assert,

    // Identifiers and literals
    Ident(String),
    NumberLit(BigInt),
    HexStringLit(String),
    StringLit(String),

    // Decorators
    At,

    // Operators
    Plus,
    Minus,
    Star,
    Slash,
    IntDiv,       // //
    Percent,
    DoubleStar,   // **
    EqEq,         // ==
    NotEq,        // !=
    Lt,
    Le,
    Gt,
    Ge,
    LShift,       // <<
    RShift,       // >>
    BitAnd,       // &
    BitOr,        // |
    BitXor,       // ^
    Tilde,        // ~
    Bang,         // !
    Eq,           // =
    PlusEq,       // +=
    MinusEq,      // -=
    StarEq,       // *=
    SlashEq,      // /=
    IntDivEq,     // //=
    PercentEq,    // %=
    Arrow,        // ->

    // Delimiters
    LParen,
    RParen,
    LBracket,
    RBracket,
    Colon,
    Comma,
    Dot,

    // Indentation
    Indent,
    Dedent,
    Newline,

    // Special
    Eof,
}

/// A token's source text, for a diagnostic (N-053).
fn py_token_text(tok: &Token) -> String {
    match tok {
        Token::Class => "class".into(),
        Token::Def => "def".into(),
        Token::Elif => "elif".into(),
        Token::Else => "else".into(),
        Token::In => "in".into(),
        Token::Range => "range".into(),
        Token::And => "and".into(),
        Token::Or => "or".into(),
        Token::From => "from".into(),
        Token::Import => "import".into(),
        Token::At => "@".into(),
        Token::Plus => "+".into(),
        Token::Star => "*".into(),
        Token::Slash => "/".into(),
        Token::IntDiv => "//".into(),
        Token::Percent => "%".into(),
        Token::DoubleStar => "**".into(),
        Token::EqEq => "==".into(),
        Token::NotEq => "!=".into(),
        Token::Lt => "<".into(),
        Token::Le => "<=".into(),
        Token::Gt => ">".into(),
        Token::Ge => ">=".into(),
        Token::LShift => "<<".into(),
        Token::RShift => ">>".into(),
        Token::BitAnd => "&".into(),
        Token::BitOr => "|".into(),
        Token::BitXor => "^".into(),
        Token::Eq => "=".into(),
        Token::PlusEq => "+=".into(),
        Token::MinusEq => "-=".into(),
        Token::StarEq => "*=".into(),
        Token::SlashEq => "/=".into(),
        Token::IntDivEq => "//=".into(),
        Token::PercentEq => "%=".into(),
        Token::Arrow => "->".into(),
        Token::RParen => ")".into(),
        Token::RBracket => "]".into(),
        Token::Colon => ":".into(),
        Token::Comma => ",".into(),
        Token::Dot => ".".into(),
        Token::Ident(name) => name.clone(),
        Token::NumberLit(n) => n.to_string(),
        Token::Indent => "INDENT".into(),
        Token::Dedent => "DEDENT".into(),
        Token::Newline => "NEWLINE".into(),
        Token::Eof => "eof".into(),
        other => format!("{:?}", other),
    }
}

/// F-203: the single-character escapes CPython defines for bytes and str.
fn py_simple_escape(c: char) -> Option<u32> {
    Some(match c {
        '\\' => 0x5c,
        '\'' => 0x27,
        '"' => 0x22,
        'a' => 0x07,
        'b' => 0x08,
        'f' => 0x0c,
        'n' => 0x0a,
        'r' => 0x0d,
        't' => 0x09,
        'v' => 0x0b,
        _ => return None,
    })
}

/// F-203: decode the body of a .runar.py quoted literal the way CPython decodes
/// a bytes (`bytes = true`) or str literal (the TS reference's
/// `decodePyLiteral`). Returns the decoded text, its bytes as hex (meaningful
/// for bytes only; `\xHH` keeps its digits verbatim) and the first refusal. A
/// trailing lone backslash only arises for an unterminated literal, which the
/// tokenizer already refuses; it is dropped.
fn decode_py_literal(body: &[char], bytes: bool) -> (String, String, Option<String>) {
    let mut text = String::new();
    let mut hex = String::new();
    let mut i = 0;
    macro_rules! push {
        ($v:expr) => {{
            let v: u32 = $v;
            text.push(char::from_u32(v).unwrap_or('\u{fffd}'));
            hex.push_str(&format!("{:02x}", v));
        }};
    }
    while i < body.len() {
        let c = body[i];
        if bytes && (c as u32) >= 0x80 {
            return (text, hex, Some(PY_BYTES_NON_ASCII.to_string()));
        }
        if c != '\\' {
            text.push(c);
            if bytes {
                hex.push_str(&format!("{:02x}", c as u32));
            }
            i += 1;
            continue;
        }
        if i + 1 >= body.len() {
            break;
        }
        let e = body[i + 1];
        if let Some(v) = py_simple_escape(e) {
            push!(v);
            i += 2;
            continue;
        }
        if ('0'..='7').contains(&e) {
            let mut j = i + 1;
            while j < body.len() && j < i + 4 && ('0'..='7').contains(&body[j]) {
                j += 1;
            }
            let digits: String = body[i + 1..j].iter().collect();
            let v = u32::from_str_radix(&digits, 8).unwrap_or(0);
            if v > 0xff {
                let esc: String = body[i..j].iter().collect();
                return (text, hex, Some(invalid_escape_sequence_message(&esc)));
            }
            push!(v);
            i = j;
            continue;
        }
        if e == 'x' {
            let ok = i + 3 < body.len() && body[i + 2].is_ascii_hexdigit() && body[i + 3].is_ascii_hexdigit();
            if !ok {
                return (text, hex, Some(invalid_escape_sequence_message("\\x")));
            }
            let digits: String = body[i + 2..i + 4].iter().collect();
            text.push(char::from_u32(u32::from_str_radix(&digits, 16).unwrap_or(0)).unwrap_or('\u{fffd}'));
            hex.push_str(&digits);
            i += 4;
            continue;
        }
        if bytes && (e as u32) >= 0x80 {
            return (text, hex, Some(PY_BYTES_NON_ASCII.to_string()));
        }
        // Anything else -- including str's \N{..}, \u and \U, which the surface
        // does not support -- is refused.
        return (text, hex, Some(invalid_escape_sequence_message(&format!("\\{}", e))));
    }
    (text, hex, None)
}

/// F-203: scan a single-line quoted literal starting just after its opening
/// quote (the TS reference's `scanPyQuoted`). A backslash always takes the
/// next character with it, so an escaped quote does not close the literal; a
/// backslash at the line break leaves the literal unterminated. Returns the
/// body, the index just past the scan, and whether the literal was closed.
fn scan_py_quoted(chars: &[char], start: usize, quote: char) -> (&[char], usize, bool) {
    let mut pos = start;
    while pos < chars.len() && chars[pos] != quote {
        pos += if chars[pos] == '\\' { 2 } else { 1 };
    }
    if pos > chars.len() {
        pos = chars.len();
    }
    let body = &chars[start.min(pos)..pos];
    if pos < chars.len() {
        (body, pos + 1, true)
    } else {
        (body, pos, false)
    }
}

/// Returns the tokens and, index for index, the (1-based line, 1-based
/// column — the AST convention; codegen/emit.rs converts) where each one
/// starts (F-337).
fn tokenize(source: &str, file: &str, errors: &mut Vec<Diagnostic>) -> (Vec<Token>, Vec<(usize, usize)>) {
    let mut tokens = Vec::new();
    let mut positions: Vec<(usize, usize)> = Vec::new();
    let mut at: (usize, usize) = (1, 0);
    let lines: Vec<&str> = source.split('\n').collect();
    let mut indent_stack: Vec<usize> = vec![0];
    let mut paren_depth: usize = 0;
    // When Some(c), we're inside a multi-line triple-quoted string and c is
    // the quote character (' or ").  Each line is skipped until we find the
    // closing triple-quote.
    let mut in_triple_quote: Option<char> = None;
    // F-011: where the open triple-quoted string started (1-based line,
    // 0-based column); still open at end of file means unterminated.
    let mut triple_start: (usize, usize) = (0, 0);

    for (line_idx, raw_line) in lines.iter().enumerate() {
        let line_num = line_idx + 1;
        // Strip trailing \r
        let line = if raw_line.ends_with('\r') {
            &raw_line[..raw_line.len() - 1]
        } else {
            raw_line
        };

        // If we're inside a multi-line triple-quoted docstring, skip lines
        // until we find the closing triple-quote.
        if let Some(q) = in_triple_quote {
            let needle: String = std::iter::repeat(q).take(3).collect();
            if line.contains(&needle) {
                in_triple_quote = None;
            }
            continue;
        }

        // Skip blank lines and comment-only lines (they don't affect indentation)
        let stripped = line.trim_start();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }

        // Skip lines that start with a triple-quoted docstring
        if stripped.starts_with("\"\"\"") || stripped.starts_with("'''") {
            let q = stripped.chars().next().unwrap();
            let needle: String = std::iter::repeat(q).take(3).collect();
            // Check for closing triple-quote on the same line (after the opener)
            let after_open = &stripped[3..];
            if after_open.contains(&needle) {
                // Single-line docstring
            } else {
                // Multi-line docstring
                in_triple_quote = Some(q);
                triple_start = (line_num, line.chars().count() - stripped.chars().count());
            }
            continue;
        }

        let chars: Vec<char> = line.chars().collect();

        // Compute indent level (only at paren depth 0)
        if paren_depth == 0 {
            let mut indent = 0usize;
            for &ch in &chars {
                if ch == ' ' {
                    indent += 1;
                } else if ch == '\t' {
                    indent += 4;
                } else {
                    break;
                }
            }

            let current_indent = *indent_stack.last().unwrap();
            if indent > current_indent {
                indent_stack.push(indent);
                tokens.push(Token::Indent);
            } else if indent < current_indent {
                while indent_stack.len() > 1 && *indent_stack.last().unwrap() > indent {
                    indent_stack.pop();
                    tokens.push(Token::Dedent);
                }
            }
        }

        // Tokenize the content of this line
        let start_offset = chars.len() - stripped.len();
        let mut pos = start_offset;

        while pos < chars.len() {
            // Tokens pushed by the previous iteration started at `at`.
            positions.resize(tokens.len(), at);
            at = (line_num, pos + 1);
            let ch = chars[pos];

            // Whitespace within line
            if ch == ' ' || ch == '\t' {
                pos += 1;
                continue;
            }

            // Comment
            if ch == '#' {
                break; // rest of line is comment
            }

            // Decorators
            if ch == '@' {
                pos += 1;
                tokens.push(Token::At);
                continue;
            }

            // Three-char operators: //=
            if ch == '/'
                && pos + 2 < chars.len()
                && chars[pos + 1] == '/'
                && chars[pos + 2] == '='
            {
                tokens.push(Token::IntDivEq);
                pos += 3;
                continue;
            }

            // Two-char operators: ** // == != <= >= << >> += -= *= /= %= ->
            if ch == '*' && pos + 1 < chars.len() && chars[pos + 1] == '*' {
                tokens.push(Token::DoubleStar);
                pos += 2;
                continue;
            }
            if ch == '/' && pos + 1 < chars.len() && chars[pos + 1] == '/' {
                tokens.push(Token::IntDiv);
                pos += 2;
                continue;
            }
            if ch == '=' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::EqEq);
                pos += 2;
                continue;
            }
            if ch == '!' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::NotEq);
                pos += 2;
                continue;
            }
            if ch == '<' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::Le);
                pos += 2;
                continue;
            }
            if ch == '>' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::Ge);
                pos += 2;
                continue;
            }
            if ch == '<' && pos + 1 < chars.len() && chars[pos + 1] == '<' {
                tokens.push(Token::LShift);
                pos += 2;
                continue;
            }
            if ch == '>' && pos + 1 < chars.len() && chars[pos + 1] == '>' {
                tokens.push(Token::RShift);
                pos += 2;
                continue;
            }
            if ch == '+' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::PlusEq);
                pos += 2;
                continue;
            }
            if ch == '-' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::MinusEq);
                pos += 2;
                continue;
            }
            if ch == '*' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::StarEq);
                pos += 2;
                continue;
            }
            if ch == '/' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::SlashEq);
                pos += 2;
                continue;
            }
            if ch == '%' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::PercentEq);
                pos += 2;
                continue;
            }
            if ch == '-' && pos + 1 < chars.len() && chars[pos + 1] == '>' {
                tokens.push(Token::Arrow);
                pos += 2;
                continue;
            }

            // Parentheses (track depth for multi-line expressions)
            if ch == '(' {
                paren_depth += 1;
                tokens.push(Token::LParen);
                pos += 1;
                continue;
            }
            if ch == ')' {
                if paren_depth > 0 {
                    paren_depth -= 1;
                }
                tokens.push(Token::RParen);
                pos += 1;
                continue;
            }
            if ch == '[' {
                paren_depth += 1;
                tokens.push(Token::LBracket);
                pos += 1;
                continue;
            }
            if ch == ']' {
                if paren_depth > 0 {
                    paren_depth -= 1;
                }
                tokens.push(Token::RBracket);
                pos += 1;
                continue;
            }

            // Single-char operators & delimiters
            match ch {
                '+' => {
                    tokens.push(Token::Plus);
                    pos += 1;
                    continue;
                }
                '-' => {
                    tokens.push(Token::Minus);
                    pos += 1;
                    continue;
                }
                '*' => {
                    tokens.push(Token::Star);
                    pos += 1;
                    continue;
                }
                '/' => {
                    tokens.push(Token::Slash);
                    pos += 1;
                    continue;
                }
                '%' => {
                    tokens.push(Token::Percent);
                    pos += 1;
                    continue;
                }
                '<' => {
                    tokens.push(Token::Lt);
                    pos += 1;
                    continue;
                }
                '>' => {
                    tokens.push(Token::Gt);
                    pos += 1;
                    continue;
                }
                '!' => {
                    tokens.push(Token::Bang);
                    pos += 1;
                    continue;
                }
                '~' => {
                    tokens.push(Token::Tilde);
                    pos += 1;
                    continue;
                }
                '&' => {
                    tokens.push(Token::BitAnd);
                    pos += 1;
                    continue;
                }
                '|' => {
                    tokens.push(Token::BitOr);
                    pos += 1;
                    continue;
                }
                '^' => {
                    tokens.push(Token::BitXor);
                    pos += 1;
                    continue;
                }
                '=' => {
                    tokens.push(Token::Eq);
                    pos += 1;
                    continue;
                }
                ':' => {
                    tokens.push(Token::Colon);
                    pos += 1;
                    continue;
                }
                ',' => {
                    tokens.push(Token::Comma);
                    pos += 1;
                    continue;
                }
                '.' => {
                    tokens.push(Token::Dot);
                    pos += 1;
                    continue;
                }
                _ => {}
            }

            // Byte string: b'..' or b".." -- escapes decode as in CPython (F-203).
            if ch == 'b'
                && pos + 1 < chars.len()
                && (chars[pos + 1] == '\'' || chars[pos + 1] == '"')
            {
                let open_col = pos;
                let (body, end, closed) = scan_py_quoted(&chars, pos + 2, chars[pos + 1]);
                pos = end;
                // F-011: a single-line literal that reaches the line break is
                // unterminated; it must never run on into the next line.
                if !closed {
                    errors.push(lex_error(UNTERMINATED_STRING_LITERAL, file, line_num, open_col));
                }
                let (_, hex, err) = decode_py_literal(body, true);
                if let Some(msg) = err {
                    errors.push(lex_error(&msg, file, line_num, open_col));
                }
                tokens.push(Token::HexStringLit(hex));
                continue;
            }

            // String literals (single or double quoted, including triple-quoted)
            if ch == '\'' || ch == '"' {
                let quote = ch;
                let open_col = pos;
                // Triple-quoted string — always a docstring in Rúnar.
                // Skip it without emitting a token.
                if pos + 2 < chars.len() && chars[pos + 1] == quote && chars[pos + 2] == quote {
                    pos += 3;
                    while pos + 2 < chars.len() {
                        if chars[pos] == quote
                            && chars[pos + 1] == quote
                            && chars[pos + 2] == quote
                        {
                            break;
                        }
                        pos += 1;
                    }
                    if pos + 2 < chars.len() {
                        pos += 3;
                    } else {
                        // F-011: not closed on this line. Like the TS
                        // reference, the following lines are string text
                        // until the closing triple quote; if none comes
                        // before end of file it is unterminated.
                        pos = chars.len();
                        in_triple_quote = Some(quote);
                        triple_start = (line_num, open_col);
                    }
                    continue;
                }
                let (body, end, closed) = scan_py_quoted(&chars, pos + 1, quote);
                pos = end;
                if !closed {
                    // F-011: reached the line break.
                    errors.push(lex_error(UNTERMINATED_STRING_LITERAL, file, line_num, open_col));
                }
                // F-203: a str literal decodes the same escapes as CPython does.
                let (val, _, err) = decode_py_literal(body, false);
                if let Some(msg) = err {
                    errors.push(lex_error(&msg, file, line_num, open_col));
                }
                tokens.push(Token::StringLit(val));
                continue;
            }

            // Numbers (F-026): the whole glued [0-9A-Za-z_] run is one literal.
            if ch.is_ascii_digit() {
                let end = scan_number_end(&chars, pos);
                let text: String = chars[pos..end].iter().collect();
                let val = match parse_int_literal("py", &text) {
                    Some(lit) => lit.value,
                    None => {
                        errors.push(lex_error(&invalid_integer_literal("py", &text), file, line_num, pos));
                        BigInt::from(0)
                    }
                };
                pos = end;
                tokens.push(Token::NumberLit(val));
                continue;
            }

            // Identifiers and keywords
            if ch.is_ascii_alphabetic() || ch == '_' {
                let start = pos;
                while pos < chars.len() && (chars[pos].is_ascii_alphanumeric() || chars[pos] == '_')
                {
                    pos += 1;
                }
                let word: String = chars[start..pos].iter().collect();
                let tok = match word.as_str() {
                    "class" => Token::Class,
                    "def" => Token::Def,
                    "if" => Token::If,
                    "elif" => Token::Elif,
                    "else" => Token::Else,
                    "for" => Token::For,
                    "in" => Token::In,
                    "range" => Token::Range,
                    "return" => Token::Return,
                    "pass" => Token::Pass,
                    "True" => Token::TrueLit,
                    "False" => Token::FalseLit,
                    "None" => Token::NoneLit,
                    "and" => Token::And,
                    "or" => Token::Or,
                    "not" => Token::Not,
                    "self" => Token::SelfKw,
                    "super" => Token::Super,
                    "from" => Token::From,
                    "import" => Token::Import,
                    "assert" => Token::Assert,
                    _ => Token::Ident(word),
                };
                tokens.push(tok);
                continue;
            }

            // N-033: a character the TS reference does not tokenize (`;`,
            // `{`, `$`, `?`, ...) is refused, never skipped.
            errors.push(lex_error(&format!("Unexpected character '{}'", ch), file, line_num, pos));
            pos += 1;
        }
        positions.resize(tokens.len(), at);

        // Emit NEWLINE at end of significant line (only if not inside parens)
        if paren_depth == 0 {
            tokens.push(Token::Newline);
        }
    }

    // F-011: a triple-quoted string still open at end of file swallowed every
    // line after it; refuse it instead.
    if in_triple_quote.is_some() {
        errors.push(lex_error(UNTERMINATED_STRING_LITERAL, file, triple_start.0, triple_start.1));
    }

    // Emit remaining DEDENTs
    while indent_stack.len() > 1 {
        indent_stack.pop();
        tokens.push(Token::Dedent);
    }

    tokens.push(Token::Eof);
    positions.resize(tokens.len(), at);
    (tokens, positions)
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct PyParser<'a> {
    tokens: Vec<Token>,
    /// F-337: start (line, column) of each token in `tokens`.
    positions: Vec<(usize, usize)>,
    pos: usize,
    file: &'a str,
    errors: &'a mut Vec<Diagnostic>,
    /// F-017: declared (spelling, Rúnar name) pairs.
    idents: DeclaredIdents,
    /// N-046: the locals already bound in the current method, so a later
    /// `name = expr` of one of them is emitted as an `Assignment`, not a fresh
    /// `VariableDecl`. Python is function-scoped, so rebinding an existing
    /// local inside a loop body or an if-arm IS an assignment; ANF lowering
    /// alpha-renames a `VariableDecl` that reuses an enclosing binding's name.
    /// Snapshot/restored around if-branches and loop bodies exactly as the
    /// Ruby parser's `declared_locals`.
    declared_locals: std::collections::HashSet<String>,
    /// F-213 measure (A): parse nesting.
    nest: NestingCounter,
}

impl<'a> PyParser<'a> {
    fn new(
        tokens: Vec<Token>,
        positions: Vec<(usize, usize)>,
        file: &'a str,
        errors: &'a mut Vec<Diagnostic>,
    ) -> Self {
        Self {
            tokens,
            positions,
            pos: 0,
            file,
            errors,
            idents: DeclaredIdents::default(),
            declared_locals: std::collections::HashSet::new(),
            nest: NestingCounter::new(),
        }
    }

    /// F-213: the source is too deep. Latch the refusal and treat the rest
    /// of the input as ended, so every loop above unwinds without building
    /// anything deeper.
    fn bail(&mut self) {
        self.nest.refuse();
        self.pos = self.tokens.len();
    }

    /// Run `f` one counted nesting level deeper (measure A), or return
    /// `fallback` once the limit is reached.
    fn nested<T>(&mut self, fallback: T, f: impl FnOnce(&mut Self) -> T) -> T {
        if !self.nest.enter() {
            self.bail();
            return fallback;
        }
        let out = f(self);
        self.nest.exit();
        out
    }

    /// May a loop wrap `acc` (and `others`) in one more node? Refuses once
    /// that node would be deeper than MAX_SOURCE_NESTING (F-213).
    fn grow(&mut self, dt: &mut DepthTracker, acc: &Expression, others: &[&Expression]) -> bool {
        if dt.wrap(acc, others) {
            return true;
        }
        self.bail();
        false
    }

    /// N-046: the statement for `name = init` — an assignment when the method
    /// already bound `name`, otherwise a declaration.
    fn bind_local(&mut self, name: String, var_type: Option<TypeNode>, init: Expression) -> Statement {
        if self.declared_locals.contains(&name) {
            return Statement::Assignment {
                target: Expression::Identifier { name },
                value: init,
                source_location: self.loc(),
            };
        }
        self.declared_locals.insert(name.clone());
        Statement::VariableDecl {
            name,
            var_type,
            mutable: true,
            init,
            source_location: self.loc(),
        }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        let t = self.tokens.get(self.pos).cloned().unwrap_or(Token::Eof);
        self.pos += 1;
        t
    }

    fn expect(&mut self, expected: &Token) -> bool {
        if std::mem::discriminant(self.peek()) == std::mem::discriminant(expected) {
            self.advance();
            true
        } else {
            self.errors.push(Diagnostic::error(format!(
                "Expected {:?}, got {:?}",
                expected,
                self.peek()
            ), None));
            false
        }
    }

    fn match_tok(&mut self, expected: &Token) -> bool {
        if std::mem::discriminant(self.peek()) == std::mem::discriminant(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect_ident(&mut self) -> String {
        match self.advance() {
            Token::Ident(name) => name,
            other => {
                self.errors
                    .push(Diagnostic::error(format!("Expected identifier, got {:?}", other), None));
                "_error".to_string()
            }
        }
    }

    /// Where the current token starts (F-337).
    fn loc(&self) -> SourceLocation {
        let (line, column) = self
            .positions
            .get(self.pos)
            .or_else(|| self.positions.last())
            .copied()
            .unwrap_or((1, 0));
        SourceLocation {
            file: self.file.to_string(),
            line,
            column,
        }
    }

    /// Skip NEWLINE tokens.
    fn skip_newlines(&mut self) {
        while *self.peek() == Token::Newline {
            self.advance();
        }
    }

    // -----------------------------------------------------------------------
    // Top-level parsing
    // -----------------------------------------------------------------------

    fn parse_contract(&mut self) -> Option<ContractNode> {
        self.skip_newlines();

        // Skip `from runar import ...` lines
        while *self.peek() == Token::From || *self.peek() == Token::Import {
            self.parse_import_line();
            self.skip_newlines();
        }

        self.skip_newlines();

        if *self.peek() != Token::Class {
            self.errors
                .push(Diagnostic::error("Expected 'class' declaration", None));
            return None;
        }

        self.advance(); // consume 'class'
        let contract_name = self.expect_ident();
        self.expect(&Token::LParen);
        let parent_class = self.expect_ident();
        self.expect(&Token::RParen);
        self.expect(&Token::Colon);
        self.skip_newlines();
        self.expect(&Token::Indent);
        self.skip_newlines();

        if parent_class != "SmartContract"
            && parent_class != "StatefulSmartContract"
            && parent_class != "UnsafeSmartContract"
        {
            self.errors.push(Diagnostic::error(format!(
                "unknown parent class: '{}', expected SmartContract, StatefulSmartContract, or UnsafeSmartContract",
                parent_class
            ), None));
            return None;
        }

        let mut properties = Vec::new();
        let mut methods = Vec::new();
        let mut constructor: Option<MethodNode> = None;

        while *self.peek() != Token::Dedent && *self.peek() != Token::Eof {
            self.skip_newlines();
            if *self.peek() == Token::Dedent || *self.peek() == Token::Eof {
                break;
            }

            // `pass` is a valid (empty) class-body statement.
            if *self.peek() == Token::Pass {
                self.advance();
                self.expect_statement_end();
                continue;
            }

            // Decorators
            let mut decorators: Vec<String> = Vec::new();
            let mut sighash_specs: Vec<Option<String>> = Vec::new();
            while *self.peek() == Token::At {
                self.advance(); // '@'
                let dec_name = match self.advance() {
                    Token::Ident(name) => name,
                    other => {
                        self.errors
                            .push(Diagnostic::error(format!("Expected decorator name, got {:?}", other), None));
                        String::new()
                    }
                };
                // N-093: `@public(sighash="FLAGS")` is the native spelling of
                // the `@sighash` directive.
                if dec_name == "public" && *self.peek() == Token::LParen {
                    let specs = self.parse_public_decorator_args();
                    sighash_specs.extend(specs);
                }
                decorators.push(dec_name);
                self.skip_newlines();
            }

            // Method definition
            if *self.peek() == Token::Def {
                let method = self.parse_method_def(&decorators, &sighash_specs);
                if method.name == "constructor" {
                    constructor = Some(method);
                } else {
                    methods.push(method);
                }
                self.skip_newlines();
                continue;
            }

            // Property: name: Type
            if let Token::Ident(_) = self.peek().clone() {
                if let Some(prop) = self.parse_property(&parent_class) {
                    properties.push(prop);
                }
                self.skip_newlines();
                continue;
            }

            // N-033: any other token is refused, never skipped.
            self.refuse_class_body_token();
        }

        self.match_tok(&Token::Dedent);

        // N-410: nothing but blank lines may follow the class (N-004 did this
        // for .runar.rb); a method or class after it used to be dropped unread.
        self.skip_newlines();
        if *self.peek() != Token::Eof {
            let loc = self.loc();
            let trailing = py_token_text(self.peek());
            self.errors.push(Diagnostic::error(unexpected_token_after_class_message(&trailing), Some(loc)));
        }

        // Auto-generate constructor if not provided
        let constructor = constructor
            .unwrap_or_else(|| build_constructor(&properties, self.file));

        Some(ContractNode {
            name: contract_name,
            parent_class,
            properties,
            constructor,
            methods,
            source_file: self.file.to_string(),
        })
    }

    fn parse_import_line(&mut self) {
        // from X import Y, Z, ...
        // or: import X
        if *self.peek() == Token::From {
            self.advance(); // 'from'
            // consume module path
            while *self.peek() != Token::Import
                && *self.peek() != Token::Newline
                && *self.peek() != Token::Eof
            {
                self.advance();
            }
            if self.match_tok(&Token::Import) {
                // consume imported names
                while *self.peek() != Token::Newline && *self.peek() != Token::Eof {
                    self.advance();
                }
            }
        } else if *self.peek() == Token::Import {
            self.advance();
            while *self.peek() != Token::Newline && *self.peek() != Token::Eof {
                self.advance();
            }
        }
        self.skip_newlines();
    }

    // -----------------------------------------------------------------------
    // Properties
    // -----------------------------------------------------------------------

    /// N-033: a class-body token that begins no property, method, decorator
    /// or `pass` is refused at that token (N-004's diagnostic), and the rest
    /// of its line is skipped.
    fn refuse_class_body_token(&mut self) {
        let loc = self.loc();
        let tok = self.advance();
        self.errors.push(Diagnostic::error(unexpected_class_body_token_message(&py_token_text(&tok)), Some(loc)));
        while !matches!(self.peek(), Token::Newline | Token::Dedent | Token::Eof) {
            self.advance();
        }
    }

    fn parse_property(&mut self, parent_class: &str) -> Option<PropertyNode> {
        if self.tokens.get(self.pos + 1) != Some(&Token::Colon) {
            // N-033: not a property -- a stray identifier line is refused.
            self.refuse_class_body_token();
            return None;
        }
        let raw_name = self.expect_ident();
        self.advance(); // consume ':'

        // Parse type (possibly Readonly[T]). N-093: `EmbedAlways[T]` is the
        // native spelling of the `@embedAlways` directive; the two wrappers
        // compose in either order.
        let mut is_readonly = false;
        let mut embed_always = false;
        let mut wrappers = 0;
        while let Token::Ident(name) = self.peek().clone() {
            if name == "Readonly" {
                is_readonly = true;
            } else if name == "EmbedAlways" {
                embed_always = true;
            } else {
                break;
            }
            self.advance(); // consume the wrapper name
            self.expect(&Token::LBracket);
            wrappers += 1;
        }
        let type_node = self.parse_type();
        for _ in 0..wrappers {
            self.expect(&Token::RBracket);
        }

        // In stateless contracts (SmartContract and UnsafeSmartContract), all
        // properties are readonly.
        if parent_class == "SmartContract" || parent_class == "UnsafeSmartContract" {
            is_readonly = true;
        }

        // Parse optional initializer: = value
        let initializer = if *self.peek() == Token::Eq {
            self.advance(); // consume '='
            Some(self.parse_expression())
        } else {
            None
        };

        // F-026: the field declaration ends at its line break.
        self.expect_statement_end();

        Some(PropertyNode {
            name: self.idents.declare(&raw_name, snake_to_camel(&raw_name)),
            prop_type: type_node,
            readonly: is_readonly,
            initializer,
            source_location: self.loc(),
            synthetic_array_chain: None,
            embed_always,
        })
    }

    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    fn parse_type(&mut self) -> TypeNode {
        // `None` is a keyword token here; as a type it is Python's "returns nothing".
        if *self.peek() == Token::NoneLit {
            self.advance();
            return TypeNode::Custom("None".to_string());
        }
        let raw_name = self.expect_ident();

        // Check for FixedArray[T, N]
        if raw_name == "FixedArray" && *self.peek() == Token::LBracket {
            self.advance(); // '['
            let element = self.nested(TypeNode::Custom("_error".to_string()), |p| p.parse_type());
            self.expect(&Token::Comma);
            let length = match self.advance() {
                Token::NumberLit(n) => n.to_usize().unwrap_or(0),
                _ => {
                    self.errors
                        .push(Diagnostic::error("FixedArray requires numeric length", None));
                    0
                }
            };
            self.expect(&Token::RBracket);
            return TypeNode::FixedArray {
                element: Box::new(element),
                length,
            };
        }

        let mapped = map_py_type(&raw_name);
        if let Some(prim) = PrimitiveTypeName::from_str(mapped) {
            TypeNode::Primitive(prim)
        } else {
            TypeNode::Custom(mapped.to_string())
        }
    }

    // -----------------------------------------------------------------------
    // Method definitions
    // -----------------------------------------------------------------------

    /// N-093: the argument list of `@public(...)`. The only argument is the
    /// keyword `sighash=<str>`; each one yields its string, and any other
    /// argument (positional, another keyword, a non-str value) yields `None`,
    /// which is refused as a malformed spelling. Mirrors
    /// `parsePublicDecoratorArgs` (01-parse-python.ts).
    fn parse_public_decorator_args(&mut self) -> Vec<Option<String>> {
        let mut specs = Vec::new();
        self.expect(&Token::LParen);
        while !matches!(self.peek(), Token::RParen | Token::Newline | Token::Eof) {
            let is_sighash_kw = matches!(self.peek(), Token::Ident(n) if n == "sighash")
                && matches!(self.tokens.get(self.pos + 1), Some(Token::Eq));
            if is_sighash_kw {
                self.advance(); // 'sighash'
                self.advance(); // '='
            }
            // One argument value: up to the next top-level ',' or ')'.
            let first = self.peek().clone();
            let mut count = 0;
            let mut depth: i32 = 0;
            while !matches!(self.peek(), Token::Newline | Token::Eof) {
                let t = self.peek().clone();
                if matches!(t, Token::Comma | Token::RParen) && depth == 0 {
                    break;
                }
                if matches!(t, Token::LParen | Token::LBracket) {
                    depth += 1;
                }
                if matches!(t, Token::RParen | Token::RBracket) {
                    depth -= 1;
                }
                self.advance();
                count += 1;
            }
            specs.push(match first {
                Token::StringLit(v) if is_sighash_kw && count == 1 => Some(v),
                _ => None,
            });
            if !self.match_tok(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RParen);
        specs
    }

    fn parse_method_def(&mut self, decorators: &[String], sighash_specs: &[Option<String>]) -> MethodNode {
        let def_loc = self.loc();
        self.expect(&Token::Def);

        let raw_name = match self.advance() {
            Token::Ident(name) => name,
            other => {
                self.errors
                    .push(Diagnostic::error(format!("Expected method name, got {:?}", other), None));
                "_error".to_string()
            }
        };

        // N-050: @staticmethod / @classmethod declare a class-level function,
        // not a contract method; `@public @staticmethod` used to be an entry point.
        if decorators.iter().any(|d| d == "staticmethod" || d == "classmethod") {
            self.errors.push(Diagnostic::error(static_method_message(&raw_name), Some(def_loc.clone())));
        }

        // N-046: reset local tracking for this method's scope.
        self.declared_locals.clear();

        self.expect(&Token::LParen);
        let params = self.parse_params();
        self.expect(&Token::RParen);

        // Optional return type annotation: -> Type
        if self.match_tok(&Token::Arrow) {
            // The AST keeps no return type; N-331 refuses an unknown name. `None`
            // is Python's spelling of "returns nothing".
            let ret_type = self.parse_type();
            if !matches!(&ret_type, TypeNode::Custom(n) if n == "None") {
                if let Some(msg) = unknown_return_type_message(&ret_type, &raw_name, decorators.iter().any(|d| d == "public")) {
                    self.errors.push(Diagnostic::error(msg, Some(def_loc.clone())));
                }
            }
        }

        self.expect(&Token::Colon);
        self.skip_newlines();
        self.expect(&Token::Indent);

        let body = self.parse_statements();

        self.match_tok(&Token::Dedent);

        // Determine if this is the constructor
        if raw_name == "__init__" {
            // N-093: the constructor is not a spending entry point.
            if !sighash_specs.is_empty() {
                self.errors.push(Diagnostic::error(lost_directive_message("@sighash"), Some(def_loc.clone())));
            }
            return MethodNode {
                name: "constructor".to_string(),
                params,
                body,
                visibility: Visibility::Public,
                source_location: self.loc(),
                sighash_type: None,
            };
        }

        let is_public = decorators.contains(&"public".to_string());
        let method_name = self.idents.declare(&raw_name, method_ast_name(&raw_name));

        let sighash_type = match resolve_native_sighash(&method_name, is_public, sighash_specs) {
            Some(Ok(v)) => Some(v),
            Some(Err(msg)) => {
                self.errors.push(Diagnostic::error(msg, Some(def_loc)));
                None
            }
            None => None,
        };

        MethodNode {
            name: method_name,
            params,
            body,
            visibility: if is_public {
                Visibility::Public
            } else {
                Visibility::Private
            },
            source_location: self.loc(),
            sighash_type,
        }
    }

    fn parse_params(&mut self) -> Vec<ParamNode> {
        let mut params = Vec::new();

        while *self.peek() != Token::RParen && *self.peek() != Token::Eof {
            // Skip 'self' parameter
            if *self.peek() == Token::SelfKw {
                self.advance();
                if *self.peek() == Token::Comma {
                    self.advance();
                }
                continue;
            }

            let raw_name = self.expect_ident();

            let param_type = if self.match_tok(&Token::Colon) {
                self.parse_type()
            } else {
                TypeNode::Custom("unknown".to_string())
            };

            params.push(ParamNode {
                name: self.idents.declare(&raw_name, map_builtin_name(&raw_name)),
                param_type,
            });

            if !self.match_tok(&Token::Comma) {
                break;
            }
        }

        params
    }

    // -----------------------------------------------------------------------
    // Statements
    // -----------------------------------------------------------------------

    fn parse_statements(&mut self) -> Vec<Statement> {
        let mut stmts = Vec::new();

        while *self.peek() != Token::Dedent && *self.peek() != Token::Eof {
            self.skip_newlines();
            if *self.peek() == Token::Dedent || *self.peek() == Token::Eof {
                break;
            }

            if let Some(stmt) = self.parse_statement() {
                stmts.push(stmt);
            }
            self.expect_statement_end();
            self.skip_newlines();
        }

        stmts
    }

    /// F-026: a simple statement ends at its line break; compound statements
    /// end on a NEWLINE / DEDENT they consumed themselves. Pre-fix,
    /// `lim = 0b1010` parsed as `lim = 0` plus a second statement `b1010`.
    fn expect_statement_end(&mut self) {
        if matches!(self.peek(), Token::Newline | Token::Dedent | Token::Eof) {
            return;
        }
        if self.pos > 0 && matches!(self.tokens.get(self.pos - 1), Some(Token::Newline | Token::Dedent)) {
            return;
        }
        self.errors.push(Diagnostic::error(PY_STATEMENT_LINE_BREAK, None));
        while !matches!(self.peek(), Token::Newline | Token::Dedent | Token::Eof) {
            self.advance();
        }
    }

    fn parse_statement(&mut self) -> Option<Statement> {
        // F-337: a statement is located at its first token; the inner
        // parsers build it only after consuming it.
        let start = self.loc();
        let mut stmt = self.nested(None, |p| p.parse_statement_inner());
        if let Some(s) = stmt.as_mut() {
            *s.source_location_mut() = start;
        }
        stmt
    }

    fn parse_statement_inner(&mut self) -> Option<Statement> {
        match self.peek().clone() {
            // assert statement: assert expr
            Token::Assert => Some(self.parse_assert_statement()),

            // if statement
            Token::If => Some(self.parse_if_statement()),

            // for statement
            Token::For => Some(self.parse_for_statement()),

            // return statement
            Token::Return => Some(self.parse_return_statement()),

            // pass statement
            Token::Pass => {
                self.advance();
                None
            }

            // super().__init__(...) -- constructor super call
            Token::Super => Some(self.parse_super_call()),

            // self.prop = expr (assignment to property) or self.method(...)
            Token::SelfKw => Some(self.parse_self_statement()),

            // Variable declaration or expression statement
            Token::Ident(_) => Some(self.parse_ident_statement()),

            // N-053: a token that can begin an expression begins an
            // expression statement.
            Token::NumberLit(_)
            | Token::StringLit(_)
            | Token::HexStringLit(_)
            | Token::TrueLit
            | Token::FalseLit
            | Token::NoneLit
            | Token::LParen
            | Token::LBracket
            | Token::Minus
            | Token::Tilde
            | Token::Bang
            | Token::Not => Some(Statement::ExpressionStatement {
                expression: self.parse_expression(),
                source_location: self.loc(),
            }),

            // N-053: any other token (a stray `elif`, `from`, `@`, an
            // unexpected indent, ...) is refused; skipping it dropped it.
            tok => {
                self.advance();
                self.errors.push(Diagnostic::error(
                    unsupported_statement_message(&py_token_text(&tok)),
                    None,
                ));
                None
            }
        }
    }

    fn parse_assert_statement(&mut self) -> Statement {
        self.advance(); // consume 'assert'
        let expr = self.parse_expression();
        Statement::ExpressionStatement {
            expression: Expression::CallExpr {
                callee: Box::new(Expression::Identifier {
                    name: "assert".to_string(),
                }),
                args: vec![expr],
                asm_return_type: None,
            },
            source_location: self.loc(),
        }
    }

    fn parse_if_statement(&mut self) -> Statement {
        self.advance(); // consume 'if'
        let condition = self.parse_expression();
        self.expect(&Token::Colon);
        self.skip_newlines();
        self.expect(&Token::Indent);
        // N-046: a name first bound inside a branch stays branch-local.
        let locals_before = self.declared_locals.clone();
        let then_branch = self.parse_statements();
        self.declared_locals = locals_before.clone();
        self.match_tok(&Token::Dedent);
        self.skip_newlines();

        let else_branch = if *self.peek() == Token::Elif {
            // elif -> else { if ... }
            // F-213: elif is an `if` statement of the else branch (+1).
            let elif = self.nested(None, |p| Some(p.parse_elif_statement()));
            self.declared_locals = locals_before.clone();
            Some(elif.into_iter().collect())
        } else if *self.peek() == Token::Else {
            self.advance(); // 'else'
            self.expect(&Token::Colon);
            self.skip_newlines();
            self.expect(&Token::Indent);
            let stmts = self.parse_statements();
            self.declared_locals = locals_before.clone();
            self.match_tok(&Token::Dedent);
            Some(stmts)
        } else {
            None
        };

        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            source_location: self.loc(),
        }
    }

    fn parse_elif_statement(&mut self) -> Statement {
        // F-337: located at the `elif` token (parse_statement never sees it).
        let loc = self.loc();
        self.advance(); // consume 'elif'
        let condition = self.parse_expression();
        self.expect(&Token::Colon);
        self.skip_newlines();
        self.expect(&Token::Indent);
        // N-046: a name first bound inside a branch stays branch-local.
        let locals_before = self.declared_locals.clone();
        let then_branch = self.parse_statements();
        self.declared_locals = locals_before.clone();
        self.match_tok(&Token::Dedent);
        self.skip_newlines();

        let else_branch = if *self.peek() == Token::Elif {
            // F-213: elif is an `if` statement of the else branch (+1).
            let elif = self.nested(None, |p| Some(p.parse_elif_statement()));
            self.declared_locals = locals_before.clone();
            Some(elif.into_iter().collect())
        } else if *self.peek() == Token::Else {
            self.advance();
            self.expect(&Token::Colon);
            self.skip_newlines();
            self.expect(&Token::Indent);
            let stmts = self.parse_statements();
            self.declared_locals = locals_before.clone();
            self.match_tok(&Token::Dedent);
            Some(stmts)
        } else {
            None
        };

        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            source_location: loc,
        }
    }

    fn parse_for_statement(&mut self) -> Statement {
        self.advance(); // consume 'for'

        let raw_var = self.expect_ident();
        let var_name = self.idents.declare(&raw_var, map_builtin_name(&raw_var));

        self.expect(&Token::In);
        self.expect(&Token::Range);
        self.expect(&Token::LParen);

        // range(n), range(a, b), or range(a, b, step) with step in {1, -1}.
        //
        // The third argument is what lets the Python surface spell a
        // COUNTDOWN. Until it existed, `range` was the surface's only loop
        // syntax and it could only ascend, so `step = -1` — a shape the ANF
        // loop node has carried since issue #121 and every tier lowers — was
        // unreachable from Python, and no fixture could exercise it across all
        // nine surfaces.
        //
        // Only ±1 is accepted: the ANF loop node synthesizes iteration k as
        // `start + k*step` with a unit step, so `range(0, 10, 2)` has no
        // representation. Refusing it is the same rule the for-header surfaces
        // enforce on `i += 2` (N-061), stated in Python's spelling.
        let first_arg = self.parse_expression();
        let mut descending = false;
        let (start_expr, end_expr) = if self.match_tok(&Token::Comma) {
            let second_arg = self.parse_expression();
            if self.match_tok(&Token::Comma) {
                let step_expr = self.parse_expression();
                match literal_int_value(&step_expr) {
                    Some(step) if step == BigInt::from(1) => descending = false,
                    Some(step) if step == BigInt::from(-1) => descending = true,
                    _ => {
                        let loc = self.loc();
                        self.errors
                            .push(Diagnostic::error(RANGE_STEP_DIAGNOSTIC.to_string(), Some(loc)));
                    }
                }
            }
            (first_arg, second_arg)
        } else {
            (Expression::BigIntLiteral { value: BigInt::from(0) }, first_arg)
        };

        self.expect(&Token::RParen);
        self.expect(&Token::Colon);
        self.skip_newlines();
        self.expect(&Token::Indent);
        // N-046: the loop variable and the body's first bindings are
        // body-local; a rebinding of the loop variable inside the body is an
        // assignment.
        let locals_before_body = self.declared_locals.clone();
        self.declared_locals.insert(var_name.clone());
        let body = self.parse_statements();
        self.declared_locals = locals_before_body;
        self.match_tok(&Token::Dedent);

        // Construct a C-style for loop AST node:
        // for (let varName: bigint = startExpr; varName < endExpr; varName++)
        let init = Statement::VariableDecl {
            name: var_name.clone(),
            var_type: Some(TypeNode::Primitive(PrimitiveTypeName::Bigint)),
            mutable: true,
            init: start_expr,
            source_location: self.loc(),
        };

        // `range` is half-open at BOTH ends: `range(5, 1, -1)` yields
        // 5, 4, 3, 2, so the descending guard is `i > stop`, exactly as `<` is
        // for ascending.
        let condition = Expression::BinaryExpr {
            op: if descending { BinaryOp::Gt } else { BinaryOp::Lt },
            left: Box::new(Expression::Identifier {
                name: var_name.clone(),
            }),
            right: Box::new(end_expr),
        };

        let update_operand = Box::new(Expression::Identifier { name: var_name });
        let update = Statement::ExpressionStatement {
            expression: if descending {
                Expression::DecrementExpr { operand: update_operand, prefix: false }
            } else {
                Expression::IncrementExpr { operand: update_operand, prefix: false }
            },
            source_location: self.loc(),
        };

        Statement::ForStatement {
            init: Box::new(init),
            condition,
            update: Box::new(update),
            body,
            source_location: self.loc(),
        }
    }

    fn parse_return_statement(&mut self) -> Statement {
        self.advance(); // consume 'return'
        let value = if *self.peek() != Token::Newline
            && *self.peek() != Token::Dedent
            && *self.peek() != Token::Eof
        {
            Some(self.parse_expression())
        } else {
            None
        };
        Statement::ReturnStatement {
            value,
            source_location: self.loc(),
        }
    }

    fn parse_super_call(&mut self) -> Statement {
        // super().__init__(...) -> super(args) in AST
        self.advance(); // 'super'
        self.expect(&Token::LParen);
        self.expect(&Token::RParen);
        self.expect(&Token::Dot);

        // Expect __init__
        let method_name = self.expect_ident();
        if method_name != "__init__" {
            self.errors.push(Diagnostic::error(format!(
                "Expected __init__ after super(), got '{}'",
                method_name
            ), None));
        }

        self.expect(&Token::LParen);
        let mut args = Vec::new();
        while *self.peek() != Token::RParen && *self.peek() != Token::Eof {
            args.push(self.parse_expression());
            if !self.match_tok(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RParen);

        Statement::ExpressionStatement {
            expression: Expression::CallExpr {
                callee: Box::new(Expression::Identifier {
                    name: "super".to_string(),
                }),
                args,
                asm_return_type: None,
            },
            source_location: self.loc(),
        }
    }

    fn parse_self_statement(&mut self) -> Statement {
        // self.prop = expr  or  self.prop += expr  or  self.method(...)
        let expr = self.parse_expression();

        // Simple assignment: self.x = expr
        if self.match_tok(&Token::Eq) {
            let value = self.parse_expression();
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }

        // Compound assignments
        if *self.peek() == Token::PlusEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Add,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }
        if *self.peek() == Token::MinusEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Sub,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }
        if *self.peek() == Token::StarEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Mul,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }
        if *self.peek() == Token::SlashEq || *self.peek() == Token::IntDivEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Div,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }
        if *self.peek() == Token::PercentEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Mod,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }

        // Expression statement (method call)
        Statement::ExpressionStatement {
            expression: expr,
            source_location: self.loc(),
        }
    }

    fn parse_ident_statement(&mut self) -> Statement {
        // Could be:
        // 1. name: Type = expr  (variable declaration with type annotation)
        // 2. name = expr  (variable declaration without type)
        // 3. name(...)  (expression statement / function call)
        // 4. name += expr (compound assignment)

        let raw_name = match self.peek().clone() {
            Token::Ident(ref name) => name.clone(),
            _ => "_error".to_string(),
        };

        // Look ahead: if next token after ident is ':', it's a typed variable decl
        if self.tokens.get(self.pos + 1).map_or(false, |t| *t == Token::Colon) {
            self.advance(); // consume ident
            self.advance(); // consume ':'

            // Check if it's Readonly[T] -- that would be a property, not a var decl,
            // but at statement level it means typed var decl with Readonly as a type name.
            let type_node = self.parse_type();

            let init = if self.match_tok(&Token::Eq) {
                self.parse_expression()
            } else {
                Expression::BigIntLiteral { value: BigInt::from(0) }
            };

            // N-046: rebinding a local of this method is an assignment in Python.
            let name = self.idents.declare(&raw_name, map_builtin_name(&raw_name));
            return self.bind_local(name, Some(type_node), init);
        }

        // Check for simple name = expr pattern (no type annotation)
        if self.tokens.get(self.pos + 1).map_or(false, |t| *t == Token::Eq) {
            self.advance(); // consume ident
            self.advance(); // consume '='
            let value = self.parse_expression();
            // N-046: rebinding a local of this method is an assignment in Python.
            let name = self.idents.declare(&raw_name, map_builtin_name(&raw_name));
            return self.bind_local(name, None, value);
        }

        // Parse as expression first
        let expr = self.parse_expression();

        // Simple assignment (for a.b = expr)
        if self.match_tok(&Token::Eq) {
            let value = self.parse_expression();
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }

        // Compound assignments
        if *self.peek() == Token::PlusEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Add,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }
        if *self.peek() == Token::MinusEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Sub,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }
        if *self.peek() == Token::StarEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Mul,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }
        if *self.peek() == Token::SlashEq || *self.peek() == Token::IntDivEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Div,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }
        if *self.peek() == Token::PercentEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Mod,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }

        // Expression statement
        Statement::ExpressionStatement {
            expression: expr,
            source_location: self.loc(),
        }
    }

    // -----------------------------------------------------------------------
    // Expressions (precedence climbing)
    // -----------------------------------------------------------------------

    fn parse_expression(&mut self) -> Expression {
        self.nested(zero(), |p| p.parse_ternary())
    }

    /// Python conditional expression: `x if cond else y`
    /// Parsed as postfix: parse or-expr first, then check for 'if'.
    fn parse_ternary(&mut self) -> Expression {
        let expr = self.parse_or();

        if *self.peek() == Token::If {
            self.advance(); // 'if'
            let condition = self.parse_or();
            self.expect(&Token::Else);
            // F-213: the alternate recurses into the ternary parser (+1).
            let alternate = self.nested(zero(), |p| p.parse_ternary());
            Expression::TernaryExpr {
                condition: Box::new(condition),
                consequent: Box::new(expr),
                alternate: Box::new(alternate),
            }
        } else {
            expr
        }
    }

    fn parse_or(&mut self) -> Expression {
        let mut left = self.parse_and();
        let mut dt = DepthTracker::new();
        while *self.peek() == Token::Or {
            self.advance();
            let right = self.parse_and();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr {
                op: BinaryOp::Or,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        left
    }

    fn parse_and(&mut self) -> Expression {
        let mut left = self.parse_not();
        let mut dt = DepthTracker::new();
        while *self.peek() == Token::And {
            self.advance();
            let right = self.parse_not();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr {
                op: BinaryOp::And,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        left
    }

    fn parse_not(&mut self) -> Expression {
        if *self.peek() == Token::Not {
            self.advance();
            let operand = self.nested(zero(), |p| p.parse_not());
            Expression::UnaryExpr {
                op: UnaryOp::Not,
                operand: Box::new(operand),
            }
        } else {
            self.parse_bit_or()
        }
    }

    fn parse_bit_or(&mut self) -> Expression {
        let mut left = self.parse_bit_xor();
        let mut dt = DepthTracker::new();
        while *self.peek() == Token::BitOr {
            self.advance();
            let right = self.parse_bit_xor();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr {
                op: BinaryOp::BitOr,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        left
    }

    fn parse_bit_xor(&mut self) -> Expression {
        let mut left = self.parse_bit_and();
        let mut dt = DepthTracker::new();
        while *self.peek() == Token::BitXor {
            self.advance();
            let right = self.parse_bit_and();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr {
                op: BinaryOp::BitXor,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        left
    }

    fn parse_bit_and(&mut self) -> Expression {
        let mut left = self.parse_equality();
        let mut dt = DepthTracker::new();
        while *self.peek() == Token::BitAnd {
            self.advance();
            let right = self.parse_equality();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr {
                op: BinaryOp::BitAnd,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        left
    }

    fn parse_equality(&mut self) -> Expression {
        let mut left = self.parse_comparison();
        let mut dt = DepthTracker::new();
        loop {
            match self.peek() {
                Token::EqEq => {
                    self.advance();
                    let right = self.parse_comparison();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    // == maps to ===
                    left = Expression::BinaryExpr {
                        op: BinaryOp::StrictEq,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::NotEq => {
                    self.advance();
                    let right = self.parse_comparison();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    // != maps to !==
                    left = Expression::BinaryExpr {
                        op: BinaryOp::StrictNe,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_comparison(&mut self) -> Expression {
        let mut left = self.parse_shift();
        let mut dt = DepthTracker::new();
        loop {
            match self.peek() {
                Token::Lt => {
                    self.advance();
                    let right = self.parse_shift();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Lt,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::Le => {
                    self.advance();
                    let right = self.parse_shift();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Le,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::Gt => {
                    self.advance();
                    let right = self.parse_shift();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Gt,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::Ge => {
                    self.advance();
                    let right = self.parse_shift();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Ge,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_shift(&mut self) -> Expression {
        let mut left = self.parse_additive();
        let mut dt = DepthTracker::new();
        loop {
            match self.peek() {
                Token::LShift => {
                    self.advance();
                    let right = self.parse_additive();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Shl,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::RShift => {
                    self.advance();
                    let right = self.parse_additive();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Shr,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_additive(&mut self) -> Expression {
        let mut left = self.parse_multiplicative();
        let mut dt = DepthTracker::new();
        loop {
            match self.peek() {
                Token::Plus => {
                    self.advance();
                    let right = self.parse_multiplicative();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Add,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::Minus => {
                    self.advance();
                    let right = self.parse_multiplicative();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Sub,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_multiplicative(&mut self) -> Expression {
        let mut left = self.parse_unary();
        let mut dt = DepthTracker::new();
        loop {
            match self.peek() {
                Token::Star => {
                    self.advance();
                    let right = self.parse_unary();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Mul,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::IntDiv => {
                    // Python integer division // maps to / in AST (OP_DIV)
                    self.advance();
                    let right = self.parse_unary();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Div,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::Slash => {
                    self.advance();
                    let right = self.parse_unary();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Div,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::Percent => {
                    self.advance();
                    let right = self.parse_unary();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Mod,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_unary(&mut self) -> Expression {
        match self.peek() {
            Token::Minus => {
                self.advance();
                let operand = self.nested(zero(), |p| p.parse_unary());
                Expression::UnaryExpr {
                    op: UnaryOp::Neg,
                    operand: Box::new(operand),
                }
            }
            Token::Tilde => {
                self.advance();
                let operand = self.nested(zero(), |p| p.parse_unary());
                Expression::UnaryExpr {
                    op: UnaryOp::BitNot,
                    operand: Box::new(operand),
                }
            }
            Token::Bang => {
                self.advance();
                let operand = self.nested(zero(), |p| p.parse_unary());
                Expression::UnaryExpr {
                    op: UnaryOp::Not,
                    operand: Box::new(operand),
                }
            }
            _ => self.parse_power(),
        }
    }

    /// `**` is the documented spelling of the builtin `pow(base, exp)`
    /// (docs/formats/python.md): right-associative, tighter than a unary minus
    /// on its left, with a unary operand allowed on its right.
    fn parse_power(&mut self) -> Expression {
        let base = self.parse_postfix();
        if *self.peek() == Token::DoubleStar {
            self.advance();
            let exp = self.nested(zero(), |p| p.parse_unary());
            return Expression::CallExpr {
                callee: Box::new(Expression::Identifier {
                    name: "pow".to_string(),
                }),
                args: vec![base, exp],
                asm_return_type: None,
            };
        }
        base
    }

    fn parse_postfix(&mut self) -> Expression {
        let mut expr = self.parse_primary();
        let mut dt = DepthTracker::new();

        loop {
            match self.peek().clone() {
                Token::Dot => {
                    self.advance(); // '.'
                    let raw_prop = self.expect_ident();
                    let is_call = *self.peek() == Token::LParen;
                    let prop = if is_call { method_ast_name(&raw_prop) } else { snake_to_camel(&raw_prop) };

                    // Check if it's a method call
                    if is_call {
                        let args = self.parse_call_args();
                        // F-213: the member node, then the call around it.
                        let arg_refs: Vec<&Expression> = args.iter().collect();
                        if !self.grow(&mut dt, &expr, &[]) || !self.grow(&mut dt, &expr, &arg_refs) { break; }
                        // Handle self.method(...) -> this.method(...)
                        if matches!(&expr, Expression::Identifier { name } if name == "this") {
                            expr = Expression::CallExpr {
                                callee: Box::new(Expression::MemberExpr {
                                    object: Box::new(Expression::Identifier {
                                        name: "this".to_string(),
                                    }),
                                    property: prop,
                                }),
                                args,
                                asm_return_type: None,
                            };
                        } else {
                            expr = Expression::CallExpr {
                                callee: Box::new(Expression::MemberExpr {
                                    object: Box::new(expr),
                                    property: prop,
                                }),
                                args,
                                asm_return_type: None,
                            };
                        }
                    } else {
                        // Property access
                        if matches!(&expr, Expression::Identifier { name } if name == "this") {
                            expr = Expression::PropertyAccess { property: prop };
                            dt = DepthTracker::new();
                        } else {
                            if !self.grow(&mut dt, &expr, &[]) { break; }
                            expr = Expression::MemberExpr {
                                object: Box::new(expr),
                                property: prop,
                            };
                        }
                    }
                }
                Token::LParen => {
                    let args = self.parse_call_args();
                    let arg_refs: Vec<&Expression> = args.iter().collect();
                    if !self.grow(&mut dt, &expr, &arg_refs) { break; }
                    expr = Expression::CallExpr {
                        callee: Box::new(expr),
                        args,
                        asm_return_type: None,
                    };
                }
                Token::LBracket => {
                    self.advance();
                    let index = self.parse_expression();
                    self.expect(&Token::RBracket);
                    if !self.grow(&mut dt, &expr, &[&index]) { break; }
                    expr = Expression::IndexAccess {
                        object: Box::new(expr),
                        index: Box::new(index),
                    };
                }
                _ => break,
            }
        }

        expr
    }

    fn parse_primary(&mut self) -> Expression {
        match self.advance() {
            Token::NumberLit(v) => Expression::BigIntLiteral { value: v },
            Token::TrueLit => Expression::BoolLiteral { value: true },
            Token::FalseLit => Expression::BoolLiteral { value: false },
            Token::NoneLit => Expression::BigIntLiteral { value: BigInt::from(0) },
            Token::HexStringLit(v) => Expression::ByteStringLiteral { value: v },
            Token::StringLit(v) => Expression::ByteStringLiteral { value: v },
            Token::SelfKw => {
                // self -> this
                Expression::Identifier {
                    name: "this".to_string(),
                }
            }
            Token::Ident(name) => {
                // Check for bytes.fromhex("...")
                if name == "bytes" && *self.peek() == Token::Dot {
                    if let Some(Token::Ident(ref next_name)) = self.tokens.get(self.pos + 1) {
                        if next_name == "fromhex" {
                            self.advance(); // '.'
                            self.advance(); // 'fromhex'
                            self.expect(&Token::LParen);
                            let val = match self.advance() {
                                Token::StringLit(s) => s,
                                _ => {
                                    self.errors
                                        .push(Diagnostic::error("Expected string in bytes.fromhex()", None));
                                    String::new()
                                }
                            };
                            self.expect(&Token::RParen);
                            return Expression::ByteStringLiteral { value: val };
                        }
                    }
                }

                let mapped = map_builtin_name(&name);
                Expression::Identifier { name: mapped }
            }
            Token::Assert => {
                // assert used as expression (unusual but handle it)
                // In Python, `assert_(expr)` is an ident, but `assert expr` uses the keyword.
                // If we get here, it means `assert` keyword was used as an expression callee.
                Expression::Identifier {
                    name: "assert".to_string(),
                }
            }
            Token::LParen => {
                let expr = self.parse_expression();
                self.expect(&Token::RParen);
                expr
            }
            Token::LBracket => {
                // Array literal: [a, b, c]
                let mut elements: Vec<Expression> = Vec::new();
                while !matches!(self.peek(), Token::RBracket | Token::Eof) {
                    elements.push(self.parse_expression());
                    if !matches!(self.peek(), Token::Comma) {
                        break;
                    }
                    self.advance();
                }
                self.expect(&Token::RBracket);
                Expression::ArrayLiteral { elements }
            }
            other => {
                self.errors
                    .push(Diagnostic::error(format!("Unexpected token in expression: {:?}", other), None));
                Expression::BigIntLiteral { value: BigInt::from(0) }
            }
        }
    }

    fn parse_call_args(&mut self) -> Vec<Expression> {
        self.expect(&Token::LParen);
        let mut args = Vec::new();
        while *self.peek() != Token::RParen && *self.peek() != Token::Eof {
            args.push(self.parse_expression());
            if !self.match_tok(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RParen);
        args
    }
}

/// Placeholder expression returned by a parse cut short by the F-213 limit.
fn zero() -> Expression {
    Expression::BigIntLiteral { value: BigInt::from(0) }
}

// ---------------------------------------------------------------------------
// Constructor builder
// ---------------------------------------------------------------------------

fn build_constructor(properties: &[PropertyNode], file: &str) -> MethodNode {
    // Only include properties without initializers as constructor params
    let uninit_props: Vec<&PropertyNode> = properties
        .iter()
        .filter(|p| p.initializer.is_none())
        .collect();

    let params: Vec<ParamNode> = uninit_props
        .iter()
        .map(|p| ParamNode {
            name: p.name.clone(),
            param_type: p.prop_type.clone(),
        })
        .collect();

    let mut body: Vec<Statement> = Vec::new();

    // super(...) call — only non-initialized property names as args
    let super_args: Vec<Expression> = uninit_props
        .iter()
        .map(|p| Expression::Identifier {
            name: p.name.clone(),
        })
        .collect();
    body.push(Statement::ExpressionStatement {
        expression: Expression::CallExpr {
            callee: Box::new(Expression::Identifier {
                name: "super".to_string(),
            }),
            args: super_args,
            asm_return_type: None,
        },
        source_location: SourceLocation {
            file: file.to_string(),
            line: 1,
            column: 0,
        },
    });

    // this.x = x for each non-initialized property
    for p in &uninit_props {
        body.push(Statement::Assignment {
            target: Expression::PropertyAccess {
                property: p.name.clone(),
            },
            value: Expression::Identifier {
                name: p.name.clone(),
            },
            source_location: SourceLocation {
                file: file.to_string(),
                line: 1,
                column: 0,
            },
        });
    }

    MethodNode {
        name: "constructor".to_string(),
        params,
        body,
        visibility: Visibility::Public,
        source_location: SourceLocation {
            file: file.to_string(),
            line: 1,
            column: 0,
        },
        sighash_type: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snake_to_camel() {
        assert_eq!(snake_to_camel("hello_world"), "helloWorld");
        assert_eq!(snake_to_camel("check_sig"), "checkSig");
        assert_eq!(snake_to_camel("already"), "already");
        assert_eq!(snake_to_camel("a_b_c"), "aBC");
        assert_eq!(snake_to_camel("pub_key_hash"), "pubKeyHash");
        assert_eq!(snake_to_camel("sum_"), "sum");
        assert_eq!(snake_to_camel("assert_"), "assert");
    }

    #[test]
    fn test_builtin_name_mapping() {
        assert_eq!(map_builtin_name("assert_"), "assert");
        assert_eq!(map_builtin_name("check_sig"), "checkSig");
        assert_eq!(map_builtin_name("hash160"), "hash160");
        assert_eq!(map_builtin_name("verify_wots"), "verifyWOTS");
        assert_eq!(
            map_builtin_name("verify_slh_dsa_sha2_128s"),
            "verifySLHDSA_SHA2_128s"
        );
        assert_eq!(map_builtin_name("ec_add"), "ecAdd");
        assert_eq!(map_builtin_name("add_output"), "addOutput");
        assert_eq!(map_builtin_name("abs"), "abs");
        assert_eq!(map_builtin_name("some_func"), "someFunc");
    }

    #[test]
    fn test_parse_simple_python_contract() {
        let source = r#"
from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig

class P2PKH(SmartContract):
    pub_key_hash: Addr

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
"#;

        let result = parse_python(source, Some("P2PKH.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.name, "P2PKH");
        assert_eq!(contract.parent_class, "SmartContract");
        assert_eq!(contract.properties.len(), 1);
        assert_eq!(contract.properties[0].name, "pubKeyHash");
        assert!(contract.properties[0].readonly);
        assert_eq!(contract.methods.len(), 1);
        assert_eq!(contract.methods[0].name, "unlock");
        assert_eq!(contract.methods[0].visibility, Visibility::Public);
        // self param should be excluded
        assert_eq!(contract.methods[0].params.len(), 2);
        assert_eq!(contract.methods[0].params[0].name, "sig");
        assert_eq!(contract.methods[0].params[1].name, "pubKey");
    }

    #[test]
    fn test_parse_stateful_python_contract() {
        let source = r#"
from runar import StatefulSmartContract, Bigint, Readonly, public, assert_

class Stateful(StatefulSmartContract):
    count: Bigint
    max_count: Readonly[Bigint]

    def __init__(self, count: Bigint, max_count: Bigint):
        super().__init__(count, max_count)
        self.count = count
        self.max_count = max_count

    @public
    def increment(self, amount: Bigint):
        self.count = self.count + amount
        assert_(self.count <= self.max_count)

    @public
    def reset(self):
        self.count = 0
"#;

        let result = parse_python(source, Some("Stateful.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.name, "Stateful");
        assert_eq!(contract.parent_class, "StatefulSmartContract");
        assert_eq!(contract.properties.len(), 2);
        assert_eq!(contract.properties[0].name, "count");
        assert!(!contract.properties[0].readonly);
        assert_eq!(contract.properties[1].name, "maxCount");
        assert!(contract.properties[1].readonly);
        assert_eq!(contract.methods.len(), 2);
    }

    #[test]
    fn test_parse_for_loop() {
        let source = r#"
from runar import SmartContract, Bigint, public, assert_

class BoundedLoop(SmartContract):
    expected_sum: Bigint

    def __init__(self, expected_sum: Bigint):
        super().__init__(expected_sum)
        self.expected_sum = expected_sum

    @public
    def verify(self, start: Bigint):
        sum_: Bigint = 0
        for i in range(5):
            sum_ = sum_ + start + i
        assert_(sum_ == self.expected_sum)
"#;

        let result = parse_python(source, Some("BoundedLoop.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods[0].name, "verify");
        // body: let sum, for, assert
        assert_eq!(contract.methods[0].body.len(), 3);
    }

    #[test]
    fn test_parse_if_else() {
        let source = r#"
from runar import SmartContract, Bigint, public, assert_

class IfElse(SmartContract):
    limit: Bigint

    def __init__(self, limit: Bigint):
        super().__init__(limit)
        self.limit = limit

    @public
    def check(self, value: Bigint, mode: bool):
        result: Bigint = 0
        if mode:
            result = value + self.limit
        else:
            result = value - self.limit
        assert_(result > 0)
"#;

        let result = parse_python(source, Some("IfElse.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods[0].body.len(), 3); // let result, if/else, assert
    }

    #[test]
    fn test_eq_maps_to_strict_eq() {
        let source = r#"
from runar import SmartContract, Bigint, public, assert_

class Test(SmartContract):
    x: Bigint

    @public
    def check(self, y: Bigint):
        assert_(self.x == y)
        assert_(self.x != y)
"#;

        let result = parse_python(source, Some("Test.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;
        assert_eq!(body.len(), 2);

        // First assert: StrictEq
        if let Statement::ExpressionStatement { expression, .. } = &body[0] {
            if let Expression::CallExpr { args, .. } = expression {
                if let Expression::BinaryExpr { op, .. } = &args[0] {
                    assert_eq!(*op, BinaryOp::StrictEq);
                } else {
                    panic!("Expected BinaryExpr inside assert");
                }
            } else {
                panic!("Expected CallExpr for assert");
            }
        }

        // Second assert: StrictNe
        if let Statement::ExpressionStatement { expression, .. } = &body[1] {
            if let Expression::CallExpr { args, .. } = expression {
                if let Expression::BinaryExpr { op, .. } = &args[0] {
                    assert_eq!(*op, BinaryOp::StrictNe);
                } else {
                    panic!("Expected BinaryExpr inside assert");
                }
            }
        }
    }

    #[test]
    fn test_self_to_this_conversion() {
        let source = r#"
from runar import StatefulSmartContract, Bigint, public

class Example(StatefulSmartContract):
    value: Bigint

    @public
    def set_value(self, new_value: Bigint):
        self.value = new_value
"#;

        let result = parse_python(source, Some("Example.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;
        assert_eq!(body.len(), 1);

        // Should be this.value = newValue (with PropertyAccess)
        if let Statement::Assignment { target, .. } = &body[0] {
            match target {
                Expression::PropertyAccess { property } => {
                    assert_eq!(property, "value");
                }
                _ => panic!("Expected PropertyAccess, got {:?}", target),
            }
        }
        // Method name and param should be camelCase
        assert_eq!(contract.methods[0].name, "setValue");
        assert_eq!(contract.methods[0].params[0].name, "newValue");
    }

    #[test]
    fn test_constructor_auto_generated() {
        let source = r#"
from runar import SmartContract, Bigint, PubKey, public, assert_

class Test(SmartContract):
    a: Bigint
    b: PubKey

    @public
    def check(self):
        assert_(self.a > 0)
"#;

        let result = parse_python(source, None);
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        // Constructor should have params for each property
        assert_eq!(contract.constructor.params.len(), 2);
        // Constructor body: super(a, b) + this.a = a + this.b = b
        assert_eq!(contract.constructor.body.len(), 3);
    }

    #[test]
    fn test_python_integer_division() {
        let source = r#"
from runar import SmartContract, Bigint, public, assert_

class DivTest(SmartContract):
    x: Bigint

    @public
    def check(self, y: Bigint):
        result: Bigint = self.x // y
        assert_(result > 0)
"#;

        let result = parse_python(source, Some("DivTest.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;

        // First statement should be a variable decl with init being BinaryExpr Div
        if let Statement::VariableDecl { init, .. } = &body[0] {
            if let Expression::BinaryExpr { op, .. } = init {
                assert_eq!(*op, BinaryOp::Div);
            } else {
                panic!("Expected BinaryExpr Div, got {:?}", init);
            }
        }
    }

    #[test]
    fn test_ternary_expression() {
        let source = r#"
from runar import SmartContract, Bigint, public, assert_

class TernTest(SmartContract):
    x: Bigint

    @public
    def check(self, cond: bool):
        result: Bigint = 1 if cond else 0
        assert_(result == self.x)
"#;

        let result = parse_python(source, Some("TernTest.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;

        // First statement should be variable decl with ternary init
        if let Statement::VariableDecl { init, .. } = &body[0] {
            match init {
                Expression::TernaryExpr { .. } => {} // OK
                _ => panic!("Expected TernaryExpr, got {:?}", init),
            }
        }
    }

    #[test]
    fn test_assert_keyword_as_statement() {
        let source = r#"
from runar import SmartContract, Bigint, public

class AssertTest(SmartContract):
    x: Bigint

    @public
    def check(self, y: Bigint):
        assert self.x == y
"#;

        let result = parse_python(source, Some("AssertTest.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;
        assert_eq!(body.len(), 1);

        if let Statement::ExpressionStatement { expression, .. } = &body[0] {
            if let Expression::CallExpr { callee, .. } = expression {
                if let Expression::Identifier { name } = callee.as_ref() {
                    assert_eq!(name, "assert");
                }
            }
        }
    }

    #[test]
    fn test_hex_byte_string() {
        let source = r#"
from runar import SmartContract, ByteString, public, assert_

class HexTest(SmartContract):
    data: ByteString

    @public
    def check(self):
        val: ByteString = b'\xde\xad'
        assert_(val == self.data)
"#;

        let result = parse_python(source, Some("HexTest.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;

        if let Statement::VariableDecl { init, .. } = &body[0] {
            if let Expression::ByteStringLiteral { value } = init {
                assert_eq!(value, "dead");
            } else {
                panic!("Expected ByteStringLiteral, got {:?}", init);
            }
        }
    }

    #[test]
    fn test_shift_operators() {
        let source = r#"
from runar import SmartContract, Bigint, public, assert_

class ShiftTest(SmartContract):
    x: Bigint

    @public
    def check(self, n: Bigint):
        a: Bigint = self.x << n
        b: Bigint = self.x >> n
        assert_(a + b > 0)
"#;

        let result = parse_python(source, Some("ShiftTest.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;

        // First var decl should have Shl
        if let Statement::VariableDecl { init, .. } = &body[0] {
            if let Expression::BinaryExpr { op, .. } = init {
                assert_eq!(*op, BinaryOp::Shl);
            }
        }
        // Second var decl should have Shr
        if let Statement::VariableDecl { init, .. } = &body[1] {
            if let Expression::BinaryExpr { op, .. } = init {
                assert_eq!(*op, BinaryOp::Shr);
            }
        }
    }
}

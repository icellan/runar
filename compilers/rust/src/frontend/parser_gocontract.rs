//! Go contract parser for Rúnar contracts (.runar.go).
//!
//! Parses Go struct-based contract definitions using a hand-written tokenizer
//! and recursive descent parser. Produces the same AST as the TypeScript parser.
//!
//! ## Expected format
//!
//! ```go
//! package contract
//!
//! import runar "github.com/icellan/runar/packages/runar-go"
//!
//! type P2PKH struct {
//!     runar.SmartContract
//!     PubKeyHash runar.Addr `runar:"readonly"`
//! }
//!
//! func (c *P2PKH) Unlock(sig runar.Sig, pubKey runar.PubKey) {
//!     runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
//!     runar.Assert(runar.CheckSig(sig, pubKey))
//! }
//! ```
//!
//! Key mappings:
//! - `runar.SmartContract` embed -> parentClass = "SmartContract"
//! - `runar.StatefulSmartContract` embed -> parentClass = "StatefulSmartContract"
//! - `runar:"readonly"` struct tag -> readonly = true
//! - Exported methods (capital first letter) -> public
//! - Unexported methods -> private
//! - `runar.Assert(x)` -> assert(x)
//! - `==` -> StrictEq (===), `!=` -> StrictNe (!==)
//! - Go type names mapped: `runar.Bigint` -> bigint, `runar.PubKey` -> PubKey, etc.
//! - Exported Go identifiers lowercased (camelCase): `PubKeyHash` -> `pubKeyHash`
//! - `init()` method -> property initializers (extracted, not emitted as a method)
//! - `++` / `--` -> IncrementExpr / DecrementExpr
//! - `:=` -> VariableDecl (mutable)
//! - standalone functions (no receiver) -> private helper methods

use num_bigint::BigInt;
use num_traits::ToPrimitive;
use super::ast::{
    BinaryOp, ContractNode, Expression, MethodNode, ParamNode, PrimitiveTypeName, PropertyNode,
    SourceLocation, Statement, TypeNode, UnaryOp, Visibility,
};
use super::diagnostic::{invalid_escape_sequence_message, lex_error, unknown_return_type_message, Diagnostic, UNTERMINATED_STRING_LITERAL};
use super::sighash_directive::{lost_directive_message, resolve_native_sighash, unknown_go_directive_message};
use super::int_literal::{invalid_integer_literal, parse_int_literal, scan_number_end};
use super::input_limits::{enforce_ast_nesting, nesting_refusal, DepthTracker, NestingCounter};
use super::parser::ParseResult;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a Go-format Rúnar contract source.
pub fn parse_go_contract(source: &str, file_name: Option<&str>) -> ParseResult {
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
    super::input_limits::run_on_parse_stack(|| parse_go_contract_on_parse_stack(source, file_name))
}

/// The body of [`parse_go_contract`], on the parse stack segment.
fn parse_go_contract_on_parse_stack(source: &str, file_name: Option<&str>) -> ParseResult {
    let file = file_name.unwrap_or("contract.runar.go");
    let mut errors: Vec<Diagnostic> = Vec::new();

    let mut directives: Vec<GoDirective> = Vec::new();
    let tokens = tokenize(source, file, &mut errors, &mut directives);
    let mut parser = GoParser::new(tokens, file, &mut errors);
    parser.directives = directives;

    let contract = parser.parse();
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

/// Convert a Go exported identifier to camelCase.
/// e.g., "PubKeyHash" -> "pubKeyHash", "Unlock" -> "unlock"
/// Lowercase identifiers pass through unchanged.
fn go_to_camel(name: &str) -> String {
    if name.is_empty() {
        return name.to_string();
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if first.is_uppercase() {
        let rest: String = chars.collect();
        format!("{}{}", first.to_lowercase(), rest)
    } else {
        name.to_string()
    }
}

/// Map Go/runar type names to Rúnar AST type nodes.
fn map_go_type(name: &str) -> TypeNode {
    match name {
        "Int" | "Bigint" | "BigintBig" | "int64" => {
            TypeNode::Primitive(PrimitiveTypeName::Bigint)
        }
        "Bool" | "bool" => TypeNode::Primitive(PrimitiveTypeName::Boolean),
        "ByteString" => TypeNode::Primitive(PrimitiveTypeName::ByteString),
        "PubKey" => TypeNode::Primitive(PrimitiveTypeName::PubKey),
        "Sig" => TypeNode::Primitive(PrimitiveTypeName::Sig),
        "Sha256" | "Sha256Digest" => TypeNode::Primitive(PrimitiveTypeName::Sha256),
        "Ripemd160" | "Ripemd160Hash" => TypeNode::Primitive(PrimitiveTypeName::Ripemd160),
        "Addr" => TypeNode::Primitive(PrimitiveTypeName::Addr),
        "SigHashPreimage" => TypeNode::Primitive(PrimitiveTypeName::SigHashPreimage),
        "RabinSig" => TypeNode::Primitive(PrimitiveTypeName::RabinSig),
        "RabinPubKey" => TypeNode::Primitive(PrimitiveTypeName::RabinPubKey),
        "Point" => TypeNode::Primitive(PrimitiveTypeName::Point),
        "P256Point" => TypeNode::Primitive(PrimitiveTypeName::P256Point),
        "P384Point" => TypeNode::Primitive(PrimitiveTypeName::P384Point),
        _ => TypeNode::Custom(name.to_string()),
    }
}

/// Map a runar.* builtin name (the part after "runar.") to the Rúnar AST callee name.
/// The Rúnar binary operator each `BigintBig` helper stands for.
///
/// Mirrors `bigintBigOpFor` in compilers/go/frontend/parser_gocontract.go,
/// `GO_BIGINTBIG_OPS` in packages/runar-compiler/src/passes/01-parse-go.ts, and
/// the eleven helpers in packages/runar-go/runar.go. All four have to agree:
/// a tier that knows a spelling the others do not is a frontend-parity break,
/// which is exactly the state this table was added to end.
fn go_bigintbig_op(name: &str) -> Option<BinaryOp> {
    match name {
        "BigintBigLess" => Some(BinaryOp::Lt),
        "BigintBigLessEq" => Some(BinaryOp::Le),
        "BigintBigGreater" => Some(BinaryOp::Gt),
        "BigintBigGreaterEq" => Some(BinaryOp::Ge),
        "BigintBigEqual" => Some(BinaryOp::StrictEq),
        "BigintBigNotEqual" => Some(BinaryOp::StrictNe),
        "BigintBigAdd" => Some(BinaryOp::Add),
        "BigintBigSub" => Some(BinaryOp::Sub),
        "BigintBigMul" => Some(BinaryOp::Mul),
        "BigintBigMod" => Some(BinaryOp::Mod),
        "BigintBigDiv" => Some(BinaryOp::Div),
        _ => None,
    }
}

fn map_go_builtin(name: &str) -> String {
    match name {
        // the *Big peers of num2bin / bin2num. They lower to the SAME builtins as Num2Bin / Bin2Num, exactly as compilers/go has always done: the suffix names a different Go RUNTIME type (*big.Int, so the Go-side mock does not truncate), not a different Script operation. Six tiers fell through to the default rule and produced `num2BinBig` / `bin2NumBig`, names no builtin registry has (R-Bigint)
        "Num2BinBig" => "num2bin".to_string(),
        "Bin2NumBig" => "bin2num".to_string(),

        // the *Big peers of abs / gcd. Same rule as Num2BinBig / Bin2NumBig above: the
        // suffix names a different Go RUNTIME type (*big.Int, so the Go-side mock does
        // not narrow at MinInt64), not a different Script operation -- OP_ABS and the
        // gcd builtin are arbitrary-width after Genesis. These were mapped in ZERO
        // tiers while `Abs(math.MinInt64)` and `Gcd(math.MinInt64, 0)` in
        // packages/runar-go panic telling the author to use them, naming the .runar.go
        // parser as the thing that lowers them.
        "AbsBig" => "abs".to_string(),
        "GcdBig" => "gcd".to_string(),
        "Assert" => "assert".to_string(),
        "Hash160" => "hash160".to_string(),
        "Hash256" => "hash256".to_string(),
        "Sha256" => "sha256".to_string(),
        "Sha256Hash" => "sha256".to_string(),
        "Ripemd160" => "ripemd160".to_string(),
        "CheckSig" => "checkSig".to_string(),
        "CheckMultiSig" => "checkMultiSig".to_string(),
        "CheckPreimage" => "checkPreimage".to_string(),
        "VerifyRabinSig" => "verifyRabinSig".to_string(),
        "VerifyWOTS" => "verifyWOTS".to_string(),
        "VerifySLHDSA_SHA2_128s" => "verifySLHDSA_SHA2_128s".to_string(),
        "VerifySLHDSA_SHA2_128f" => "verifySLHDSA_SHA2_128f".to_string(),
        "VerifySLHDSA_SHA2_192s" => "verifySLHDSA_SHA2_192s".to_string(),
        "VerifySLHDSA_SHA2_192f" => "verifySLHDSA_SHA2_192f".to_string(),
        "VerifySLHDSA_SHA2_256s" => "verifySLHDSA_SHA2_256s".to_string(),
        "VerifySLHDSA_SHA2_256f" => "verifySLHDSA_SHA2_256f".to_string(),
        "Num2Bin" => "num2bin".to_string(),
        "Bin2Num" => "bin2num".to_string(),
        // `Int2Str` is the spelling docs/formats/go.md documents. Without it the
        // default rule camel-cases the leading character to `int2Str`, which is
        // registered nowhere — the call is rejected as an unknown function.
        "Int2Str" => "int2str".to_string(),
        "Cat" => "cat".to_string(),
        "Substr" => "substr".to_string(),
        "Len" => "len".to_string(),
        "ReverseBytes" => "reverseBytes".to_string(),
        "ExtractLocktime" => "extractLocktime".to_string(),
        "ExtractOutputHash" => "extractOutputHash".to_string(),
        // Intent sub-covenant intrinsics (BSVM Phase 13).
        "ExtractPrevOutputScript" => "extractPrevOutputScript".to_string(),
        "RequireOutputP2PKH" => "requireOutputP2PKH".to_string(),
        "CurrentBlockHeight" => "currentBlockHeight".to_string(),
        "ContinuationAmount" => "continuationAmount".to_string(),
        "AddOutput" => "addOutput".to_string(),
        "AddRawOutput" => "addRawOutput".to_string(),
        "AddDataOutput" => "addDataOutput".to_string(),
        "GetStateScript" => "getStateScript".to_string(),
        "Safediv" => "safediv".to_string(),
        "Safemod" => "safemod".to_string(),
        "Clamp" => "clamp".to_string(),
        "Sign" => "sign".to_string(),
        "Pow" => "pow".to_string(),
        "MulDiv" => "mulDiv".to_string(),
        "PercentOf" => "percentOf".to_string(),
        "Sqrt" => "sqrt".to_string(),
        "Gcd" => "gcd".to_string(),
        "Divmod" => "divmod".to_string(),
        "Log2" => "log2".to_string(),
        "ToBool" => "bool".to_string(),
        "Abs" => "abs".to_string(),
        "Min" => "min".to_string(),
        "Max" => "max".to_string(),
        "Within" => "within".to_string(),
        "EcAdd" => "ecAdd".to_string(),
        "EcMul" => "ecMul".to_string(),
        "EcMulGen" => "ecMulGen".to_string(),
        "EcNegate" => "ecNegate".to_string(),
        "EcOnCurve" => "ecOnCurve".to_string(),
        "EcModReduce" => "ecModReduce".to_string(),
        "EcEncodeCompressed" => "ecEncodeCompressed".to_string(),
        "EcMakePoint" => "ecMakePoint".to_string(),
        "EcPointX" => "ecPointX".to_string(),
        "EcPointY" => "ecPointY".to_string(),
        "Sha256Compress" => "sha256Compress".to_string(),
        "Sha256Finalize" => "sha256Finalize".to_string(),
        "VerifyECDSAP256" => "verifyECDSA_P256".to_string(),
        "VerifyECDSAP384" => "verifyECDSA_P384".to_string(),
        _ => go_to_camel(name),
    }
}

// ---------------------------------------------------------------------------
// Token types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum TokenType {
    // Keywords
    Package,
    Import,
    Type,
    Struct,
    Func,
    If,
    Else,
    For,
    Return,
    Var,
    Const,
    True,
    False,
    // Punctuation
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Semi,
    Comma,
    Dot,
    Colon,
    Star,
    // Operators
    Plus,
    Minus,
    Slash,
    Percent,
    EqEq,   // ==
    BangEq, // !=
    Lt,
    LtEq,
    Gt,
    GtEq,
    Shl,    // <<
    Shr,    // >>
    AmpAmp, // &&
    PipePipe, // ||
    Amp,
    Pipe,
    Caret,
    Tilde,
    Bang,
    Eq,       // =
    ColonEq,  // :=
    PlusEq,   // +=
    MinusEq,  // -=
    StarEq,    // *=
    SlashEq,   // /=
    PercentEq, // %=
    // A Go compound assignment the Rúnar Go surface does not accept
    // (&= |= ^= <<= >>= &^=). Lexed as one token so the parser can refuse it
    // by name instead of mis-parsing it as `x & (= ...)` and dropping it.
    UnsupportedCompoundAssign(&'static str),
    PlusPlus, // ++
    MinusMinus, // --
    // Literals
    Ident(String),
    Number(BigInt),
    StringLit(String), // backtick or double-quoted
    // End
    Eof,
}

#[derive(Debug, Clone)]
struct Token {
    typ: TokenType,
    line: usize,
    col: usize,
    /// N-435: double-quoted `StringLit` only -- the Go string's bytes (literal
    /// text UTF-8 encoded, a `\xNN` escape the single byte NN).
    raw: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

/// N-093: the comma-separated options of a struct tag's `runar` key (the
/// first match of `(?:^|\s)runar:"([^"]*)"`), trimmed; empty when there is no
/// such key. Mirrors the TS reference (01-parse-go.ts).
fn runar_tag_options(tag: &str) -> Vec<String> {
    let key = "runar:\"";
    let mut from = 0;
    while let Some(rel) = tag[from..].find(key) {
        let at = from + rel;
        let boundary = at == 0 || tag[..at].chars().next_back().is_some_and(char::is_whitespace);
        if boundary {
            let rest = &tag[at + key.len()..];
            if let Some(end) = rest.find('"') {
                return rest[..end].split(',').map(|o| o.trim().to_string()).collect();
            }
        }
        from = at + 1;
    }
    Vec::new()
}

/// N-093: a Go DSL directive comment `//runar:<name> <args>` (Go's own `//go:`
/// convention: no space after `//`). `token_index` is the index of the first
/// token after the comment, so a directive attaches to the declaration that
/// follows it, with only comments and blank lines in between. Mirrors
/// `GoDirective` in the TS reference (01-parse-go.ts).
struct GoDirective {
    name: String,
    args: String,
    token_index: usize,
    line: usize,
    col: usize,
}

/// N-437: decode the body of a Go interpreted string literal with Go's rules
/// (https://go.dev/ref/spec#String_literals). Returns `(val, raw, error)`:
/// `raw` is the Go string's BYTES (literal text and `\u`/`\U` escapes UTF-8
/// encoded, `\xNN` and `\NNN` octal (at most 255) the single byte); `val`
/// keeps one char per escape for the bare-literal (hex) path; `error` is the
/// shared invalid-escape diagnostic for an escape Go refuses.
fn decode_go_string(body: &[char]) -> (String, Vec<u8>, Option<String>) {
    let mut val = String::new();
    let mut raw: Vec<u8> = Vec::new();
    let mut i = 0;
    let n = body.len();
    macro_rules! fail {
        ($esc:expr) => {
            return (val, raw, Some(invalid_escape_sequence_message(&$esc)))
        };
    }
    while i < n {
        let c = body[i];
        if c != '\\' {
            val.push(c);
            raw.extend_from_slice(c.to_string().as_bytes());
            i += 1;
            continue;
        }
        let e = if i + 1 < n { Some(body[i + 1]) } else { None };
        let simple = match e {
            Some('a') => Some('\x07'),
            Some('b') => Some('\x08'),
            Some('f') => Some('\x0c'),
            Some('n') => Some('\n'),
            Some('r') => Some('\r'),
            Some('t') => Some('\t'),
            Some('v') => Some('\x0b'),
            Some('\\') => Some('\\'),
            Some('"') => Some('"'),
            _ => None,
        };
        if let Some(s) = simple {
            val.push(s);
            raw.push(s as u8);
            i += 2;
            continue;
        }
        match e {
            Some('x') => {
                let h: String = body.iter().skip(i + 2).take(2).collect();
                if h.chars().count() != 2 || !h.chars().all(|d| d.is_ascii_hexdigit()) {
                    fail!("\\x".to_string());
                }
                let b = u8::from_str_radix(&h, 16).unwrap();
                val.push(b as char);
                raw.push(b);
                i += 4;
            }
            Some(u @ ('u' | 'U')) => {
                let width = if u == 'u' { 4 } else { 8 };
                let h: String = body.iter().skip(i + 2).take(width).collect();
                let cp = if h.chars().count() == width && h.chars().all(|d| d.is_ascii_hexdigit()) {
                    u32::from_str_radix(&h, 16).ok()
                } else {
                    None
                };
                match cp.and_then(char::from_u32) {
                    Some(ch) => {
                        val.push(ch);
                        raw.extend_from_slice(ch.to_string().as_bytes());
                        i += 2 + width;
                    }
                    None => fail!(format!("\\{}", u)),
                }
            }
            Some(d) if ('0'..='7').contains(&d) => {
                let run: String = body.iter().skip(i + 1).take(3).take_while(|x| ('0'..='7').contains(*x)).collect();
                if run.len() < 3 || u32::from_str_radix(&run, 8).unwrap() > 0xff {
                    fail!(format!("\\{}", run));
                }
                let b = u32::from_str_radix(&run, 8).unwrap() as u8;
                val.push(b as char);
                raw.push(b);
                i += 4;
            }
            Some(other) => fail!(format!("\\{}", other)),
            None => fail!("\\".to_string()),
        }
    }
    (val, raw, None)
}

fn tokenize(source: &str, file: &str, errors: &mut Vec<Diagnostic>, directives: &mut Vec<GoDirective>) -> Vec<Token> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut pos = 0usize;
    let mut line = 1usize;
    let mut col = 1usize;

    while pos < chars.len() {
        let ch = chars[pos];
        let l = line;
        let c = col;

        // Whitespace (skip semicolons that Go inserts — we handle real `;` and newlines)
        // N-407: exactly the TS reference's whitespace (' ', '\t', '\r', '\n'); a
        // non-ASCII space such as U+00A0 is refused as an unexpected character.
        if matches!(ch, ' ' | '\t' | '\r' | '\n') {
            if ch == '\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
            pos += 1;
            continue;
        }

        // Line comments
        if ch == '/' && pos + 1 < chars.len() && chars[pos + 1] == '/' {
            let start = pos;
            while pos < chars.len() && chars[pos] != '\n' {
                pos += 1;
            }
            // N-093: `//runar:<name> <args>` is a directive, not prose.
            let text: String = chars[start..pos].iter().collect();
            let text = text.strip_suffix('\r').unwrap_or(&text);
            if let Some(body) = text.strip_prefix("//runar:") {
                let n = body.find([' ', '\t']).unwrap_or(body.len());
                directives.push(GoDirective {
                    name: body[..n].to_string(),
                    args: body[n..].to_string(),
                    token_index: tokens.len(),
                    line: l,
                    col: c,
                });
            }
            continue;
        }

        // Block comments
        if ch == '/' && pos + 1 < chars.len() && chars[pos + 1] == '*' {
            pos += 2;
            col += 2;
            while pos + 1 < chars.len() {
                if chars[pos] == '\n' {
                    line += 1;
                    col = 1;
                }
                if chars[pos] == '*' && chars[pos + 1] == '/' {
                    pos += 2;
                    col += 2;
                    break;
                }
                pos += 1;
                col += 1;
            }
            continue;
        }

        // Backtick string (struct tags like `runar:"readonly"`)
        if ch == '`' {
            let mut val = String::new();
            pos += 1;
            col += 1;
            while pos < chars.len() && chars[pos] != '`' {
                val.push(chars[pos]);
                pos += 1;
                col += 1;
            }
            // F-011: a raw string may span lines, so only end of file leaves
            // it unterminated.
            if pos < chars.len() {
                pos += 1;
                col += 1;
            } else {
                errors.push(lex_error(UNTERMINATED_STRING_LITERAL, file, l, c - 1));
            }
            // N-437: a raw string is its text verbatim, carriage returns discarded (Go spec).
            // N-439: the bare-literal (hex) path reads the token text, so it is
            // the CR-free text too.
            let val = val.replace('\r', "");
            let raw = Some(val.clone().into_bytes());
            tokens.push(Token { typ: TokenType::StringLit(val), line: l, col: c, raw });
            continue;
        }

        // Double-quoted string
        if ch == '"' {
            let mut body: Vec<char> = Vec::new();
            pos += 1;
            col += 1;
            // F-011: a Go interpreted string cannot span lines; one that
            // reaches a line break (escaped or not) or end of file is
            // unterminated and must never run on into the following lines.
            while pos < chars.len() && chars[pos] != '"' && chars[pos] != '\n' && chars[pos] != '\r' {
                if chars[pos] == '\\' && (pos + 1 >= chars.len() || chars[pos + 1] == '\n' || chars[pos + 1] == '\r') {
                    break;
                }
                if chars[pos] == '\\' && pos + 1 < chars.len() {
                    body.push('\\');
                    pos += 1;
                    col += 1;
                }
                body.push(chars[pos]);
                pos += 1;
                col += 1;
            }
            if pos < chars.len() && chars[pos] == '"' {
                pos += 1;
                col += 1;
            } else {
                errors.push(lex_error(UNTERMINATED_STRING_LITERAL, file, l, c - 1));
            }
            // N-437: decode with Go's string-literal rules; an escape Go
            // refuses is refused here too.
            let (val, raw, esc_err) = decode_go_string(&body);
            if let Some(msg) = esc_err {
                errors.push(lex_error(&msg, file, l, c - 1));
            }
            tokens.push(Token { typ: TokenType::StringLit(val), line: l, col: c, raw: Some(raw) });
            continue;
        }

        // Three-char operators first
        if pos + 2 < chars.len() {
            let tok = match (ch, chars[pos + 1], chars[pos + 2]) {
                ('<', '<', '=') => Some(TokenType::UnsupportedCompoundAssign("<<=")),
                ('>', '>', '=') => Some(TokenType::UnsupportedCompoundAssign(">>=")),
                ('&', '^', '=') => Some(TokenType::UnsupportedCompoundAssign("&^=")),
                _ => None,
            };
            if let Some(t) = tok {
                tokens.push(Token { typ: t, line: l, col: c, raw: None });
                pos += 3;
                col += 3;
                continue;
            }
        }

        // Two-char operators
        if pos + 1 < chars.len() {
            let two = (ch, chars[pos + 1]);
            let tok = match two {
                (':', '=') => Some(TokenType::ColonEq),
                ('=', '=') => Some(TokenType::EqEq),
                ('!', '=') => Some(TokenType::BangEq),
                ('<', '=') => Some(TokenType::LtEq),
                ('>', '=') => Some(TokenType::GtEq),
                ('&', '&') => Some(TokenType::AmpAmp),
                ('|', '|') => Some(TokenType::PipePipe),
                ('+', '=') => Some(TokenType::PlusEq),
                ('-', '=') => Some(TokenType::MinusEq),
                ('*', '=') => Some(TokenType::StarEq),
                ('/', '=') => Some(TokenType::SlashEq),
                ('%', '=') => Some(TokenType::PercentEq),
                ('&', '=') => Some(TokenType::UnsupportedCompoundAssign("&=")),
                ('|', '=') => Some(TokenType::UnsupportedCompoundAssign("|=")),
                ('^', '=') => Some(TokenType::UnsupportedCompoundAssign("^=")),
                ('+', '+') => Some(TokenType::PlusPlus),
                ('-', '-') => Some(TokenType::MinusMinus),
                ('<', '<') => Some(TokenType::Shl),
                ('>', '>') => Some(TokenType::Shr),
                _ => None,
            };
            if let Some(t) = tok {
                tokens.push(Token { typ: t, line: l, col: c, raw: None });
                pos += 2;
                col += 2;
                continue;
            }
        }

        // Single-char tokens
        let single = match ch {
            '(' => Some(TokenType::LParen),
            ')' => Some(TokenType::RParen),
            '{' => Some(TokenType::LBrace),
            '}' => Some(TokenType::RBrace),
            '[' => Some(TokenType::LBracket),
            ']' => Some(TokenType::RBracket),
            ';' => Some(TokenType::Semi),
            ',' => Some(TokenType::Comma),
            '.' => Some(TokenType::Dot),
            ':' => Some(TokenType::Colon),
            '*' => Some(TokenType::Star),
            '+' => Some(TokenType::Plus),
            '-' => Some(TokenType::Minus),
            '/' => Some(TokenType::Slash),
            '%' => Some(TokenType::Percent),
            '<' => Some(TokenType::Lt),
            '>' => Some(TokenType::Gt),
            '&' => Some(TokenType::Amp),
            '|' => Some(TokenType::Pipe),
            '^' => Some(TokenType::Caret),
            '~' => Some(TokenType::Tilde),
            '!' => Some(TokenType::Bang),
            '=' => Some(TokenType::Eq),
            _ => None,
        };
        if let Some(t) = single {
            tokens.push(Token { typ: t, line: l, col: c, raw: None });
            pos += 1;
            col += 1;
            continue;
        }

        // Number literal (F-026): the whole glued [0-9A-Za-z_] run is one Go
        // integer literal, `0x` / `0o` / `0b` and legacy octal included.
        if ch.is_ascii_digit() {
            let end = scan_number_end(&chars, pos);
            let text: String = chars[pos..end].iter().collect();
            col += end - pos;
            pos = end;
            let n = match parse_int_literal("go", &text) {
                Some(lit) => lit.value,
                None => {
                    errors.push(lex_error(&invalid_integer_literal("go", &text), file, l, c - 1));
                    BigInt::from(0)
                }
            };
            tokens.push(Token { typ: TokenType::Number(n), line: l, col: c, raw: None });
            continue;
        }

        // Identifier / keyword
        // N-407: ASCII only, as the TS reference; a non-ASCII letter is refused
        // as an unexpected character.
        if ch.is_ascii_alphabetic() || ch == '_' {
            let mut val = String::new();
            while pos < chars.len() && (chars[pos].is_ascii_alphanumeric() || chars[pos] == '_') {
                val.push(chars[pos]);
                pos += 1;
                col += 1;
            }
            let tok = match val.as_str() {
                "package" => TokenType::Package,
                "import" => TokenType::Import,
                "type" => TokenType::Type,
                "struct" => TokenType::Struct,
                "func" => TokenType::Func,
                "if" => TokenType::If,
                "else" => TokenType::Else,
                "for" => TokenType::For,
                "return" => TokenType::Return,
                "var" => TokenType::Var,
                "const" => TokenType::Const,
                "true" => TokenType::True,
                "false" => TokenType::False,
                _ => TokenType::Ident(val),
            };
            tokens.push(Token { typ: tok, line: l, col: c, raw: None });
            continue;
        }

        // N-214: an unrecognised character is refused, as the TS reference
        // does, rather than skipped: skipping compiled `a + § b` as `a + b`.
        errors.push(lex_error(&format!("Unexpected character '{}'", ch), file, l, c - 1));
        pos += 1;
        col += 1;
    }

    tokens.push(Token { typ: TokenType::Eof, line, col, raw: None });
    tokens
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

// F-010 diagnostics — emitted verbatim by every tier's .runar.go parser
// (TS reference: goNoContractMessage / goMultipleContractsMessage /
// goForeignReceiverMessage in packages/runar-compiler/src/passes/01-parse-go.ts).
/// N-448 -- every tier's .runar.go parser emits this verbatim.
fn go_bare_string_literal_message(lit: &str) -> String {
    format!(
        "bare string literal \"{lit}\" is ambiguous in .runar.go source: natively it is ASCII text but the compiler reads it as hex \u{2014} write runar.HexToBytes(\"{lit}\") for hex bytes or runar.ByteString(\"{lit}\") for the text"
    )
}

const GO_NO_CONTRACT_MESSAGE: &str = "no Rúnar contract struct found in Go source";

fn go_multiple_contracts_message(first: &str, second: &str) -> String {
    format!(
        "multiple Rúnar contract structs found in Go source: '{}' and '{}'; exactly one struct may embed runar.SmartContract, runar.StatefulSmartContract or runar.UnsafeSmartContract",
        first, second
    )
}

fn go_foreign_receiver_message(method: &str, receiver_type: &str, contract: &str) -> String {
    format!(
        "method '{}' has receiver type '{}', not the contract type '{}'; methods on other types are not allowed",
        method, receiver_type, contract
    )
}

// ---------------------------------------------------------------------------
// N-056 — ambiguous operator precedence (mirrors 01-parse-go.ts)
// ---------------------------------------------------------------------------
//
// Go: `* / % << >> & &^` > `+ - | ^` > comparisons > `&&` > `||`. C ladder
// (this parser): MulDiv > AddSub > Shift > Comparison > Equality > BitAnd >
// BitXor > BitOr > And > Or. For `x OP1 y OP2 z` a scheme groups left iff
// prec(OP1) >= prec(OP2). The ordered (OP1 class, OP2 class) pairs on which
// the schemes disagree: 23 class pairs, 72 operator pairs. `&^` lexes as `&`
// over a prefix `^`, i.e. `&`.

const GO_AMBIGUOUS_PRECEDENCE_PAIRS: &[(&str, &str)] = &[
    ("shift", "mul"), ("shift", "add"),
    ("and", "mul"), ("and", "shift"), ("and", "add"), ("and", "rel"), ("and", "eq"),
    ("add", "shift"), ("add", "and"),
    ("or", "add"), ("or", "xor"), ("or", "rel"), ("or", "eq"),
    ("xor", "add"), ("xor", "rel"), ("xor", "eq"),
    ("rel", "and"), ("rel", "or"), ("rel", "xor"),
    ("eq", "and"), ("eq", "or"), ("eq", "xor"), ("eq", "rel"),
];

fn go_precedence_class(op: &BinaryOp) -> &'static str {
    match op {
        BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => "mul",
        BinaryOp::Shl | BinaryOp::Shr => "shift",
        BinaryOp::BitAnd => "and",
        BinaryOp::Add | BinaryOp::Sub => "add",
        BinaryOp::BitOr => "or",
        BinaryOp::BitXor => "xor",
        BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => "rel",
        BinaryOp::StrictEq | BinaryOp::StrictNe => "eq",
        BinaryOp::And => "land",
        BinaryOp::Or => "lor",
    }
}

fn is_go_ambiguous_precedence(first: &BinaryOp, second: &BinaryOp) -> bool {
    let pair = (go_precedence_class(first), go_precedence_class(second));
    GO_AMBIGUOUS_PRECEDENCE_PAIRS.contains(&pair)
}

fn go_ambiguous_precedence_message(first: &BinaryOp, second: &BinaryOp) -> String {
    let go = |op: &BinaryOp| match op {
        BinaryOp::StrictEq => "==",
        BinaryOp::StrictNe => "!=",
        other => other.as_str(),
    };
    format!(
        "ambiguous operator precedence in .runar.go: `a {} b {} c` groups differently \
         under Go precedence than in Rúnar's other surfaces; add parentheses",
        go(first),
        go(second)
    )
}

struct GoParser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    file: String,
    errors: &'a mut Vec<Diagnostic>,
    /// The current method's receiver name (e.g. "c", "self", "m")
    receiver_name: String,
    /// F-017: declared (spelling, Rúnar name) pairs.
    idents: super::identifier_collision::DeclaredIdents,
    /// N-056: top-level unparenthesised operator of the last parsed operand.
    ladder_top: Option<BinaryOp>,
    /// F-213 measure (A): parse nesting.
    nest: NestingCounter,
    /// N-093: every `//runar:` directive in the file, in source order, and
    /// which of them a func declaration consumed.
    directives: Vec<GoDirective>,
    consumed: Vec<bool>,
    /// N-181: token range `[start, end)` of the last `[N]…[N]` dimension
    /// chain whose composite-literal lookahead failed. Every `[` inside it
    /// starts a dimension group whose lookahead would scan the same tail and
    /// fail the same way, so it is not re-run (it made `int[][]…[]` quadratic).
    composite_miss: Option<(usize, usize)>,
    /// N-448: token indexes of string literals whose bare use is legal (the
    /// opcode body of `runar.Asm`).
    bare_literal_ok: std::collections::HashSet<usize>,
}

impl<'a> GoParser<'a> {
    fn new(tokens: Vec<Token>, file: &str, errors: &'a mut Vec<Diagnostic>) -> Self {
        Self {
            tokens,
            pos: 0,
            file: file.to_string(),
            errors,
            receiver_name: "c".to_string(),
            idents: Default::default(),
            ladder_top: None,
            nest: NestingCounter::new(),
            directives: Vec::new(),
            consumed: Vec::new(),
            composite_miss: None,
            bare_literal_ok: std::collections::HashSet::new(),
        }
    }

    /// N-093: resolve the `//runar:sighash` directives attached to the func
    /// declaration starting at token `token_index` (directly above it, with
    /// only comments and blank lines between), with the shared diagnostics.
    /// A malformed argument segment yields a `None` spec. Mirrors
    /// `takeSighashDirectives` + `resolveNativeSighash` (01-parse-go.ts).
    fn take_sighash(&mut self, token_index: usize, method: &mut MethodNode) {
        self.consumed.resize(self.directives.len(), false);
        let mut specs: Vec<Option<String>> = Vec::new();
        for (i, d) in self.directives.iter().enumerate() {
            if d.token_index != token_index || d.name != "sighash" {
                continue;
            }
            self.consumed[i] = true;
            let ok = d.args.is_empty()
                || (d.args.starts_with([' ', '\t'])
                    && d.args.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '|' || c == ' ' || c == '\t'));
            specs.push(if ok { Some(d.args.clone()) } else { None });
        }
        match resolve_native_sighash(&method.name, method.visibility == Visibility::Public, &specs) {
            Some(Ok(v)) => method.sighash_type = Some(v),
            Some(Err(msg)) => self.errors.push(Diagnostic::error(msg, Some(method.source_location.clone()))),
            None => {}
        }
    }

    /// N-300: a free `init` / `main` is dropped (N-018), so a
    /// `//runar:sighash` above it is refused as on a private func, with the
    /// same diagnostic as the TS reference (which parses these as private
    /// helpers). The current token is the func's name.
    fn refuse_sighash_on_dropped_func(&mut self, func_token_index: usize) {
        let name = match self.current().typ.clone() {
            TokenType::Ident(n) if n == "init" || n == "main" => n,
            _ => return,
        };
        let mut stub = MethodNode {
            name,
            params: Vec::new(),
            body: Vec::new(),
            visibility: Visibility::Private,
            sighash_type: None,
            source_location: SourceLocation {
                file: self.file.clone(),
                line: self.current().line,
                column: self.current().col,
            },
        };
        self.take_sighash(func_token_index, &mut stub);
    }

    /// N-093: refuse every directive that is unknown or attached to no func
    /// declaration that becomes a contract method.
    fn report_stray_directives(&mut self) {
        self.consumed.resize(self.directives.len(), false);
        for (i, d) in self.directives.iter().enumerate() {
            if self.consumed[i] {
                continue;
            }
            let msg = if d.name == "sighash" {
                lost_directive_message("@sighash")
            } else {
                unknown_go_directive_message(&format!("{}{}", d.name, d.args))
            };
            let loc = SourceLocation { file: self.file.clone(), line: d.line, column: d.col };
            self.errors.push(Diagnostic::error(msg, Some(loc)));
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

    fn current(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(self.tokens.last().unwrap())
    }

    fn advance(&mut self) -> Token {
        let t = self.current().clone();
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        t
    }

    fn skip_semis(&mut self) {
        while matches!(self.current().typ, TokenType::Semi) {
            self.advance();
        }
    }

    fn loc(&self) -> SourceLocation {
        SourceLocation {
            file: self.file.clone(),
            line: self.current().line,
            column: self.current().col,
        }
    }

    fn loc_at(file: &str, line: usize, col: usize) -> SourceLocation {
        SourceLocation { file: file.to_string(), line, column: col }
    }

    /// Expect an identifier, returning its value.
    fn expect_ident(&mut self) -> String {
        if let TokenType::Ident(name) = self.current().typ.clone() {
            self.advance();
            name
        } else {
            self.errors.push(Diagnostic::error(format!(
                "Expected identifier, got {:?} at {}:{}",
                self.current().typ,
                self.current().line,
                self.current().col.saturating_sub(1)
            ), None));
            String::new()
        }
    }

    fn expect_tok(&mut self, expected: &TokenType) {
        if std::mem::discriminant(&self.current().typ) != std::mem::discriminant(expected) {
            self.errors.push(Diagnostic::error(format!(
                "Expected {:?}, got {:?} at {}:{}:{}",
                expected,
                self.current().typ,
                self.file,
                self.current().line,
                self.current().col.saturating_sub(1)
            ), None));
        }
        self.advance();
    }

    fn match_tok(&mut self, expected: &TokenType) -> bool {
        if std::mem::discriminant(&self.current().typ) == std::mem::discriminant(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    // ---------------------------------------------------------------------------
    // Top-level parse
    // ---------------------------------------------------------------------------

    fn parse(&mut self) -> Option<ContractNode> {
        // Skip `package <name>`
        if matches!(self.current().typ, TokenType::Package) {
            self.advance();
            self.expect_ident();
            self.skip_semis();
        }

        // Skip `import ...` statements
        while matches!(self.current().typ, TokenType::Import) {
            self.advance();
            self.skip_import_block();
            self.skip_semis();
        }

        let mut contract_name = String::new();
        let mut parent_class = "SmartContract".to_string();
        let mut properties: Vec<PropertyNode> = Vec::new();
        // N-490: the synthesized constructor is anchored at the contract's
        // `struct` keyword, not a fake 1:1.
        let mut ctor_loc = Self::loc_at(&self.file, 1, 1);
        // (method, Go spelling of its name, receiver type or None for a free function)
        let mut funcs: Vec<(MethodNode, String, Option<String>)> = Vec::new();

        // F-010: one pass over every top-level declaration, in source order.
        // The contract is THE struct embedding a runar base (the first one;
        // any further one is refused); `func`s anywhere in the file are
        // collected and checked against it afterwards, so a method declared
        // before the contract struct is neither lost nor let through.
        while !matches!(self.current().typ, TokenType::Eof) {
            self.skip_semis();
            if matches!(self.current().typ, TokenType::Func) {
                // N-093: the `//runar:sighash` directives directly above this func.
                let func_token_index = self.pos;
                self.advance(); // consume 'func'
                if matches!(self.current().typ, TokenType::LParen) {
                    // Method: func (recv *Type) MethodName(...)
                    let (mut method, go_name, recv) = self.parse_method();
                    self.take_sighash(func_token_index, &mut method);
                    funcs.push((method, go_name, recv));
                } else {
                    self.refuse_sighash_on_dropped_func(func_token_index);
                    if let Some((mut func, go_name)) = self.parse_standalone_func() {
                        self.take_sighash(func_token_index, &mut func);
                        funcs.push((func, go_name, None));
                    }
                }
            } else if matches!(self.current().typ, TokenType::Type) {
                let saved_pos = self.pos;
                self.advance(); // consume 'type'
                if let TokenType::Ident(name) = self.current().typ.clone() {
                    self.advance(); // consume name
                    if matches!(self.current().typ, TokenType::Struct) {
                        let struct_loc = self.loc();
                        self.advance(); // consume 'struct'
                        if matches!(self.current().typ, TokenType::LBrace) {
                            // Try to find runar.SmartContract or runar.StatefulSmartContract
                            let (found_parent, props) = self.parse_struct_body();
                            if let Some(found_parent) = found_parent {
                                if contract_name.is_empty() {
                                    contract_name = name;
                                    parent_class = found_parent;
                                    properties = props;
                                    ctor_loc = struct_loc;
                                } else {
                                    self.errors.push(Diagnostic::error(
                                        go_multiple_contracts_message(&contract_name, &name),
                                        None,
                                    ));
                                }
                                continue;
                            }
                        }
                        // Not a Rúnar contract struct, restore position
                        self.pos = saved_pos;
                        self.advance(); // skip 'type'
                    } else {
                        self.pos = saved_pos;
                        self.advance();
                    }
                } else {
                    self.pos = saved_pos;
                    self.advance();
                }
            } else {
                self.advance();
            }
        }

        self.report_stray_directives();

        if contract_name.is_empty() {
            self.errors.push(Diagnostic::error(GO_NO_CONTRACT_MESSAGE, None));
            return None;
        }

        // F-010: a method whose receiver (value or pointer) is not the
        // contract type is refused, never silently dropped or admitted.
        let mut raw_methods: Vec<MethodNode> = Vec::new();
        for (method, go_name, recv_type) in funcs {
            match recv_type {
                Some(recv_type) if recv_type != contract_name => {
                    self.errors.push(Diagnostic::error(
                        go_foreign_receiver_message(&go_name, &recv_type, &contract_name),
                        None,
                    ));
                }
                _ => raw_methods.push(method),
            }
        }

        // Separate init() method (property initializers) from regular methods
        let mut final_methods: Vec<MethodNode> = Vec::new();
        for m in raw_methods {
            if m.name == "init" && m.params.is_empty() {
                // Extract property assignments as initializers
                for stmt in &m.body {
                    if let Statement::Assignment { target, value, .. } = stmt {
                        if let Expression::PropertyAccess { property, .. } = target {
                            for prop in properties.iter_mut() {
                                if &prop.name == property {
                                    prop.initializer = Some(value.clone());
                                    break;
                                }
                            }
                        }
                    }
                }
            } else {
                final_methods.push(m);
            }
        }

        // Build constructor from non-initialized properties
        let uninit_props: Vec<&PropertyNode> =
            properties.iter().filter(|p| p.initializer.is_none()).collect();

        let constructor_params: Vec<ParamNode> = uninit_props
            .iter()
            .map(|p| ParamNode { name: p.name.clone(), param_type: p.prop_type.clone() })
            .collect();

        // super(...) call
        let super_args: Vec<Expression> = uninit_props
            .iter()
            .map(|p| Expression::Identifier { name: p.name.clone(), source_location: None })
            .collect();

        let super_loc = ctor_loc;
        let mut constructor_body: Vec<Statement> = Vec::new();
        constructor_body.push(Statement::ExpressionStatement {
            expression: Expression::CallExpr {
                callee: Box::new(Expression::Identifier { name: "super".to_string(), source_location: None }),
                args: super_args,
                asm_return_type: None,
            },
            source_location: super_loc.clone(),
        });

        for prop in uninit_props.iter() {
            constructor_body.push(Statement::Assignment {
                target: Expression::PropertyAccess { property: prop.name.clone(), source_location: None },
                value: Expression::Identifier { name: prop.name.clone(), source_location: None },
                source_location: super_loc.clone(),
            });
        }

        let constructor = MethodNode {
            name: "constructor".to_string(),
            params: constructor_params,
            body: constructor_body,
            visibility: Visibility::Public,
            source_location: super_loc,
            sighash_type: None,
        };

        Some(ContractNode {
            name: contract_name,
            parent_class,
            properties,
            constructor,
            methods: final_methods,
            source_file: self.file.clone(),
        })
    }

    // ---------------------------------------------------------------------------
    // Import skipping
    // ---------------------------------------------------------------------------

    fn skip_import_block(&mut self) {
        if matches!(self.current().typ, TokenType::LParen) {
            // import ( ... )
            self.advance();
            let mut depth = 1usize;
            while !matches!(self.current().typ, TokenType::Eof) {
                match self.current().typ {
                    TokenType::LParen => { depth += 1; self.advance(); }
                    TokenType::RParen => {
                        depth -= 1;
                        self.advance();
                        if depth == 0 { break; }
                    }
                    _ => { self.advance(); }
                }
            }
        } else {
            // import "..." or import alias "path"
            // Since we don't emit implicit semicolons, skip tokens until we hit
            // a StringLit (the path), then stop. This handles both forms:
            //   import "path"
            //   import alias "path"
            while !matches!(self.current().typ, TokenType::Eof) {
                if let TokenType::StringLit(_) = self.current().typ.clone() {
                    self.advance(); // consume the path string
                    break;
                }
                // Also stop if we hit a top-level keyword (defensive)
                if matches!(self.current().typ,
                    TokenType::Type | TokenType::Func | TokenType::Package) {
                    break;
                }
                self.advance();
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Struct body parsing
    // ---------------------------------------------------------------------------

    /// Parse `{ ... }` struct body. Returns (Option<parentClass>, Vec<PropertyNode>).
    /// Returns (None, _) if no runar.SmartContract embed is found.
    fn parse_struct_body(&mut self) -> (Option<String>, Vec<PropertyNode>) {
        self.expect_tok(&TokenType::LBrace);

        let mut parent_class: Option<String> = None;
        let mut properties: Vec<PropertyNode> = Vec::new();

        while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
            self.skip_semis();
            if matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
                break;
            }

            // Could be:
            // - runar.SmartContract (embed, no name)
            // - FieldName runar.Type `tag`
            // - FieldName runar.Type
            // We need to look ahead to determine what we have.

            let line = self.current().line;
            let col_start = self.current().col;

            // Try to read the first identifier
            let first_name = if let TokenType::Ident(n) = self.current().typ.clone() {
                self.advance();
                n
            } else {
                self.advance();
                continue;
            };

            // If followed by '.', it could be `runar.SmartContract` (embedded type)
            if matches!(self.current().typ, TokenType::Dot) {
                self.advance(); // consume '.'
                let second = if let TokenType::Ident(n) = self.current().typ.clone() {
                    self.advance();
                    n
                } else {
                    continue;
                };

                if first_name == "runar" {
                    match second.as_str() {
                        "SmartContract" => {
                            parent_class = Some("SmartContract".to_string());
                        }
                        "StatefulSmartContract" => {
                            parent_class = Some("StatefulSmartContract".to_string());
                        }
                        "UnsafeSmartContract" => {
                            parent_class = Some("UnsafeSmartContract".to_string());
                        }
                        _ => {
                            // Might be a field of type runar.Type — but we need a field name first
                            // This is unlikely in embedded form, skip
                        }
                    }
                    // Skip optional struct tag on this line
                    if matches!(self.current().typ, TokenType::StringLit(_)) {
                        self.advance();
                    }
                    self.skip_semis();
                    continue;
                }

                // Otherwise: first_name is the field name and first_name.second is the type
                // e.g., "Balance runar.Bigint" (but we already consumed "Balance" and "runar.Bigint")
                // Actually first_name here is NOT the field name — it's like "runar" but not equal
                // Could be another package reference. Skip.
                if matches!(self.current().typ, TokenType::StringLit(_)) {
                    self.advance();
                }
                self.skip_semis();
                continue;
            }

            // Otherwise first_name is a field name, next is the type
            // e.g. `PubKeyHash runar.Addr `runar:"readonly"``
            let prop_type = self.parse_type();
            let prop_name = self.idents.declare(&first_name, go_to_camel(&first_name));

            // Check for struct tag. The `runar` key holds comma-separated
            // options (N-093): `readonly`, and `embedAlways` — the native
            // spelling of the `@embedAlways` directive — in any order.
            let mut readonly = false;
            let mut embed_always = false;
            if let TokenType::StringLit(tag) = self.current().typ.clone() {
                self.advance();
                let options = runar_tag_options(&tag);
                readonly = options.iter().any(|o| o == "readonly");
                embed_always = options.iter().any(|o| o == "embedAlways");
            }

            let loc = SourceLocation { file: self.file.clone(), line, column: col_start };
            properties.push(PropertyNode {
                name: prop_name,
                prop_type,
                readonly,
                initializer: None,
                source_location: loc,
                synthetic_array_chain: None,
                embed_always,
            });

            self.skip_semis();
        }

        self.match_tok(&TokenType::RBrace);

        (parent_class, properties)
    }

    // ---------------------------------------------------------------------------
    // Type parsing
    // ---------------------------------------------------------------------------

    fn parse_type(&mut self) -> TypeNode {
        // `[]byte` — slice type
        if matches!(self.current().typ, TokenType::LBracket) {
            self.advance(); // '['
            if matches!(self.current().typ, TokenType::RBracket) {
                self.advance(); // ']'
                // F-213: `[][]…T` is consumed iteratively; the element type
                // is parsed only to consume it.
                while matches!(self.current().typ, TokenType::LBracket)
                    && matches!(self.tokens.get(self.pos + 1).map(|t| &t.typ), Some(TokenType::RBracket))
                {
                    self.advance();
                    self.advance();
                }
                let inner = self.parse_type();
                // N-338: a slice type (`[]byte` included) is not a documented
                // Go-surface spelling (docs/formats/go.md); it stays an unknown
                // type name so the validator refuses it, quoting the spelling.
                let elem = match &inner {
                    TypeNode::Custom(n) => n.clone(),
                    _ => "T".to_string(),
                };
                return TypeNode::Custom(format!("[]{}", elem));
            }
            // Fixed-size array [N]T
            let size = if let TokenType::Number(n) = self.current().typ.clone() {
                self.advance();
                n.to_usize().unwrap_or(0)
            } else {
                0
            };
            self.match_tok(&TokenType::RBracket);
            // F-213: a nested element type is one level deeper (+1).
            let inner = self.nested(TypeNode::Custom("_error".to_string()), |p| p.parse_type());
            return TypeNode::FixedArray { element: Box::new(inner), length: size };
        }

        // `runar.TypeName` or plain ident
        if let TokenType::Ident(first) = self.current().typ.clone() {
            self.advance();
            if matches!(self.current().typ, TokenType::Dot) {
                self.advance();
                if let TokenType::Ident(second) = self.current().typ.clone() {
                    self.advance();
                    if first == "runar" {
                        return map_go_type(&second);
                    }
                    return TypeNode::Custom(format!("{}.{}", first, second));
                }
            }
            // Plain identifier like `bool`, `int64`, `string`
            return map_go_type(&first);
        }

        TypeNode::Custom("unknown".to_string())
    }

    // ---------------------------------------------------------------------------
    // Method parsing
    // ---------------------------------------------------------------------------

    /// Parse a method: `(recv *Type) MethodName(params) ReturnType { body }`
    /// The `func` keyword has already been consumed. Returns the method, the
    /// Go spelling of its name and its receiver type (`*` stripped); `parse`
    /// checks the receiver type against the contract (F-010).
    fn parse_method(&mut self) -> (MethodNode, String, Option<String>) {
        // (recv *Type)
        self.expect_tok(&TokenType::LParen);

        let mut recv_name = if let TokenType::Ident(n) = self.current().typ.clone() {
            let n_clone = n.clone();
            self.advance();
            n_clone
        } else {
            "c".to_string()
        };

        // *Type or Type
        self.match_tok(&TokenType::Star);

        let recv_type = if let TokenType::Ident(n) = self.current().typ.clone() {
            self.advance();
            n
        } else if matches!(self.current().typ, TokenType::RParen) {
            // Unnamed receiver `(Type)`: the only identifier is the type.
            // N-018: real Go forbids referencing it in the method body at
            // all, so it must not default to "c" -- that wrongly turned a
            // same-spelled parameter into a self-reference.
            std::mem::replace(&mut recv_name, String::new())
        } else {
            String::new()
        };

        self.expect_tok(&TokenType::RParen);

        self.receiver_name = recv_name;

        let method_name_raw = self.expect_ident();
        let method_name = self.idents.declare(&method_name_raw, go_to_camel(&method_name_raw));

        // Exported = public, unexported = private
        let visibility = if method_name_raw.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
            Visibility::Public
        } else {
            Visibility::Private
        };

        let loc = SourceLocation {
            file: self.file.clone(),
            line: self.current().line,
            column: self.current().col,
        };

        // Parameters
        let params = self.parse_params();

        // Optional return type (Rúnar doesn't use it structurally; N-331
        // refuses an unknown name)
        self.skip_return_type(&method_name, &loc, visibility == Visibility::Public);

        // Body
        let body = self.parse_block();

        (
            MethodNode {
                name: method_name,
                params,
                body,
                visibility,
                source_location: loc,
                sighash_type: None,
            },
            method_name_raw,
            Some(recv_type),
        )
    }

    /// Parse a standalone function (no receiver): `FuncName(params) ReturnType { body }`
    /// The `func` keyword has already been consumed.
    fn parse_standalone_func(&mut self) -> Option<(MethodNode, String)> {
        let func_name_raw = self.expect_ident();

        // Skip init() and main()
        if func_name_raw == "init" || func_name_raw == "main" {
            self.skip_to_matching_brace();
            return None;
        }

        let func_name = self.idents.declare(&func_name_raw, go_to_camel(&func_name_raw));
        // Standalone functions with receiver = "" → private
        let saved_recv = self.receiver_name.clone();
        self.receiver_name = String::new(); // no receiver

        let loc = SourceLocation {
            file: self.file.clone(),
            line: self.current().line,
            column: self.current().col,
        };

        let params = self.parse_params();
        self.skip_return_type(&func_name, &loc, false);
        let body = self.parse_block();

        self.receiver_name = saved_recv;

        // F-010: an exported standalone function is a private helper too,
        // exactly as in the TS reference.
        Some((
            MethodNode {
                name: func_name,
                params,
                body,
                visibility: Visibility::Private,
                source_location: loc,
                sighash_type: None,
            },
            func_name_raw,
        ))
    }

    /// Parse parameter list: `(a runar.Type, b runar.Type, ...)`
    fn parse_params(&mut self) -> Vec<ParamNode> {
        self.expect_tok(&TokenType::LParen);
        let mut params = Vec::new();

        while !matches!(self.current().typ, TokenType::RParen | TokenType::Eof) {
            // Could be `name runar.Type`, `name1, name2 runar.Type` or just `,`
            if matches!(self.current().typ, TokenType::Comma) {
                self.advance();
                continue;
            }

            // Collect one or more grouped names sharing a single type.
            // In Go: `(a, b, expected runar.Bigint)` means all three params
            // have type `runar.Bigint`.
            let mut param_names: Vec<String> = Vec::new();

            let first = if let TokenType::Ident(n) = self.current().typ.clone() {
                self.advance();
                n
            } else {
                break;
            };
            param_names.push(first);

            // While the next tokens look like another grouped name followed
            // by either more names or a type, keep collecting.
            // Pattern is: `, <ident>` where <ident> is NOT the start of the
            // shared type (i.e. not followed by `.` for `runar.Type`, not
            // followed by `[` for array types).
            while matches!(self.current().typ, TokenType::Comma) {
                // Peek the two tokens after the comma.
                let next_typ = self.tokens.get(self.pos + 1).map(|t| t.typ.clone());
                let after_next_typ = self.tokens.get(self.pos + 2).map(|t| t.typ.clone());

                // Must have `, <ident>` to continue the group.
                if !matches!(next_typ, Some(TokenType::Ident(_))) {
                    break;
                }

                // If the ident is followed by `.` or `[`, it is the start of
                // the shared type (e.g. `runar.Bigint`, `[N]T`) — stop so
                // parse_type() can consume it as the type.
                let ident_starts_type = matches!(
                    after_next_typ,
                    Some(TokenType::Dot) | Some(TokenType::LBracket)
                );
                if ident_starts_type {
                    break;
                }

                // Otherwise, the ident is another grouped name. Consume the
                // comma and the ident, then loop to check for more.
                self.advance(); // `,`
                if let TokenType::Ident(n) = self.current().typ.clone() {
                    self.advance();
                    param_names.push(n);
                } else {
                    break;
                }
            }

            let param_type = self.parse_type();
            for raw in param_names {
                let name = self.idents.declare(&raw, go_to_camel(&raw));
                params.push(ParamNode {
                    name,
                    param_type: param_type.clone(),
                });
            }

            self.match_tok(&TokenType::Comma);
        }

        self.expect_tok(&TokenType::RParen);
        params
    }

    /// Skip an optional return type declaration (everything up to `{` or EOF).
    /// N-331: the AST keeps no return type, so a result type that is not a
    /// Rúnar type is refused here, where it is spelled.
    fn skip_return_type(&mut self, method_name: &str, loc: &SourceLocation, is_public: bool) {
        // If next token is `{`, no return type
        if matches!(self.current().typ, TokenType::LBrace | TokenType::Eof) {
            return;
        }
        if matches!(self.current().typ, TokenType::LParen) {
            // Parenthesised result list: `(T, U)` or named `(x T, y U)`.
            self.advance();
            while !matches!(self.current().typ, TokenType::RParen | TokenType::LBrace | TokenType::Eof) {
                let next = self.tokens.get(self.pos + 1).map(|t| t.typ.clone());
                if matches!(self.current().typ, TokenType::Ident(_))
                    && !matches!(next, Some(TokenType::Dot) | Some(TokenType::Comma) | Some(TokenType::RParen))
                {
                    self.advance(); // result name
                }
                let ret = self.parse_type();
                if let Some(msg) = unknown_return_type_message(&ret, method_name, is_public) {
                    self.errors.push(Diagnostic::error(msg, Some(loc.clone())));
                }
                if !self.match_tok(&TokenType::Comma) {
                    break;
                }
            }
        } else {
            let ret = self.parse_type();
            if let Some(msg) = unknown_return_type_message(&ret, method_name, is_public) {
                self.errors.push(Diagnostic::error(msg, Some(loc.clone())));
            }
        }
        // Otherwise skip until we find `{` (possibly a parenthesized multi-return)
        let mut depth = 0usize;
        while !matches!(self.current().typ, TokenType::Eof) {
            match self.current().typ {
                TokenType::LParen => { depth += 1; self.advance(); }
                TokenType::RParen => {
                    if depth > 0 { depth -= 1; }
                    self.advance();
                }
                TokenType::LBrace => break,
                _ => { self.advance(); }
            }
        }
    }

    /// Parse a block `{ ... }` and return the statements.
    fn parse_block(&mut self) -> Vec<Statement> {
        self.expect_tok(&TokenType::LBrace);
        let mut stmts = Vec::new();

        while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
            self.skip_statement_separators();
            if matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
                break;
            }
            // N-153: a `{` cannot start a statement (no block statement, and
            // not a brace composite literal). Refuse it, as the TS reference
            // does, and skip the balanced braces.
            if matches!(self.current().typ, TokenType::LBrace) {
                self.errors.push(Diagnostic::error("Unexpected token in expression: '{'", Some(self.loc())));
                let mut depth = 0usize;
                loop {
                    match self.advance().typ {
                        TokenType::LBrace => depth += 1,
                        TokenType::RBrace => depth -= 1,
                        _ => {}
                    }
                    if depth == 0 || matches!(self.current().typ, TokenType::Eof) {
                        break;
                    }
                }
                continue;
            }
            if let Some(s) = self.parse_statement() {
                stmts.push(s);
            } else {
                // N-010 (CL-BUG-167): parse_statement_inner already tried every
                // statement shape, including the expression-statement
                // fallback; reaching here means the current token cannot
                // start anything. Silently skipping it (as this used to do)
                // was fail-open: the statement just vanished and the rest of
                // the block kept parsing, so the contract compiled clean with
                // a different, unintended program. Report it, like the
                // `{`-token and `;`-separator recoveries above do, then skip
                // the one token that blocked it so the loop still terminates.
                self.errors.push(Diagnostic::error(
                    format!("Unexpected token in expression: {:?}", self.current().typ),
                    Some(self.loc()),
                ));
                self.advance();
            }
            self.skip_statement_separators();
        }

        self.match_tok(&TokenType::RBrace);
        stmts
    }

    /// N-153: a `;` that ends a statement on the same line separates it from
    /// the next one (what go/parser accepts). Any other `;` — at the start of
    /// a block, after another `;`, or on a later line than the statement it
    /// would end (where Go has already inserted one) — is an EMPTY statement,
    /// which the TS reference and the Go tier refuse.
    fn skip_statement_separators(&mut self) {
        while matches!(self.current().typ, TokenType::Semi) {
            let separates = self.pos > 0 && {
                let prev = &self.tokens[self.pos - 1];
                !matches!(prev.typ, TokenType::LBrace | TokenType::Semi) && prev.line == self.current().line
            };
            if !separates {
                self.errors.push(Diagnostic::error("Unexpected token in expression: ';'", Some(self.loc())));
            }
            self.advance();
        }
    }

    // ---------------------------------------------------------------------------
    // Statement parsing
    // ---------------------------------------------------------------------------

    fn parse_statement(&mut self) -> Option<Statement> {
        self.nested(None, |p| p.parse_statement_inner())
    }

    fn parse_statement_inner(&mut self) -> Option<Statement> {
        let loc = self.loc();

        match self.current().typ.clone() {
            TokenType::If => {
                self.advance();
                let cond = self.parse_expr()?;
                let then_branch = self.parse_block();
                let else_branch = if matches!(self.current().typ, TokenType::Else) {
                    self.advance();
                    if matches!(self.current().typ, TokenType::If) {
                        // else if → wrap in a single-statement else branch
                        if let Some(s) = self.parse_statement() {
                            Some(vec![s])
                        } else {
                            None
                        }
                    } else {
                        Some(self.parse_block())
                    }
                } else {
                    None
                };
                Some(Statement::IfStatement { condition: cond, then_branch, else_branch, source_location: loc })
            }

            TokenType::For => {
                self.advance();
                self.parse_for_statement(loc)
            }

            TokenType::Return => {
                self.advance();
                let value = if matches!(self.current().typ, TokenType::Semi | TokenType::RBrace | TokenType::Eof) {
                    None
                } else {
                    self.parse_expr()
                };
                Some(Statement::ReturnStatement { value, source_location: loc })
            }

            TokenType::Var | TokenType::Const => {
                // var/const Name Type = Expr
                let is_var = matches!(self.current().typ, TokenType::Var);
                self.advance();
                let name_raw = self.expect_ident();
                let name = self.idents.declare(&name_raw, go_to_camel(&name_raw));

                // Optional type
                let var_type = if !matches!(self.current().typ, TokenType::Eq | TokenType::Semi | TokenType::Eof) {
                    Some(self.parse_type())
                } else {
                    None
                };

                let init = if matches!(self.current().typ, TokenType::Eq) {
                    self.advance();
                    self.parse_expr()?
                } else {
                    return None;
                };

                Some(Statement::VariableDecl {
                    name,
                    var_type,
                    mutable: is_var,
                    init,
                    source_location: loc,
                })
            }

            TokenType::Ident(_) => {
                // Could be:
                // - `name := expr`  (short variable decl)
                // - `name = expr`   (assignment)
                // - `name.field = expr`
                // - `name++` / `name--`
                // - expression statement (function call, etc.)
                self.parse_ident_statement(loc)
            }

            // Standalone increment/decrement is unlikely at statement start but handle anyway
            TokenType::PlusPlus | TokenType::MinusMinus => {
                let is_inc = matches!(self.current().typ, TokenType::PlusPlus);
                self.advance();
                let operand = self.parse_primary()?;
                if is_inc {
                    Some(Statement::ExpressionStatement {
                        expression: Expression::IncrementExpr { operand: Box::new(operand), prefix: true },
                        source_location: loc,
                    })
                } else {
                    Some(Statement::ExpressionStatement {
                        expression: Expression::DecrementExpr { operand: Box::new(operand), prefix: true },
                        source_location: loc,
                    })
                }
            }

            _ => {
                // Try as expression statement
                if let Some(expr) = self.parse_expr() {
                    Some(Statement::ExpressionStatement { expression: expr, source_location: loc })
                } else {
                    None
                }
            }
        }
    }

    fn parse_ident_statement(&mut self, loc: SourceLocation) -> Option<Statement> {
        let lhs_tok = self.current().typ.clone();
        // Parse the left-hand side expression
        let lhs = self.parse_expr()?;

        match self.current().typ.clone() {
            TokenType::ColonEq => {
                // name := expr
                self.advance();
                let rhs = self.parse_expr()?;
                let name = if let Expression::Identifier { name, .. } = &lhs {
                    if let TokenType::Ident(raw) = &lhs_tok {
                        self.idents.declare(raw, name.clone());
                    }
                    name.clone()
                } else {
                    String::new()
                };
                Some(Statement::VariableDecl {
                    name,
                    var_type: None,
                    mutable: true,
                    init: rhs,
                    source_location: loc,
                })
            }

            TokenType::Eq => {
                // target = expr
                self.advance();
                let rhs = self.parse_expr()?;
                Some(Statement::Assignment { target: lhs, value: rhs, source_location: loc })
            }

            TokenType::PlusEq => {
                // target += expr  ->  target = target + expr
                self.advance();
                let rhs = self.parse_expr()?;
                let new_val = Expression::BinaryExpr {
                    op: BinaryOp::Add,
                    left: Box::new(lhs.clone()),
                    right: Box::new(rhs),
                    source_location: None,
                };
                Some(Statement::Assignment { target: lhs, value: new_val, source_location: loc })
            }

            TokenType::MinusEq => {
                // target -= expr  ->  target = target - expr
                self.advance();
                let rhs = self.parse_expr()?;
                let new_val = Expression::BinaryExpr {
                    op: BinaryOp::Sub,
                    left: Box::new(lhs.clone()),
                    right: Box::new(rhs),
                    source_location: None,
                };
                Some(Statement::Assignment { target: lhs, value: new_val, source_location: loc })
            }

            TokenType::StarEq
            | TokenType::SlashEq
            | TokenType::PercentEq
            | TokenType::UnsupportedCompoundAssign(_) => self.parse_compound_assign(lhs, loc),

            TokenType::PlusPlus => {
                // x++ -> ExpressionStatement(IncrementExpr)
                self.advance();
                Some(Statement::ExpressionStatement {
                    expression: Expression::IncrementExpr { operand: Box::new(lhs), prefix: false },
                    source_location: loc,
                })
            }

            TokenType::MinusMinus => {
                // x-- -> ExpressionStatement(DecrementExpr)
                self.advance();
                Some(Statement::ExpressionStatement {
                    expression: Expression::DecrementExpr { operand: Box::new(lhs), prefix: false },
                    source_location: loc,
                })
            }

            _ => {
                // Expression statement (e.g., function call)
                Some(Statement::ExpressionStatement { expression: lhs, source_location: loc })
            }
        }
    }

    fn parse_for_statement(&mut self, loc: SourceLocation) -> Option<Statement> {
        // for { body }  — infinite loop (not valid Rúnar but handle gracefully)
        // for i := 0; i < n; i++ { body }
        // for i < n { body }  — Go while-equivalent

        // Check if it's a simple condition for (no init/post)
        // We peek ahead: if next token starts a block immediately or is a simple expr
        // A three-part for has `:=` or `=` followed by `;`
        // Heuristic: look for `;` before `{`
        let is_three_part = self.has_semi_before_brace();

        if is_three_part {
            // Parse init statement
            let init = self.parse_for_init_statement()?;
            self.skip_semis();

            // Parse condition
            let condition = if matches!(self.current().typ, TokenType::Semi) {
                // No condition (always true), use BoolLiteral true
                Expression::BoolLiteral { value: true }
            } else {
                self.parse_expr()?
            };
            self.skip_semis();

            // Parse post statement
            let update = self.parse_for_post_statement()?;

            let body = self.parse_block();

            Some(Statement::ForStatement {
                init: Box::new(init),
                condition,
                update: Box::new(update),
                body,
                source_location: loc,
            })
        } else {
            // R-065 — `for cond { body }` and bare `for { body }`.
            //
            // This arm used to SYNTHESISE a header the source never wrote:
            // `_i := 0` for the init and a bare `Identifier("_i")` for the
            // update. A bare identifier is on R-029's accepted-update list on
            // purpose — it is the no-op sentinel the zig / move while-shaped
            // parsers emit when the surface has no continue expression — so
            // R-065 waved the loop through and the iteration count came out of
            // the CONDITION alone.
            //
            // That derivation is not sound. Whatever advances the loop lives
            // in the body, where nothing proves it runs unconditionally, runs
            // once per iteration, or advances by one. Measured before this
            // change, on `for i < 5 { ... }`:
            //
            //     body `sum = sum + start + i; i++`        184 hexchars
            //     body `if start > 3 { i++ }; sum = sum+i` 234 hexchars
            //
            // The second is a Go program that never terminates when
            // `start <= 3`. It compiled clean to a fixed five-iteration
            // script — a locking script for a program nobody wrote, which is
            // worse than no script. spec/grammar.md:420 already requires a
            // simple `++` / `--` update clause, and six of the seven tiers
            // refuse both shapes (five at the parser, one at R-065); Zig, the
            // only other tier that accepted them, emitted a DIFFERENT wrong
            // answer (the body silently dropped) and has been fixed to refuse.
            //
            // Refusing here rather than in the validator keeps the no-op
            // sentinel available to the while-shaped parsers that need it.
            self.errors.push(Diagnostic::error(
                "For loop header must be the three-part form `for i := <literal>; i < <bound>; i++`. \
                 A `for <cond> { }` or bare `for { }` loop carries no update clause, so the unrolled \
                 loop model -- which synthesises iteration k as `start + k*step` -- has no iteration \
                 count to derive; an update written in the body is not guaranteed to run, to run once \
                 per iteration, or to advance by one",
                Some(loc.clone()),
            ));
            // Consume the header and body so the rest of the file still parses
            // and the user sees every diagnostic, not only this one. The
            // statement is dropped: a loop whose shape could not be derived has
            // no honest AST, and returning one with an invented header is the
            // defect itself.
            while !matches!(self.current().typ, TokenType::LBrace | TokenType::Eof) {
                self.advance();
            }
            let _ = self.parse_block();
            None
        }
    }

    fn has_semi_before_brace(&self) -> bool {
        let mut i = self.pos;
        while i < self.tokens.len() {
            match self.tokens[i].typ {
                TokenType::Semi => return true,
                TokenType::LBrace => return false,
                TokenType::Eof => return false,
                _ => {}
            }
            i += 1;
        }
        false
    }

    fn parse_for_init_statement(&mut self) -> Option<Statement> {
        let loc = self.loc();
        // `i := 0` or `var i int = 0`
        if let TokenType::Ident(name_raw) = self.current().typ.clone() {
            let name = go_to_camel(&name_raw);
            self.advance();
            if matches!(self.current().typ, TokenType::ColonEq) {
                self.advance();
                let name = self.idents.declare(&name_raw, name);
                let init = self.parse_expr()?;
                return Some(Statement::VariableDecl {
                    name,
                    var_type: None,
                    mutable: true,
                    init,
                    source_location: loc,
                });
            }
        }
        // Fallback: parse as expression
        let expr = self.parse_expr()?;
        Some(Statement::ExpressionStatement { expression: expr, source_location: loc })
    }

    fn parse_for_post_statement(&mut self) -> Option<Statement> {
        let loc = self.loc();
        // `i++`, `i--`, `i += 1`, etc.
        let lhs = self.parse_expr()?;
        match self.current().typ.clone() {
            TokenType::PlusPlus => {
                self.advance();
                Some(Statement::ExpressionStatement {
                    expression: Expression::IncrementExpr { operand: Box::new(lhs), prefix: false },
                    source_location: loc,
                })
            }
            TokenType::MinusMinus => {
                self.advance();
                Some(Statement::ExpressionStatement {
                    expression: Expression::DecrementExpr { operand: Box::new(lhs), prefix: false },
                    source_location: loc,
                })
            }
            TokenType::PlusEq => {
                self.advance();
                let rhs = self.parse_expr()?;
                let new_val = Expression::BinaryExpr {
                    op: BinaryOp::Add,
                    left: Box::new(lhs.clone()),
                    right: Box::new(rhs),
                    source_location: None,
                };
                Some(Statement::Assignment { target: lhs, value: new_val, source_location: loc })
            }
            TokenType::MinusEq => {
                self.advance();
                let rhs = self.parse_expr()?;
                let new_val = Expression::BinaryExpr {
                    op: BinaryOp::Sub,
                    left: Box::new(lhs.clone()),
                    right: Box::new(rhs),
                    source_location: None,
                };
                Some(Statement::Assignment { target: lhs, value: new_val, source_location: loc })
            }
            TokenType::StarEq
            | TokenType::SlashEq
            | TokenType::PercentEq
            | TokenType::UnsupportedCompoundAssign(_) => self.parse_compound_assign(lhs, loc),

            _ => Some(Statement::ExpressionStatement { expression: lhs, source_location: loc }),
        }
    }

    /// `target *= expr` / `/=` / `%=`  ->  `target = target op expr`.
    ///
    /// Together with the `+=` / `-=` arms this is exactly the compound set the
    /// TS reference Go-surface parser (01-parse-go.ts) accepts. Every other Go
    /// compound operator (&= |= ^= <<= >>= &^=) is a parse error: rewriting it
    /// here would accept programs the reference refuses, and dropping it (the
    /// F-019 defect) compiles a script that does not do what the source says.
    fn parse_compound_assign(&mut self, lhs: Expression, loc: SourceLocation) -> Option<Statement> {
        let op = match self.current().typ.clone() {
            TokenType::StarEq => BinaryOp::Mul,
            TokenType::SlashEq => BinaryOp::Div,
            TokenType::PercentEq => BinaryOp::Mod,
            TokenType::UnsupportedCompoundAssign(text) => {
                self.errors.push(Diagnostic::error(
                    format!(
                        "unsupported compound assignment operator '{}' at {}:{}:{}; \
                         the Go surface accepts only += -= *= /= %=",
                        text,
                        self.file,
                        self.current().line,
                        self.current().col.saturating_sub(1)
                    ),
                    Some(loc.clone()),
                ));
                // Consume the operator and its operand so parsing resumes at the
                // next statement; the diagnostic already makes the compile fail.
                self.advance();
                let _ = self.parse_expr();
                return Some(Statement::ExpressionStatement { expression: lhs, source_location: loc });
            }
            _ => return None,
        };
        self.advance();
        let rhs = self.parse_expr()?;
        let new_val = Expression::BinaryExpr {
            op,
            left: Box::new(lhs.clone()),
            right: Box::new(rhs),
            source_location: None,
        };
        Some(Statement::Assignment { target: lhs, value: new_val, source_location: loc })
    }

    // ---------------------------------------------------------------------------
    // Expression parsing (Pratt-style precedence climbing)
    // ---------------------------------------------------------------------------

    fn parse_expr(&mut self) -> Option<Expression> {
        self.nested(None, |p| p.parse_or())
    }

    /// N-056: build `left op right`, refusing an unparenthesised operand edge
    /// whose grouping differs between Go precedence and the C ladder.
    /// `left_top` / `self.ladder_top` hold each operand's top-level
    /// unparenthesised operator (None for an atom: primary, call, `( … )`).
    /// N-233: `start` is where `left` begins, the TS reference's anchor for
    /// the refusal (the binary expression's leftmost operand).
    fn go_bin(&mut self, op: BinaryOp, left: Expression, left_top: Option<BinaryOp>, right: Expression, start: &SourceLocation) -> Expression {
        let right_top = self.ladder_top.take();
        let edge = match (left_top, right_top) {
            (Some(l), _) if is_go_ambiguous_precedence(&l, &op) => Some((l, op.clone())),
            (_, Some(r)) if is_go_ambiguous_precedence(&op, &r) => Some((op.clone(), r)),
            _ => None,
        };
        if let Some((first, second)) = edge {
            self.errors.push(Diagnostic::error(go_ambiguous_precedence_message(&first, &second), Some(start.clone())));
        }
        self.ladder_top = Some(op.clone());
        Expression::BinaryExpr { op, left: Box::new(left), right: Box::new(right), source_location: None }
    }

    fn parse_or(&mut self) -> Option<Expression> {
        let start = self.loc();
        let mut left = self.parse_and()?;
        let mut dt = DepthTracker::new();
        while matches!(self.current().typ, TokenType::PipePipe) {
            let left_top = self.ladder_top.take();
            self.advance();
            let right = self.parse_and()?;
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = self.go_bin(BinaryOp::Or, left, left_top, right, &start);
        }
        Some(left)
    }

    fn parse_and(&mut self) -> Option<Expression> {
        let start = self.loc();
        let mut left = self.parse_bitor()?;
        let mut dt = DepthTracker::new();
        while matches!(self.current().typ, TokenType::AmpAmp) {
            let left_top = self.ladder_top.take();
            self.advance();
            let right = self.parse_bitor()?;
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = self.go_bin(BinaryOp::And, left, left_top, right, &start);
        }
        Some(left)
    }

    fn parse_bitor(&mut self) -> Option<Expression> {
        let start = self.loc();
        let mut left = self.parse_bitxor()?;
        let mut dt = DepthTracker::new();
        while matches!(self.current().typ, TokenType::Pipe) {
            let left_top = self.ladder_top.take();
            self.advance();
            let right = self.parse_bitxor()?;
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = self.go_bin(BinaryOp::BitOr, left, left_top, right, &start);
        }
        Some(left)
    }

    fn parse_bitxor(&mut self) -> Option<Expression> {
        let start = self.loc();
        let mut left = self.parse_bitand()?;
        let mut dt = DepthTracker::new();
        while matches!(self.current().typ, TokenType::Caret) {
            let left_top = self.ladder_top.take();
            self.advance();
            let right = self.parse_bitand()?;
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = self.go_bin(BinaryOp::BitXor, left, left_top, right, &start);
        }
        Some(left)
    }

    fn parse_bitand(&mut self) -> Option<Expression> {
        let start = self.loc();
        let mut left = self.parse_equality()?;
        let mut dt = DepthTracker::new();
        while matches!(self.current().typ, TokenType::Amp) {
            let left_top = self.ladder_top.take();
            self.advance();
            let right = self.parse_equality()?;
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = self.go_bin(BinaryOp::BitAnd, left, left_top, right, &start);
        }
        Some(left)
    }

    fn parse_equality(&mut self) -> Option<Expression> {
        let start = self.loc();
        let mut left = self.parse_relational()?;
        let mut dt = DepthTracker::new();
        loop {
            let op = match self.current().typ {
                TokenType::EqEq => BinaryOp::StrictEq,
                TokenType::BangEq => BinaryOp::StrictNe,
                _ => break,
            };
            let left_top = self.ladder_top.take();
            self.advance();
            let right = self.parse_relational()?;
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = self.go_bin(op, left, left_top, right, &start);
        }
        Some(left)
    }

    fn parse_relational(&mut self) -> Option<Expression> {
        let start = self.loc();
        let mut left = self.parse_shift()?;
        let mut dt = DepthTracker::new();
        loop {
            let op = match self.current().typ {
                TokenType::Lt => BinaryOp::Lt,
                TokenType::LtEq => BinaryOp::Le,
                TokenType::Gt => BinaryOp::Gt,
                TokenType::GtEq => BinaryOp::Ge,
                _ => break,
            };
            let left_top = self.ladder_top.take();
            self.advance();
            let right = self.parse_shift()?;
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = self.go_bin(op, left, left_top, right, &start);
        }
        Some(left)
    }

    fn parse_shift(&mut self) -> Option<Expression> {
        let start = self.loc();
        let mut left = self.parse_additive()?;
        let mut dt = DepthTracker::new();
        loop {
            let op = match self.current().typ {
                TokenType::Shl => BinaryOp::Shl,
                TokenType::Shr => BinaryOp::Shr,
                _ => break,
            };
            let left_top = self.ladder_top.take();
            self.advance();
            let right = self.parse_additive()?;
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = self.go_bin(op, left, left_top, right, &start);
        }
        Some(left)
    }

    fn parse_additive(&mut self) -> Option<Expression> {
        let start = self.loc();
        let mut left = self.parse_multiplicative()?;
        let mut dt = DepthTracker::new();
        loop {
            let op = match self.current().typ {
                TokenType::Plus => BinaryOp::Add,
                TokenType::Minus => BinaryOp::Sub,
                _ => break,
            };
            let left_top = self.ladder_top.take();
            self.advance();
            let right = self.parse_multiplicative()?;
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = self.go_bin(op, left, left_top, right, &start);
        }
        Some(left)
    }

    fn parse_multiplicative(&mut self) -> Option<Expression> {
        let start = self.loc();
        let mut left = self.parse_unary()?;
        let mut dt = DepthTracker::new();
        self.ladder_top = None; // N-056: a unary/primary operand is an atom
        loop {
            let op = match self.current().typ {
                TokenType::Star => BinaryOp::Mul,
                TokenType::Slash => BinaryOp::Div,
                TokenType::Percent => BinaryOp::Mod,
                _ => break,
            };
            let left_top = self.ladder_top.take();
            self.advance();
            let right = self.parse_unary()?;
            self.ladder_top = None;
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = self.go_bin(op, left, left_top, right, &start);
        }
        Some(left)
    }

    fn parse_unary(&mut self) -> Option<Expression> {
        match self.current().typ.clone() {
            TokenType::Bang => {
                self.advance();
                let operand = self.nested(None, |p| p.parse_unary())?;
                Some(Expression::UnaryExpr { op: UnaryOp::Not, operand: Box::new(operand), source_location: None })
            }
            TokenType::Minus => {
                self.advance();
                let operand = self.nested(None, |p| p.parse_unary())?;
                Some(Expression::UnaryExpr { op: UnaryOp::Neg, operand: Box::new(operand), source_location: None })
            }
            TokenType::Tilde | TokenType::Caret => {
                self.advance();
                let operand = self.nested(None, |p| p.parse_unary())?;
                Some(Expression::UnaryExpr { op: UnaryOp::BitNot, operand: Box::new(operand), source_location: None })
            }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Option<Expression> {
        let mut expr = self.parse_primary()?;
        let mut dt = DepthTracker::new();

        loop {
            match self.current().typ.clone() {
                TokenType::Dot => {
                    self.advance();
                    let prop_raw = self.expect_ident();
                    let prop = go_to_camel(&prop_raw);
                    if !self.grow(&mut dt, &expr, &[]) { break; }

                    // Check if it's a call: expr.method(...)
                    if matches!(self.current().typ, TokenType::LParen) {
                        let args = self.parse_call_args();
                        // The member node above is accounted; now the call.
                        let arg_refs: Vec<&Expression> = args.iter().collect();
                        if !self.grow(&mut dt, &expr, &arg_refs) { break; }
                        expr = Expression::CallExpr {
                            callee: Box::new(Expression::MemberExpr {
                                object: Box::new(expr),
                                property: prop,
                            }),
                            args,
                            asm_return_type: None,
                        };
                    } else {
                        // field access
                        expr = Expression::MemberExpr { object: Box::new(expr), property: prop };
                    }
                }

                TokenType::LBracket => {
                    self.advance();
                    let index = self.parse_expr()?;
                    self.expect_tok(&TokenType::RBracket);
                    if !self.grow(&mut dt, &expr, &[&index]) { break; }
                    expr = Expression::IndexAccess { object: Box::new(expr), index: Box::new(index) };
                }

                TokenType::LParen => {
                    // Direct call: func(...)
                    let args = self.parse_call_args();
                    let arg_refs: Vec<&Expression> = args.iter().collect();
                    if !self.grow(&mut dt, &expr, &arg_refs) { break; }
                    expr = Expression::CallExpr { callee: Box::new(expr), args, asm_return_type: None };
                }

                _ => break,
            }
        }

        Some(expr)
    }

    fn parse_primary(&mut self) -> Option<Expression> {
        match self.current().typ.clone() {
            TokenType::Number(n) => {
                self.advance();
                Some(Expression::BigIntLiteral { value: n })
            }

            TokenType::True => {
                self.advance();
                Some(Expression::BoolLiteral { value: true })
            }

            TokenType::False => {
                self.advance();
                Some(Expression::BoolLiteral { value: false })
            }

            TokenType::StringLit(s) => {
                // N-448: a bare non-empty literal is refused (natively ASCII
                // text, to the compiler hex). Exempt: "" and a runar.Asm body.
                if !s.is_empty() && !self.bare_literal_ok.contains(&self.pos) {
                    let loc = SourceLocation {
                        file: self.file.clone(),
                        line: self.current().line,
                        column: self.current().col,
                    };
                    self.errors.push(Diagnostic::error(go_bare_string_literal_message(&s), Some(loc)));
                }
                let lit_loc = self.loc();
                self.advance();
                Some(Expression::ByteStringLiteral { value: s, source_location: Some(lit_loc) })
            }

            TokenType::LParen => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect_tok(&TokenType::RParen);
                Some(expr)
            }

            TokenType::LBracket => {
                // Two shapes share the `[` prefix in the Go DSL:
                //   1. Bare array literal `[a, b, c]` — emits ArrayLiteral.
                //   2. Go composite literal `[N]T{a, b, c}` (also `[]T{...}`)
                //      — peel off the leading `[N]…T` and emit ArrayLiteral
                //      from the brace body so all 7 tiers lower to identical
                //      Stack IR.
                let saved = self.pos;
                self.advance(); // consume '['
                // Try to detect composite literal: `[ <number>? ] <type>+ {`.
                let mut composite = false;
                let known_miss = matches!(self.composite_miss, Some((start, end)) if saved >= start && saved < end);
                if !known_miss && matches!(self.current().typ, TokenType::Number(_) | TokenType::RBracket) {
                    if matches!(self.current().typ, TokenType::Number(_)) {
                        self.advance();
                    }
                    if matches!(self.current().typ, TokenType::RBracket) {
                        self.advance(); // consume ']'
                        // Consume any additional `[N]` dims for multi-dim arrays.
                        while matches!(self.current().typ, TokenType::LBracket) {
                            let dim_saved = self.pos;
                            self.advance();
                            if matches!(self.current().typ, TokenType::Number(_)) {
                                self.advance();
                            }
                            if !matches!(self.current().typ, TokenType::RBracket) {
                                self.pos = dim_saved;
                                break;
                            }
                            self.advance();
                        }
                        let dims_end = self.pos;
                        // Consume the element type: `runar.Foo`, `Foo`, or `*Foo`.
                        if matches!(self.current().typ, TokenType::Star) {
                            self.advance();
                        }
                        if matches!(self.current().typ, TokenType::Ident(_)) {
                            self.advance();
                            while matches!(self.current().typ, TokenType::Dot) {
                                self.advance();
                                if matches!(self.current().typ, TokenType::Ident(_)) {
                                    self.advance();
                                } else {
                                    break;
                                }
                            }
                        }
                        if matches!(self.current().typ, TokenType::LBrace) {
                            composite = true;
                            return Some(self.parse_go_brace_literal());
                        }
                        self.composite_miss = Some((saved, dims_end));
                    }
                }
                if !composite {
                    self.pos = saved;
                    self.advance(); // re-consume '['
                }
                let mut elements: Vec<Expression> = Vec::new();
                while !matches!(self.current().typ, TokenType::RBracket | TokenType::Eof) {
                    if matches!(self.current().typ, TokenType::Comma) {
                        self.advance();
                        continue;
                    }
                    if let Some(elem) = self.parse_expr() {
                        elements.push(elem);
                    } else {
                        break;
                    }
                    if !matches!(self.current().typ, TokenType::Comma) {
                        break;
                    }
                    self.advance();
                }
                self.expect_tok(&TokenType::RBracket);
                Some(Expression::ArrayLiteral { elements })
            }

            TokenType::LBrace => {
                // Nested composite literal body inside an outer multi-dim
                // composite literal: `{e, e, …}` or `{ {…}, {…} }`.
                Some(self.parse_go_brace_literal())
            }

            TokenType::Ident(name) => {
                let ident_loc = self.loc();
                self.advance();

                // `runar.Something` — could be type conversion or builtin call
                if name == "runar" && matches!(self.current().typ, TokenType::Dot) {
                    self.advance(); // consume '.'
                    let member_raw = self.expect_ident();

                    // Type conversion: runar.Int(x), runar.Bigint(x), runar.BigintBig(x), runar.Bool(x)
                    if matches!(member_raw.as_str(), "Int" | "Bigint" | "BigintBig" | "Bool") {
                        if matches!(self.current().typ, TokenType::LParen) {
                            let args = self.parse_call_args();
                            // Unwrap: runar.Int(x) -> x
                            if args.len() == 1 {
                                return Some(args.into_iter().next().unwrap());
                            }
                        }
                    }

                    // BigintBig operator helper: runar.BigintBigEqual(a, b) is
                    // `a === b`. `runar.BigintBig` is *big.Int in
                    // packages/runar-go and Go has no operator overloading, so
                    // contract source carrying arbitrary-precision values has to
                    // spell its arithmetic as a call; the emitted script must be
                    // the one the operator itself produces.
                    //
                    // This lived only in compilers/go until R-Bigint even though
                    // all seven tiers parse `.runar.go`. See go_bigintbig_op.
                    if let Some(op) = go_bigintbig_op(&member_raw) {
                        if matches!(self.current().typ, TokenType::LParen) {
                            let mut args = self.parse_call_args();
                            if args.len() == 2 {
                                let right = args.pop().unwrap();
                                let left = args.pop().unwrap();
                                return Some(Expression::BinaryExpr {
                                    op,
                                    left: Box::new(left),
                                    right: Box::new(right),
                                    source_location: None,
                                });
                            }
                        }
                    }

                    // N-448: runar.HexToBytes("deadbeef") is the explicit hex
                    // spelling of a ByteString literal.
                    if member_raw == "HexToBytes" && matches!(self.current().typ, TokenType::LParen) {
                        if let (Some(TokenType::StringLit(s)), Some(TokenType::RParen)) = (
                            self.tokens.get(self.pos + 1).map(|t| t.typ.clone()),
                            self.tokens.get(self.pos + 2).map(|t| t.typ.clone()),
                        ) {
                            self.advance(); // '('
                            let lit_loc = self.loc();
                            self.advance(); // literal
                            self.advance(); // ')'
                            return Some(Expression::ByteStringLiteral { value: s, source_location: Some(lit_loc) });
                        }
                        let loc = SourceLocation {
                            file: self.file.clone(),
                            line: self.tokens[self.pos.saturating_sub(1)].line,
                            column: self.tokens[self.pos.saturating_sub(1)].col,
                        };
                        self.errors.push(Diagnostic::error(
                            "runar.HexToBytes expects a single string literal argument".to_string(),
                            Some(loc),
                        ));
                    }

                    // N-448: the first argument of runar.Asm(...) is an opcode body.
                    if member_raw == "Asm" && matches!(self.current().typ, TokenType::LParen) {
                        if let Some(TokenType::StringLit(_)) = self.tokens.get(self.pos + 1).map(|t| t.typ.clone()) {
                            self.bare_literal_ok.insert(self.pos + 1);
                        }
                    }

                    // runar.ByteString("literal") -> ByteStringLiteral (hex-encoded);
                    // runar.ByteString(variable) -> unwrap (type conversion no-op).
                    if member_raw == "ByteString" && matches!(self.current().typ, TokenType::LParen) {
                        // Peek at the next meaningful token to check for a string literal
                        // argument (optionally preceded by LParen-only whitespace tokens — there aren't
                        // any in this tokenizer, so we look directly after `(`).
                        let saved = self.pos;
                        self.advance(); // consume '('
                        if let TokenType::StringLit(s) = self.current().typ.clone() {
                            let raw = self.current().raw.clone();
                            self.advance(); // consume string
                            if matches!(self.current().typ, TokenType::RParen) {
                                self.advance(); // consume ')'
                                // Hex-encode the Go string's bytes (N-435: UTF-8 for
                                // literal text, the raw byte for a \xNN escape).
                                let bytes = raw.unwrap_or_else(|| s.clone().into_bytes());
                                let hex_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                                return Some(Expression::ByteStringLiteral { value: hex_str, source_location: None });
                            }
                        }
                        // Roll back and fall through to default parse_call_args path.
                        self.pos = saved;
                        let args = self.parse_call_args();
                        if args.len() == 1 {
                            return Some(args.into_iter().next().unwrap());
                        }
                        // Not exactly one arg — leave as a call expression (will error downstream).
                        return Some(Expression::CallExpr {
                            callee: Box::new(Expression::Identifier { name: "byteString".to_string(), source_location: None }),
                            args,
                            asm_return_type: None,
                        });
                    }

                    let callee_name = map_go_builtin(&member_raw);

                    if matches!(self.current().typ, TokenType::LParen) {
                        let args = self.parse_call_args();
                        return Some(Expression::CallExpr {
                            callee: Box::new(Expression::Identifier { name: callee_name, source_location: None }),
                            args,
                            asm_return_type: None,
                        });
                    }

                    return Some(Expression::Identifier { name: callee_name, source_location: None });
                }

                // Receiver access: <receiver_name>.Field. N-018: this must be
                // an exact match on the actual declared receiver name, never
                // a hardcoded "c"/"self" -- that wrongly turned ANY
                // same-spelled parameter or local into a self-reference even
                // when the receiver was named something else, or unnamed
                // (receiver_name == "", which real Go forbids referencing at
                // all).
                if name == self.receiver_name && !self.receiver_name.is_empty() {
                    if matches!(self.current().typ, TokenType::Dot) {
                        self.advance(); // consume '.'
                        let prop_raw = self.expect_ident();
                        let prop = go_to_camel(&prop_raw);

                        // Check for method call on receiver: c.privateMethod(...)
                        if matches!(self.current().typ, TokenType::LParen) {
                            let args = self.parse_call_args();
                            return Some(Expression::CallExpr {
                                callee: Box::new(Expression::MemberExpr {
                                    object: Box::new(Expression::Identifier { name: "this".to_string(), source_location: None }),
                                    property: prop,
                                }),
                                args,
                                asm_return_type: None,
                            });
                        }

                        return Some(Expression::PropertyAccess { property: prop, source_location: None });
                    }
                    // Receiver as value without field access — skip returning Identifier
                }

                // Regular identifier
                let camel = go_to_camel(&name);
                Some(Expression::Identifier { name: camel, source_location: Some(ident_loc) })
            }

            _ => None,
        }
    }

    /// Parse a Go composite-literal body `{e, e, …}`. Each element may
    /// itself be a nested `{ … }` body for multi-dimensional arrays.
    /// Returns an `ArrayLiteral`.
    fn parse_go_brace_literal(&mut self) -> Expression {
        self.expect_tok(&TokenType::LBrace);
        let mut elements: Vec<Expression> = Vec::new();
        while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
            if matches!(self.current().typ, TokenType::LBrace) {
                // F-213: a nested brace element is an array element (+1).
                let el = self.nested(None, |p| Some(p.parse_go_brace_literal()));
                elements.extend(el);
            } else if let Some(e) = self.parse_expr() {
                elements.push(e);
            } else {
                break;
            }
            if matches!(self.current().typ, TokenType::Comma) {
                self.advance();
            } else {
                break;
            }
        }
        self.expect_tok(&TokenType::RBrace);
        Expression::ArrayLiteral { elements }
    }

    fn parse_call_args(&mut self) -> Vec<Expression> {
        self.expect_tok(&TokenType::LParen);
        let mut args = Vec::new();

        while !matches!(self.current().typ, TokenType::RParen | TokenType::Eof) {
            if matches!(self.current().typ, TokenType::Comma) {
                self.advance();
                continue;
            }
            if let Some(arg) = self.parse_expr() {
                args.push(arg);
            } else {
                break;
            }
            self.match_tok(&TokenType::Comma);
        }

        self.expect_tok(&TokenType::RParen);
        args
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    /// Skip to the matching `}` brace (used when skipping non-contract methods).
    fn skip_to_matching_brace(&mut self) {
        // Find the next `{` first
        while !matches!(self.current().typ, TokenType::LBrace | TokenType::Eof) {
            self.advance();
        }
        if matches!(self.current().typ, TokenType::Eof) {
            return;
        }
        let mut depth = 0usize;
        while !matches!(self.current().typ, TokenType::Eof) {
            match self.current().typ {
                TokenType::LBrace => { depth += 1; self.advance(); }
                TokenType::RBrace => {
                    if depth > 0 { depth -= 1; }
                    self.advance();
                    if depth == 0 { break; }
                }
                _ => { self.advance(); }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test: basic stateless P2PKH contract
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_go_p2pkh() {
        let source = r#"package contract

import runar "github.com/icellan/runar/packages/runar-go"

type P2PKH struct {
    runar.SmartContract
    PubKeyHash runar.Addr `runar:"readonly"`
}

func (c *P2PKH) Unlock(sig runar.Sig, pubKey runar.PubKey) {
    runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
    runar.Assert(runar.CheckSig(sig, pubKey))
}
"#;

        let result = parse_go_contract(source, Some("P2PKH.runar.go"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.expect("should produce a contract");
        assert_eq!(contract.name, "P2PKH");
        assert_eq!(contract.parent_class, "SmartContract");
        assert_eq!(contract.properties.len(), 1);
        assert_eq!(contract.properties[0].name, "pubKeyHash");
        assert!(contract.properties[0].readonly);
        assert_eq!(contract.methods.len(), 1);
        assert_eq!(contract.methods[0].name, "unlock");
        assert_eq!(contract.methods[0].visibility, Visibility::Public);
        assert_eq!(contract.methods[0].params.len(), 2);
        assert_eq!(contract.methods[0].params[0].name, "sig");
        assert_eq!(contract.methods[0].params[1].name, "pubKey");
    }

    // -----------------------------------------------------------------------
    // Test: stateful counter contract
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_go_stateful_counter() {
        let source = r#"package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Counter struct {
    runar.StatefulSmartContract
    Count runar.Bigint
}

func (c *Counter) Increment() {
    c.Count++
}

func (c *Counter) Decrement() {
    runar.Assert(c.Count > 0)
    c.Count--
}
"#;

        let result = parse_go_contract(source, Some("Counter.runar.go"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.expect("should produce a contract");
        assert_eq!(contract.name, "Counter");
        assert_eq!(contract.parent_class, "StatefulSmartContract");
        assert_eq!(contract.properties.len(), 1);
        assert!(!contract.properties[0].readonly, "count should be mutable");
        assert_eq!(contract.methods.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Test: multiple readonly properties (Escrow-style)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_go_multiple_properties() {
        let source = r#"package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Escrow struct {
    runar.SmartContract
    Buyer   runar.PubKey `runar:"readonly"`
    Seller  runar.PubKey `runar:"readonly"`
    Arbiter runar.PubKey `runar:"readonly"`
}

func (c *Escrow) Release(sellerSig runar.Sig, arbiterSig runar.Sig) {
    runar.Assert(runar.CheckSig(sellerSig, c.Seller))
    runar.Assert(runar.CheckSig(arbiterSig, c.Arbiter))
}

func (c *Escrow) Refund(buyerSig runar.Sig, arbiterSig runar.Sig) {
    runar.Assert(runar.CheckSig(buyerSig, c.Buyer))
    runar.Assert(runar.CheckSig(arbiterSig, c.Arbiter))
}
"#;

        let result = parse_go_contract(source, Some("Escrow.runar.go"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.expect("should produce a contract");
        assert_eq!(contract.name, "Escrow");
        assert_eq!(contract.properties.len(), 3);
        assert_eq!(contract.properties[0].name, "buyer");
        assert_eq!(contract.properties[1].name, "seller");
        assert_eq!(contract.properties[2].name, "arbiter");
        assert!(contract.properties[0].readonly);
        assert!(contract.properties[1].readonly);
        assert!(contract.properties[2].readonly);
        assert_eq!(contract.methods.len(), 2);
        let names: Vec<&str> = contract.methods.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"release"), "expected method 'release'");
        assert!(names.contains(&"refund"), "expected method 'refund'");
    }

    // -----------------------------------------------------------------------
    // Test: exported identifiers are lowercased (camelCase conversion)
    // -----------------------------------------------------------------------

    #[test]
    fn test_go_identifier_camel_case() {
        let source = r#"package contract

import runar "github.com/icellan/runar/packages/runar-go"

type MyContract struct {
    runar.SmartContract
    PubKeyHash runar.Addr `runar:"readonly"`
}

func (c *MyContract) CheckHash(sig runar.Sig, pubKey runar.PubKey) {
    runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
}
"#;

        let result = parse_go_contract(source, Some("MyContract.runar.go"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.expect("should produce a contract");
        // Exported field name PubKeyHash -> pubKeyHash
        assert_eq!(contract.properties[0].name, "pubKeyHash");
        // Exported method name CheckHash -> checkHash
        assert_eq!(contract.methods[0].name, "checkHash");
        // Exported param name PubKey -> pubKey (params stay as provided)
        assert_eq!(contract.methods[0].params[1].name, "pubKey");
    }

    // -----------------------------------------------------------------------
    // Test: invalid/empty source produces an error or no contract
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_go_invalid_syntax() {
        // No struct definition at all
        let source = r#"package contract
// no type definition here
"#;

        let result = parse_go_contract(source, Some("bad.runar.go"));
        // Should produce no contract (empty source with no struct)
        let is_bad = !result.errors.is_empty() || result.contract.is_none();
        assert!(
            is_bad,
            "expected errors or no contract for source with no struct definition"
        );
    }

    // -----------------------------------------------------------------------
    // Test: property initializers via init() method
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_go_property_initializers() {
        let source = r#"package contract

import runar "github.com/icellan/runar/packages/runar-go"

type BoundedCounter struct {
    runar.StatefulSmartContract
    Count    runar.Bigint
    MaxCount runar.Bigint `runar:"readonly"`
    Active   runar.Bool   `runar:"readonly"`
}

func (c *BoundedCounter) init() {
    c.Count = 0
    c.Active = true
}

func (c *BoundedCounter) Increment(amount runar.Bigint) {
    runar.Assert(c.Active)
    c.Count = c.Count + amount
    runar.Assert(c.Count <= c.MaxCount)
}
"#;

        let result = parse_go_contract(source, Some("BoundedCounter.runar.go"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.expect("should produce a contract");
        assert_eq!(contract.name, "BoundedCounter");
        assert_eq!(contract.parent_class, "StatefulSmartContract");
        // init() should NOT appear as a regular method
        let method_names: Vec<&str> = contract.methods.iter().map(|m| m.name.as_str()).collect();
        assert!(
            !method_names.contains(&"init"),
            "init() should be consumed as initializers, not emitted as a method"
        );
        // Increment should be present
        assert!(
            method_names.contains(&"increment"),
            "expected method 'increment'"
        );
    }

    /// `runar.BigintBig` is a Go-side alias for arbitrary-precision math on the
    /// mock side. In the DSL it must map to the same `bigint` primitive so
    /// arithmetic against `runar.Bigint` typechecks cleanly.
    #[test]
    fn test_parse_go_bigint_big_is_bigint() {
        let source = r#"package contract

import runar "github.com/icellan/runar/packages/runar-go"

type BigMath struct {
    runar.SmartContract
    Target runar.BigintBig `runar:"readonly"`
}

func (c *BigMath) Check(a runar.Bigint, b runar.BigintBig) {
    runar.Assert(a + b == c.Target)
}
"#;
        let result = parse_go_contract(source, Some("BigMath.runar.go"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.expect("should produce a contract");
        // Property Target maps to bigint
        let target = contract
            .properties
            .iter()
            .find(|p| p.name == "target")
            .expect("target prop");
        match &target.prop_type {
            TypeNode::Primitive(PrimitiveTypeName::Bigint) => {}
            other => panic!("expected Bigint primitive for target, got {:?}", other),
        }
        // Method param `b runar.BigintBig` also maps to bigint
        let m = &contract.methods[0];
        match &m.params[1].param_type {
            TypeNode::Primitive(PrimitiveTypeName::Bigint) => {}
            other => panic!("expected Bigint primitive for param b, got {:?}", other),
        }
    }

    /// `runar.ByteString("\x00\x6a")` emits a ByteString literal whose value
    /// is the hex encoding of the raw literal bytes.
    #[test]
    fn test_parse_go_bytestring_literal() {
        let source = r#"package contract

import runar "github.com/icellan/runar/packages/runar-go"

type LitDemo struct {
    runar.SmartContract
    Expected runar.ByteString `runar:"readonly"`
}

func (c *LitDemo) Check() {
    runar.Assert(runar.ByteString("\x00\x6a") == c.Expected)
}
"#;
        let result = parse_go_contract(source, Some("LitDemo.runar.go"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.expect("should produce a contract");
        let m = &contract.methods[0];

        // Walk the method body looking for a ByteString literal equal to "006a".
        fn find_bytestring_lit(expr: &Expression) -> Option<String> {
            match expr {
                Expression::ByteStringLiteral { value, .. } => Some(value.clone()),
                Expression::CallExpr { callee, args, .. } => {
                    if let Some(v) = find_bytestring_lit(callee) {
                        return Some(v);
                    }
                    for a in args {
                        if let Some(v) = find_bytestring_lit(a) {
                            return Some(v);
                        }
                    }
                    None
                }
                Expression::BinaryExpr { left, right, .. } => {
                    find_bytestring_lit(left).or_else(|| find_bytestring_lit(right))
                }
                _ => None,
            }
        }

        let mut found = None;
        for stmt in &m.body {
            if let Statement::ExpressionStatement { expression: expr, .. } = stmt {
                if let Some(v) = find_bytestring_lit(expr) {
                    found = Some(v);
                    break;
                }
            }
        }
        assert_eq!(found.as_deref(), Some("006a"), "expected ByteStringLiteral '006a'");
    }

    /// `runar.ByteString(variable)` is a plain type-conversion no-op; the
    /// inner identifier must flow through unchanged (no wrapping call).
    #[test]
    fn test_parse_go_bytestring_of_variable_unwraps() {
        let source = r#"package contract

import runar "github.com/icellan/runar/packages/runar-go"

type VarDemo struct {
    runar.SmartContract
    Expected runar.ByteString `runar:"readonly"`
}

func (c *VarDemo) Check(data runar.ByteString) {
    runar.Assert(runar.ByteString(data) == c.Expected)
}
"#;
        let result = parse_go_contract(source, Some("VarDemo.runar.go"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.expect("should produce a contract");
        let m = &contract.methods[0];

        fn has_plain_data_ident(expr: &Expression) -> bool {
            match expr {
                Expression::Identifier { name, .. } => name == "data",
                Expression::BinaryExpr { left, right, .. } => {
                    has_plain_data_ident(left) || has_plain_data_ident(right)
                }
                Expression::CallExpr { callee, args, .. } => {
                    // must not be a byteString(...) call
                    if let Expression::Identifier { name, .. } = &**callee {
                        if name == "byteString" {
                            return false;
                        }
                    }
                    args.iter().any(has_plain_data_ident) || has_plain_data_ident(callee)
                }
                _ => false,
            }
        }

        let mut ok = false;
        for stmt in &m.body {
            if let Statement::ExpressionStatement { expression: expr, .. } = stmt {
                if has_plain_data_ident(expr) {
                    ok = true;
                    break;
                }
            }
        }
        assert!(ok, "expected runar.ByteString(data) to unwrap to identifier 'data'");
    }

    // -----------------------------------------------------------------------
    // F-010: a method is a contract method only if its receiver IS the
    // contract. This tier silently dropped a method on another type (and
    // every method declared before the contract struct); the TS reference,
    // the Go tier and the Ruby tier made it a PUBLIC entry point. The rule
    // (user decision R9), with diagnostics shared verbatim by all 7 tiers:
    //   - the contract is THE struct embedding a runar base; others ignored;
    //   - zero or several such structs refuse the file;
    //   - a method whose receiver (value or pointer) is another type refuses it;
    //   - a free function, exported or not, is a private helper.
    // Proves: this tier's .runar.go diagnostics and method set per shape.
    // Does NOT prove: the other tiers, or anything on chain.
    // -----------------------------------------------------------------------

    const F010_PRELUDE: &str = "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n";
    const F010_GUARDED: &str = "\ntype Guarded struct {\n\trunar.SmartContract\n\tPubKey runar.PubKey `runar:\"readonly\"`\n}\n\nfunc (c *Guarded) Unlock(sig runar.Sig) {\n\trunar.Assert(runar.CheckSig(sig, c.PubKey))\n}\n";
    const F010_RECEIVER_ERROR: &str = "method 'Drain' has receiver type 'Unrelated', not the contract type 'Guarded'; methods on other types are not allowed";

    fn f010_unrelated(recv: &str) -> String {
        format!("\ntype Unrelated struct{{}}\n\nfunc ({}) Drain(amount runar.Bigint) {{\n\trunar.Assert(true)\n}}\n", recv)
    }

    fn f010_errors(src: &str) -> Vec<String> {
        parse_go_contract(src, Some("Guarded.runar.go"))
            .errors
            .iter()
            .filter(|d| d.severity == crate::frontend::diagnostic::Severity::Error)
            .map(|d| d.message.clone())
            .collect()
    }

    fn f010_methods(src: &str) -> Vec<String> {
        let result = parse_go_contract(src, Some("Guarded.runar.go"));
        let contract = result.contract.expect("contract");
        contract
            .methods
            .iter()
            .map(|m| format!("{}({})", m.name, if m.visibility == Visibility::Public { "public" } else { "private" }))
            .collect()
    }

    #[test]
    fn test_f010_foreign_receiver_refused() {
        let cases = [
            format!("{}{}{}", F010_PRELUDE, F010_GUARDED, f010_unrelated("u Unrelated")),
            format!("{}{}{}", F010_PRELUDE, F010_GUARDED, f010_unrelated("u *Unrelated")),
            format!("{}{}{}", F010_PRELUDE, f010_unrelated("u Unrelated"), F010_GUARDED),
            format!("{}{}{}", F010_PRELUDE, f010_unrelated("u *Unrelated"), F010_GUARDED),
            format!("{}{}\nfunc (u Unrelated) Drain(amount runar.Bigint) {{\n\trunar.Assert(true)\n}}\n", F010_PRELUDE, F010_GUARDED),
        ];
        for (i, src) in cases.iter().enumerate() {
            assert_eq!(f010_errors(src), vec![F010_RECEIVER_ERROR.to_string()], "case {}", i);
        }
    }

    #[test]
    fn test_f010_contract_receivers_kept() {
        let src = format!("{}{}\nfunc (c Guarded) Drain(amount runar.Bigint) {{\n\trunar.Assert(amount > 0)\n}}\n", F010_PRELUDE, F010_GUARDED);
        assert_eq!(f010_errors(&src), Vec::<String>::new());
        assert_eq!(f010_methods(&src), vec!["unlock(public)", "drain(public)"]);
    }

    #[test]
    fn test_f010_exported_free_function_is_private_helper() {
        let src = format!("{}{}\nfunc Drain(amount runar.Bigint) {{\n\trunar.Assert(true)\n}}\n", F010_PRELUDE, F010_GUARDED);
        assert_eq!(f010_errors(&src), Vec::<String>::new());
        assert_eq!(f010_methods(&src), vec!["unlock(public)", "drain(private)"]);
    }

    #[test]
    fn test_f010_helper_struct_ignored() {
        let helper = "\ntype Helper struct {\n\tAmount runar.Bigint\n}\n";
        for src in [format!("{}{}{}", F010_PRELUDE, F010_GUARDED, helper), format!("{}{}{}", F010_PRELUDE, helper, F010_GUARDED)] {
            let result = parse_go_contract(&src, Some("Guarded.runar.go"));
            assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
            let contract = result.contract.expect("contract");
            assert_eq!(contract.name, "Guarded");
            let props: Vec<&str> = contract.properties.iter().map(|p| p.name.as_str()).collect();
            assert_eq!(props, vec!["pubKey"]);
        }
    }

    #[test]
    fn test_f010_no_contract_struct() {
        let src = format!("{}\ntype Helper struct {{\n\tAmount runar.Bigint\n}}\n", F010_PRELUDE);
        assert_eq!(f010_errors(&src), vec!["no Rúnar contract struct found in Go source".to_string()]);
    }

    #[test]
    fn test_f010_two_contract_structs() {
        let src = format!("{}{}\ntype Other struct {{\n\trunar.StatefulSmartContract\n\tCount runar.Bigint\n}}\n", F010_PRELUDE, F010_GUARDED);
        assert_eq!(
            f010_errors(&src),
            vec!["multiple Rúnar contract structs found in Go source: 'Guarded' and 'Other'; exactly one struct may embed runar.SmartContract, runar.StatefulSmartContract or runar.UnsafeSmartContract".to_string()]
        );
    }

    // -------------------------------------------------------------------------
    // N-018: a free `init`/`main` is not an ordinary private helper. Real Go
    // reserves both names for the package initializer / entry point, which
    // can never be called as a function; this tier already skips it (the
    // fix for TS/Ruby/Zig matches this tier's existing behaviour; see their
    // own suites). This locks the behaviour in.
    //
    // A 0-param free `init()` is not a case this test reaches: the existing
    // init-extraction pass (`m.name == "init" && m.params.is_empty()`)
    // already absorbs it regardless of receiver. A free `init` WITH a
    // parameter does reach `parse_standalone_func`'s skip.
    // -------------------------------------------------------------------------
    #[test]
    fn test_n018_free_init_param_and_main_are_dropped() {
        let src = format!(
            "{}{}\nfunc main() {{\n\trunar.Assert(true)\n}}\n\nfunc init(amount runar.Bigint) {{\n\trunar.Assert(amount > 0)\n}}\n",
            F010_PRELUDE, F010_GUARDED
        );
        assert_eq!(f010_errors(&src), Vec::<String>::new());
        assert_eq!(f010_methods(&src), vec!["unlock(public)"]);
    }

    // -------------------------------------------------------------------------
    // N-018: the unnamed receiver `(T)` must leave the receiver
    // unreferenceable. Real Go forbids referencing an unnamed receiver in
    // the method body at all -- there is no name bound to it. This tier
    // instead defaulted the unnamed receiver's name to "c" AND
    // (independently) hardcoded "c"/"self" as always meaning "the receiver"
    // regardless of the actual declared name, so a parameter literally
    // named `c` was silently read as the contract's own `PubKey` --
    // `this.pubKey`, not the parameter. The TS/Ruby reference already gets
    // this right; Go, Zig, Python and Java carried the identical
    // hardcoded-alias bug and are fixed alongside this one (see their own
    // suites).
    //
    // Proves: this tier's .runar.go parser never treats a same-spelled
    // non-receiver identifier as the contract's self, for an unnamed
    // receiver; `c.PubKey` parses as a MemberExpr on the identifier `c`, not
    // a PropertyAccess on the contract. Does NOT prove: the other six
    // tiers.
    // -------------------------------------------------------------------------
    #[test]
    fn test_n018_unnamed_receiver_param_named_c_stays_plain() {
        let src = format!(
            "{}{}\nfunc (Guarded) CheckC(c runar.PubKey) {{\n\trunar.Assert(c.PubKey)\n}}\n",
            F010_PRELUDE, F010_GUARDED
        );
        let result = parse_go_contract(&src, Some("Guarded.runar.go"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.expect("contract");
        let method = contract.methods.iter().find(|m| m.name == "checkC").expect("checkC method");
        let Statement::ExpressionStatement { expression, .. } = &method.body[0] else {
            panic!("body[0] is not an ExpressionStatement: {:?}", method.body[0]);
        };
        let Expression::CallExpr { args, .. } = expression else {
            panic!("expression is not a CallExpr: {:?}", expression);
        };
        let Expression::MemberExpr { object, property } = &args[0] else {
            panic!(
                "c.PubKey parsed as {:?}, want MemberExpr -- the unnamed receiver must not bind the name \"c\"",
                args[0]
            );
        };
        let Expression::Identifier { name, .. } = object.as_ref() else {
            panic!("member.object is not an Identifier: {:?}", object);
        };
        assert_eq!(name, "c");
        assert_eq!(property, "pubKey");
    }
}

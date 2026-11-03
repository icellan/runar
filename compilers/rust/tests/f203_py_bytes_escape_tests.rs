//! F-203 (CL-BUG-208..213) — .runar.py byte literals decode escapes the way
//! CPython bytes literals do.
//!
//! Pre-fix this tier's .runar.py tokenizer hex-encoded every character of a
//! b'..' literal except `\xHH`, so `b'\0'` became 5c 30 and `b'\n'` became
//! 5c 6e, while CPython (what pytest runs) reads one byte; its plain strings
//! dropped the backslash and kept the next character (`"\a\b"` read as "ab").
//!
//! The rule is the TS reference's (packages/runar-compiler/src/passes/
//! 01-parse-python.ts, decodePyLiteral): b'..' / b".." decode
//! `\\ \' \" \a \b \f \n \r \t \v`, octal `\NNN` (1-3 digits, at most 0o377)
//! and `\xHH` (exactly two hex digits); any other escape is refused with
//! "invalid escape sequence '<escape>'", a non-ASCII character in b'..' with
//! "bytes can only contain ASCII literal characters"; plain strings decode the
//! same escapes (and refuse \N, \u, \U). Every expected byte string is
//! CPython's own: `python3 -c "print(b'..'.hex())"`.
//!
//! What this proves: this tier compiles each escape to CPython's bytes and
//! refuses each undefined or unsupported form with the shared diagnostic.
//! What it does NOT prove: anything about the other tiers (their suites and
//! conformance/negatives/py-bytes-escape-parity.test.ts).

use runar_compiler_rust::compile_from_source_str;
use runar_compiler_rust::frontend::parser::parse_source;

const FILE: &str = "Esc.runar.py";

fn contract(lit: &str) -> String {
    format!(
        "from runar import SmartContract, ByteString, public, assert_\n\n\nclass Esc(SmartContract):\n    def __init__(self):\n        super().__init__()\n\n    @public\n    def unlock(self, x: ByteString):\n        assert_(x == {})\n",
        lit
    )
}

/// Minimal push of `hex` as the emitter encodes byte strings, then OP_EQUAL.
fn guard_hex(hex: &str) -> String {
    let n = hex.len() / 2;
    let v = u8::from_str_radix(&hex[..2.min(hex.len())], 16).unwrap_or(0);
    let push = if n == 1 && (1..=16).contains(&v) {
        format!("{:02x}", 0x50 + v)
    } else if n == 1 && v == 0x81 {
        "4f".to_string()
    } else {
        format!("{:02x}{}", n, hex)
    };
    format!("{}87", push)
}

/// [Python source body between b'..', CPython's b'..'.hex()].
const BYTES_CASES: &[(&str, &str)] = &[
    ("\\0", "00"),
    ("\\00", "00"),
    ("\\000", "00"),
    ("\\7", "07"),
    ("\\101", "41"),
    ("\\377", "ff"),
    ("\\1234", "5334"),
    ("a\\0b", "610062"),
    ("\\08", "0038"),
    ("\\n", "0a"),
    ("\\t", "09"),
    ("\\r", "0d"),
    ("\\\\", "5c"),
    ("\\'", "27"),
    ("\\\"", "22"),
    ("\\a", "07"),
    ("\\b", "08"),
    ("\\f", "0c"),
    ("\\v", "0b"),
    ("\\xde\\xAD", "dead"),
    ("\\x00\\x6a", "006a"),
    ("ab", "6162"),
    ("\\\\n", "5c6e"),
    ("x\\ty\\nz", "7809790a7a"),
];

fn script(lit: &str) -> String {
    compile_from_source_str(&contract(lit), Some(FILE))
        .unwrap_or_else(|e| panic!("{}: {}", lit, e))
        .script
}

fn errors(lit: &str) -> Vec<String> {
    parse_source(&contract(lit), Some(FILE)).errors.iter().map(|d| d.message.clone()).collect()
}

#[test]
fn f203_bytes_escapes_decode_to_cpython_bytes() {
    for (body, hex) in BYTES_CASES {
        let lit = format!("b'{}'", body);
        assert_eq!(script(&lit), guard_hex(hex), "{}", lit);
    }
    assert_eq!(script("b\"\\'\\\"\""), guard_hex("2722"));
}

#[test]
fn f203_plain_string_decodes_before_hex_check() {
    assert_eq!(script("\"\\x61\\x62\""), guard_hex("ab"));
}

#[test]
fn f203_refusals_use_the_shared_diagnostic() {
    let cases: &[(&str, &str)] = &[
        ("b'\\q'", "\\q"),
        ("b'\\x4'", "\\x"),
        ("b'\\xg0'", "\\x"),
        ("b'\\400'", "\\400"),
        ("b'\\N{DIGIT ONE}'", "\\N"),
        ("b'\\u0041'", "\\u"),
        ("b'\\U00000041'", "\\U"),
        ("\"\\q\"", "\\q"),
        ("\"\\u0061\"", "\\u"),
    ];
    for (lit, esc) in cases {
        let want = format!("invalid escape sequence '{}'", esc);
        let errs = errors(lit);
        assert!(errs.contains(&want), "{}: want {:?}, got {:?}", lit, want, errs);
        assert!(compile_from_source_str(&contract(lit), Some(FILE)).is_err(), "{} compiled", lit);
    }
    let errs = errors("b'\u{e9}'");
    assert!(
        errs.iter().any(|m| m == "bytes can only contain ASCII literal characters"),
        "non-ASCII: {:?}",
        errs
    );
}

#[test]
fn f203_prefixes_and_continuation_stay_refused() {
    for lit in ["rb'\\n'", "br'\\n'", "B'\\n'", "r'ab'", "u'ab'", "f'ab'", "b'ab\\\ncd'"] {
        assert!(compile_from_source_str(&contract(lit), Some(FILE)).is_err(), "{} compiled", lit);
    }
}

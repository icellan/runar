//! DoS-bound input limits + typed errors for the Rust ANF IR loader.
//!
//! Mirrors `InputLimits` from `packages/runar-ir-schema/src/input-limits.ts`
//! and the Go reference at `compilers/go/ir/input_limits.go`.
//!
//! BUG-008 follow-up.

use std::fmt;

/// Mirrors `InputLimits.MAX_IR_BYTES` (16 MiB) from the TS schema package.
/// Any ANF IR JSON larger than this is rejected at the loader entry points
/// (`load_ir` / `load_ir_from_str`) BEFORE `serde_json::from_str` runs so
/// a malicious caller cannot exhaust memory / CPU with a giant payload.
pub const MAX_IR_BYTES: usize = 16 * 1024 * 1024;

/// Mirrors `InputLimits.MAX_NESTING` (512) from the TS schema package.
/// ANF IR JSON whose structural nesting (objects + arrays) exceeds this
/// is rejected. Prevents stack-exhaustion DoS via deeply nested JSON.
pub const MAX_IR_NESTING: usize = 512;

/// Returned when an IR JSON payload exceeds [`MAX_IR_BYTES`] at a public
/// loader entry point. Distinct typed error so callers can distinguish
/// DoS-bound rejection from generic deserialisation failures.
#[derive(Debug, Clone)]
pub struct IRSizeExceededError {
    pub limit: usize,
    pub actual: usize,
}

impl fmt::Display for IRSizeExceededError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IR JSON exceeds MAX_IR_BYTES (limit={}, actual={})",
            self.limit, self.actual
        )
    }
}

impl std::error::Error for IRSizeExceededError {}

/// Returned when an IR JSON payload's structural nesting (objects +
/// arrays) exceeds [`MAX_IR_NESTING`].
#[derive(Debug, Clone)]
pub struct IRNestingExceededError {
    pub limit: usize,
}

impl fmt::Display for IRNestingExceededError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IR JSON nesting exceeds MAX_NESTING (limit={})",
            self.limit
        )
    }
}

impl std::error::Error for IRNestingExceededError {}

/// Returns `Some(IRSizeExceededError)` if `data.len() > MAX_IR_BYTES`.
pub fn assert_ir_bytes_under_limit(data: &[u8]) -> Option<IRSizeExceededError> {
    if data.len() > MAX_IR_BYTES {
        Some(IRSizeExceededError {
            limit: MAX_IR_BYTES,
            actual: data.len(),
        })
    } else {
        None
    }
}

/// Iteratively walks the raw JSON bytes and returns
/// `Some(IRNestingExceededError)` the first time the nesting depth
/// (objects + arrays) exceeds [`MAX_IR_NESTING`]. Runs BEFORE
/// `serde_json::from_str` so a deeply-nested payload cannot exhaust the
/// thread stack inside the deserializer.
///
/// Skips strings (respecting backslash-escapes) so a `{` inside a JSON
/// string doesn't count toward depth.
pub fn assert_ir_nesting_under_limit(data: &[u8]) -> Option<IRNestingExceededError> {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in data {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            if b == b'\\' {
                escaped = true;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_IR_NESTING {
                    return Some(IRNestingExceededError {
                        limit: MAX_IR_NESTING,
                    });
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    None
}

/// Returned when an IR JSON payload contains a number written in float
/// syntax. N-131.
#[derive(Debug, Clone)]
pub struct IRFloatValueError {
    /// The offending token, verbatim, so the diagnostic names what was read.
    pub token: String,
}

impl fmt::Display for IRFloatValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IR JSON contains a floating-point number ({}); every numeric \
             field in the ANF IR is an integer (write an oversize value as a \
             decimal string with an `n` suffix)",
            self.token
        )
    }
}

impl std::error::Error for IRFloatValueError {}

/// Walks the raw JSON bytes and returns `Some(IRFloatValueError)` the first
/// time a number is written in float syntax — that is, with a `.` or an
/// exponent. N-131.
///
/// # Why this is a rejection at all
///
/// The ANF IR has no float-typed field. The schema
/// (`packages/runar-ir-schema/src/schemas/anf-ir.schema.json`) types
/// `loop.count`, `loop.step` and the `raw_script` arities as `integer`, and
/// `loop.start` / `load_const.value` as integer-or-string. Every tier's
/// `--emit-ir` writes integers, and the `n`-suffixed decimal string already
/// carries values too large for a native integer.
///
/// What the six `--ir` tiers did with a float was therefore unspecified, and
/// they disagreed — in emitted BYTES, not in diagnostics. `{"start":1e30}`
/// alone produced three different answers across the tiers, and `1e50` in a
/// `load_const` made this tier saturate to `i128::MAX` and push
/// `10ffffffffffffffffffffffffffffff7f` — a number the IR never contained.
///
/// # Why the rule is lexical
///
/// `1.0` and `1e2` name integers, so a value-based rule would admit them.
/// This one refuses them, because that is what Go and Java — the two tiers
/// that were already right — do, and because every tier's JSON parser draws
/// the integer/float line at the token rather than the value. A syntactic
/// rule is the one six independent implementations can agree on by
/// construction.
///
/// # Why a byte scan and not a walk of the parsed document
///
/// Two reasons, both learned from how this defect survived. A walk has to
/// name every numeric field, and the fields nobody thought to name
/// (`loop.step`, `raw_script.out_arity`) are exactly the ones that diverged.
/// And serde has already made its narrowing decisions by the time a parsed
/// document exists: `serde_json::from_str` into a typed struct is where the
/// f64 -> i128 saturation happens, so a post-parse check cannot see the
/// original token. Running before the parser is what makes the guard total.
///
/// Skips strings (respecting backslash-escapes), so `"1.5"` — a legal
/// `ByteString` or `n`-suffixed constant — is untouched.
pub fn assert_no_json_floats(data: &[u8]) -> Option<IRFloatValueError> {
    let mut in_string = false;
    let mut escaped = false;
    let mut i = 0usize;
    while i < data.len() {
        let b = data[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            i += 1;
            continue;
        }
        // A number token starts with `-` or a digit. Nothing else outside a
        // string can, so the `e` in `true`/`false` is never scanned here.
        if b == b'-' || b.is_ascii_digit() {
            let start = i;
            let mut is_float = false;
            while i < data.len() {
                let c = data[i];
                if c.is_ascii_digit() || c == b'-' || c == b'+' {
                    i += 1;
                } else if c == b'.' || c == b'e' || c == b'E' {
                    is_float = true;
                    i += 1;
                } else {
                    break;
                }
            }
            if is_float {
                return Some(IRFloatValueError {
                    token: String::from_utf8_lossy(&data[start..i]).into_owned(),
                });
            }
            continue;
        }
        i += 1;
    }
    None
}

/// N-212 (decision R82: every tier parses a bare JSON integer exactly).
///
/// `serde_json` (built without `arbitrary_precision`) turns an integer token
/// too wide for `i64`/`u64` into an `f64` while parsing, and `ANFValue` is an
/// internally tagged enum, so serde buffers it before `LoadConst` ever sees
/// it: the digits of a 256-bit constant are gone before any Rúnar code runs,
/// and `parse_const_value` then saturated the double to `i128::MAX`.
///
/// This rewrites, in the raw text, every bare integer that is the value of a
/// `"value"` or `"initialValue"` member and does not fit an `i64` into the
/// sanctioned `"<decimal>n"` string, which `parse_const_value` already reads
/// exactly. Narrower than enabling `arbitrary_precision`, which is
/// crate-wide and breaks numbers inside serde's internally tagged and
/// untagged enums — the shape `ANFValue` uses.
///
/// Run after `assert_no_json_floats`, so every number token here is an
/// integer. Returns `None` when nothing needs rewriting.
pub fn quote_wide_integer_constants(json: &str) -> Option<String> {
    let data = json.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut str_start = 0usize;
    // The last complete string token, and whether a `:` has followed it.
    let mut last_key: Option<(usize, usize)> = None;
    let mut after_colon = false;
    let mut i = 0usize;
    while i < data.len() {
        let b = data[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
                last_key = Some((str_start, i));
                after_colon = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => {
                in_string = true;
                str_start = i + 1;
                i += 1;
            }
            b':' => {
                after_colon = last_key.is_some();
                i += 1;
            }
            b'-' | b'0'..=b'9' => {
                let start = i;
                while i < data.len() && (data[i] == b'-' || data[i].is_ascii_digit()) {
                    i += 1;
                }
                let key = if after_colon {
                    last_key.map(|(s, e)| &json[s..e])
                } else {
                    None
                };
                let token = &json[start..i];
                let digits = token.strip_prefix('-').unwrap_or(token);
                if matches!(key, Some("value") | Some("initialValue"))
                    && !digits.is_empty()
                    && digits.bytes().all(|c| c.is_ascii_digit())
                    && token.parse::<i64>().is_err()
                {
                    let o = out.get_or_insert_with(|| String::with_capacity(json.len() + 16));
                    o.push_str(&json[copied..start]);
                    o.push('"');
                    o.push_str(token);
                    o.push_str("n\"");
                    copied = i;
                }
                last_key = None;
                after_colon = false;
            }
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            _ => {
                last_key = None;
                after_colon = false;
                i += 1;
            }
        }
    }
    out.map(|mut o| {
        o.push_str(&json[copied..]);
        o
    })
}

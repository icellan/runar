//! Byte-exact JSON emitter per spec §3.5.
//!
//! 2-space indent, LF line endings, trailing newline, optional fields
//! omitted (never `null`), keys in the §3 order, `/` not escaped, em-dashes
//! emitted as UTF-8 verbatim.

use super::types::{AnalysisResult, ExecutionPath, Finding, Summary};

/// Render an [`AnalysisResult`] as the canonical JSON report (with a
/// trailing `\n`).
pub fn serialize_report(result: &AnalysisResult) -> String {
    let mut s = String::new();
    s.push_str("{\n");
    push_kv_string(&mut s, 1, "script", &result.script, true);
    push_kv_uint(&mut s, 1, "scriptSize", result.script_size, true);
    push_findings(&mut s, 1, "findings", &result.findings, true);
    push_paths(&mut s, 1, "paths", &result.paths, true);
    push_summary(&mut s, 1, "summary", &result.summary, false);
    s.push_str("}\n");
    s
}

fn indent(s: &mut String, level: usize) {
    for _ in 0..level {
        s.push_str("  ");
    }
}

fn push_string_literal(s: &mut String, value: &str) {
    s.push('"');
    for c in value.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\u{0008}' => s.push_str("\\b"),
            '\u{000C}' => s.push_str("\\f"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                s.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => s.push(c),
        }
    }
    s.push('"');
}

fn push_kv_string(s: &mut String, level: usize, key: &str, value: &str, comma: bool) {
    indent(s, level);
    push_string_literal(s, key);
    s.push_str(": ");
    push_string_literal(s, value);
    if comma {
        s.push(',');
    }
    s.push('\n');
}

fn push_kv_uint(s: &mut String, level: usize, key: &str, value: usize, comma: bool) {
    indent(s, level);
    push_string_literal(s, key);
    s.push_str(": ");
    s.push_str(&value.to_string());
    if comma {
        s.push(',');
    }
    s.push('\n');
}

fn push_kv_int(s: &mut String, level: usize, key: &str, value: i64, comma: bool) {
    indent(s, level);
    push_string_literal(s, key);
    s.push_str(": ");
    s.push_str(&value.to_string());
    if comma {
        s.push(',');
    }
    s.push('\n');
}

fn push_kv_bool(s: &mut String, level: usize, key: &str, value: bool, comma: bool) {
    indent(s, level);
    push_string_literal(s, key);
    s.push_str(": ");
    s.push_str(if value { "true" } else { "false" });
    if comma {
        s.push(',');
    }
    s.push('\n');
}

fn push_findings(s: &mut String, level: usize, key: &str, findings: &[Finding], comma: bool) {
    indent(s, level);
    push_string_literal(s, key);
    s.push_str(": ");
    if findings.is_empty() {
        s.push_str("[]");
        if comma {
            s.push(',');
        }
        s.push('\n');
        return;
    }
    s.push_str("[\n");
    for (i, f) in findings.iter().enumerate() {
        push_finding_obj(s, level + 1, f);
        if i + 1 < findings.len() {
            s.push(',');
        }
        s.push('\n');
    }
    indent(s, level);
    s.push(']');
    if comma {
        s.push(',');
    }
    s.push('\n');
}

/// One rendered key/value pair, deferred so we can determine the comma
/// suffix only after counting how many keys actually exist.
enum FieldValue<'a> {
    Str(&'a str),
    Uint(usize),
}

fn push_finding_obj(s: &mut String, level: usize, f: &Finding) {
    indent(s, level);
    s.push_str("{\n");

    let mut entries: Vec<(&str, FieldValue<'_>)> = Vec::with_capacity(6);
    entries.push(("severity", FieldValue::Str(f.severity.as_str())));
    entries.push(("code", FieldValue::Str(&f.code)));
    entries.push(("message", FieldValue::Str(&f.message)));
    if let Some(o) = f.offset {
        entries.push(("offset", FieldValue::Uint(o)));
    }
    if let Some(ref op) = f.opcode {
        entries.push(("opcode", FieldValue::Str(op)));
    }
    if let Some(ref p) = f.path {
        entries.push(("path", FieldValue::Str(p)));
    }

    for (i, (k, v)) in entries.iter().enumerate() {
        indent(s, level + 1);
        push_string_literal(s, k);
        s.push_str(": ");
        match v {
            FieldValue::Str(value) => push_string_literal(s, value),
            FieldValue::Uint(value) => s.push_str(&value.to_string()),
        }
        if i + 1 < entries.len() {
            s.push(',');
        }
        s.push('\n');
    }

    indent(s, level);
    s.push('}');
}

fn push_paths(s: &mut String, level: usize, key: &str, paths: &[ExecutionPath], comma: bool) {
    indent(s, level);
    push_string_literal(s, key);
    s.push_str(": ");
    if paths.is_empty() {
        s.push_str("[]");
        if comma {
            s.push(',');
        }
        s.push('\n');
        return;
    }
    s.push_str("[\n");
    for (i, p) in paths.iter().enumerate() {
        push_path_obj(s, level + 1, p);
        if i + 1 < paths.len() {
            s.push(',');
        }
        s.push('\n');
    }
    indent(s, level);
    s.push(']');
    if comma {
        s.push(',');
    }
    s.push('\n');
}

fn push_path_obj(s: &mut String, level: usize, p: &ExecutionPath) {
    indent(s, level);
    s.push_str("{\n");
    push_kv_uint(s, level + 1, "id", p.id, true);
    push_kv_string(s, level + 1, "description", &p.description, true);
    push_bool_array(s, level + 1, "branchChoices", &p.branch_choices, true);
    push_kv_bool(s, level + 1, "reachable", p.reachable, true);
    push_kv_bool(s, level + 1, "hasCheckSig", p.has_check_sig, true);
    push_kv_int(s, level + 1, "stackDepthAtEnd", p.stack_depth_at_end, false);
    indent(s, level);
    s.push('}');
}

fn push_bool_array(s: &mut String, level: usize, key: &str, arr: &[bool], comma: bool) {
    indent(s, level);
    push_string_literal(s, key);
    s.push_str(": ");
    if arr.is_empty() {
        s.push_str("[]");
        if comma {
            s.push(',');
        }
        s.push('\n');
        return;
    }
    s.push_str("[\n");
    for (i, b) in arr.iter().enumerate() {
        indent(s, level + 1);
        s.push_str(if *b { "true" } else { "false" });
        if i + 1 < arr.len() {
            s.push(',');
        }
        s.push('\n');
    }
    indent(s, level);
    s.push(']');
    if comma {
        s.push(',');
    }
    s.push('\n');
}

fn push_summary(s: &mut String, level: usize, key: &str, sum: &Summary, comma: bool) {
    indent(s, level);
    push_string_literal(s, key);
    s.push_str(": {\n");
    push_kv_uint(s, level + 1, "totalPaths", sum.total_paths, true);
    push_kv_uint(s, level + 1, "reachablePaths", sum.reachable_paths, true);
    push_kv_uint(s, level + 1, "pathsWithCheckSig", sum.paths_with_check_sig, true);
    push_kv_uint(
        s,
        level + 1,
        "pathsWithoutCheckSig",
        sum.paths_without_check_sig,
        true,
    );
    push_kv_int(s, level + 1, "maxStackDepth", sum.max_stack_depth, true);
    push_kv_uint(s, level + 1, "scriptSizeBytes", sum.script_size_bytes, false);
    indent(s, level);
    s.push('}');
    if comma {
        s.push(',');
    }
    s.push('\n');
}

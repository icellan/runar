//! Pass 6: opcode concerns. See spec §10.

use super::types::{Finding, ParsedOp, PushEncoding, Severity};

pub fn analyze_opcode_concerns(opcodes: &[ParsedOp], script_size_bytes: usize) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();

    if script_size_bytes > 500_000 {
        let kb = format_kb(script_size_bytes);
        out.push(Finding {
            severity: Severity::Info,
            code: "LARGE_SCRIPT".to_string(),
            message: format!(
                "Script is {} bytes ({} KB) — consider if this is intentional",
                script_size_bytes, kb
            ),
            offset: None,
            opcode: None,
            path: None,
        });
    }

    for op in opcodes {
        if op.opcode == 0xab {
            out.push(Finding {
                severity: Severity::Info,
                code: "CODESEPARATOR_PRESENT".to_string(),
                message: "OP_CODESEPARATOR found — expected for stateful contracts, unusual otherwise".to_string(),
                offset: Some(op.offset),
                opcode: Some(op.name.clone()),
                path: None,
            });
        }
        if let Some(enc) = op.push_encoding {
            let declared = op.declared_data_length.unwrap_or(0);
            match enc {
                PushEncoding::Pushdata1 if declared <= 75 => {
                    out.push(Finding {
                        severity: Severity::Info,
                        code: "INEFFICIENT_PUSH".to_string(),
                        message: format!(
                            "OP_PUSHDATA1 used for {}-byte data — direct push (opcode 0x{:02x}) would be more efficient",
                            declared, declared
                        ),
                        offset: Some(op.offset),
                        opcode: Some(op.name.clone()),
                        path: None,
                    });
                }
                PushEncoding::Pushdata2 if declared <= 255 => {
                    out.push(Finding {
                        severity: Severity::Info,
                        code: "INEFFICIENT_PUSH".to_string(),
                        message: format!(
                            "OP_PUSHDATA2 used for {}-byte data — OP_PUSHDATA1 would be more efficient",
                            declared
                        ),
                        offset: Some(op.offset),
                        opcode: Some(op.name.clone()),
                        path: None,
                    });
                }
                PushEncoding::Pushdata4 if declared <= 65535 => {
                    out.push(Finding {
                        severity: Severity::Info,
                        code: "INEFFICIENT_PUSH".to_string(),
                        message: format!(
                            "OP_PUSHDATA4 used for {}-byte data — OP_PUSHDATA2 would be more efficient",
                            declared
                        ),
                        offset: Some(op.offset),
                        opcode: Some(op.name.clone()),
                        path: None,
                    });
                }
                _ => {}
            }
        }
    }

    out
}

/// Format `n / 1024` to exactly one decimal place using IEEE-754
/// round-half-to-even semantics on the tenths digit. Matches JS
/// `(n/1024).toFixed(1)`.
pub fn format_kb(n: usize) -> String {
    // Canonical formula from spec §5.1: round_half_to_even(n * 10 / 1024) / 10
    // Use a direct integer-banker's-rounding to avoid f64 surprises.
    let num = (n as u128) * 10;
    let denom: u128 = 1024;
    let q = num / denom;
    let r = num % denom;
    // Compare 2*r vs denom for half detection.
    let twice = r * 2;
    let rounded: u128 = match twice.cmp(&denom) {
        std::cmp::Ordering::Less => q,
        std::cmp::Ordering::Greater => q + 1,
        std::cmp::Ordering::Equal => {
            // Half — round to even.
            if q.is_multiple_of(2) {
                q
            } else {
                q + 1
            }
        }
    };
    let integer = rounded / 10;
    let tenths = rounded % 10;
    format!("{}.{}", integer, tenths)
}

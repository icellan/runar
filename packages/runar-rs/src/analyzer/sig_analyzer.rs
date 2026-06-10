//! Pass 5: signature hygiene. See spec §9.

use super::types::{ExecutionPath, Finding, ParsedOp, Severity};

/// Returns NO_SIG_CHECK and CHECKSIG_RESULT_DROPPED findings.
pub fn analyze_sig_hygiene(opcodes: &[ParsedOp], paths: &[ExecutionPath]) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();

    // NO_SIG_CHECK per reachable path.
    for path in paths {
        if path.reachable && !path.has_check_sig {
            out.push(Finding {
                severity: Severity::Warning,
                code: "NO_SIG_CHECK".to_string(),
                message: "Execution path has no signature verification (OP_CHECKSIG/OP_CHECKMULTISIG)".to_string(),
                offset: None,
                opcode: None,
                path: Some(path.description.clone()),
            });
        }
    }

    // CHECKSIG_RESULT_DROPPED — only OP_CHECKSIG (0xac) and OP_CHECKMULTISIG
    // (0xae); the *VERIFY variants don't leave a result.
    for i in 0..opcodes.len().saturating_sub(1) {
        let here = &opcodes[i];
        let next = &opcodes[i + 1];
        if (here.opcode == 0xac || here.opcode == 0xae) && next.opcode == 0x75 {
            out.push(Finding {
                severity: Severity::Warning,
                code: "CHECKSIG_RESULT_DROPPED".to_string(),
                message: format!(
                    "{} result is dropped by {} — signature check has no effect",
                    here.name, next.name
                ),
                offset: Some(here.offset),
                opcode: Some(here.name.clone()),
                path: None,
            });
        }
    }

    out
}

//! Bitcoin Script virtual machine for off-chain testing.
//!
//! Thin wrapper around the `bsv-sdk` crate's `Spend` script interpreter
//! (`bsv::script::spend::Spend`). It does NOT re-implement Bitcoin
//! Script — the upstream interpreter does all execution.
//!
//! # Step-mode API divergence
//!
//! The TypeScript / Go ScriptVMs expose a step-mode debugger API
//! (`step()`, `pc`, `current_stack`, …). The `bsv-sdk` `Spend` interpreter
//! keeps its execution state — stack, alt-stack, program counter, script
//! context — as `pub(crate)` fields, so a downstream crate cannot observe
//! the VM state between `Spend::step()` calls. Per the cross-language
//! plan's "wrap the upstream SDK, do not write a custom VM" directive, the
//! Rust tier therefore ships **execute-only** (`execute` / `execute_hex`):
//! a script's pass/fail outcome is reported, but per-opcode stepping is not
//! available. This is a documented, intentional divergence — see
//! `audits/cross-language-completeness-20260513.md` § GAP-M2.

use bsv::script::locking_script::LockingScript;
use bsv::script::spend::{Spend, SpendParams};
use bsv::script::unlocking_script::UnlockingScript;

/// Configuration for a [`ScriptVm`].
#[derive(Debug, Clone, Default)]
pub struct VmOptions {
    /// Relaxed mode disables the interpreter's push-only, clean-stack,
    /// minimal-encoding, NULLDUMMY and low-S checks. Off by default —
    /// strict evaluation matches on-chain consensus semantics.
    pub relaxed: bool,
}

/// The outcome of a full script execution.
#[derive(Debug, Clone)]
pub struct VmResult {
    /// `true` when the script ran to completion and left a truthy value on
    /// top of the stack (and, in strict mode, satisfied the clean-stack
    /// rule).
    pub success: bool,
    /// The interpreter error string, or `None` when the script either
    /// succeeded or cleanly evaluated to `false`.
    pub error: Option<String>,
}

/// Executes Bitcoin Script bytes via the `bsv-sdk` `Spend` interpreter.
pub struct ScriptVm {
    opts: VmOptions,
}

impl ScriptVm {
    /// Create a `ScriptVm` with the given options.
    pub fn new(opts: VmOptions) -> Self {
        Self { opts }
    }

    /// Run the unlocking script followed by the locking script and return
    /// the pass/fail outcome. An empty unlocking script is allowed
    /// (equivalent to executing the locking script alone).
    pub fn execute(&self, unlocking: &[u8], locking: &[u8]) -> VmResult {
        let params = SpendParams {
            locking_script: LockingScript::from_binary(locking),
            unlocking_script: UnlockingScript::from_binary(unlocking),
            // Dummy transaction context — sufficient for non-CHECKSIG
            // scripts. CHECKSIG-bearing scripts require a real spending
            // transaction, which is out of scope for this off-chain probe.
            source_txid: "0".repeat(64),
            source_output_index: 0,
            source_satoshis: 0,
            transaction_version: 1,
            transaction_lock_time: 0,
            transaction_sequence: 0xffff_ffff,
            other_inputs: Vec::new(),
            other_outputs: Vec::new(),
            input_index: 0,
        };
        let mut spend = Spend::new(params);
        if self.opts.relaxed {
            spend.set_relaxed_override(true);
        }
        match spend.validate() {
            Ok(true) => VmResult { success: true, error: None },
            Ok(false) => VmResult { success: false, error: None },
            Err(e) => VmResult { success: false, error: Some(format!("{e:?}")) },
        }
    }

    /// Run a single hex-encoded script (as the locking script, with an
    /// empty unlocking script) and return the pass/fail outcome.
    pub fn execute_hex(&self, script_hex: &str) -> Result<VmResult, String> {
        let bytes = decode_hex(script_hex)
            .map_err(|e| format!("ScriptVm::execute_hex: {e}"))?;
        Ok(self.execute(&[], &bytes))
    }
}

/// Decode a hex string to bytes. Kept local so the SDK keeps its minimal
/// dependency footprint (no `hex` crate).
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex string".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let nibble = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(format!("invalid hex character {:?}", c as char)),
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        out.push((nibble(bytes[i])? << 4) | nibble(bytes[i + 1])?);
        i += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // "OP_2 OP_3 OP_ADD OP_5 OP_EQUAL" (hex 5253935587): 2 + 3 == 5.
    #[test]
    fn execute_hex_arithmetic_succeeds() {
        let vm = ScriptVm::new(VmOptions::default());
        let res = vm.execute_hex("5253935587").expect("valid hex");
        assert!(res.success, "expected 2 + 3 == 5 to succeed, error: {:?}", res.error);
        assert!(res.error.is_none());
    }

    // "OP_2 OP_3 OP_EQUAL" (hex 525387): 2 == 3 is false.
    #[test]
    fn execute_hex_false_comparison_fails() {
        let vm = ScriptVm::new(VmOptions::default());
        let res = vm.execute_hex("525387").expect("valid hex");
        assert!(!res.success, "expected 2 == 3 to evaluate false");
    }

    // Split unlocking + locking: unlocking pushes OP_5, locking checks == 5.
    #[test]
    fn execute_unlocking_and_locking() {
        let vm = ScriptVm::new(VmOptions::default());
        let res = vm.execute(&[0x55], &[0x55, 0x87]);
        assert!(res.success, "expected OP_5 / OP_5 OP_EQUAL to succeed, error: {:?}", res.error);
    }

    // A malformed/odd-length hex string is a wrapper error, not a VmResult.
    #[test]
    fn execute_hex_rejects_invalid_hex() {
        let vm = ScriptVm::new(VmOptions::default());
        assert!(vm.execute_hex("xyz").is_err());
        assert!(vm.execute_hex("abc").is_err()); // odd length
    }

    // A hard interpreter error (unbalanced OP_ENDIF, hex 68) surfaces as
    // success=false with a populated error string.
    #[test]
    fn execute_hex_malformed_script_reports_error() {
        let vm = ScriptVm::new(VmOptions::default());
        let res = vm.execute_hex("68").expect("valid hex");
        assert!(!res.success);
        assert!(res.error.is_some(), "malformed script should populate error");
    }
}

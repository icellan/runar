//! Typed SDK errors + DoS-bound constants.
//!
//! `MAX_SCRIPT_BYTES` mirrors `InputLimits.MAX_SCRIPT_BYTES` (4 MiB) from the
//! TS schema package. Any locking script larger than this is rejected at SDK
//! entry points (`deploy` / `call` / `Provider::get_utxos` /
//! `Provider::get_contract_utxo`) BEFORE any signing or broadcast work
//! happens. Largest legitimate script measured is `p384-wallet` at ~1.87 MB;
//! 4 MiB gives ~2× headroom.

use std::error::Error;
use std::fmt;

/// Mirrors `InputLimits.MAX_SCRIPT_BYTES` in the TypeScript schema package.
pub const MAX_SCRIPT_BYTES: usize = 4 * 1024 * 1024;

/// Returned when a script exceeds [`MAX_SCRIPT_BYTES`] at a public SDK entry
/// point. Distinct typed error so callers can distinguish DoS-bound rejection
/// from generic decode / network errors.
#[derive(Debug, Clone)]
pub struct ScriptSizeExceededError {
    pub limit: usize,
    pub actual: usize,
    pub context: String,
}

impl fmt::Display for ScriptSizeExceededError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "script exceeds MAX_SCRIPT_BYTES (limit={}, actual={}, context={})",
            self.limit, self.actual, self.context,
        )
    }
}

impl Error for ScriptSizeExceededError {}

/// Convert into the SDK's `String`-based error currency used by `Provider`
/// / `RunarContract` methods.
impl From<ScriptSizeExceededError> for String {
    fn from(err: ScriptSizeExceededError) -> String {
        err.to_string()
    }
}

/// Assert that a hex-encoded script is at or under [`MAX_SCRIPT_BYTES`].
///
/// Returns `Ok(())` for empty / under-limit inputs; otherwise returns a
/// [`ScriptSizeExceededError`] whose `actual` field is the script's byte
/// length (rounded up for odd-length hex inputs).
pub fn assert_script_hex_under_limit(
    script_hex: &str,
    limit: usize,
    context: &str,
) -> Result<(), ScriptSizeExceededError> {
    // hex string is 2 chars per byte; tolerate odd-length defensively.
    let actual_bytes = script_hex.len().saturating_add(1) / 2;
    if actual_bytes > limit {
        return Err(ScriptSizeExceededError {
            limit,
            actual: actual_bytes,
            context: context.to_string(),
        });
    }
    Ok(())
}

/// Returned when a method call requires a caller-supplied intent-intrinsic
/// witness value (auto-injected `_prevOutScript_<i>` or `_serialisedOutputs`)
/// that has not been set on the `RunarContract`.
///
/// Auto-injected witness params come from the compiler when a contract method
/// uses `extractPrevOutputScript(i)` or `requireOutputP2PKH(...)`. The caller
/// must supply concrete bytes for each before invoking `call()` /
/// `prepare_call()` via `RunarContract::set_prev_out_script` and
/// `RunarContract::set_serialised_outputs`.
#[derive(Debug, Clone)]
pub struct WitnessValueMissingError {
    pub param_name: String,
    pub method_name: String,
    pub contract_name: String,
}

impl fmt::Display for WitnessValueMissingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "witness value missing for auto-injected param '{}' on {}.{} — call set_prev_out_script(i, bytes) or set_serialised_outputs(bytes) before invoking the method",
            self.param_name, self.contract_name, self.method_name,
        )
    }
}

impl Error for WitnessValueMissingError {}

impl From<WitnessValueMissingError> for String {
    fn from(err: WitnessValueMissingError) -> String {
        err.to_string()
    }
}

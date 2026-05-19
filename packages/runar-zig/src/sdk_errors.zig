//! Typed SDK errors + DoS-bound constants for the Zig SDK.
//!
//! `MAX_SCRIPT_BYTES` mirrors `InputLimits.MAX_SCRIPT_BYTES` (4 MiB) from
//! the TS schema package. Any locking script larger than this is rejected
//! at SDK entry points (deploy / call / Provider.getUtxos /
//! Provider.getContractUtxo) BEFORE any signing or broadcast work runs.
//! Largest legitimate script measured is `p384-wallet` at ~1.87 MB;
//! 4 MiB gives ~2× headroom.

/// Mirrors InputLimits.MAX_SCRIPT_BYTES in the TypeScript schema package.
pub const MAX_SCRIPT_BYTES: usize = 4 * 1024 * 1024;

/// Distinct typed error for DoS-bound script size rejection. Lives in its
/// own error set so callers can distinguish it from generic CallFailed /
/// DeployFailed buckets.
pub const ScriptSizeError = error{ScriptSizeExceeded};

/// Last-recorded ScriptSizeExceeded context, populated by
/// `assertScriptHexUnderLimit`. Zig errors don't carry payloads, so tests
/// (and callers that want a structured message) read this side channel.
/// Single-threaded SDK usage assumed (matches the TS / Go / Python tiers).
pub var last_error: ?LastError = null;

pub const LastError = struct {
    limit: usize,
    actual: usize,
    context_buf: [256]u8,
    context_len: usize,

    pub fn contextSlice(self: *const LastError) []const u8 {
        return self.context_buf[0..self.context_len];
    }
};

/// Assert that a hex-encoded script is at or under `limit` bytes. Records
/// limit / actual / context into `last_error` and returns
/// `error.ScriptSizeExceeded` on violation. No allocation: the context
/// string is truncated into a fixed-size buffer.
pub fn assertScriptHexUnderLimit(
    script_hex: []const u8,
    limit: usize,
    context: []const u8,
) ScriptSizeError!void {
    // hex string is 2 chars per byte; tolerate odd-length defensively.
    const actual_bytes = (script_hex.len + 1) / 2;
    if (actual_bytes > limit) {
        var rec = LastError{
            .limit = limit,
            .actual = actual_bytes,
            .context_buf = undefined,
            .context_len = 0,
        };
        const copy_len = @min(context.len, rec.context_buf.len);
        @memcpy(rec.context_buf[0..copy_len], context[0..copy_len]);
        rec.context_len = copy_len;
        last_error = rec;
        return error.ScriptSizeExceeded;
    }
}

/// Distinct typed error returned when a method call requires a caller-supplied
/// intent-intrinsic witness value (auto-injected `_prevOutScript_<i>` or
/// `_serialisedOutputs`) that has not been set on the `RunarContract`.
///
/// Auto-injected witness params come from the compiler when a contract method
/// uses `extractPrevOutputScript(i)` or `requireOutputP2PKH(...)`. Callers
/// must supply concrete bytes for each via `RunarContract.setPrevOutScript`
/// and `RunarContract.setSerialisedOutputs` before invoking the method.
pub const WitnessValueError = error{WitnessValueMissing};

/// Last-recorded WitnessValueMissing diagnostic. Same single-threaded-SDK
/// rationale as `last_error` above — Zig errors don't carry payloads, so we
/// stash the structured info in a side channel for tests / callers that need
/// to report which param was missing.
pub var last_witness_error: ?LastWitnessError = null;

pub const LastWitnessError = struct {
    param_name_buf: [128]u8,
    param_name_len: usize,
    method_name_buf: [128]u8,
    method_name_len: usize,
    contract_name_buf: [128]u8,
    contract_name_len: usize,

    pub fn paramName(self: *const LastWitnessError) []const u8 {
        return self.param_name_buf[0..self.param_name_len];
    }
    pub fn methodName(self: *const LastWitnessError) []const u8 {
        return self.method_name_buf[0..self.method_name_len];
    }
    pub fn contractName(self: *const LastWitnessError) []const u8 {
        return self.contract_name_buf[0..self.contract_name_len];
    }
};

/// Record a `WitnessValueMissing` diagnostic into `last_witness_error` and
/// return the typed error. No allocation; string fields are truncated into
/// fixed buffers.
pub fn raiseWitnessValueMissing(
    param_name: []const u8,
    method_name: []const u8,
    contract_name: []const u8,
) WitnessValueError {
    var rec = LastWitnessError{
        .param_name_buf = undefined,
        .param_name_len = 0,
        .method_name_buf = undefined,
        .method_name_len = 0,
        .contract_name_buf = undefined,
        .contract_name_len = 0,
    };
    const p = @min(param_name.len, rec.param_name_buf.len);
    @memcpy(rec.param_name_buf[0..p], param_name[0..p]);
    rec.param_name_len = p;
    const m = @min(method_name.len, rec.method_name_buf.len);
    @memcpy(rec.method_name_buf[0..m], method_name[0..m]);
    rec.method_name_len = m;
    const c = @min(contract_name.len, rec.contract_name_buf.len);
    @memcpy(rec.contract_name_buf[0..c], contract_name[0..c]);
    rec.contract_name_len = c;
    last_witness_error = rec;
    return error.WitnessValueMissing;
}

//! N-189: the off-chain scriptCode `call` hands the ANF interpreter
//! (what `extractScriptCode(txPreimage)` returns while the SDK predicts the
//! post-state) must be the scriptCode field of the BIP-143 preimage the call
//! actually signs: the SPENT UTXO's locking script after the
//! OP_CODESEPARATOR, code AND the `OP_RETURN <state>` tail. R67 built it from
//! the bare template codePart, so a method whose post-state depends on its
//! own scriptCode committed a continuation the covenant's hashOutputs check
//! rejects (shown on @bsv/sdk Spend by
//! packages/runar-sdk/src/__tests__/n189-scriptcode-intent-includes-state.test.ts).
//!
//! Proves: for the contract below, the `n` call() commits equals the length of the
//! signed preimage's scriptCode field, `preimage[104 .. len-52]` (CompactSize
//! prefix included), on the `autoComputeState` path. Does NOT prove: on-chain
//! acceptance (Zig ships no ScriptVM); the `autoComputeDataOutputs` path (a
//! caller-supplied `new_state`), which got the same one-line change but is not
//! pinned here; extra contract inputs of a multi-input call. The fixture is
//! the Zig compiler's artifact for:
//!
//!   class ScLen extends StatefulSmartContract {
//!     n: bigint;
//!     constructor(n: bigint) { super(n); this.n = n; }
//!     public rec(): void { this.n = len(extractScriptCode(this.txPreimage)); }
//!   }

const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");

const ARTIFACT_JSON = @embedFile("fixtures/n189-sclen-artifact.json");
const KEY = "00" ** 31 ++ "05";
const FUND_SCRIPT = "76a914" ++ "00" ** 20 ++ "88ac";

test "N-189: the scriptCode intent is the signed preimage's scriptCode (state tail included)" {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, ARTIFACT_JSON);
    defer artifact.deinit();
    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex(KEY);
    {
        const addr = try signer.signer().getAddress(allocator);
        defer allocator.free(addr);
        try prov.addUtxo(addr, .{ .txid = "aa" ** 32, .output_index = 0, .satoshis = 500_000, .script = FUND_SCRIPT });
        try prov.addUtxo(addr, .{ .txid = "bb" ** 32, .output_index = 0, .satoshis = 500_000, .script = FUND_SCRIPT });
    }
    const ctor = [_]types.StateValue{.{ .int = 0 }};
    var contract = try contract_mod.RunarContract.init(allocator, &artifact, &ctor);
    defer contract.deinit();
    const deploy_txid = try contract.deploy(prov.provider(), signer.signer(), .{ .satoshis = 10_000 });
    defer allocator.free(deploy_txid);

    const args = [_]types.StateValue{};
    var prepared = try contract.prepareCall("rec", &args, prov.provider(), signer.signer(), null);
    defer prepared.deinit(allocator);
    const preimage_len = prepared.preimage.len / 2;
    try std.testing.expect(preimage_len > 156);
    const signed_script_code_len: i64 = @intCast(preimage_len - 104 - 52);

    // This tier's prepareCall does no ANF auto-compute (the caller passes
    // `new_state`), so the prediction under test runs in call(); prepareCall
    // above only supplies the preimage the spend signs (same spent UTXO).
    const call_txid = try contract.call("rec", &args, prov.provider(), signer.signer(), null);
    defer allocator.free(call_txid);
    try std.testing.expectEqual(signed_script_code_len, contract.state[0].int);
}

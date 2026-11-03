//! F-024 (R14): the SDK's ANF interpreter derives the post-call state before
//! the tx exists; the covenant re-derives it on-chain. For a contract whose
//! state depends on `continuationAmount()` (the injected `_newAmount`) and
//! `extractAmount(txPreimage)` (the spent UTXO's satoshis), the SDK must feed
//! the interpreter those real values.
//!
//! Proves: the Zig SDK call path derives `lastDeposit = continuation - input`
//! from the call's real amounts. Does NOT prove on-chain acceptance (Zig ships
//! no ScriptVM); the TS/Go SDK tests cover the spend. The fixture is the Zig
//! compiler's artifact for the Tip source quoted below.
//!
//!   class Tip extends StatefulSmartContract {
//!     lastDeposit: bigint;
//!     constructor(lastDeposit: bigint) { super(lastDeposit); this.lastDeposit = lastDeposit; }
//!     public deposit() {
//!       this.lastDeposit = continuationAmount() - extractAmount(this.txPreimage);
//!     }
//!   }

const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");

const ARTIFACT_JSON = @embedFile("fixtures/f024-tip-artifact.json");
const KEY = "00" ** 31 ++ "05";
const FUND_SCRIPT = "76a914" ++ "00" ** 20 ++ "88ac";

test "F-024: the call path derives state from continuationAmount() and extractAmount()" {
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
    const call_txid = try contract.call("deposit", &args, prov.provider(), signer.signer(), .{ .satoshis = 12_500 });
    defer allocator.free(call_txid);
    try std.testing.expectEqual(@as(i64, 2_500), contract.state[0].int);
}

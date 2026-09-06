//! Zig SDK — a malformed embedded ANF IR must FAIL the call, not be swallowed.
//!
//! NEW-006 made the Zig call path fail closed when the ANF INTERPRETER errors:
//! swallowing that built the stateful continuation from the CURRENT (pre-call)
//! state, which the covenant's `hashOutputs` binding then rejects — a silent
//! "your call cannot be broadcast", plus silent loss of the method's data / raw
//! outputs.
//!
//! One step earlier in the same two functions the ANF PARSE was still swallowed
//! (`parseANFFromJson(...) catch return empty`), which lands in exactly the same
//! place by a different door and has no peer-tier analogue — the TS, Go, Rust,
//! Python, Ruby and Java tiers all propagate a parse failure. Silence here is
//! strictly worse than the interpreter case it sits above: `autoComputeState`
//! returns before it ever reaches the state-application loop, so `self.state`
//! keeps its pre-call value AND the caller is told the call succeeded.
//!
//! The artifact JSON below is the shipped G1 fixture with its `anf` object
//! replaced by a truncated one. `RunarArtifact.fromJson` re-stringifies whatever
//! it finds under `"anf"`, so a syntactically broken ANF cannot be produced
//! through that door; the test therefore overwrites `artifact.anf_json` directly,
//! which is the shape any non-`fromJson` artifact source (hand-built artifact,
//! alternative loader, corrupted cache) hands the call path.

const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");

const RunarContract = contract_mod.RunarContract;

const ARTIFACT_JSON = @embedFile("fixtures/g1-raw-output-artifact.json");

const DEPLOYER_KEY = "00" ** 31 ++ "03";
const CALLER_KEY = "00" ** 31 ++ "04";

const RAW_SCRIPT = "76a914" ++ "ab" ** 20 ++ "88ac";
const FUND_SCRIPT = "76a914" ++ "00" ** 20 ++ "88ac";

/// Truncated JSON: `parseFromSlice` fails on the unterminated object.
const MALFORMED_ANF = "{\"contractName\":\"RawOutputTest\",\"methods\":[";

test "a malformed embedded ANF fails the call instead of committing the pre-call state" {
    const allocator = std.testing.allocator;

    var artifact = try types.RunarArtifact.fromJson(allocator, ARTIFACT_JSON);
    defer artifact.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();

    var deployer = try signer_mod.LocalSigner.fromHex(DEPLOYER_KEY);
    var caller = try signer_mod.LocalSigner.fromHex(CALLER_KEY);

    {
        const dep_addr = try deployer.signer().getAddress(allocator);
        defer allocator.free(dep_addr);
        try prov.addUtxo(dep_addr, .{ .txid = "aa" ** 32, .output_index = 0, .satoshis = 500_000, .script = FUND_SCRIPT });
        const call_addr = try caller.signer().getAddress(allocator);
        defer allocator.free(call_addr);
        try prov.addUtxo(call_addr, .{ .txid = "bb" ** 32, .output_index = 0, .satoshis = 500_000, .script = FUND_SCRIPT });
    }

    const ctor = [_]types.StateValue{.{ .int = 0 }};
    var contract = try RunarContract.init(allocator, &artifact, &ctor);
    defer contract.deinit();

    // Deploy with the REAL ANF so the deploy path is unaffected; the defect
    // under test lives on the call path.
    const deploy_txid = try contract.deploy(prov.provider(), deployer.signer(), .{ .satoshis = 50_000 });
    defer allocator.free(deploy_txid);

    // Corrupt the embedded ANF. `artifact.deinit()` frees `anf_json`, so the
    // replacement must be allocator-owned exactly like the value it replaces.
    if (artifact.anf_json) |old| allocator.free(old);
    artifact.anf_json = try allocator.dupe(u8, MALFORMED_ANF);

    const args = [_]types.StateValue{.{ .bytes = RAW_SCRIPT }};
    const result = contract.call("sendToScript", &args, prov.provider(), caller.signer(), null);

    // The call must NOT report success. Before the fix it returned a txid for a
    // transaction whose continuation output carried `count = 0` — the pre-call
    // value — and whose raw output was missing entirely.
    if (result) |txid| {
        allocator.free(txid);
        try std.testing.expect(false); // unreachable: the call must fail
    } else |_| {}

    // Exactly one broadcast: the deploy. The call never reached the network.
    try std.testing.expectEqual(@as(usize, 1), prov.getBroadcastedTxs().len);
}

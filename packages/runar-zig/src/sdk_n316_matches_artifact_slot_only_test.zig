//! N-316: `matchesArtifact` must treat codeSepIndexSlots and codePartLenSlots
//! as variable script elements even when `constructorSlots` is empty.
//!
//! Replays the shared cross-tier fixture
//! `conformance/sdk-matches-artifact/fixtures.json` (also replayed by the TS,
//! Go, Rust, Python, Ruby and Java SDKs). Its first artifact is real compiler
//! output for a stateful contract with no constructor args.
//!
//! Proves: an honest deployment of such an artifact matches it, and a script
//! differing in one code byte before/after the slot does not.
//! Does NOT prove: on-chain spendability, or slot layouts beyond the fixture.

const std = @import("std");
const types = @import("sdk_types.zig");
const script_utils = @import("sdk_script_utils.zig");

const FIXTURE_PATH = "../../conformance/sdk-matches-artifact/fixtures.json";

test "N-316: matchesArtifact accepts honest deployments of slot-only artifacts" {
    const allocator = std.testing.allocator;
    const raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, FIXTURE_PATH, allocator, .limited(1024 * 1024));
    defer allocator.free(raw);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const cases = parsed.value.object.get("cases").?.array.items;
    try std.testing.expect(cases.len > 0);
    for (cases) |c| {
        const o = c.object;
        const artifact_json = try std.json.Stringify.valueAlloc(allocator, o.get("artifact").?, .{});
        defer allocator.free(artifact_json);
        var artifact = try types.RunarArtifact.fromJson(allocator, artifact_json);
        defer artifact.deinit();
        const got = try script_utils.matchesArtifact(&artifact, o.get("script_hex").?.string);
        std.testing.expectEqual(o.get("expected").?.bool, got) catch |err| {
            std.debug.print("N-316 case failed: {s}\n", .{o.get("name").?.string});
            return err;
        };
    }
}

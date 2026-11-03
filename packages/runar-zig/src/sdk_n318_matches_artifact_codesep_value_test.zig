//! N-318: `matchesArtifact` must check the VALUE at every codeSepIndex slot.
//! Deploy bakes encodeScriptNumber(codeSepIndex + shift) there (shift = growth
//! of every constructor slot, and every earlier codeSep slot, before
//! codeSepIndex); the matcher used to accept any element at the slot.
//!
//! Replays the shared cross-tier vector
//! `conformance/sdk-matches-artifact/codesep.json` (also replayed by the TS,
//! Go, Rust, Python, Ruby and Java SDKs): honest TS-SDK deployments of a real
//! compiled artifact and of a synthetic artifact whose baked values depend on
//! a variable-length constructor arg, plus forgeries differing only in the
//! number pushed at a codeSep slot.
//!
//! Proves: honest deployments match whatever the constructor-arg width, and a
//! forged separator index (OP_0, off by one, non-minimal, unshifted) does not.
//! Does NOT prove: on-chain spendability of the honest scripts.

const std = @import("std");
const types = @import("sdk_types.zig");
const script_utils = @import("sdk_script_utils.zig");

const FIXTURE_PATH = "../../conformance/sdk-matches-artifact/codesep.json";

test "N-318: matchesArtifact rejects a forged value at a codeSepIndex slot" {
    const allocator = std.testing.allocator;
    const raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, FIXTURE_PATH, allocator, .limited(4 * 1024 * 1024));
    defer allocator.free(raw);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const artifacts = parsed.value.object.get("artifacts").?.object;
    const cases = parsed.value.object.get("cases").?.array.items;
    try std.testing.expect(cases.len > 0);
    var wrong: usize = 0;
    for (cases) |c| {
        const o = c.object;
        const artifact_json = try std.json.Stringify.valueAlloc(allocator, artifacts.get(o.get("artifact").?.string).?, .{});
        defer allocator.free(artifact_json);
        var artifact = try types.RunarArtifact.fromJson(allocator, artifact_json);
        defer artifact.deinit();
        const got = try script_utils.matchesArtifact(&artifact, o.get("script_hex").?.string);
        if (got != o.get("expected").?.bool) {
            std.debug.print("N-318 case wrong: {s} (got {})\n", .{ o.get("name").?.string, got });
            wrong += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), wrong);
}

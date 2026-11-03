//! Issue #109 (Option 4): warn when DCE strips an un-annotated readonly field.
//!
//! Such a field carries no compile-time value (no initializer) and is
//! referenced by no method, so it is eliminated from the locking script
//! entirely — silently dropping deploy-time metadata an author may intend to
//! recover from the on-chain script later. `@embedAlways` fields were forced
//! back in during ANF lowering (a preserved load_prop), so they are
//! "referenced" here and never warn.
//!
//! Faithful port of the check in the TS reference compile() (index.ts) and its
//! Go peer (frontend/embed_always_dce.go): it reads the set of props with a
//! surviving load_prop from the (post-lowering, post-DCE) ANF program. In the
//! Zig pipeline the ec_optimizer has already run its fixpoint dead-binding DCE
//! by the time this is called, so the surviving load_props ARE the referenced
//! set — no separate probe DCE is needed.

const std = @import("std");
const types = @import("../ir/types.zig");

const ContractNode = types.ContractNode;
const ANFProgram = types.ANFProgram;
const ANFBinding = types.ANFBinding;
const CompilerDiagnostic = types.CompilerDiagnostic;

/// Collect DCE warnings for un-annotated, unreferenced readonly fields. The
/// returned slice (and each message string) is allocated with `allocator`; the
/// caller owns them.
pub fn collectDceWarnings(
    allocator: std.mem.Allocator,
    contract: ContractNode,
    program: *const ANFProgram,
) ![]CompilerDiagnostic {
    var referenced = std.StringHashMap(void).init(allocator);
    defer referenced.deinit();
    for (program.methods) |method| {
        if (std.mem.eql(u8, method.name, "constructor")) continue;
        const body = if (method.body.len > 0) method.body else method.bindings;
        try collectLoadProps(body, &referenced);
    }

    var diags: std.ArrayListUnmanaged(CompilerDiagnostic) = .empty;
    errdefer diags.deinit(allocator);
    for (contract.properties) |prop| {
        if (prop.readonly and !prop.embed_always and prop.initializer == null and !referenced.contains(prop.name)) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "readonly field '{s}' is not referenced in any method body and may " ++
                    "be eliminated by DCE; mark it with the embedAlways directive to preserve it in the " ++
                    "on-chain script",
                .{prop.name},
            );
            try diags.append(allocator, .{ .message = msg, .severity = .warning });
        }
    }
    return diags.toOwnedSlice(allocator);
}

/// Collect the names of every property that has a surviving load_prop binding,
/// recursing into nested if/loop bodies.
fn collectLoadProps(bindings: []const ANFBinding, out: *std.StringHashMap(void)) !void {
    for (bindings) |binding| {
        switch (binding.value) {
            .load_prop => |lp| try out.put(lp.name, {}),
            .@"if" => |v| {
                try collectLoadProps(v.then, out);
                try collectLoadProps(v.@"else", out);
            },
            .loop => |v| try collectLoadProps(v.body, out),
            else => {},
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

test "collectDceWarnings warns on un-annotated unreferenced readonly field only" {
    const a = std.testing.allocator;
    // Contract: pubKeyHash (referenced) + metadataId (un-annotated, unreferenced)
    // + tagId (@embedAlways, unreferenced but preserved) + counted (has initializer).
    const props = [_]types.PropertyNode{
        .{ .name = "pubKeyHash", .type_info = .addr, .readonly = true },
        .{ .name = "metadataId", .type_info = .byte_string, .readonly = true },
        .{ .name = "tagId", .type_info = .byte_string, .readonly = true, .embed_always = true },
        .{ .name = "counted", .type_info = .bigint, .readonly = true, .initializer = .{ .literal_int = 0 } },
    };
    const contract = ContractNode{
        .name = "Meta",
        .parent_class = .smart_contract,
        .properties = @constCast(props[0..]),
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    };
    // Post-DCE program: only pubKeyHash has a surviving load_prop (in `unlock`).
    var unlock_body = [_]ANFBinding{
        .{ .name = "t0", .value = .{ .load_prop = .{ .name = "pubKeyHash" } } },
    };
    var methods = [_]types.ANFMethod{
        .{ .name = "unlock", .is_public = true, .bindings = unlock_body[0..], .body = unlock_body[0..] },
    };
    const program = ANFProgram{
        .contract_name = "Meta",
        .parent_class = .smart_contract,
        .properties = &.{},
        .methods = methods[0..],
    };

    const diags = try collectDceWarnings(a, contract, &program);
    defer {
        for (diags) |d| a.free(d.message);
        a.free(diags);
    }
    // Exactly one warning — for metadataId. pubKeyHash is referenced, tagId is
    // @embedAlways (preserved), counted has an initializer.
    try std.testing.expectEqual(@as(usize, 1), diags.len);
    try std.testing.expect(std.mem.indexOf(u8, diags[0].message, "metadataId") != null);
    try std.testing.expect(std.mem.indexOf(u8, diags[0].message, "embedAlways directive") != null);
    try std.testing.expect(diags[0].severity == .warning);
}

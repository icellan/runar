//! D25: `anf_lower.lowerToANF` is a public entry point. A caller that
//! assembles its own pipeline (parse -> validate -> typecheck -> lowerToANF)
//! and never runs `continuation_binding.inject` would otherwise lower a mixed
//! ("bind") contract with no `_spentOutpointHash`: its continuations would not
//! be bound to the spent outpoint, which is the twin-input theft D25 closes.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const validate = @import("../passes/validate.zig");
const typecheck = @import("../passes/typecheck.zig");
const anf_lower = @import("../passes/anf_lower.zig");
const continuation_binding = @import("../passes/continuation_binding.zig");
const types = @import("../ir/types.zig");

const FIELD = continuation_binding.TWIN_BINDING_FIELD;

const MIXED =
    "import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';\n" ++
    "class MixedPot extends StatefulSmartContract {\n" ++
    "  count: bigint;\n" ++
    "  constructor(count: bigint) { super(count); this.count = count; }\n" ++
    "  public increment() { this.count++; }\n" ++
    "  public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }\n" ++
    "}\n";

fn frontend(a: std.mem.Allocator) !types.ContractNode {
    const parsed = parse_ts.parseTs(a, MIXED, "MixedPot.runar.ts");
    if (parsed.errors.len > 0) return error.ParseFailed;
    const contract = parsed.contract orelse return error.ParseFailed;
    const val = try validate.validate(a, contract);
    if (val.errors.len > 0) return error.ValidateFailed;
    const tc = try typecheck.typeCheck(a, contract);
    if (tc.errors.len > 0) return error.TypeCheckFailed;
    return contract;
}

test "D25: lowerToANF injects the binding when the caller skipped injection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const program = try anf_lower.lowerToANF(a, try frontend(a));
    try std.testing.expect(program.properties.len > 0);
    try std.testing.expectEqualStrings(FIELD, program.properties[program.properties.len - 1].name);
}

test "D25: lowerToANF does not inject the binding twice" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const injected = try continuation_binding.inject(a, try frontend(a));
    const program = try anf_lower.lowerToANF(a, injected);
    var n: usize = 0;
    for (program.properties) |p| {
        if (std.mem.eql(u8, p.name, FIELD)) n += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), n);
}

const std = @import("std");
const frontend = @import("runar_frontend");
const bsvz = @import("bsvz");

const Script = bsvz.script.Script;

fn compileLockingScript(
    allocator: std.mem.Allocator,
    source: []const u8,
    file_name: []const u8,
) !Script {
    const script_hex = try frontend.compileSourceToHex(allocator, source, file_name);
    defer allocator.free(script_hex);

    const script_bytes = try bsvz.primitives.hex.decode(allocator, script_hex);
    return Script.init(script_bytes);
}

fn executeLockingScript(
    allocator: std.mem.Allocator,
    locking_script: Script,
) !bool {
    var result = try bsvz.script.engine.executeScript(.{
        .allocator = allocator,
    }, locking_script);
    defer result.deinit(allocator);
    return result.success;
}

test "compile constant arithmetic script executes successfully in bsvz" {
    const allocator = std.testing.allocator;
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const ConstantArithmetic = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    pub fn verify(_: *const ConstantArithmetic) void {
        \\        const sum = 3 + 7;
        \\        const diff = 7 - 3;
        \\        const prod = 3 * 7;
        \\        runar.assert(sum + diff + prod == 31);
        \\    }
        \\};
    ;

    const locking_script = try compileLockingScript(allocator, source, "ConstantArithmetic.runar.zig");
    defer allocator.free(locking_script.bytes);

    try std.testing.expect(try executeLockingScript(allocator, locking_script));
}

test "compile constant arithmetic failure executes as false in bsvz" {
    const allocator = std.testing.allocator;
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const ConstantArithmeticFail = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    pub fn verify(_: *const ConstantArithmeticFail) void {
        \\        const sum = 3 + 7;
        \\        const diff = 7 - 3;
        \\        const prod = 3 * 7;
        \\        runar.assert(sum + diff + prod == 32);
        \\    }
        \\};
    ;

    const locking_script = try compileLockingScript(allocator, source, "ConstantArithmeticFail.runar.zig");
    defer allocator.free(locking_script.bytes);

    try std.testing.expect(!(try executeLockingScript(allocator, locking_script)));
}

test "compile constant hash equality script executes successfully in bsvz" {
    const allocator = std.testing.allocator;
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const ConstantHashCheck = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    pub fn verify(_: *const ConstantHashCheck) void {
        \\        runar.assert(runar.bytesEq(runar.sha256("abc"), runar.sha256("abc")));
        \\    }
        \\};
    ;

    const locking_script = try compileLockingScript(allocator, source, "ConstantHashCheck.runar.zig");
    defer allocator.free(locking_script.bytes);

    try std.testing.expect(try executeLockingScript(allocator, locking_script));
}

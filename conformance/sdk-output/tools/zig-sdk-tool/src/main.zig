const std = @import("std");
const runar = @import("runar");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.debug.print("Usage: zig-sdk-tool <input.json>\n", .{});
        std.process.exit(1);
    }

    const file_path = args[1];
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();
    const data = try file.readToEndAlloc(allocator, 16 * 1024 * 1024);
    defer allocator.free(data);

    // Parse the top-level JSON to extract artifact and constructorArgs
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();

    const root = parsed.value.object;

    // Extract and re-serialize the artifact JSON
    const artifact_val = root.get("artifact") orelse {
        std.debug.print("Missing 'artifact' field\n", .{});
        std.process.exit(1);
    };

    const artifact_json = try std.json.Stringify.valueAlloc(allocator, artifact_val, .{});
    defer allocator.free(artifact_json);

    // Parse the artifact
    var artifact = try runar.RunarArtifact.fromJson(allocator, artifact_json);
    defer artifact.deinit();

    // Parse constructorArgs
    const ctor_args_val = root.get("constructorArgs") orelse {
        std.debug.print("Missing 'constructorArgs' field\n", .{});
        std.process.exit(1);
    };

    const ctor_args_arr = ctor_args_val.array.items;
    var ctor_args = try allocator.alloc(runar.StateValue, ctor_args_arr.len);
    defer {
        for (ctor_args) |*arg| arg.deinit(allocator);
        allocator.free(ctor_args);
    }

    for (ctor_args_arr, 0..) |item, i| {
        const obj = item.object;
        const type_str = if (obj.get("type")) |t| t.string else "";
        const value_val = obj.get("value") orelse std.json.Value{ .string = "" };

        ctor_args[i] = try convertArg(allocator, type_str, value_val);
    }

    // Create contract and get locking script
    var contract = try runar.RunarContract.init(allocator, &artifact, ctor_args);
    defer contract.deinit();

    const locking_script = try contract.getLockingScript();
    defer allocator.free(locking_script);

    const stdout = std.fs.File.stdout();
    try stdout.writeAll(locking_script);
}

fn convertArg(allocator: std.mem.Allocator, type_str: []const u8, value: std.json.Value) !runar.StateValue {
    if (std.mem.eql(u8, type_str, "bigint") or std.mem.eql(u8, type_str, "int")) {
        const str = switch (value) {
            .string => |s| s,
            .integer => |n| return .{ .int = n },
            else => return .{ .int = 0 },
        };
        const n = try std.fmt.parseInt(i64, str, 10);
        return .{ .int = n };
    } else if (std.mem.eql(u8, type_str, "bool")) {
        const str = switch (value) {
            .string => |s| s,
            .bool => |b| return .{ .boolean = b },
            else => return .{ .boolean = false },
        };
        return .{ .boolean = std.mem.eql(u8, str, "true") };
    } else {
        // All other types (ByteString, Addr, PubKey, Sig, Ripemd160, etc.) are hex strings
        const str = switch (value) {
            .string => |s| s,
            else => return .{ .bytes = try allocator.dupe(u8, "") },
        };
        return .{ .bytes = try allocator.dupe(u8, str) };
    }
}

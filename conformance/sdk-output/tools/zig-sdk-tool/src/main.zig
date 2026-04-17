const std = @import("std");
const runar = @import("runar");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer args_list.deinit(allocator);
    var args_iter = std.process.Args.Iterator.init(init.minimal.args);
    while (args_iter.next()) |arg| {
        try args_list.append(allocator, arg);
    }
    const args = args_list.items;

    if (args.len < 2) {
        std.debug.print("Usage: zig-sdk-tool <input.json>\n", .{});
        std.process.exit(1);
    }

    const file_path = args[1];
    const data = try std.Io.Dir.cwd().readFileAlloc(io, file_path, allocator, .limited(16 * 1024 * 1024));
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

    const stdout = std.Io.File.stdout();
    try stdout.writeStreamingAll(io, locking_script);
}

fn convertArg(allocator: std.mem.Allocator, type_str: []const u8, value: std.json.Value) !runar.StateValue {
    if (std.mem.eql(u8, type_str, "bigint") or std.mem.eql(u8, type_str, "int")) {
        const str = switch (value) {
            .string => |s| s,
            .integer => |n| return .{ .int = n },
            else => return .{ .int = 0 },
        };
        // Try i64 first; fall back to big_int for values exceeding i64 range
        if (std.fmt.parseInt(i64, str, 10)) |n| {
            return .{ .int = n };
        } else |_| {
            return .{ .big_int = try allocator.dupe(u8, str) };
        }
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

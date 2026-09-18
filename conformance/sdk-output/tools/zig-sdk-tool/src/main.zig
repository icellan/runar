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

    // Handle optional inscription
    if (root.get("inscription")) |insc_val| {
        const insc_obj = insc_val.object;
        const ct = if (insc_obj.get("contentType")) |v| v.string else "";
        const d = if (insc_obj.get("data")) |v| v.string else "";
        // N-043: a refused attach is a RESULT, not a crash — exit non-zero with
        // the reason on stderr so the runner can compare the refusal verdict
        // across all seven tiers.
        contract.withInscription(.{
            .content_type = try allocator.dupe(u8, ct),
            .data = try allocator.dupe(u8, d),
        }) catch |err| {
            if (err == error.CodePartLengthPinViolated) {
                const rec = runar.sdk_errors.last_codepart_pin_error.?;
                std.debug.print(
                    "RunarContract.withInscription: {s} pins SIZE(_codePart) == {d}, but with " ++
                        "this inscription attached the code part is {d} bytes. Deploying it would " ++
                        "make every spend fail OP_VERIFY and lock the contract's funds permanently. " ++
                        "An inscription cannot be attached to a stateful contract with a " ++
                        "variable-length state section: the envelope is part of the code part, and " ++
                        "its length is not known when the pin is compiled\n",
                    .{ rec.contractName(), rec.pinned, rec.actual },
                );
                std.process.exit(1);
            }
            return err;
        };
    }

    // R-062: drive the WALLET funding path rather than only building the
    // locking script, so all seven tiers can be asked to agree on
    // accept-vs-refuse for one artifact. A refusal is a RESULT, not a crash —
    // exit non-zero with the reason on stderr.
    if (root.get("walletDeploy")) |wd_val| {
        const wd = wd_val.object;
        const satoshis: i64 = if (wd.get("satoshis")) |v| switch (v) {
            .integer => |n| n,
            else => 1,
        } else 1;

        var ack_list: std.ArrayListUnmanaged([]const u8) = .empty;
        defer ack_list.deinit(allocator);
        if (wd.get("acknowledgeUnsound")) |a| {
            for (a.array.items) |item| try ack_list.append(allocator, item.string);
        }

        var mock = runar.MockWalletClient.init(allocator);
        defer mock.deinit();

        // Fund the wallet at the address deployWithWallet derives for its
        // UTXO filter: hash160 of the mock wallet's deterministic pubkey.
        var ws = runar.WalletSigner.init(allocator, mock.walletClient(), .{ .level = 2, .name = "conformance" }, "1");
        defer ws.deinit();
        const pkh = try ws.signer().getAddress(allocator);
        defer allocator.free(pkh);
        const funding_script = try runar.buildP2PKHScript(allocator, pkh);
        defer allocator.free(funding_script);
        const outpoint = try std.fmt.allocPrint(allocator, "{s}.0", .{"ab" ** 32});
        defer allocator.free(outpoint);
        try mock.addOutput(.{
            .outpoint = outpoint,
            .satoshis = 100_000,
            .locking_script = funding_script,
            .spendable = true,
        });

        const txid = runar.deployWithWallet(&contract, mock.walletClient(), .{
            .satoshis = satoshis,
            .basket = "conformance",
            .protocol_id = .{ .level = 2, .name = "conformance" },
            .key_id = "1",
            .acknowledge_unsound = ack_list.items,
        }) catch |err| {
            if (err == error.UnsoundPrimitiveNotAcknowledged) {
                // Zig errors carry no payload; the SDK records the primitive and
                // the call-site context, and the message is rendered from those.
                const rec = runar.sdk_errors.last_unsound.?;
                std.debug.print(
                    "{s}: this artifact reaches 1 builtin the compiler does not claim is " ++
                        "sound: {s}. The compiler emitted it only because the gap was " ++
                        "acknowledged at COMPILE time; funding it is a second decision, and " ++
                        "this SDK will not make it for you. Set " ++
                        "DeployOptions.acknowledge_unsound to proceed\n",
                    .{ rec.contextSlice(), rec.primitiveSlice() },
                );
                std.process.exit(1);
            }
            return err;
        };
        allocator.free(txid);
    }

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
    } else if (std.mem.eql(u8, type_str, "bool") or std.mem.eql(u8, type_str, "boolean")) {
        // `boolean` is the spelling the compiler's ABI carries; `bool` is the
        // alias some frontends use. Accept both (R-248).
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

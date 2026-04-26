const std = @import("std");
const types = @import("sdk_types.zig");

// ---------------------------------------------------------------------------
// generateZig — produce a typed Zig wrapper from a compiled RunarArtifact
// ---------------------------------------------------------------------------
//
// Parity target: TypeScript `generateTypescript()` (packages/runar-sdk/src/
// codegen/gen-typescript.ts) and Ruby `Runar::SDK::Codegen.generate_ruby`
// (packages/runar-rb/lib/runar/sdk/codegen.rb).
//
// The generated wrapper exposes:
//   • <Name>ConstructorArgs struct (when the constructor takes params)
//   • <Name>StatefulCallOptions struct (when the contract has non-terminal
//     stateful methods) and OutputSpec helper
//   • TerminalOutput struct (when the contract has terminal methods)
//   • <Name>Contract struct holding a *RunarContract, with:
//       init(allocator, artifact, args) / init(allocator, artifact)
//       fromUtxo(allocator, artifact, utxo)
//       fromTxId(allocator, artifact, txid, output_index, provider)
//       deinit(allocator)
//       connect(provider, signer)
//       attachInscription(insc)
//       getLockingScript()
//       deploy(satoshis) — delegates to RunarContract.deploy
//       one method per public ABI entry point
//       prepare<Method> / finalize<Method> for any Sig-bearing method
//       typed state accessors per state field
//
// `Sig` and `SigHashPreimage` parameters are elided from the user-visible
// signature (auto-resolved by the SDK at call time). Stateful internals
// (`_changePKH`, `_changeAmount`, `_newAmount`) are entirely hidden.

/// Map a Rúnar ABI type to a Zig type for the user-visible signature.
fn mapTypeToZig(abi_type: []const u8) []const u8 {
    if (std.mem.eql(u8, abi_type, "bigint")) return "i64";
    if (std.mem.eql(u8, abi_type, "int")) return "i64";
    if (std.mem.eql(u8, abi_type, "boolean")) return "bool";
    if (std.mem.eql(u8, abi_type, "bool")) return "bool";
    // Sig / PubKey / Addr / ByteString / Ripemd160 / Sha256 / Point /
    // SigHashPreimage are all hex-encoded byte strings on the wire.
    return "[]const u8";
}

/// Convert a user-typed value name into the `StateValue` constructor
/// expression the SDK's call layer expects.
fn toStateValueExpr(allocator: std.mem.Allocator, name: []const u8, abi_type: []const u8) ![]u8 {
    if (std.mem.eql(u8, abi_type, "bigint") or std.mem.eql(u8, abi_type, "int")) {
        return std.fmt.allocPrint(allocator, ".{{ .int = {s} }}", .{name});
    }
    if (std.mem.eql(u8, abi_type, "boolean") or std.mem.eql(u8, abi_type, "bool")) {
        return std.fmt.allocPrint(allocator, ".{{ .boolean = {s} }}", .{name});
    }
    return std.fmt.allocPrint(allocator, ".{{ .bytes = {s} }}", .{name});
}

const ParamRole = enum {
    /// Visible to the user, passed through to the SDK args list.
    user_visible,
    /// Hidden from the user; the SDK auto-fills (Sig / PubKey / SigHashPreimage on stateless).
    hidden_in_args,
    /// Fully internal; never appears in user signature or SDK args list.
    internal,
};

fn classifyParam(p: types.ABIParam, is_stateful: bool) ParamRole {
    if (std.mem.eql(u8, p.type_name, "Sig")) return .hidden_in_args;
    if (is_stateful) {
        if (std.mem.eql(u8, p.type_name, "SigHashPreimage")) return .internal;
        if (std.mem.eql(u8, p.name, "_changePKH")) return .internal;
        if (std.mem.eql(u8, p.name, "_changeAmount")) return .internal;
        if (std.mem.eql(u8, p.name, "_newAmount")) return .internal;
    } else if (std.mem.eql(u8, p.type_name, "SigHashPreimage")) {
        return .hidden_in_args;
    }
    return .user_visible;
}

fn isTerminal(m: types.ABIMethod, is_stateful: bool) bool {
    if (!is_stateful) return true;
    if (m.is_terminal) |t| return t;
    for (m.params) |p| {
        if (std.mem.eql(u8, p.name, "_changePKH")) return false;
    }
    return true;
}

fn methodHasSig(m: types.ABIMethod) bool {
    for (m.params) |p| {
        if (std.mem.eql(u8, p.type_name, "Sig")) return true;
    }
    return false;
}

fn appendFmt(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    const piece = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(piece);
    try out.appendSlice(allocator, piece);
}

fn capitalize(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    if (s.len == 0) return allocator.dupe(u8, s);
    var out = try allocator.alloc(u8, s.len);
    out[0] = std.ascii.toUpper(s[0]);
    @memcpy(out[1..], s[1..]);
    return out;
}

/// generateZig produces a Zig source file string that wraps the artifact's
/// contract API with a typed wrapper struct + per-method helpers. Caller
/// owns the returned slice.
pub fn generateZig(allocator: std.mem.Allocator, artifact: *const types.RunarArtifact) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    const name = if (artifact.contract_name.len > 0) artifact.contract_name else "Contract";
    const is_stateful = artifact.state_fields.len > 0;

    // --- Discover what to emit --------------------------------------------
    var has_terminal_methods = false;
    var has_stateful_methods = false;
    for (artifact.abi.methods) |m| {
        if (!m.is_public) continue;
        if (isTerminal(m, is_stateful)) {
            has_terminal_methods = true;
        } else if (is_stateful) {
            has_stateful_methods = true;
        }
    }
    const ctor_params = artifact.abi.constructor.params;

    // --- Header + imports -------------------------------------------------
    try appendFmt(&out, allocator, "// Generated by: runar codegen\n", .{});
    try appendFmt(&out, allocator, "// Source: {s}\n", .{name});
    try appendFmt(&out, allocator, "// Do not edit manually.\n\n", .{});
    try appendFmt(&out, allocator, "const std = @import(\"std\");\n", .{});
    try appendFmt(&out, allocator, "const sdk = @import(\"runar-zig\");\n\n", .{});

    // --- ConstructorArgs struct ------------------------------------------
    if (ctor_params.len > 0) {
        try appendFmt(&out, allocator, "pub const {s}ConstructorArgs = struct {{\n", .{name});
        for (ctor_params) |p| {
            try appendFmt(&out, allocator, "    {s}: {s},\n", .{ p.name, mapTypeToZig(p.type_name) });
        }
        try appendFmt(&out, allocator, "}};\n\n", .{});
    }

    // --- StatefulCallOptions struct + OutputSpec -------------------------
    if (has_stateful_methods) {
        try appendFmt(&out, allocator, "pub const {s}StatefulCallOptions = struct {{\n", .{name});
        try appendFmt(&out, allocator, "    satoshis: ?i64 = null,\n", .{});
        try appendFmt(&out, allocator, "    change_address: ?[]const u8 = null,\n", .{});
        try appendFmt(&out, allocator, "    change_pub_key: ?[]const u8 = null,\n", .{});
        try appendFmt(&out, allocator, "    new_state: ?[]const sdk.StateValue = null,\n", .{});
        try appendFmt(&out, allocator, "    outputs: ?[]const OutputSpec = null,\n", .{});
        try appendFmt(&out, allocator, "}};\n\n", .{});

        try appendFmt(&out, allocator, "pub const OutputSpec = struct {{\n", .{});
        try appendFmt(&out, allocator, "    satoshis: i64,\n", .{});
        try appendFmt(&out, allocator, "    state: []const sdk.StateValue,\n", .{});
        try appendFmt(&out, allocator, "}};\n\n", .{});
    }

    // --- TerminalOutput struct -------------------------------------------
    if (has_terminal_methods) {
        try appendFmt(&out, allocator, "pub const TerminalOutput = struct {{\n", .{});
        try appendFmt(&out, allocator, "    satoshis: i64,\n", .{});
        try appendFmt(&out, allocator, "    /// Recipient address; converted to a P2PKH script. Set this OR script_hex.\n", .{});
        try appendFmt(&out, allocator, "    address: ?[]const u8 = null,\n", .{});
        try appendFmt(&out, allocator, "    /// Raw locking script hex. Used if address is null.\n", .{});
        try appendFmt(&out, allocator, "    script_hex: ?[]const u8 = null,\n", .{});
        try appendFmt(&out, allocator, "}};\n\n", .{});
    }

    // --- Wrapper struct ---------------------------------------------------
    try appendFmt(&out, allocator, "pub const {s}Contract = struct {{\n", .{name});
    try appendFmt(&out, allocator, "    allocator: std.mem.Allocator,\n", .{});
    try appendFmt(&out, allocator, "    inner: *sdk.RunarContract,\n\n", .{});

    // init — with or without args record
    if (ctor_params.len > 0) {
        try appendFmt(&out, allocator, "    /// Constructs a wrapper around a fresh {s} contract.\n", .{name});
        try appendFmt(&out, allocator, "    pub fn init(\n", .{});
        try appendFmt(&out, allocator, "        allocator: std.mem.Allocator,\n", .{});
        try appendFmt(&out, allocator, "        artifact: *sdk.RunarArtifact,\n", .{});
        try appendFmt(&out, allocator, "        args: {s}ConstructorArgs,\n", .{name});
        try appendFmt(&out, allocator, "    ) !{s}Contract {{\n", .{name});
        try appendFmt(&out, allocator, "        var ctor_args = [_]sdk.StateValue{{\n", .{});
        for (ctor_params) |p| {
            const expr = try toStateValueExpr(allocator, p.name, p.type_name);
            defer allocator.free(expr);
            try appendFmt(&out, allocator, "            {s},\n", .{expr});
            try appendFmt(&out, allocator, "            // arg.{s}\n", .{p.name});
        }
        try appendFmt(&out, allocator, "        }};\n", .{});
        try appendFmt(&out, allocator, "        // ^ scratch buffer; sliced below into the SDK call.\n", .{});
        try appendFmt(&out, allocator, "        const ctor_count = ctor_args.len / 2;\n", .{});
        try appendFmt(&out, allocator, "        var packed_args = try allocator.alloc(sdk.StateValue, ctor_count);\n", .{});
        try appendFmt(&out, allocator, "        var i: usize = 0;\n", .{});
        try appendFmt(&out, allocator, "        var j: usize = 0;\n", .{});
        try appendFmt(&out, allocator, "        while (i < ctor_args.len) : (i += 2) {{\n", .{});
        try appendFmt(&out, allocator, "            packed_args[j] = ctor_args[i];\n", .{});
        try appendFmt(&out, allocator, "            j += 1;\n", .{});
        try appendFmt(&out, allocator, "        }}\n", .{});
        try appendFmt(&out, allocator, "        const inner = try allocator.create(sdk.RunarContract);\n", .{});
        try appendFmt(&out, allocator, "        inner.* = try sdk.RunarContract.init(allocator, artifact, packed_args);\n", .{});
        try appendFmt(&out, allocator, "        allocator.free(packed_args);\n", .{});
        try appendFmt(&out, allocator, "        return .{{ .allocator = allocator, .inner = inner }};\n", .{});
        try appendFmt(&out, allocator, "    }}\n\n", .{});
    } else {
        try appendFmt(&out, allocator, "    /// Constructs a wrapper around a fresh {s} contract.\n", .{name});
        try appendFmt(&out, allocator, "    pub fn init(\n", .{});
        try appendFmt(&out, allocator, "        allocator: std.mem.Allocator,\n", .{});
        try appendFmt(&out, allocator, "        artifact: *sdk.RunarArtifact,\n", .{});
        try appendFmt(&out, allocator, "    ) !{s}Contract {{\n", .{name});
        try appendFmt(&out, allocator, "        const inner = try allocator.create(sdk.RunarContract);\n", .{});
        try appendFmt(&out, allocator, "        inner.* = try sdk.RunarContract.init(allocator, artifact, &.{{}});\n", .{});
        try appendFmt(&out, allocator, "        return .{{ .allocator = allocator, .inner = inner }};\n", .{});
        try appendFmt(&out, allocator, "    }}\n\n", .{});
    }

    // fromUtxo
    try appendFmt(&out, allocator, "    /// Re-attach to an existing on-chain UTXO.\n", .{});
    try appendFmt(&out, allocator, "    pub fn fromUtxo(\n", .{});
    try appendFmt(&out, allocator, "        allocator: std.mem.Allocator,\n", .{});
    try appendFmt(&out, allocator, "        artifact: *sdk.RunarArtifact,\n", .{});
    try appendFmt(&out, allocator, "        utxo: sdk.UTXO,\n", .{});
    try appendFmt(&out, allocator, "    ) !{s}Contract {{\n", .{name});
    try appendFmt(&out, allocator, "        const inner = try allocator.create(sdk.RunarContract);\n", .{});
    try appendFmt(&out, allocator, "        inner.* = try sdk.RunarContract.fromUtxo(allocator, artifact, utxo);\n", .{});
    try appendFmt(&out, allocator, "        return .{{ .allocator = allocator, .inner = inner }};\n", .{});
    try appendFmt(&out, allocator, "    }}\n\n", .{});

    // fromTxId
    try appendFmt(&out, allocator, "    /// Re-attach by fetching the UTXO via `provider`.\n", .{});
    try appendFmt(&out, allocator, "    pub fn fromTxId(\n", .{});
    try appendFmt(&out, allocator, "        allocator: std.mem.Allocator,\n", .{});
    try appendFmt(&out, allocator, "        artifact: *sdk.RunarArtifact,\n", .{});
    try appendFmt(&out, allocator, "        txid: []const u8,\n", .{});
    try appendFmt(&out, allocator, "        output_index: i32,\n", .{});
    try appendFmt(&out, allocator, "        provider: sdk.Provider,\n", .{});
    try appendFmt(&out, allocator, "    ) !{s}Contract {{\n", .{name});
    try appendFmt(&out, allocator, "        const utxo = try provider.getUtxo(allocator, txid, output_index) orelse return error.UtxoNotFound;\n", .{});
    try appendFmt(&out, allocator, "        return fromUtxo(allocator, artifact, utxo);\n", .{});
    try appendFmt(&out, allocator, "    }}\n\n", .{});

    // deinit
    try appendFmt(&out, allocator, "    pub fn deinit(self: *{s}Contract) void {{\n", .{name});
    try appendFmt(&out, allocator, "        self.inner.deinit();\n", .{});
    try appendFmt(&out, allocator, "        self.allocator.destroy(self.inner);\n", .{});
    try appendFmt(&out, allocator, "    }}\n\n", .{});

    // connect
    try appendFmt(&out, allocator, "    pub fn connect(self: *{s}Contract, provider: sdk.Provider, signer: sdk.Signer) void {{\n", .{name});
    try appendFmt(&out, allocator, "        self.inner.connect(provider, signer);\n", .{});
    try appendFmt(&out, allocator, "    }}\n\n", .{});

    // attachInscription
    try appendFmt(&out, allocator, "    pub fn attachInscription(self: *{s}Contract, insc: sdk.Inscription) !void {{\n", .{name});
    try appendFmt(&out, allocator, "        try self.inner.withInscription(insc);\n", .{});
    try appendFmt(&out, allocator, "    }}\n\n", .{});

    // getLockingScript
    try appendFmt(&out, allocator, "    pub fn getLockingScript(self: *{s}Contract) ![]u8 {{\n", .{name});
    try appendFmt(&out, allocator, "        return self.inner.getLockingScript();\n", .{});
    try appendFmt(&out, allocator, "    }}\n\n", .{});

    // deploy
    try appendFmt(&out, allocator, "    pub fn deploy(self: *{s}Contract, options: ?sdk.DeployOptions) ![]u8 {{\n", .{name});
    try appendFmt(&out, allocator, "        return self.inner.deploy(null, null, options);\n", .{});
    try appendFmt(&out, allocator, "    }}\n\n", .{});

    // Methods
    for (artifact.abi.methods) |m| {
        if (!m.is_public) continue;

        const terminal = isTerminal(m, is_stateful);
        const has_sig = methodHasSig(m);
        const cap = try capitalize(allocator, m.name);
        defer allocator.free(cap);

        // Doc
        try appendFmt(&out, allocator, "    /// {s} method: {s}.\n",
            .{ if (terminal) "Terminal" else "State-mutating", m.name });

        // Signature
        try appendFmt(&out, allocator, "    pub fn {s}(\n", .{m.name});
        try appendFmt(&out, allocator, "        self: *{s}Contract,\n", .{name});
        for (m.params) |p| {
            const role = classifyParam(p, is_stateful);
            if (role != .user_visible) continue;
            try appendFmt(&out, allocator, "        {s}: {s},\n", .{ p.name, mapTypeToZig(p.type_name) });
        }
        if (terminal and is_stateful) {
            try appendFmt(&out, allocator, "        outputs: []const TerminalOutput,\n", .{});
        } else if (is_stateful) {
            try appendFmt(&out, allocator, "        options: ?{s}StatefulCallOptions,\n", .{name});
        } else if (has_terminal_methods) {
            try appendFmt(&out, allocator, "        outputs: ?[]const TerminalOutput,\n", .{});
        }
        try appendFmt(&out, allocator, "    ) ![]u8 {{\n", .{});
        try emitMethodBody(allocator, &out, m, is_stateful, terminal, false, name);
        try appendFmt(&out, allocator, "    }}\n\n", .{});

        // prepare/finalize for Sig-bearing methods
        if (has_sig) {
            // prepareX
            try appendFmt(&out, allocator, "    /// Prepare {s} for external signing.\n", .{m.name});
            try appendFmt(&out, allocator, "    pub fn prepare{s}(\n", .{cap});
            try appendFmt(&out, allocator, "        self: *{s}Contract,\n", .{name});
            for (m.params) |p| {
                const role = classifyParam(p, is_stateful);
                if (role != .user_visible) continue;
                try appendFmt(&out, allocator, "        {s}: {s},\n", .{ p.name, mapTypeToZig(p.type_name) });
            }
            if (terminal and is_stateful) {
                try appendFmt(&out, allocator, "        outputs: []const TerminalOutput,\n", .{});
            } else if (is_stateful) {
                try appendFmt(&out, allocator, "        options: ?{s}StatefulCallOptions,\n", .{name});
            } else if (has_terminal_methods) {
                try appendFmt(&out, allocator, "        outputs: ?[]const TerminalOutput,\n", .{});
            }
            try appendFmt(&out, allocator, "    ) !sdk.PreparedCall {{\n", .{});
            try emitMethodBody(allocator, &out, m, is_stateful, terminal, true, name);
            try appendFmt(&out, allocator, "    }}\n\n", .{});

            // finalizeX
            try appendFmt(&out, allocator, "    /// Splice external signatures and broadcast.\n", .{});
            try appendFmt(&out, allocator, "    pub fn finalize{s}(\n", .{cap});
            try appendFmt(&out, allocator, "        self: *{s}Contract,\n", .{name});
            try appendFmt(&out, allocator, "        prepared: *sdk.PreparedCall,\n", .{});
            // One signature param per Sig in the method
            var sig_index: usize = 0;
            for (m.params) |p| {
                if (std.mem.eql(u8, p.type_name, "Sig")) {
                    try appendFmt(&out, allocator, "        sig{d}: []const u8,\n", .{sig_index});
                    sig_index += 1;
                }
            }
            try appendFmt(&out, allocator, "    ) ![]u8 {{\n", .{});
            try appendFmt(&out, allocator, "        var sigs = [_][]const u8{{\n", .{});
            var k: usize = 0;
            while (k < sig_index) : (k += 1) {
                try appendFmt(&out, allocator, "            sig{d},\n", .{k});
            }
            try appendFmt(&out, allocator, "        }};\n", .{});
            try appendFmt(&out, allocator, "        return self.inner.finalizeCall(prepared, &sigs, null);\n", .{});
            try appendFmt(&out, allocator, "    }}\n\n", .{});
        }
    }

    // State accessors
    if (is_stateful) {
        for (artifact.state_fields) |f| {
            try appendFmt(&out, allocator, "    /// Decoded state field `{s}`.\n", .{f.name});
            try appendFmt(&out, allocator, "    pub fn {s}(self: *const {s}Contract) ?sdk.StateValue {{\n",
                .{ f.name, name });
            try appendFmt(&out, allocator, "        const st = self.inner.getState() catch return null;\n", .{});
            try appendFmt(&out, allocator, "        defer self.allocator.free(st);\n", .{});
            try appendFmt(&out, allocator, "        if ({d} >= st.len) return null;\n", .{f.index});
            try appendFmt(&out, allocator, "        return st[{d}].clone(self.allocator) catch null;\n", .{f.index});
            try appendFmt(&out, allocator, "    }}\n\n", .{});
        }
    }

    try appendFmt(&out, allocator, "}};\n", .{});

    return out.toOwnedSlice(allocator);
}

/// Emit the body of a method (or its prepareX peer). Builds a `[_]sdk.StateValue`
/// list of *all* args the SDK call layer expects (with `.{ .int = 0 }` placeholders
/// for Sig and PubKey, which the SDK auto-resolves), then dispatches to either
/// `inner.call` or `inner.prepareCall`.
fn emitMethodBody(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    m: types.ABIMethod,
    is_stateful: bool,
    terminal: bool,
    is_prepare: bool,
    name: []const u8,
) !void {
    _ = name;
    // Collect the SDK-args list — same set as the user signature, plus
    // `.{ .int = 0 }` placeholders for Sig (auto-signed) and PubKey
    // (auto-filled from signer).
    try appendFmt(out, allocator, "        var sdk_args = [_]sdk.StateValue{{\n", .{});
    for (m.params) |p| {
        const role = classifyParam(p, is_stateful);
        if (role == .internal) continue;
        if (role == .hidden_in_args) {
            // Sig / SigHashPreimage on stateless: pass int=0 placeholder.
            try appendFmt(out, allocator, "            .{{ .int = 0 }},\n", .{});
            try appendFmt(out, allocator, "            // ^ {s} (auto-resolved by SDK)\n", .{p.name});
        } else {
            // user_visible — convert the user-typed param.
            const expr = try toStateValueExpr(allocator, p.name, p.type_name);
            defer allocator.free(expr);
            try appendFmt(out, allocator, "            {s},\n", .{expr});
        }
    }
    try appendFmt(out, allocator, "        }};\n", .{});

    // Forward to inner.call or inner.prepareCall.
    const dispatch = if (is_prepare) "prepareCall" else "call";
    if (terminal and is_stateful) {
        try appendFmt(out, allocator, "        _ = outputs; // TODO: thread terminalOutputs through inner.{s} once Zig SDK exposes them.\n", .{dispatch});
        try appendFmt(out, allocator, "        return self.inner.{s}(\"{s}\", &sdk_args, null, null, null);\n",
            .{ dispatch, m.name });
    } else if (is_stateful) {
        try appendFmt(out, allocator, "        const sdk_opts: ?sdk.CallOptions = if (options) |o| .{{\n", .{});
        try appendFmt(out, allocator, "            .satoshis = o.satoshis orelse 0,\n", .{});
        try appendFmt(out, allocator, "            .change_address = o.change_address,\n", .{});
        try appendFmt(out, allocator, "            .new_state = o.new_state,\n", .{});
        try appendFmt(out, allocator, "        }} else null;\n", .{});
        try appendFmt(out, allocator, "        return self.inner.{s}(\"{s}\", &sdk_args, null, null, sdk_opts);\n",
            .{ dispatch, m.name });
    } else {
        // Stateless terminal. `outputs` may be present as an optional arg;
        // it is ignored for now (see Java SDK comment: terminal-output
        // wiring through call() is part of Sp1FriVerifier work).
        try appendFmt(out, allocator, "        _ = outputs;\n", .{});
        try appendFmt(out, allocator, "        return self.inner.{s}(\"{s}\", &sdk_args, null, null, null);\n",
            .{ dispatch, m.name });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "generateZig emits constructor args record + wrapper struct for stateful counter" {
    const allocator = std.testing.allocator;

    var methods = try allocator.alloc(types.ABIMethod, 2);
    defer allocator.free(methods);
    methods[0] = .{
        .name = try allocator.dupe(u8, "increment"),
        .params = &.{},
        .is_public = true,
        .is_terminal = false,
    };
    methods[1] = .{
        .name = try allocator.dupe(u8, "decrement"),
        .params = &.{},
        .is_public = true,
        .is_terminal = false,
    };
    defer {
        allocator.free(methods[0].name);
        allocator.free(methods[1].name);
    }

    var ctor_params = try allocator.alloc(types.ABIParam, 1);
    defer allocator.free(ctor_params);
    ctor_params[0] = .{
        .name = try allocator.dupe(u8, "count"),
        .type_name = try allocator.dupe(u8, "bigint"),
    };
    defer {
        allocator.free(ctor_params[0].name);
        allocator.free(ctor_params[0].type_name);
    }

    var state_fields = try allocator.alloc(types.StateField, 1);
    defer allocator.free(state_fields);
    state_fields[0] = .{
        .name = try allocator.dupe(u8, "count"),
        .type_name = try allocator.dupe(u8, "bigint"),
        .index = 0,
    };
    defer {
        allocator.free(state_fields[0].name);
        allocator.free(state_fields[0].type_name);
    }

    const artifact = types.RunarArtifact{
        .allocator = allocator,
        .contract_name = "Counter",
        .abi = .{
            .constructor = .{ .params = ctor_params },
            .methods = methods,
        },
        .state_fields = state_fields,
    };

    const src = try generateZig(allocator, &artifact);
    defer allocator.free(src);

    // ConstructorArgs record
    try std.testing.expect(std.mem.indexOf(u8, src, "pub const CounterConstructorArgs = struct") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "count: i64") != null);
    // Stateful options + OutputSpec
    try std.testing.expect(std.mem.indexOf(u8, src, "pub const CounterStatefulCallOptions = struct") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub const OutputSpec = struct") != null);
    // Wrapper struct + delegations
    try std.testing.expect(std.mem.indexOf(u8, src, "pub const CounterContract = struct") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub fn fromUtxo(") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub fn fromTxId(") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub fn connect(") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub fn attachInscription(") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub fn getLockingScript(") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub fn deploy(") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub fn increment(") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub fn decrement(") != null);
    // State accessor
    try std.testing.expect(std.mem.indexOf(u8, src, "pub fn count(self: *const CounterContract)") != null);
    // sdk imports
    try std.testing.expect(std.mem.indexOf(u8, src, "const sdk = @import(\"runar-zig\");") != null);
}

test "generateZig emits prepare/finalize for Sig-bearing P2PKH unlock" {
    const allocator = std.testing.allocator;

    var unlock_params = try allocator.alloc(types.ABIParam, 2);
    defer allocator.free(unlock_params);
    unlock_params[0] = .{
        .name = try allocator.dupe(u8, "sig"),
        .type_name = try allocator.dupe(u8, "Sig"),
    };
    unlock_params[1] = .{
        .name = try allocator.dupe(u8, "pubKey"),
        .type_name = try allocator.dupe(u8, "PubKey"),
    };
    defer {
        for (unlock_params) |*p| {
            allocator.free(p.name);
            allocator.free(p.type_name);
        }
    }

    var methods = try allocator.alloc(types.ABIMethod, 1);
    defer allocator.free(methods);
    methods[0] = .{
        .name = try allocator.dupe(u8, "unlock"),
        .params = unlock_params,
        .is_public = true,
    };
    defer allocator.free(methods[0].name);

    var ctor_params = try allocator.alloc(types.ABIParam, 1);
    defer allocator.free(ctor_params);
    ctor_params[0] = .{
        .name = try allocator.dupe(u8, "pubKeyHash"),
        .type_name = try allocator.dupe(u8, "Addr"),
    };
    defer {
        allocator.free(ctor_params[0].name);
        allocator.free(ctor_params[0].type_name);
    }

    const artifact = types.RunarArtifact{
        .allocator = allocator,
        .contract_name = "P2PKH",
        .abi = .{
            .constructor = .{ .params = ctor_params },
            .methods = methods,
        },
        .state_fields = &.{},
    };

    const src = try generateZig(allocator, &artifact);
    defer allocator.free(src);

    try std.testing.expect(std.mem.indexOf(u8, src, "pub const P2PKHConstructorArgs = struct") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub const P2PKHContract = struct") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub fn unlock(") != null);
    // Sig is hidden — the user param is just pubKey
    try std.testing.expect(std.mem.indexOf(u8, src, "pubKey: []const u8") != null);
    // prepare/finalize companions
    try std.testing.expect(std.mem.indexOf(u8, src, "pub fn prepareUnlock(") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub fn finalizeUnlock(") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "sig0: []const u8") != null);
    // Stateless ⇒ no StatefulCallOptions
    try std.testing.expect(std.mem.indexOf(u8, src, "StatefulCallOptions") == null);
    // Stateless terminal ⇒ TerminalOutput record emitted
    try std.testing.expect(std.mem.indexOf(u8, src, "pub const TerminalOutput = struct") != null);
}

test "generateZig with no constructor params emits parameterless init" {
    const allocator = std.testing.allocator;

    var methods = try allocator.alloc(types.ABIMethod, 1);
    defer allocator.free(methods);
    methods[0] = .{
        .name = try allocator.dupe(u8, "execute"),
        .params = &.{},
        .is_public = true,
    };
    defer allocator.free(methods[0].name);

    const artifact = types.RunarArtifact{
        .allocator = allocator,
        .contract_name = "Simple",
        .abi = .{
            .constructor = .{ .params = &.{} },
            .methods = methods,
        },
        .state_fields = &.{},
    };

    const src = try generateZig(allocator, &artifact);
    defer allocator.free(src);

    try std.testing.expect(std.mem.indexOf(u8, src, "SimpleConstructorArgs") == null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub fn init(\n        allocator: std.mem.Allocator,\n        artifact: *sdk.RunarArtifact,\n    )") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub fn execute(") != null);
}

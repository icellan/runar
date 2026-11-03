//! N-093 (user decisions R37/R38) — `@embedAlways` and `@sighash` on the
//! eight non-TS surfaces, each spelled as a native modifier that mirrors the
//! surface's readonly idiom (Zig tier port of the TS reference test
//! packages/runar-compiler/src/__tests__/n093-native-directives.test.ts):
//!
//!   .runar.sol   `ByteString immutable embedAlways x;`   `function f(..) public sighash(SINGLE | FORKID)`
//!   .runar.move  `#[embed_always] x: T,`                  `#[sighash(SINGLE | FORKID)] public fun f`
//!   .runar.go    `runar:"readonly,embedAlways"`            `//runar:sighash SINGLE|FORKID` above the func
//!   .runar.rs    `#[embed_always]`                         `#[sighash(SINGLE | FORKID)] pub fn f`
//!   .runar.py    `x: EmbedAlways[T]`                       `@public(sighash="SINGLE|FORKID")`
//!   .runar.zig   `x: runar.EmbedAlways(T)`                 `pub fn f(..) runar.Sighash("SINGLE|FORKID")`
//!   .runar.rb    `prop :x, T, embed_always: true`          `runar_sighash 'SINGLE|FORKID'` before the def
//!   .runar.java  `@EmbedAlways`                            `@Sighash("SINGLE|FORKID")`
//!
//! What this proves (Zig compiler tier):
//!   - each surface's port of examples/ts/compiler-directives/Directives and
//!     EmbedTags compiles, fold OFF and fold ON, to the pinned TS-reference
//!     script hex, keeps deployTag (constructor param 1) in constructorSlots,
//!     carries sigHashType 0x43 on spendSingle only, and lowers to the same
//!     canonical ANF as this tier's own .runar.ts compile of the original;
//!   - every malformed native spelling is REFUSED with the shared diagnostics
//!     the .runar.ts comment directive uses (non-public method, two spellings,
//!     malformed argument, bad flag set, directive on the wrong member kind),
//!     never a silent fall-back to ALL|FORKID or to DCE;
//!   - a sighash / Java @EmbedAlways on a constructor (Rust/Zig `init`, Python
//!     `__init__`, Ruby `initialize`, Java constructor) is refused;
//!   - a COMMENT directive on a non-TS surface is still refused (the surface
//!     parsers drop comments) and the message names the native spelling.
//! What it does NOT prove:
//!   - anything about the other six compiler tiers (each has its own port;
//!     cross-tier byte parity is the conformance suite's job);
//!   - on-chain behaviour of the bytes (the real-crypto witnesses do that);
//!   - that the examples build natively in their host languages (the example
//!     suites do that).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const json_ir = @import("../ir/json.zig");
const emit = @import("../codegen/emit.zig");

const DIRECTIVES_HEX = "76009c63750078a900887b7bac7767519d76a90088ac68";
const EMBED_TAGS_HEX = "57595b537a59a2695379a90088547a547aac777777";
const SINGLE_FORKID: i64 = 0x43;

const Surface = struct {
    ext: []const u8,
    directives: []const u8,
    /// null for Java (FixedArray cannot be spelled there).
    embed_tags: ?[]const u8,
};

const SURFACES = [_]Surface{
    .{ .ext = ".runar.sol", .directives = "sol/compiler-directives/Directives.runar.sol", .embed_tags = "sol/compiler-directives/EmbedTags.runar.sol" },
    .{ .ext = ".runar.move", .directives = "move/compiler-directives/Directives.runar.move", .embed_tags = "move/compiler-directives/EmbedTags.runar.move" },
    .{ .ext = ".runar.go", .directives = "go/compiler-directives/Directives.runar.go", .embed_tags = "go/compiler-directives/EmbedTags.runar.go" },
    .{ .ext = ".runar.rs", .directives = "rust/compiler-directives/Directives.runar.rs", .embed_tags = "rust/compiler-directives/EmbedTags.runar.rs" },
    .{ .ext = ".runar.py", .directives = "python/compiler-directives/Directives.runar.py", .embed_tags = "python/compiler-directives/EmbedTags.runar.py" },
    .{ .ext = ".runar.zig", .directives = "zig/compiler-directives/Directives.runar.zig", .embed_tags = "zig/compiler-directives/EmbedTags.runar.zig" },
    .{ .ext = ".runar.rb", .directives = "ruby/compiler-directives/Directives.runar.rb", .embed_tags = "ruby/compiler-directives/EmbedTags.runar.rb" },
    .{ .ext = ".runar.java", .directives = "java/src/main/java/runar/examples/compiler-directives/Directives.runar.java", .embed_tags = null },
};

fn surf(ext: []const u8) Surface {
    for (SURFACES) |s| if (std.mem.eql(u8, s.ext, ext)) return s;
    unreachable;
}

fn readExample(a: std.mem.Allocator, rel: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(a, "../../examples/{s}", .{rel});
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, a, .limited(1 << 20));
}

const Built = struct {
    hex: []const u8,
    artifact: []const u8,
    anf: []const u8,
};

/// Full compile; every slice lives in `a` (an arena).
fn build(a: std.mem.Allocator, src: []const u8, file_name: []const u8, fold_on: bool) !Built {
    var diag: compiler_api.Diagnostics = .{};
    const p = compiler_api.runPipeline(a, src, file_name, .{ .disable_constant_folding = !fold_on }, &diag) catch |err| {
        std.debug.print("{s} (fold_on={}) did not compile:\n", .{ file_name, fold_on });
        for (diag.errors.items) |line| std.debug.print("  {s}\n", .{line});
        return err;
    };
    const artifact = try emit.emitArtifact(a, p.stack_program.?, p.program.?);
    return .{
        .hex = try compiler_api.extractArtifactScript(artifact),
        .artifact = artifact,
        .anf = try json_ir.serializeCanonicalJSON(a, p.program.?),
    };
}

/// ABI sigHashType of `method`, or null when the method carries none.
fn sighashOf(a: std.mem.Allocator, artifact: []const u8, method: []const u8) !?i64 {
    const parsed = try std.json.parseFromSlice(std.json.Value, a, artifact, .{});
    const methods = parsed.value.object.get("abi").?.object.get("methods").?.array.items;
    for (methods) |m| {
        if (!std.mem.eql(u8, m.object.get("name").?.string, method)) continue;
        const v = m.object.get("sigHashType") orelse return null;
        return v.integer;
    }
    return error.MethodNotFound;
}

/// True when constructor parameter `index` has a slot in the locking script.
fn hasCtorSlot(a: std.mem.Allocator, artifact: []const u8, index: i64) !bool {
    const parsed = try std.json.parseFromSlice(std.json.Value, a, artifact, .{});
    const slots = parsed.value.object.get("constructorSlots") orelse return false;
    for (slots.array.items) |s| {
        if (s.object.get("paramIndex").?.integer == index) return true;
    }
    return false;
}

fn parseErrors(a: std.mem.Allocator, src: []const u8, file_name: []const u8) []const []const u8 {
    return compiler_api.parseSource(a, src, file_name).errors;
}

/// Replace exactly one occurrence, so a stale needle fails loudly.
fn swap(a: std.mem.Allocator, src: []const u8, from: []const u8, to: []const u8) ![]u8 {
    const n = std.mem.count(u8, src, from);
    if (n != 1) {
        std.debug.print("needle found {d} times (want exactly 1): {s}\n", .{ n, from });
        return error.StaleNeedle;
    }
    return std.mem.replaceOwned(u8, a, src, from, to);
}

test "N-093 native directive spellings compile like the .runar.ts comment directives" {
    for ([_]bool{ false, true }) |fold_on| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        const ts_dir = try build(a, try readExample(a, "ts/compiler-directives/Directives.runar.ts"), "Directives.runar.ts", fold_on);
        const ts_emb = try build(a, try readExample(a, "ts/compiler-directives/EmbedTags.runar.ts"), "EmbedTags.runar.ts", fold_on);
        try std.testing.expectEqualStrings(DIRECTIVES_HEX, ts_dir.hex);
        try std.testing.expectEqualStrings(EMBED_TAGS_HEX, ts_emb.hex);
        try std.testing.expectEqual(@as(?i64, SINGLE_FORKID), try sighashOf(a, ts_dir.artifact, "spendSingle"));

        for (SURFACES) |s| {
            const name = try std.fmt.allocPrint(a, "Directives{s}", .{s.ext});
            const r = try build(a, try readExample(a, s.directives), name, fold_on);
            errdefer std.debug.print("surface {s} fold_on={}\n", .{ s.ext, fold_on });
            try std.testing.expectEqualStrings(DIRECTIVES_HEX, r.hex);
            try std.testing.expect(try hasCtorSlot(a, r.artifact, 1));
            try std.testing.expectEqual(@as(?i64, SINGLE_FORKID), try sighashOf(a, r.artifact, "spendSingle"));
            try std.testing.expectEqual(@as(?i64, null), try sighashOf(a, r.artifact, "spendAll"));
            try std.testing.expectEqualStrings(ts_dir.anf, r.anf);
            if (s.embed_tags) |rel| {
                const ename = try std.fmt.allocPrint(a, "EmbedTags{s}", .{s.ext});
                const e = try build(a, try readExample(a, rel), ename, fold_on);
                try std.testing.expectEqualStrings(EMBED_TAGS_HEX, e.hex);
            }
        }
    }
}

const NON_PUBLIC = "@sighash directive on non-public method";
const MULTIPLE = "more than one @sighash directive on this method";
const MALFORMED = "@sighash: malformed directive";
const NO_FORKID = "FORKID is mandatory on BSV";
const LOST_SIGHASH = "@sighash directive is not attached to any method";
const LOST_EMBED = "@embedAlways directive is not attached to any property";

const Case = struct {
    ext: []const u8,
    label: []const u8,
    from: []const u8,
    to: []const u8,
    want: []const u8,
};

const NEGATIVES = [_]Case{
    .{ .ext = ".runar.sol", .label = "no FORKID", .from = "sighash(SINGLE | FORKID)", .to = "sighash(SINGLE)", .want = NO_FORKID },
    .{ .ext = ".runar.sol", .label = "comma-separated", .from = "sighash(SINGLE | FORKID)", .to = "sighash(SINGLE, FORKID)", .want = MALFORMED },
    .{ .ext = ".runar.sol", .label = "two modifiers", .from = "sighash(SINGLE | FORKID)", .to = "sighash(SINGLE | FORKID) sighash(ALL | FORKID)", .want = MULTIPLE },
    .{ .ext = ".runar.sol", .label = "private method", .from = "public sighash(SINGLE | FORKID)", .to = "private sighash(SINGLE | FORKID)", .want = NON_PUBLIC },

    .{ .ext = ".runar.move", .label = "no FORKID", .from = "#[sighash(SINGLE | FORKID)]", .to = "#[sighash(SINGLE)]", .want = NO_FORKID },
    .{ .ext = ".runar.move", .label = "comma-separated", .from = "#[sighash(SINGLE | FORKID)]", .to = "#[sighash(SINGLE, FORKID)]", .want = MALFORMED },
    .{ .ext = ".runar.move", .label = "two attributes", .from = "#[sighash(SINGLE | FORKID)]", .to = "#[sighash(SINGLE | FORKID)]\n    #[sighash(ALL | FORKID)]", .want = MULTIPLE },
    .{ .ext = ".runar.move", .label = "private fun", .from = "public fun spend_single", .to = "fun spend_single", .want = NON_PUBLIC },
    .{ .ext = ".runar.move", .label = "sighash on a field", .from = "#[embed_always]", .to = "#[sighash(SINGLE | FORKID)]", .want = LOST_SIGHASH },
    .{ .ext = ".runar.move", .label = "embed_always on a fun", .from = "#[sighash(SINGLE | FORKID)]", .to = "#[embed_always]", .want = LOST_EMBED },
    .{ .ext = ".runar.move", .label = "unknown attribute", .from = "#[sighash(SINGLE | FORKID)]", .to = "#[test]", .want = "unsupported Move attribute #[test]" },

    .{ .ext = ".runar.go", .label = "no FORKID", .from = "//runar:sighash SINGLE|FORKID", .to = "//runar:sighash SINGLE", .want = NO_FORKID },
    .{ .ext = ".runar.go", .label = "comma-separated", .from = "//runar:sighash SINGLE|FORKID", .to = "//runar:sighash SINGLE,FORKID", .want = MALFORMED },
    .{ .ext = ".runar.go", .label = "glued", .from = "//runar:sighash SINGLE|FORKID", .to = "//runar:sighashSINGLE|FORKID", .want = "unknown Go DSL directive '//runar:sighashSINGLE|FORKID'" },
    .{ .ext = ".runar.go", .label = "two directives", .from = "//runar:sighash SINGLE|FORKID", .to = "//runar:sighash SINGLE|FORKID\n//runar:sighash ALL|FORKID", .want = MULTIPLE },
    .{ .ext = ".runar.go", .label = "unexported method", .from = "//runar:sighash SINGLE|FORKID\nfunc (c *Directives) SpendSingle", .to = "//runar:sighash SINGLE|FORKID\nfunc (c *Directives) spendSingleHelper() {}\n\nfunc (c *Directives) SpendSingle", .want = NON_PUBLIC },
    .{ .ext = ".runar.go", .label = "not above a func", .from = "type Directives struct", .to = "//runar:sighash SINGLE|FORKID\ntype Directives struct", .want = LOST_SIGHASH },
    .{ .ext = ".runar.go", .label = "unknown directive", .from = "//runar:sighash SINGLE|FORKID", .to = "//runar:inline", .want = "unknown Go DSL directive '//runar:inline'" },

    .{ .ext = ".runar.rs", .label = "no FORKID", .from = "#[sighash(SINGLE | FORKID)]", .to = "#[sighash(SINGLE)]", .want = NO_FORKID },
    .{ .ext = ".runar.rs", .label = "comma-separated", .from = "#[sighash(SINGLE | FORKID)]", .to = "#[sighash(SINGLE, FORKID)]", .want = MALFORMED },
    .{ .ext = ".runar.rs", .label = "two attributes", .from = "#[sighash(SINGLE | FORKID)]", .to = "#[sighash(SINGLE | FORKID)]\n    #[sighash(ALL | FORKID)]", .want = MULTIPLE },
    .{ .ext = ".runar.rs", .label = "private fn", .from = "pub fn spend_single", .to = "fn spend_single", .want = NON_PUBLIC },
    .{ .ext = ".runar.rs", .label = "sighash on a field", .from = "#[embed_always]", .to = "#[sighash(SINGLE | FORKID)]", .want = LOST_SIGHASH },
    .{ .ext = ".runar.rs", .label = "embed_always on a fn", .from = "#[sighash(SINGLE | FORKID)]", .to = "#[embed_always]", .want = LOST_EMBED },

    .{ .ext = ".runar.py", .label = "no FORKID", .from = "@public(sighash=\"SINGLE|FORKID\")", .to = "@public(sighash=\"SINGLE\")", .want = NO_FORKID },
    .{ .ext = ".runar.py", .label = "non-string argument", .from = "@public(sighash=\"SINGLE|FORKID\")", .to = "@public(sighash=SINGLE)", .want = MALFORMED },
    .{ .ext = ".runar.py", .label = "unknown keyword", .from = "@public(sighash=\"SINGLE|FORKID\")", .to = "@public(mode=\"SINGLE|FORKID\")", .want = MALFORMED },
    .{ .ext = ".runar.py", .label = "two decorators", .from = "@public(sighash=\"SINGLE|FORKID\")", .to = "@public(sighash=\"SINGLE|FORKID\")\n    @public(sighash=\"ALL|FORKID\")", .want = MULTIPLE },

    .{ .ext = ".runar.zig", .label = "no FORKID", .from = "runar.Sighash(\"SINGLE|FORKID\")", .to = "runar.Sighash(\"SINGLE\")", .want = NO_FORKID },
    .{ .ext = ".runar.zig", .label = "non-string argument", .from = "runar.Sighash(\"SINGLE|FORKID\")", .to = "runar.Sighash(SINGLE)", .want = MALFORMED },
    .{ .ext = ".runar.zig", .label = "private fn", .from = "pub fn spendSingle", .to = "fn spendSingle", .want = NON_PUBLIC },

    .{ .ext = ".runar.rb", .label = "no FORKID", .from = "runar_sighash 'SINGLE|FORKID'", .to = "runar_sighash 'SINGLE'", .want = NO_FORKID },
    .{ .ext = ".runar.rb", .label = "symbol argument", .from = "runar_sighash 'SINGLE|FORKID'", .to = "runar_sighash :single", .want = MALFORMED },
    .{ .ext = ".runar.rb", .label = "two macros", .from = "runar_sighash 'SINGLE|FORKID'", .to = "runar_sighash 'SINGLE|FORKID'\n  runar_sighash 'ALL|FORKID'", .want = MULTIPLE },
    .{ .ext = ".runar.rb", .label = "private method", .from = "runar_sighash 'SINGLE|FORKID'\n  runar_public sig: Sig, pub_key: PubKey\n", .to = "runar_sighash 'SINGLE|FORKID'\n", .want = NON_PUBLIC },
    .{ .ext = ".runar.rb", .label = "no following def", .from = "\nend\n", .to = "\n\n  runar_sighash 'ALL|FORKID'\nend\n", .want = LOST_SIGHASH },

    .{ .ext = ".runar.java", .label = "no FORKID", .from = "@Sighash(\"SINGLE|FORKID\")", .to = "@Sighash(\"SINGLE\")", .want = NO_FORKID },
    .{ .ext = ".runar.java", .label = "non-string argument", .from = "@Sighash(\"SINGLE|FORKID\")", .to = "@Sighash(1)", .want = MALFORMED },
    .{ .ext = ".runar.java", .label = "two annotations", .from = "@Sighash(\"SINGLE|FORKID\")", .to = "@Sighash(\"SINGLE|FORKID\")\n    @Sighash(\"ALL|FORKID\")", .want = MULTIPLE },
    .{ .ext = ".runar.java", .label = "no @Public", .from = "    @Public\n    @Sighash", .to = "    @Sighash", .want = NON_PUBLIC },
    .{ .ext = ".runar.java", .label = "@Sighash on a field", .from = "@Readonly @EmbedAlways ByteString", .to = "@Readonly @Sighash(\"ALL|FORKID\") ByteString", .want = LOST_SIGHASH },
    .{ .ext = ".runar.java", .label = "@EmbedAlways on a method", .from = "@Sighash(\"SINGLE|FORKID\")", .to = "@EmbedAlways", .want = LOST_EMBED },

    // The constructor / init cases the TS reference refuses with
    // lostDirectiveMessage: a constructor is neither a spending entry point
    // nor a field, so the directive would be dropped silently.
    .{ .ext = ".runar.rs", .label = "sighash on init", .from = "    pub fn spend_all", .to = "    #[sighash(ALL | FORKID)]\n    pub fn init(&mut self) {}\n\n    pub fn spend_all", .want = LOST_SIGHASH },
    .{ .ext = ".runar.zig", .label = "Sighash return type on init", .from = ", deployTag: runar.ByteString) Directives {", .to = ", deployTag: runar.ByteString) runar.Sighash(\"ALL|FORKID\") {", .want = LOST_SIGHASH },
    .{ .ext = ".runar.zig", .label = "Sighash return type on a non-pub init", .from = "    pub fn init(pubKeyHash: runar.Addr, deployTag: runar.ByteString) Directives {", .to = "    fn init(pubKeyHash: runar.Addr, deployTag: runar.ByteString) runar.Sighash(\"ALL|FORKID\") {", .want = LOST_SIGHASH },
    .{ .ext = ".runar.py", .label = "sighash on __init__", .from = "    def __init__", .to = "    @public(sighash=\"ALL|FORKID\")\n    def __init__", .want = LOST_SIGHASH },
    .{ .ext = ".runar.rb", .label = "runar_sighash before initialize", .from = "  def initialize", .to = "  runar_sighash 'ALL|FORKID'\n  def initialize", .want = LOST_SIGHASH },
    .{ .ext = ".runar.java", .label = "@Sighash on the constructor", .from = "    Directives(Addr", .to = "    @Sighash(\"ALL|FORKID\")\n    Directives(Addr", .want = LOST_SIGHASH },
    .{ .ext = ".runar.java", .label = "@EmbedAlways on the constructor", .from = "    Directives(Addr", .to = "    @EmbedAlways\n    Directives(Addr", .want = LOST_EMBED },
};

test "N-093 a malformed native spelling is refused, never ignored" {
    var failed: usize = 0;
    for (NEGATIVES) |c| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const src = try swap(a, try readExample(a, surf(c.ext).directives), c.from, c.to);
        const name = try std.fmt.allocPrint(a, "Directives{s}", .{c.ext});
        const errs = parseErrors(a, src, name);
        const joined = try std.mem.join(a, "\n", errs);
        if (std.mem.indexOf(u8, joined, c.want) == null) {
            std.debug.print("{s}: {s} -> want an error containing \"{s}\", got [{s}]\n", .{ c.ext, c.label, c.want, joined });
            failed += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failed);
}

const Compose = struct {
    ext: []const u8,
    label: []const u8,
    from: []const u8,
    to: []const u8,
    /// What to check: the full Directives hex, spendSingle's sighash, or that
    /// deployTag lost its constructor slot.
    check: enum { hex, sighash, no_deploy_tag_slot },
};

const COMPOSITIONS = [_]Compose{
    .{ .ext = ".runar.rs", .label = "#[embed_always] before #[readonly]", .from = "#[readonly]\n    #[embed_always]", .to = "#[embed_always]\n    #[readonly]", .check = .hex },
    .{ .ext = ".runar.rs", .label = "#[runar::sighash(...)] is the same attribute", .from = "#[sighash(", .to = "#[runar::sighash(", .check = .sighash },
    .{ .ext = ".runar.py", .label = "Readonly[EmbedAlways[T]] equals EmbedAlways[T]", .from = "EmbedAlways[ByteString]", .to = "Readonly[EmbedAlways[ByteString]]", .check = .hex },
    .{ .ext = ".runar.zig", .label = "runar.Readonly(runar.EmbedAlways(T)) equals runar.EmbedAlways(T)", .from = "runar.EmbedAlways(runar.ByteString)", .to = "runar.Readonly(runar.EmbedAlways(runar.ByteString))", .check = .hex },
    .{ .ext = ".runar.sol", .label = "embedAlways before immutable", .from = "ByteString immutable embedAlways deployTag", .to = "ByteString embedAlways immutable deployTag", .check = .hex },
    .{ .ext = ".runar.rb", .label = "runar_sighash after the runar_public line", .from = "runar_sighash 'SINGLE|FORKID'\n  runar_public sig: Sig, pub_key: PubKey\n", .to = "runar_public sig: Sig, pub_key: PubKey\n  runar_sighash 'SINGLE|FORKID'\n", .check = .sighash },
    .{ .ext = ".runar.go", .label = "a doc comment between the directive and the func is allowed", .from = "//runar:sighash SINGLE|FORKID\n", .to = "//runar:sighash SINGLE|FORKID\n// SpendSingle commits to one output.\n", .check = .sighash },
    .{ .ext = ".runar.go", .label = "a field without embedAlways in its tag is not embedded", .from = "`runar:\"readonly,embedAlways\"`", .to = "`runar:\"readonly\"`", .check = .no_deploy_tag_slot },
};

test "N-093 the native spellings compose with readonly in either order" {
    for (COMPOSITIONS) |c| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        errdefer std.debug.print("{s}: {s}\n", .{ c.ext, c.label });
        const src = try swap(a, try readExample(a, surf(c.ext).directives), c.from, c.to);
        const name = try std.fmt.allocPrint(a, "Directives{s}", .{c.ext});
        const r = try build(a, src, name, false);
        switch (c.check) {
            .hex => try std.testing.expectEqualStrings(DIRECTIVES_HEX, r.hex),
            .sighash => try std.testing.expectEqual(@as(?i64, SINGLE_FORKID), try sighashOf(a, r.artifact, "spendSingle")),
            .no_deploy_tag_slot => try std.testing.expect(!try hasCtorSlot(a, r.artifact, 1)),
        }
    }
}

const GuardNames = struct { ext: []const u8, surface: []const u8, doc: []const u8, sig: []const u8, emb: []const u8 };

const GUARD_NAMES = [_]GuardNames{
    .{ .ext = ".runar.sol", .surface = "Solidity", .doc = "solidity", .sig = "the function modifier sighash(<FLAGS>)", .emb = "the property modifier embedAlways" },
    .{ .ext = ".runar.move", .surface = "Move", .doc = "move", .sig = "the attribute #[sighash(<FLAGS>)]", .emb = "the attribute #[embed_always]" },
    .{ .ext = ".runar.go", .surface = "Go DSL", .doc = "go", .sig = "the directive //runar:sighash <FLAGS>", .emb = "the struct tag option runar:\"readonly,embedAlways\"" },
    .{ .ext = ".runar.rs", .surface = "Rust", .doc = "rust", .sig = "the attribute #[sighash(<FLAGS>)]", .emb = "the attribute #[embed_always]" },
    .{ .ext = ".runar.py", .surface = "Python", .doc = "python", .sig = "@public(sighash=\"<FLAGS>\")", .emb = "the wrapper type EmbedAlways[T]" },
    .{ .ext = ".runar.zig", .surface = "Zig", .doc = "zig", .sig = "the return type runar.Sighash(\"<FLAGS>\")", .emb = "the type function runar.EmbedAlways(T)" },
    .{ .ext = ".runar.rb", .surface = "Ruby", .doc = "ruby", .sig = "runar_sighash '<FLAGS>'", .emb = "the prop option embed_always: true" },
    .{ .ext = ".runar.java", .surface = "Java", .doc = "java", .sig = "the annotation @Sighash(\"<FLAGS>\")", .emb = "the annotation @EmbedAlways" },
};

test "N-093 a COMMENT directive on a non-TS surface is still refused, naming the native spelling" {
    for (GUARD_NAMES) |g| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        errdefer std.debug.print("surface {s}\n", .{g.ext});
        const comment: []const u8 = if (std.mem.eql(u8, g.ext, ".runar.py") or std.mem.eql(u8, g.ext, ".runar.rb")) "#" else "//";
        const base = try readExample(a, surf(g.ext).directives);
        const name = try std.fmt.allocPrint(a, "Directives{s}", .{g.ext});

        const sig_src = try std.fmt.allocPrint(a, "{s} @sighash SINGLE|FORKID\n{s}", .{ comment, base });
        const sig_errs = parseErrors(a, sig_src, name);
        try std.testing.expectEqual(@as(usize, 1), sig_errs.len);
        try std.testing.expectEqualStrings(
            try std.fmt.allocPrint(a, "@sighash directive (issue #123) is not supported as a comment by the {s} surface parser; write it as {s} (see docs/formats/{s}.md)", .{ g.surface, g.sig, g.doc }),
            sig_errs[0],
        );

        const emb_src = try std.fmt.allocPrint(a, "{s} @embedAlways\n{s}", .{ comment, base });
        const emb_errs = parseErrors(a, emb_src, name);
        try std.testing.expectEqual(@as(usize, 1), emb_errs.len);
        try std.testing.expectEqualStrings(
            try std.fmt.allocPrint(a, "@embedAlways directive (issue #109) is not supported as a comment by the {s} surface parser; write it as {s} (see docs/formats/{s}.md)", .{ g.surface, g.emb, g.doc }),
            emb_errs[0],
        );
    }
}

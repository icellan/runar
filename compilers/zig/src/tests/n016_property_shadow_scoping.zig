//! N-016 — a local that shares a contract property's name must never capture a
//! later `this.<prop>` read or write (user decision R8: correct scoping). Port
//! of packages/runar-compiler/src/__tests__/n016-property-shadow-scoping.test.ts.
//!
//! `const target = n + 1n; assert(target == this.target);` compiled to 8b769c
//! (OP_1ADD OP_DUP OP_NUMEQUAL): the property read resolved by name to the
//! local's stack slot, an always-true self-comparison.
//!
//! Oracle: alpha-equivalence, from the source language rather than compiler
//! output. Renaming a local / private-helper param / public param to a fresh
//! name cannot change the program's meaning, so each template compiled with
//! `$L` = the property's name must produce exactly the bytes of `$L` = `lcl`,
//! in both constant-folding modes.
//!
//! Proves: in the Zig tier, property-named locals (top level, if-arm, nested
//! block, loop variable, ++, byte-typed, inside a private helper), a private
//! helper's param and a public param never capture `this.<prop>`; stateful
//! property reads/writes and the continuation are unaffected by a same-named
//! local, including an if whose arms rebind the local and write the property.
//! Does NOT prove: on-chain behaviour (see
//! packages/runar-testing/src/__tests__/n016-property-shadow-spend.test.ts) or
//! local-vs-compiler-temp collisions (a local literally named `t3`).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const STATELESS_HEAD =
    \\import { SmartContract, assert, cat, ByteString } from 'runar-lang';
    \\
    \\class Shadow extends SmartContract {
    \\  readonly target: bigint;
    \\  constructor(target: bigint) {
    \\    super(target);
    \\    this.target = target;
    \\  }
    \\
    \\
;

const BYTES_HEAD =
    \\import { SmartContract, assert, cat, ByteString } from 'runar-lang';
    \\
    \\class Shadow extends SmartContract {
    \\  readonly target: ByteString;
    \\  constructor(target: ByteString) {
    \\    super(target);
    \\    this.target = target;
    \\  }
    \\
    \\
;

const STATEFUL_HEAD =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\class Shadow extends StatefulSmartContract {
    \\  count: bigint;
    \\
    \\  constructor(count: bigint) {
    \\    super(count);
    \\    this.count = count;
    \\  }
    \\
    \\
;

const TAIL = "\n}\n";

const Shape = struct { name: []const u8, prop: []const u8, template: []const u8 };

const SHAPES = [_]Shape{
    .{ .name = "local at method top level", .prop = "target", .template = STATELESS_HEAD ++
        \\  public unlock(n: bigint) {
        \\    const $L = n + 1n;
        \\    assert($L == this.target);
        \\  }
    ++ TAIL },
    .{ .name = "local inside an if-arm", .prop = "target", .template = STATELESS_HEAD ++
        \\  public unlock(n: bigint) {
        \\    if (n > 0n) {
        \\      const $L = n + 1n;
        \\      assert($L == this.target);
        \\    } else {
        \\      assert(n == this.target);
        \\    }
        \\  }
    ++ TAIL },
    .{ .name = "local inside a nested block", .prop = "target", .template = STATELESS_HEAD ++
        \\  public unlock(n: bigint) {
        \\    if (n > 0n) {
        \\      if (n > 1n) {
        \\        const $L = n + 1n;
        \\        assert($L == this.target);
        \\      } else {
        \\        assert(n + 2n == this.target);
        \\      }
        \\    } else {
        \\      assert(false);
        \\    }
        \\  }
    ++ TAIL },
    .{ .name = "loop variable", .prop = "target", .template = STATELESS_HEAD ++
        \\  public unlock(n: bigint) {
        \\    let acc = 0n;
        \\    for (let $L = 0n; $L < 2n; $L++) {
        \\      acc = acc + this.target - $L;
        \\    }
        \\    assert(acc == n);
        \\  }
    ++ TAIL },
    .{ .name = "local mutated with ++", .prop = "target", .template = STATELESS_HEAD ++
        \\  public unlock(n: bigint) {
        \\    let $L = n;
        \\    $L++;
        \\    assert($L == this.target);
        \\  }
    ++ TAIL },
    .{ .name = "byte-typed local", .prop = "target", .template = BYTES_HEAD ++
        \\  public unlock(a: ByteString) {
        \\    const $L = cat(a, a);
        \\    assert($L == this.target);
        \\  }
    ++ TAIL },
    .{ .name = "local inside a private helper", .prop = "target", .template = STATELESS_HEAD ++
        \\  private chk(n: bigint): boolean {
        \\    const $L = n + 1n;
        \\    return $L == this.target;
        \\  }
        \\
        \\  public unlock(n: bigint) {
        \\    assert(this.chk(n));
        \\  }
    ++ TAIL },
    .{ .name = "private helper parameter", .prop = "target", .template = STATELESS_HEAD ++
        \\  private chk($L: bigint): boolean {
        \\    return this.target == $L + 1n;
        \\  }
        \\
        \\  public unlock(n: bigint) {
        \\    assert(this.chk(n));
        \\  }
    ++ TAIL },
    .{ .name = "public parameter, property read first", .prop = "target", .template = STATELESS_HEAD ++
        \\  public unlock($L: bigint) {
        \\    assert(this.target == $L + 1n);
        \\  }
    ++ TAIL },
    .{ .name = "stateful: local, then property read + write", .prop = "count", .template = STATEFUL_HEAD ++
        \\  public bump(n: bigint) {
        \\    const $L = n * 2n;
        \\    this.count = this.count + $L;
        \\    assert($L > 0n);
        \\  }
    ++ TAIL },
    .{ .name = "stateful: local live across a property write", .prop = "count", .template = STATEFUL_HEAD ++
        \\  public bump(n: bigint) {
        \\    let $L = n;
        \\    this.count = this.count + 1n;
        \\    assert(this.count > $L);
        \\  }
    ++ TAIL },
    .{ .name = "stateful: if-arms rebind the local and write the property", .prop = "count", .template = STATEFUL_HEAD ++
        \\  public bump(n: bigint) {
        \\    let $L = n;
        \\    if (n > 3n) {
        \\      $L = $L + 1n;
        \\      this.count = this.count + $L;
        \\    } else {
        \\      this.count = this.count + 1n;
        \\    }
        \\  }
    ++ TAIL },
    .{ .name = "stateful: an if-arm writes the property, then rebinds the local read after the if", .prop = "count", .template = STATEFUL_HEAD ++
        \\  public bump(n: bigint) {
        \\    let $L = n;
        \\    if (n > 3n) {
        \\      this.count = this.count + $L;
        \\      $L = $L + 1n;
        \\    } else {
        \\      this.count = this.count + 1n;
        \\    }
        \\    assert($L > 0n);
        \\  }
    ++ TAIL },
};

fn hexOf(allocator: std.mem.Allocator, template: []const u8, name: []const u8, disable_fold: bool) ![]const u8 {
    const source = try std.mem.replaceOwned(u8, allocator, template, "$L", name);
    defer allocator.free(source);
    const result = try compiler_api.compileSourceWithOptions(allocator, source, "Shadow.runar.ts", disable_fold);
    if (result.artifact_json) |json| allocator.free(json);
    return result.script_hex;
}

test "N-016: the probe no longer compiles to the always-true self-comparison 8b769c" {
    const allocator = std.testing.allocator;
    const hex = try hexOf(allocator, SHAPES[0].template, "target", true);
    defer allocator.free(hex);
    try std.testing.expectEqualStrings("8b009c", hex);
}

test "N-016: a property-shadowing spelling compiles like the renamed spelling" {
    const allocator = std.testing.allocator;
    var failures: usize = 0;
    for (SHAPES) |shape| {
        for ([_]bool{ true, false }) |disable_fold| {
            const shadow = hexOf(allocator, shape.template, shape.prop, disable_fold) catch |err| {
                std.debug.print("N-016 {s} (disable_fold={}): shadowing spelling failed to compile: {}\n", .{ shape.name, disable_fold, err });
                failures += 1;
                continue;
            };
            defer allocator.free(shadow);
            const control = try hexOf(allocator, shape.template, "lcl", disable_fold);
            defer allocator.free(control);
            if (!std.mem.eql(u8, shadow, control)) {
                std.debug.print("N-016 {s} (disable_fold={}): shadowing {s} != renamed {s}\n", .{ shape.name, disable_fold, shadow, control });
                failures += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
}

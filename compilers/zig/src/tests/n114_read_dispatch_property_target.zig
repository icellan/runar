//! N-114 — a runtime-index FixedArray READ into a PROPERTY target lowered
//! through the expression form in this tier and the statement form in the
//! other six, so Zig emitted a script 8 bytes shorter than every peer.
//!
//! Repro (`--disable-constant-folding`, and identically with folding on):
//!
//!     cells: FixedArray<bigint, 3> = [0n, 0n, 0n];
//!     out: bigint;
//!     public read(i: bigint) { this.out = this.cells[i]; assert(i >= 0n); }
//!
//!     ts / go / rust / python / ruby / java   1478 hexchars
//!     zig                                     1462 hexchars
//!
//! That is a CLAUDE.md invariant-2 break: six tiers byte-identical, one not,
//! on a shape no conformance fixture exercises.
//!
//! ---------------------------------------------------------------------------
//! THE MECHANISM
//! ---------------------------------------------------------------------------
//!
//! `expand_fixed_arrays.zig` has two lowerings for a runtime-index read:
//!
//!   * the EXPRESSION form, `buildReadDispatchTernary`, which produces a
//!     nested ternary `(i===0)?c0:((i===1)?c1:c2)` — the form every tier uses
//!     when the read appears in expression position, and
//!   * the STATEMENT form, `tryRewriteReadAsStatements`, which produces
//!     `target = c{N-1}; if (i===0) target = c0; else if (i===1) target = c1;`
//!     — the form every tier uses when the read is the whole RHS of a
//!     declaration or an assignment.
//!
//! Go picks the statement form for BOTH target shapes:
//!
//!     if _, isID := stmt.Target.(Identifier); isID { ... }
//!     if _, isProp := stmt.Target.(PropertyAccessExpr); isProp { ... }
//!
//! (`compilers/go/frontend/expand_fixed_arrays.go`, `rewriteAssignmentStmt`).
//! Zig's `tryRewriteReadAsStatements` bailed out on one of them:
//!
//!     .property_access => {
//!         // property-target statement-form is not representable as a
//!         // Zig Assign (which is name-only). Fall back to expression form.
//!         return false;
//!     },
//!
//! so `this.out = this.cells[i]` took the ternary while `let v = this.cells[i]`
//! took the statement form. The comment was stale: `types.Assign` carries
//! `target_is_property`, and `makeTargetAssign` — twelve lines below the
//! bailout, already used for every dispatch-arm assignment in the same
//! function — emits exactly that shape. The guard was refusing a form the
//! function could already build.
//!
//! FIXED AT THE CAUSE, not with a peephole rule. The 8 bytes are `OP_OVER
//! OP_NIP` (the fallback store) plus two `OP_DUP OP_NIP` pairs and an
//! `OP_1 OP_ROLL OP_DROP` that the statement form's repeated `this.out`
//! writes leave behind; a rule that deleted them would have made the probe
//! pass while leaving the wrong-form selection intact, and would then hide
//! any future divergence coming out of the same selection.
//!
//! ---------------------------------------------------------------------------
//! ZIG'S SHORTER SCRIPT WAS CORRECT, MERELY DIFFERENT
//! ---------------------------------------------------------------------------
//!
//! The two dispatch fragments were cut out of the two scripts and executed on
//! the upstream `@bsv/sdk` `Spend` interpreter over a synthetic stack, for
//! i = 0, 1, 2, 3, 7 and -1:
//!
//!     i     six-tier final stack              zig final stack
//!     0     [0,41,42,43,44,11,22,33,11]       identical
//!     1     [1,41,42,43,44,11,22,33,22]       identical
//!     2     [2,41,42,43,44,11,22,33,33]       identical
//!     3     [3,41,42,43,44,11,22,33,33]       identical
//!     7     [7,41,42,43,44,11,22,33,33]       identical
//!    -1    [-1,41,42,43,44,11,22,33,33]       identical
//!
//! Same selected element in range, same fall-through to the last slot out of
//! range, no evaluation error on either side. So this is a PARITY item, not a
//! correctness bug — but not a harmless one: the same source deployed from Zig
//! was a different locking script, hence a different scriptPubKey and
//! different `constructorSlots` byte offsets, than from any other tier.
//!
//! R-066's separate observation — that the read chain's final `else` is the
//! last slot, UNGUARDED, while the write chain terminates in `assert(false)` —
//! is identical in all seven tiers (rows i=3/7/-1 above), so it is a language
//! design question and is deliberately NOT touched here.
//!
//! ---------------------------------------------------------------------------
//! SHAPE MATRIX (measured across all seven tiers, both fold modes)
//! ---------------------------------------------------------------------------
//!
//!     shape                                  six tiers  zig before  zig after
//!     A  this.out = this.cells[i]   (N=3)     1478       1462        1478
//!     B  this.out = this.cells[0n]            1430       1430        1430
//!     C  let v = this.cells[i]; this.out = v  1478       1478        1478
//!     D  assert(this.cells[i] === 0n)         1460       1460        1460
//!     E  this.out = this.cells[i]   (N=2)     1428       1424        1428
//!     F  this.cells[i] = v          (write)   1588       1588        1588
//!
//! Only the property-target read rows moved. B / C / D / F are the controls
//! and are pinned here so a future change to the selection cannot silently
//! move the shapes this fix is not about.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

const A_PROP_TARGET_RUNTIME =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\import type { FixedArray } from 'runar-lang';
    \\
    \\export class C extends StatefulSmartContract {
    \\  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  out: bigint;
    \\
    \\  constructor(out: bigint) { super(out); this.out = out; }
    \\
    \\  public read(i: bigint) {
    \\    this.out = this.cells[i];
    \\    assert(i >= 0n);
    \\  }
    \\}
;

const B_PROP_TARGET_LITERAL =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\import type { FixedArray } from 'runar-lang';
    \\
    \\export class C extends StatefulSmartContract {
    \\  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  out: bigint;
    \\
    \\  constructor(out: bigint) { super(out); this.out = out; }
    \\
    \\  public read(i: bigint) {
    \\    this.out = this.cells[0n];
    \\    assert(i >= 0n);
    \\  }
    \\}
;

const C_LOCAL_TARGET_RUNTIME =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\import type { FixedArray } from 'runar-lang';
    \\
    \\export class C extends StatefulSmartContract {
    \\  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  out: bigint;
    \\
    \\  constructor(out: bigint) { super(out); this.out = out; }
    \\
    \\  public read(i: bigint) {
    \\    let v: bigint = this.cells[i];
    \\    this.out = v;
    \\    assert(i >= 0n);
    \\  }
    \\}
;

const D_EXPR_POSITION =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\import type { FixedArray } from 'runar-lang';
    \\
    \\export class C extends StatefulSmartContract {
    \\  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  out: bigint;
    \\
    \\  constructor(out: bigint) { super(out); this.out = out; }
    \\
    \\  public read(i: bigint) {
    \\    assert(this.cells[i] === 0n);
    \\    this.out = i;
    \\  }
    \\}
;

const E_PROP_TARGET_LEN2 =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\import type { FixedArray } from 'runar-lang';
    \\
    \\export class C extends StatefulSmartContract {
    \\  cells: FixedArray<bigint, 2> = [0n, 0n];
    \\  out: bigint;
    \\
    \\  constructor(out: bigint) { super(out); this.out = out; }
    \\
    \\  public read(i: bigint) {
    \\    this.out = this.cells[i];
    \\    assert(i >= 0n);
    \\  }
    \\}
;

const G_LOCAL_ASSIGN_RUNTIME =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\import type { FixedArray } from 'runar-lang';
    \\
    \\export class C extends StatefulSmartContract {
    \\  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  out: bigint;
    \\
    \\  constructor(out: bigint) { super(out); this.out = out; }
    \\
    \\  public read(i: bigint) {
    \\    let v: bigint = 0n;
    \\    v = this.cells[i];
    \\    this.out = v;
    \\    assert(i >= 0n);
    \\  }
    \\}
;

const F_WRITE_RUNTIME =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\import type { FixedArray } from 'runar-lang';
    \\
    \\export class C extends StatefulSmartContract {
    \\  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  out: bigint;
    \\
    \\  constructor(out: bigint) { super(out); this.out = out; }
    \\
    \\  public write(i: bigint, v: bigint) {
    \\    this.cells[i] = v;
    \\    assert(i >= 0n);
    \\  }
    \\}
;

// ---------------------------------------------------------------------------
// The six-tier expected hex. Every string below was produced by the go, rust,
// python, ruby, java and ts compilers agreeing byte-for-byte, in BOTH fold
// modes, at the commit this test landed on. They are not zig's own output.
// ---------------------------------------------------------------------------

const SIX_A_PROP_TARGET_RUNTIME = "61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f8201219d517f75016a880261ab7c7e8869768254947f778101419d7601687f7782012c947f758258947f75820120947f77587f7c817c587f7c817c587f7c817c8178775879916353797677675879519c635279677668777668517a75587a00a269577a577a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b757768547a5880547a58807e537a58807e7b58807e5279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777";
const SIX_B_PROP_TARGET_LITERAL = "61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f8201219d517f75016a880261ab7c7e8869768254947f778101419d7601687f7782012c947f758258947f75820120947f77587f7c817c587f7c817c587f7c817c81537977587a00a269577a577a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b757768547a5880547a58807e537a58807e7b58807e5279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777";
const SIX_C_LOCAL_TARGET_RUNTIME = "61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f8201219d517f75016a880261ab7c7e8869768254947f778101419d7601687f7782012c947f758258947f75820120947f77587f7c817c587f7c817c587f7c817c81785979916354797677675979519c635379677668777668517a7577587a00a269577a577a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b757768547a5880547a58807e537a58807e7b58807e5279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777";
const SIX_D_EXPR_POSITION = "61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f8201219d517f75016a880261ab7c7e8869768254947f778101419d7601687f7782012c947f758258947f75820120947f77587f7c817c587f7c817c587f7c817c81587991635379675879519c63527967786868009d587a77577a577a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b757768547a5880547a58807e537a58807e7b58807e5279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777";
const SIX_E_PROP_TARGET_LEN2 = "61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f8201199d517f75016a880261ab7c7e8869768254947f778101419d7601687f7782012c947f758258947f75820118947f77587f7c817c587f7c817c81787757799163527967766877577a00a269567a567a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b757768537a5880537a58807e7b58807e5279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777";
const SIX_F_WRITE_RUNTIME = "61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686858798252947b7c7f8201219d517f75016a880261ab7c7e8869768254947f778101419d7601687f7782012c947f758258947f75820120947f77587f7c817c587f7c817c587f7c817c815979915a79519c5b79529c5279917653799a5379917b7c9a52799a5479547a9b537a9b695679537a635b79677668577a755679547a635b79677668577a755679557a635b7a67765c7a7568577a755b7a00a2695a7a5a7a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b757768557a5880547a58807e7b58807e557a58807e5579577a7c7558806b5679016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa547a820128947f7701207f758777777777";
const SIX_G_LOCAL_ASSIGN_RUNTIME = "61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f8201219d517f75016a880261ab7c7e8869768254947f778101419d7601687f7782012c947f758258947f75820120947f77587f7c817c587f7c817c587f7c817c810052795a79916355797677675a79519c635479677668777668517a75527a75597a00a269587a587a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b757768557a5880557a58807e547a58807e7b58807e5379557a7c7558806b5479016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7b820128947f7701207f75877777";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const Case = struct {
    label: []const u8,
    source: []const u8,
    want: []const u8,
};

const REGRESSION_CASES = [_]Case{
    .{ .label = "A: this.out = this.cells[i] (N=3)", .source = A_PROP_TARGET_RUNTIME, .want = SIX_A_PROP_TARGET_RUNTIME },
    .{ .label = "E: this.out = this.cells[i] (N=2)", .source = E_PROP_TARGET_LEN2, .want = SIX_E_PROP_TARGET_LEN2 },
    .{ .label = "G: v = this.cells[i] (plain assign to a local)", .source = G_LOCAL_ASSIGN_RUNTIME, .want = SIX_G_LOCAL_ASSIGN_RUNTIME },
};

const CONTROL_CASES = [_]Case{
    .{ .label = "B: literal index into a property target", .source = B_PROP_TARGET_LITERAL, .want = SIX_B_PROP_TARGET_LITERAL },
    .{ .label = "C: runtime index into a local target", .source = C_LOCAL_TARGET_RUNTIME, .want = SIX_C_LOCAL_TARGET_RUNTIME },
    .{ .label = "D: runtime index in expression position", .source = D_EXPR_POSITION, .want = SIX_D_EXPR_POSITION },
    .{ .label = "F: runtime-index WRITE dispatch", .source = F_WRITE_RUNTIME, .want = SIX_F_WRITE_RUNTIME },
};

fn checkCases(cases: []const Case) !void {
    const allocator = std.testing.allocator;
    for (cases) |tc| {
        for ([_]bool{ true, false }) |disable_constant_folding| {
            const result = try compiler_api.compileSourceWithOptions(
                allocator,
                tc.source,
                "C.runar.ts",
                disable_constant_folding,
            );
            defer allocator.free(result.script_hex);
            defer if (result.artifact_json) |a| allocator.free(a);
            std.testing.expectEqualStrings(tc.want, result.script_hex) catch |err| {
                std.debug.print(
                    "{s} (disable_constant_folding={}): zig hex ({d} chars) diverged from the six-tier hex ({d} chars)\n",
                    .{ tc.label, disable_constant_folding, result.script_hex.len, tc.want.len },
                );
                return err;
            };
        }
    }
}

test "a runtime-index read into a property target takes the statement form, as the other six do" {
    try checkCases(&REGRESSION_CASES);
}

test "the read/write dispatch shapes N-114 does not touch keep their bytes" {
    try checkCases(&CONTROL_CASES);
}

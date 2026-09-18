// N-099: a ternary whose two arms have incompatible types.
//
//     const y: ByteString = f ? this.blob : x;   // blob: ByteString, x: bigint
//
// Three tiers refused this and four accepted it:
//
//     ts / rust / java   REJECT
//     go / python / zig / ruby   ACCEPT, 12 hexchars
//
// The four permissive tiers silently take the CONSEQUENT's type as the
// expression's type. That is not a lint gap. A ByteString and a bigint do not
// share a stack representation — one is a byte string, the other a script
// number — so the branch that was silently retyped leaves the wrong kind of
// value on the stack, and every operation downstream of the ternary is reading
// a value of a type the author never wrote. This is the same class as the
// operand-position `<unknown>` escapes R-092 closed: a 33-byte push into an
// arithmetic opcode succeeds post-Genesis and computes something meaningless
// rather than failing.
//
// The rule the fix ports is the TypeScript reference's, and Rust already
// carries it verbatim: if the arms differ, each is tried as a subtype of the
// other, and only a pair related in NEITHER direction is refused. The four
// tiers already had that exact `is_subtype(alt, cons) || is_subtype(cons, alt)`
// fall-through — they returned the consequent type from it instead of raising.
//
// `<unknown>` stays accepted, as in TS: `isSubtype` treats it as top of the
// lattice, so `f ? this.helper() : x` (a private helper's return type, which no
// tier derives) is related to everything and never reaches the error.
//
// The shape stays invalid regardless of how inference evolves: ByteString and
// bigint are in different families under every tier's subtype relation.
import { SmartContract, ByteString, assert } from 'runar-lang';

export class TernaryBranchTypes extends SmartContract {
  readonly blob: ByteString;

  constructor(blob: ByteString) {
    super(blob);
    this.blob = blob;
  }

  public go(x: bigint, f: boolean) {
    const y: ByteString = f ? this.blob : x;
    assert(y == this.blob);
  }
}

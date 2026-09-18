// N-104 — the ByteString / bigint families are BIDIRECTIONALLY assignable.
//
// This is the pair that split the tiers 3-vs-4 before the fix:
//
//     const asSha: Sha256 = sibling;      // sibling: Ripemd160
//
//     ts / rust / zig            ACCEPT
//     go / python / ruby / java  REJECT ("type 'Ripemd160' is not assignable
//                                        to type 'Sha256'")
//
// The reference tier's `isSubtype`
// (packages/runar-compiler/src/passes/03-typecheck.ts) carries six family
// clauses: subtype -> base, base -> subtype, and both-in-family, for each of
// the two families. Four tiers carried only the first of each, so assignment
// inside a family worked in one direction and not the other.
//
// The asymmetry was already known to be wrong AT THE CALLSITES THAT NEEDED IT:
// go, zig, python, ruby and java each grew a private `outputStateValueMatches`
// helper that re-added the missing clauses just for `addOutput`'s state
// values, with a comment saying the narrow predicate "would have REJECTED
// working code that the reference tier accepts". Those helpers are gone; the
// general predicate now is the reference's.
//
// Every assignment below is a family move the reference tier accepts:
//   - sibling -> sibling inside the ByteString family (Ripemd160 -> Sha256)
//   - base    -> subtype inside the ByteString family (ByteString -> Addr)
//   - sibling -> sibling inside the bigint family     (RabinSig -> RabinPubKey)
//   - base    -> subtype inside the bigint family     (bigint -> RabinSig)
//
// CROSS-family moves stay rejected everywhere — that is N02/N16/N17/N19/N21 in
// conformance/negatives, and this fixture deliberately contains none.
import {
  SmartContract,
  ByteString,
  Sha256,
  Ripemd160,
  Addr,
  RabinSig,
  RabinPubKey,
  assert,
} from 'runar-lang';

export class FamilyWidening extends SmartContract {
  readonly expected: Ripemd160;

  constructor(expected: Ripemd160) {
    super(expected);
    this.expected = expected;
  }

  public unlock(sibling: Ripemd160, blob: ByteString, rabin: RabinSig, n: bigint) {
    const asSha: Sha256 = sibling;
    const asAddr: Addr = blob;
    const asRabinPub: RabinPubKey = rabin;
    const asRabinSig: RabinSig = n;
    assert(asSha === this.expected);
    assert(asAddr === blob);
    assert(asRabinPub === rabin);
    assert(asRabinSig === n);
  }
}

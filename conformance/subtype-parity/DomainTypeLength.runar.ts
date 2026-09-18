// The byte lengths in the domain-type table are DOCUMENTATION, not a checked
// constraint. This fixture pins that as a deliberate language property.
//
// `spec/type-system.md` §2.2 gives every domain type a size: `PubKey` 33,
// `Sha256` 32, `Ripemd160` 20, `Addr` 20. No tier verifies any of them. A
// 1-byte literal annotated `Sha256` compiles, and assigning it onward to a
// `PubKey` compiles too — the annotation names the author's intent for a human
// reader and constrains nothing the compiler can see.
//
// The decision is to KEEP it that way, so the property needs a gate rather
// than an implicit reliance on seven implementations happening to agree:
//
//   - Script has no type tags. Every domain type is the same stack item as a
//     ByteString of the same bytes, so a narrowing rule could only ever reject
//     source — it could never make an emitted script safer.
//   - Lengths are rarely knowable statically. The values that reach domain-typed
//     slots come from `split()` halves, `OP_CAT` results, preimage extractors and
//     hash builtins, and a rule strict enough to catch this literal would reject
//     the working patterns those produce.
//   - A contract that genuinely needs a length guarantee already has the tool for
//     it, and it is the one that survives to the chain: `assert(len(x) === 33n)`
//     emits `OP_SIZE`, the annotation emits nothing.
//
// The ByteString-family lattice itself is FamilyWidening.runar.ts; this is the
// orthogonal axis — that fixture moves values between families at their declared
// sizes, this one moves values that were never the declared size to begin with.
//
// If a future change starts enforcing declared sizes, this fixture goes RED in
// whichever tier enforces first, and that is the signal to change the spec
// deliberately rather than to discover a split later from a cross-tier hex
// mismatch.
import {
  SmartContract,
  ByteString,
  Sha256,
  PubKey,
  Addr,
  toByteString,
  len,
  assert,
} from 'runar-lang';

export class DomainTypeLength extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public unlock(blob: ByteString) {
    // 1 byte into a type the spec documents as 32.
    const shortDigest: Sha256 = toByteString('aa');
    // and onward into a type the spec documents as 33.
    const asPubKey: PubKey = shortDigest;
    // 25 bytes into a type the spec documents as 20.
    const longAddr: Addr = toByteString('00112233445566778899aabbccddeeff00112233445566778899');

    assert(len(asPubKey) === 1n);
    assert(len(longAddr) === 25n);
    assert(blob === this.expected);
  }
}

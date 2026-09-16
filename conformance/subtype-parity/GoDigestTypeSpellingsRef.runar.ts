import {
  StatefulSmartContract,
  ByteString,
  Sha256,
  Ripemd160,
  assert,
  sha256,
  ripemd160,
} from 'runar-lang';

/**
 * F1-type — the reference half of the Go-surface digest-type pair.
 *
 * This is GoDigestTypeSpellings.runar.go written with the canonical Rúnar
 * primitive names. The two files must compile to the SAME script hex, in every
 * tier, and subtype-parity.test.ts asserts exactly that.
 *
 * Why the pair and not just the `.runar.go` file. The per-fixture block in
 * subtype-parity.test.ts asks whether the tiers agree with EACH OTHER. On this
 * defect they already did: all seven refused `runar.Ripemd160Hash`, the only
 * spelling packages/runar-go declares for the RIPEMD-160 digest type, and all
 * seven accepted `runar.Ripemd160`, which it declares as a FUNCTION and not a
 * type at all. Unanimity was the state of the bug, not evidence against it. So
 * the mapping is checked against the primitive it claims to be, not against six
 * copies of itself.
 *
 * The state properties are what carry the claim. A readonly version of this
 * pair was measured and could not fail: with the digests as constructor
 * arguments, mapping `Ripemd160Hash` to `ByteString` emitted byte-identical
 * script, because every domain type is a ByteString subtype and no tier emits a
 * length check for a domain-typed argument. Mutable state is deserialized at a
 * width its TYPE decides, so there the three candidate mappings — Ripemd160,
 * Sha256, ByteString — produce three different scripts.
 *
 * Keep the two files in lockstep: same base class, same properties in the same
 * order, same method names, same parameter names, same order. The claim is byte
 * equality, and any of those changes it.
 */
export class GoDigestTypeSpellingsRef extends StatefulSmartContract {
  sha: Sha256;
  ripemd: Ripemd160;

  constructor(sha: Sha256, ripemd: Ripemd160) {
    super(sha, ripemd);
    this.sha = sha;
    this.ripemd = ripemd;
  }

  public update(preimage: ByteString) {
    this.sha = sha256(preimage);
    this.ripemd = ripemd160(preimage);
  }

  public check(witnessSha: Sha256, witnessRipemd: Ripemd160) {
    assert(witnessSha === this.sha);
    assert(witnessRipemd === this.ripemd);
  }
}

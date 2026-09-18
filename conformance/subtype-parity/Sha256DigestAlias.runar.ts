// N-104 — `Sha256Digest` is an ALIAS for `Sha256`, on every surface and in
// every tier.
//
// `packages/runar-lang/src/types.ts` declares `export type Sha256Digest =
// Sha256`; it is the cross-language spelling, and contracts use it in field
// and parameter annotations. Normalising it is the PARSER's job — by the time
// the typechecker sees a type it must already be the canonical name.
//
// This is the pair that split the tiers 2-vs-5 before the fix:
//
//     const asDigest: Sha256Digest = sibling;   // sibling: Ripemd160
//
//     ts / zig                          ACCEPT
//     python / ruby / java              REJECT  ("type 'Ripemd160' is not
//                                                assignable to type 'Sha256'")
//     go / rust                         REJECT  ("... to type 'Sha256Digest'")
//
// The two rejection messages are different defects wearing the same exit code.
// python / ruby / java HAD normalised the alias and then refused the
// assignment on the family lattice — that is N-104's first axis, and
// FamilyWidening.runar.ts is its fixture. go and rust named `Sha256Digest` in
// the diagnostic, which is the tell: their `.runar.ts` frontends never mapped
// the alias at all, so the name reached the typechecker as an opaque custom
// type that matched nothing in any table. Every OTHER surface parser in both
// tiers already mapped it — Go's parser_gocontract / parser_java /
// parser_python / parser_ruby / parser_zig, and Rust's equivalents — which is
// why a comment in 01-parse.ts asserted, wrongly, that they all did.
//
// Both directions are exercised: the alias as the DECLARED type and as the
// SOURCE type. A tier that resolves it in only one position passes half of
// this fixture.
import {
  SmartContract,
  Sha256,
  Sha256Digest,
  Ripemd160,
  assert,
} from 'runar-lang';

export class Sha256DigestAlias extends SmartContract {
  readonly digest: Sha256Digest;

  constructor(digest: Sha256Digest) {
    super(digest);
    this.digest = digest;
  }

  public unlock(sibling: Ripemd160, canonical: Sha256) {
    const asDigest: Sha256Digest = sibling;
    const asCanonical: Sha256 = this.digest;
    assert(asDigest === canonical);
    assert(asCanonical === this.digest);
  }
}

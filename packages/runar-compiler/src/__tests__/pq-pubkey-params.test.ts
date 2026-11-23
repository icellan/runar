/**
 * PQ-F1: the artifact names every constructor param that flows, as a property
 * load, into the public-key operand of verifyWOTS / verifySLHDSA_SHA2_*, with
 * the exact byte length that verifier needs (`pqPubKeyParams`).
 *
 * A wrong-length key deploys fine and then refuses the owner's valid signature
 * forever. The SDKs already refused one at construction by walking the
 * artifact's ANF, but only stateful artifacts carry ANF, so a stateless
 * contract had no guard. The field is what the SDKs read instead.
 *
 * Proves: the field's exact value for a stateless WOTS contract, a stateless
 * SLH-DSA-128s contract, a key reached through a local alias, a key used in a
 * private helper, two keys in one contract, and a stateful contract; and that
 * the key is ABSENT for a contract with no PQ verifier and for a key supplied
 * as a method argument.
 * Does not prove: anything about the other six compilers (see
 * conformance/negatives/artifact-flag-parity.test.ts) or the SDKs.
 */
import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { canonicalJsonStringify } from 'runar-ir-schema';
import { validateArtifact } from 'runar-ir-schema/validators';

function artifactOf(source: string) {
  const r = compile(source, { fileName: 'C.runar.ts' });
  expect(r.diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
  expect(r.artifact).toBeDefined();
  return r.artifact!;
}

const WOTS_STATELESS = `import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
class C extends SmartContract {
  readonly pk: ByteString;
  constructor(pk: ByteString) { super(pk); this.pk = pk; }
  public spend(msg: ByteString, sig: ByteString) { assert(verifyWOTS(msg, sig, this.pk)); }
}`;

describe('PQ-F1: artifact pqPubKeyParams', () => {
  it('stateless verifyWOTS key; the artifact still validates against the JSON schema', () => {
    const a = artifactOf(WOTS_STATELESS);
    expect(a.pqPubKeyParams).toEqual([{ index: 0, name: 'pk', scheme: 'verifyWOTS', length: 64 }]);
    expect(Object.keys(a.pqPubKeyParams![0]!)).toEqual(['index', 'name', 'scheme', 'length']);
    const v = validateArtifact(JSON.parse(canonicalJsonStringify(a)));
    expect(v.valid, JSON.stringify(v.valid ? [] : v.errors)).toBe(true);
  });

  it('stateless SLH-DSA-128s key', () => {
    const a = artifactOf(`import { SmartContract, ByteString, assert, verifySLHDSA_SHA2_128s } from 'runar-lang';
class C extends SmartContract {
  readonly pk: ByteString;
  constructor(pk: ByteString) { super(pk); this.pk = pk; }
  public spend(msg: ByteString, sig: ByteString) { assert(verifySLHDSA_SHA2_128s(msg, sig, this.pk)); }
}`);
    expect(a.pqPubKeyParams).toEqual([{ index: 0, name: 'pk', scheme: 'verifySLHDSA_SHA2_128s', length: 32 }]);
  });

  it('key through a local, key in a private helper, two keys sorted by index', () => {
    const a = artifactOf(`import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
class C extends SmartContract {
  readonly tag: bigint;
  readonly a: ByteString;
  readonly b: ByteString;
  constructor(tag: bigint, a: ByteString, b: ByteString) { super(tag, a, b); this.tag = tag; this.a = a; this.b = b; }
  private checkB(msg: ByteString, sig: ByteString): boolean { return verifyWOTS(msg, sig, this.b); }
  public spend(msg: ByteString, sig: ByteString, sig2: ByteString) {
    assert(this.checkB(msg, sig2));
    const k = this.a;
    assert(verifyWOTS(msg, sig, k));
    assert(this.tag > 0n);
  }
}`);
    expect(a.pqPubKeyParams).toEqual([
      { index: 1, name: 'a', scheme: 'verifyWOTS', length: 64 },
      { index: 2, name: 'b', scheme: 'verifyWOTS', length: 64 },
    ]);
  });

  it('stateful contract', () => {
    const a = artifactOf(`import { StatefulSmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
class C extends StatefulSmartContract {
  readonly pk: ByteString;
  n: bigint;
  constructor(pk: ByteString, n: bigint) { super(pk, n); this.pk = pk; this.n = n; }
  public spend(msg: ByteString, sig: ByteString) { assert(verifyWOTS(msg, sig, this.pk)); this.n = this.n + 1n; }
}`);
    expect(a.pqPubKeyParams).toEqual([{ index: 0, name: 'pk', scheme: 'verifyWOTS', length: 64 }]);
  });

  it('absent with no PQ verifier, and for a key passed as a method argument', () => {
    const none = artifactOf(`import { SmartContract, Sha256, ByteString, assert, sha256 } from 'runar-lang';
class C extends SmartContract {
  readonly h: Sha256;
  constructor(h: Sha256) { super(h); this.h = h; }
  public spend(p: ByteString) { assert(sha256(p) === this.h); }
}`);
    expect('pqPubKeyParams' in none).toBe(false);
    const arg = artifactOf(`import { SmartContract, ByteString, Sha256, assert, sha256, verifyWOTS } from 'runar-lang';
class C extends SmartContract {
  readonly h: Sha256;
  constructor(h: Sha256) { super(h); this.h = h; }
  public spend(msg: ByteString, sig: ByteString, pk: ByteString) { assert(sha256(pk) === this.h); assert(verifyWOTS(msg, sig, pk)); }
}`);
    expect('pqPubKeyParams' in arg).toBe(false);
  });
});

/**
 * Verification descriptors in the compiled artifact:
 *  - constructorSlots enriched with name/type/valueEncoding + fixed sizes
 *  - stateFields annotated with byte layout (encoding/byteOffset/byteLength/tailOffset)
 *  - templateDigest recipe for the slot-excised template hash
 *
 * The contract shape mirrors the EAC pattern that motivated the feature: a
 * stateful token whose readonly provenance fields (issuer PubKey + source
 * enum) are baked into the code part BECAUSE a method references them —
 * unreferenced readonly props are eliminated and get no slot.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { canonicalJsonStringify } from 'runar-ir-schema';
import { validateArtifact } from 'runar-ir-schema/validators';

const EAC_SHAPED_SOURCE = `
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class EacShaped extends StatefulSmartContract {
  owner: PubKey;
  quantityWh: bigint;
  status: bigint;

  readonly issuer: PubKey;
  readonly source: bigint;
  /** Never referenced by a method — must be ELIMINATED (no slot). */
  readonly tokenId: ByteString;

  constructor(
    owner: PubKey,
    quantityWh: bigint,
    status: bigint,
    issuer: PubKey,
    source: bigint,
    tokenId: ByteString,
  ) {
    super(owner, quantityWh, status, issuer, source, tokenId);
    this.owner = owner;
    this.quantityWh = quantityWh;
    this.status = status;
    this.issuer = issuer;
    this.source = source;
    this.tokenId = tokenId;
  }

  public retire(sig: Sig, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(this.status === 1n);
    assert(outputSatoshis >= 1n);
    this.addOutput(outputSatoshis, this.owner, this.quantityWh, 3n);
  }

  public withdraw(sig: Sig, outputSatoshis: bigint) {
    assert(checkSig(sig, this.issuer));
    assert(this.source >= 1n);
    assert(this.status === 1n);
    assert(outputSatoshis >= 1n);
    this.addOutput(outputSatoshis, this.owner, this.quantityWh, 4n);
  }
}
`;

function compileEacShaped() {
  const result = compile(EAC_SHAPED_SOURCE, { fileName: 'EacShaped.runar.ts' });
  if (!result.artifact) {
    throw new Error('compile failed: ' + JSON.stringify(result.diagnostics));
  }
  return result.artifact;
}

describe('constructorSlots verification descriptors', () => {
  const artifact = compileEacShaped();
  const slots = artifact.constructorSlots ?? [];

  it('emits enriched slots for referenced readonly props (issuer + source)', () => {
    const issuer = slots.find(s => s.name === 'issuer');
    expect(issuer).toBeDefined();
    expect(issuer).toMatchObject({
      paramIndex: 3,
      type: 'PubKey',
      valueEncoding: 'data',
      fixedValueByteLength: 33,
      fixedPushHeaderBytes: 1,
    });

    const source = slots.find(s => s.name === 'source');
    expect(source).toBeDefined();
    expect(source).toMatchObject({
      paramIndex: 4,
      type: 'bigint',
      valueEncoding: 'scriptnum',
    });
    // scriptnum slots have NO fixed width — the baked length depends on the
    // value (1..16 = single OP_N byte, >= 17 = multi-byte push).
    expect(source!.fixedValueByteLength).toBeUndefined();
    expect(source!.fixedPushHeaderBytes).toBeUndefined();
  });

  it('emits NO slot for an eliminated (unreferenced) readonly prop', () => {
    expect(slots.find(s => s.name === 'tokenId')).toBeUndefined();
    expect(slots.find(s => s.paramIndex === 5)).toBeUndefined();
  });

  it('slot names/types match abi.constructor.params[paramIndex]', () => {
    for (const slot of slots) {
      const param = artifact.abi.constructor.params[slot.paramIndex]!;
      expect(slot.name).toBe(param.name);
      expect(slot.type).toBe(param.type);
    }
  });
});

describe('stateFields byte-layout annotation', () => {
  const artifact = compileEacShaped();

  it('annotates owner/quantityWh/status with serializeState layout', () => {
    const fields = artifact.stateFields!;
    expect(fields.map(f => f.name)).toEqual(['owner', 'quantityWh', 'status']);

    // owner: PubKey — 33 raw bytes at the start of the state tail
    expect(fields[0]).toMatchObject({
      encoding: 'raw', byteOffset: 0, byteLength: 33, tailOffset: -49,
    });
    // quantityWh: bigint — 8 bytes LE sign-magnitude (NUM2BIN 8)
    expect(fields[1]).toMatchObject({
      encoding: 'num2bin-le8', byteOffset: 33, byteLength: 8, tailOffset: -16,
    });
    // status: bigint — final 8 bytes of the script
    expect(fields[2]).toMatchObject({
      encoding: 'num2bin-le8', byteOffset: 41, byteLength: 8, tailOffset: -8,
    });
  });
});

describe('templateDigest recipe', () => {
  const artifact = compileEacShaped();

  it('emits alternating code/slot pieces in script order', () => {
    const digest = artifact.templateDigest!;
    expect(digest.algorithm).toBe('hash256-excised-slots');

    const slotPieces = digest.pieces.filter(p => p.kind === 'slot');
    const codePieces = digest.pieces.filter(p => p.kind === 'code');
    // code piece before, between, and after each slot
    expect(codePieces.length).toBe(slotPieces.length + 1);
    expect(digest.pieces[0]!.kind).toBe('code');
    expect(digest.pieces[digest.pieces.length - 1]!.kind).toBe('code');

    // slot pieces in ascending template byte offset, named
    const offsets = slotPieces.map(p => p.byteOffset!);
    expect([...offsets].sort((a, b) => a - b)).toEqual(offsets);
    expect(new Set(slotPieces.map(p => p.slot))).toEqual(new Set(['issuer', 'source']));
  });
});

describe('artifact schema accepts the descriptor fields', () => {
  it('validateArtifact passes on an artifact carrying all new fields', () => {
    const artifact = compileEacShaped();
    expect(artifact.templateDigest).toBeDefined();
    // Round-trip through canonical JSON (bigints → plain integers) — the
    // on-disk shape the schema validator sees. Same pattern as
    // artifact-schema.test.ts. `anf` is stripped: the ANF sub-schema has a
    // PRE-EXISTING gap for this contract's add_output shape that is
    // unrelated to the descriptor fields under test here.
    const { anf: _anf, ...rest } = artifact;
    const plain = JSON.parse(canonicalJsonStringify(rest));
    const result = validateArtifact(plain);
    expect(result.valid, JSON.stringify((result as { errors?: unknown }).errors)).toBe(true);
  });
});

describe('stateless contracts are unaffected', () => {
  it('a slotless contract gets no templateDigest', () => {
    const result = compile(`
import { SmartContract, assert } from 'runar-lang';
class AlwaysTrue extends SmartContract {
  readonly threshold: bigint;
  constructor(threshold: bigint) { super(threshold); this.threshold = threshold; }
  public unlock(x: bigint) { assert(x === 1n); }
}
`, { fileName: 'AlwaysTrue.runar.ts' });
    expect(result.artifact, JSON.stringify(result.diagnostics)).toBeDefined();
    // threshold is never referenced by a method — eliminated, no slots.
    expect(result.artifact!.constructorSlots).toBeUndefined();
    expect(result.artifact!.templateDigest).toBeUndefined();
  });
});

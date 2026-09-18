// ---------------------------------------------------------------------------
// N-070 — `slotValueEncoding()` must classify a bigint-ALIASED constructor
// param as a script number.
//
// `RabinSig` / `RabinPubKey` are plain `bigint` aliases
// (`runar-lang/src/types.ts:68-71`), and `emitVerifyRabinSig` consumes the
// modulus with OP_MOD — i.e. as a Script number, little-endian
// sign-magnitude. The assembler special-cased only the spellings
// `int|bigint|bool|boolean`, so a Rabin slot was stamped
// `valueEncoding: 'data'`: a descriptor that tells every consumer the slot
// holds an opaque big-endian byte push. `runar-cli`'s `parseConstructorArgs`
// is that consumer, and it then spliced the operator's bytes in verbatim for
// OP_MOD to read backwards.
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import type { RunarArtifact } from 'runar-ir-schema';

function compileOk(source: string, fileName: string): RunarArtifact {
  const result = compile(source, { fileName });
  if (!result.artifact) {
    throw new Error(`fixture failed to compile: ${result.diagnostics.map((d: { message: string }) => d.message).join('; ')}`);
  }
  return result.artifact;
}

const RABIN_SOURCE = `
import { SmartContract, assert, PubKey, Sig, ByteString, RabinSig, RabinPubKey, checkSig, verifyRabinSig, num2bin } from 'runar-lang';

class RabinSlots extends SmartContract {
  readonly oraclePubKey: RabinPubKey;
  readonly plainModulus: bigint;
  readonly receiver: PubKey;
  readonly enabled: boolean;

  constructor(oraclePubKey: RabinPubKey, plainModulus: bigint, receiver: PubKey, enabled: boolean) {
    super(oraclePubKey, plainModulus, receiver, enabled);
    this.oraclePubKey = oraclePubKey;
    this.plainModulus = plainModulus;
    this.receiver = receiver;
    this.enabled = enabled;
  }

  public settle(price: bigint, rabinSig: RabinSig, padding: ByteString, sig: Sig) {
    const msg = num2bin(price, 8n);
    assert(verifyRabinSig(msg, rabinSig, padding, this.oraclePubKey));
    assert(price > this.plainModulus);
    assert(this.enabled);
    assert(checkSig(sig, this.receiver));
  }
}
`;

describe('N-070: constructor-slot value encoding for bigint-aliased types', () => {
  it('stamps a RabinPubKey slot as scriptnum, exactly like the bigint it aliases', () => {
    const artifact = compileOk(RABIN_SOURCE, 'RabinSlots.runar.ts');
    const slots = artifact.constructorSlots!;
    const byName = new Map(slots.map(s => [s.name, s]));

    expect(byName.get('oraclePubKey')!.type).toBe('RabinPubKey');
    expect(byName.get('oraclePubKey')!.valueEncoding).toBe('scriptnum');
    // The alias and the underlying type must be classified identically.
    expect(byName.get('oraclePubKey')!.valueEncoding)
      .toBe(byName.get('plainModulus')!.valueEncoding);
  });

  it('a scriptnum slot carries no fixed data width (a modulus has no fixed size)', () => {
    const artifact = compileOk(RABIN_SOURCE, 'RabinSlots.runar.ts');
    const slot = artifact.constructorSlots!.find(s => s.name === 'oraclePubKey')!;
    expect(slot.fixedValueByteLength).toBeUndefined();
    expect(slot.fixedPushHeaderBytes).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // CONTROLS — every other classification is byte-unchanged.
  // -------------------------------------------------------------------------
  it('CONTROL: PubKey stays data with its 33-byte width, boolean stays bool', () => {
    const artifact = compileOk(RABIN_SOURCE, 'RabinSlots.runar.ts');
    const byName = new Map(artifact.constructorSlots!.map(s => [s.name, s]));

    expect(byName.get('receiver')!.valueEncoding).toBe('data');
    expect(byName.get('receiver')!.fixedValueByteLength).toBe(33);
    expect(byName.get('receiver')!.fixedPushHeaderBytes).toBe(1);
    expect(byName.get('enabled')!.valueEncoding).toBe('bool');
    expect(byName.get('plainModulus')!.valueEncoding).toBe('scriptnum');
  });

  it('CONTROL: the oracle-price template script is byte-unchanged', () => {
    const src = `
import { SmartContract, assert, PubKey, Sig, ByteString, RabinSig, RabinPubKey, checkSig, verifyRabinSig, num2bin } from 'runar-lang';

class OraclePriceFeed extends SmartContract {
  readonly oraclePubKey: RabinPubKey;
  readonly receiver: PubKey;

  constructor(oraclePubKey: RabinPubKey, receiver: PubKey) {
    super(oraclePubKey, receiver);
    this.oraclePubKey = oraclePubKey;
    this.receiver = receiver;
  }

  public settle(price: bigint, rabinSig: RabinSig, padding: ByteString, sig: Sig) {
    const msg = num2bin(price, 8n);
    assert(verifyRabinSig(msg, rabinSig, padding, this.oraclePubKey));
    assert(price > 50000n);
    assert(checkSig(sig, this.receiver));
  }
}
`;
    const artifact = compileOk(src, 'OraclePriceFeed.runar.ts');
    // The classification is descriptor-only: it must not move a single
    // template byte (this is the conformance golden for sdk-output/oracle-price).
    expect(artifact.script).toBe(
      '53795880537a537a00537a537a537a537a7c760003000001a5697b7695937c977ca801007e819d7c0350c300a06900ac',
    );
    expect(artifact.constructorSlots!.map(s => s.byteOffset)).toEqual([8, 46]);
  });
});

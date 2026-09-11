// ---------------------------------------------------------------------------
// N-070 (extract half) — `interpretScriptElement` must know every spelling the
// compiler can put in `abi.constructor.params[].type`.
//
// Two concrete holes, both of which make `extractConstructorArgs` hand back a
// hex STRING where the deploy side took a value:
//
//   RabinSig / RabinPubKey — `bigint` aliases (runar-lang/src/types.ts:68-71)
//     that the compiler pushes as a script number. Absent from the switch in
//     all seven tiers, so a restored contract's modulus came back as the
//     little-endian hex blob `'d20a1feb8ca954ab00'` instead of
//     `12345678901234567890n`. Feed that back into a call and the rebuilt
//     locking script no longer matches the one on chain.
//
//   boolean — the CANONICAL Rúnar primitive name (`state.ts:327-334` says so
//     in as many words, and the compiler emits `{"type":"boolean"}`; see
//     conformance/sdk-vertical/artifacts/SlotBool.json). Only the alias
//     `'bool'` was handled, so a boolean slot fell through to the byte branch:
//     `true` came back as the string `'01'` and `false` as `''`. Java
//     (`ContractScript.java:249`) was the only tier of seven that tested both
//     spellings — a 6-vs-1 parity break.
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import { extractConstructorArgs } from '../script-utils.js';
import { RunarContract } from '../contract.js';
import type { RunarArtifact } from 'runar-ir-schema';

const PK = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

/** The real `examples/ts/oracle-price` template: RabinPubKey slot @8, PubKey @46. */
function oracleArtifact(): RunarArtifact {
  return {
    version: 'runar-v1.0.0-rc.1',
    compilerVersion: '1.0.0-rc.1',
    contractName: 'OraclePriceFeed',
    parentClass: 'SmartContract',
    abi: {
      constructor: {
        params: [
          { name: 'oraclePubKey', type: 'RabinPubKey' },
          { name: 'receiver', type: 'PubKey' },
        ],
      },
      methods: [],
    },
    script:
      '53795880537a537a00537a537a537a537a7c760003000001a5697b7695937c977ca801007e819d7c0350c300a06900ac',
    constructorSlots: [
      { paramIndex: 0, byteOffset: 8, name: 'oraclePubKey', type: 'RabinPubKey', valueEncoding: 'scriptnum' },
      { paramIndex: 1, byteOffset: 46, name: 'receiver', type: 'PubKey', valueEncoding: 'data', fixedValueByteLength: 33, fixedPushHeaderBytes: 1 },
    ],
    buildTimestamp: '1970-01-01T00:00:00.000Z',
  } as unknown as RunarArtifact;
}

/** conformance/sdk-vertical/artifacts/SlotBool.json — a canonical `boolean` slot. */
function slotBoolArtifact(): RunarArtifact {
  return {
    version: 'runar-v1.0.0-rc.1',
    compilerVersion: '1.0.0-rc.1',
    contractName: 'SlotBool',
    parentClass: 'SmartContract',
    abi: {
      constructor: {
        params: [
          { name: 'flag', type: 'boolean' },
          { name: 'owner', type: 'PubKey' },
        ],
      },
      methods: [],
    },
    script: '007c9d00ac',
    constructorSlots: [
      { paramIndex: 0, byteOffset: 0, name: 'flag', type: 'boolean', valueEncoding: 'bool' },
      { paramIndex: 1, byteOffset: 3, name: 'owner', type: 'PubKey', valueEncoding: 'data', fixedValueByteLength: 33, fixedPushHeaderBytes: 1 },
    ],
    buildTimestamp: '1970-01-01T00:00:00.000Z',
  } as unknown as RunarArtifact;
}

/** Same shape, spelled with the `bool` alias — the spelling that already worked. */
function slotBoolAliasArtifact(): RunarArtifact {
  const a = slotBoolArtifact();
  a.abi.constructor.params[0]!.type = 'bool';
  a.constructorSlots![0]!.type = 'bool';
  return a;
}

describe('N-070: extractConstructorArgs round-trips every slot type', () => {
  const MODULUS = 12345678901234567890n;

  it('a RabinPubKey slot round-trips as a bigint, not a hex blob', () => {
    const artifact = oracleArtifact();
    const script = new RunarContract(artifact, [MODULUS, PK]).getLockingScript();
    // Pin the on-chain bytes: OP_MOD reads this slot little-endian.
    expect(script.slice(8 * 2, 8 * 2 + 20)).toBe('09d20a1feb8ca954ab00');

    const args = extractConstructorArgs(artifact, script);
    expect(args.oraclePubKey).toBe(MODULUS);
    expect(args.receiver).toBe(PK);
  });

  it('a RabinSig-typed slot round-trips as a bigint too', () => {
    const artifact = oracleArtifact();
    artifact.abi.constructor.params[0]!.type = 'RabinSig';
    artifact.constructorSlots![0]!.type = 'RabinSig';
    const script = new RunarContract(artifact, [MODULUS, PK]).getLockingScript();
    expect(extractConstructorArgs(artifact, script).oraclePubKey).toBe(MODULUS);
  });

  it('a `boolean`-typed slot round-trips as a boolean in both polarities', () => {
    const artifact = slotBoolArtifact();

    const trueScript = new RunarContract(artifact, [true, PK]).getLockingScript();
    expect(trueScript.slice(0, 2)).toBe('51'); // OP_1
    expect(extractConstructorArgs(artifact, trueScript).flag).toBe(true);

    const falseScript = new RunarContract(artifact, [false, PK]).getLockingScript();
    expect(falseScript.slice(0, 2)).toBe('00'); // OP_0
    expect(extractConstructorArgs(artifact, falseScript).flag).toBe(false);
  });

  it('the `boolean` and `bool` spellings extract identically', () => {
    for (const flag of [true, false]) {
      const canonical = slotBoolArtifact();
      const alias = slotBoolAliasArtifact();
      const script = new RunarContract(canonical, [flag, PK]).getLockingScript();
      expect(extractConstructorArgs(canonical, script).flag)
        .toBe(extractConstructorArgs(alias, script).flag);
      expect(extractConstructorArgs(canonical, script).flag).toBe(flag);
    }
  });

  // -------------------------------------------------------------------------
  // CONTROLS — the classes that already worked must not move.
  // -------------------------------------------------------------------------
  it('CONTROL: bigint / int / PubKey / ByteString slots are unchanged', () => {
    const artifact = oracleArtifact();
    for (const t of ['bigint', 'int']) {
      artifact.abi.constructor.params[0]!.type = t;
      artifact.constructorSlots![0]!.type = t;
      const script = new RunarContract(artifact, [MODULUS, PK]).getLockingScript();
      expect(extractConstructorArgs(artifact, script).oraclePubKey).toBe(MODULUS);
    }
    // A ByteString slot still comes back as its hex payload, NOT a number.
    artifact.abi.constructor.params[0]!.type = 'ByteString';
    artifact.constructorSlots![0]!.type = 'ByteString';
    const bs = new RunarContract(artifact, ['deadbeef', PK]).getLockingScript();
    expect(extractConstructorArgs(artifact, bs).oraclePubKey).toBe('deadbeef');
    expect(extractConstructorArgs(artifact, bs).receiver).toBe(PK);
  });

  it('CONTROL: the S1 single-opcode byte reconstruction still applies to byte types', () => {
    const artifact = oracleArtifact();
    artifact.abi.constructor.params[0]!.type = 'ByteString';
    artifact.constructorSlots![0]!.type = 'ByteString';
    const script = new RunarContract(artifact, ['05', PK]).getLockingScript();
    expect(script.slice(16, 18)).toBe('55'); // OP_5, MINIMALDATA
    expect(extractConstructorArgs(artifact, script).oraclePubKey).toBe('05');
  });
});

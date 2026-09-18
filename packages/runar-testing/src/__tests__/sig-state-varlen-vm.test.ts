/**
 * A `Sig` / `SigHashPreimage` state field must survive a real spend.
 *
 * The compiler's on-chain state WRITER (`lowerAddOutput` /
 * `lowerComputeStateBytes`) tested the literal string `'ByteString'` before
 * emitting the push-data length prefix, while the on-chain state READER
 * (`lowerDeserializeState`) push-data-DECODES every variable-length type —
 * `ByteString`, `Sig` and `SigHashPreimage` alike, matching what all seven
 * SDKs' `encodeStateValue` writes at deploy time.
 *
 * So for a contract with a mutable `Sig` field:
 *
 *   deploy  — SDK writes  <len> || DER      → correct, spendable
 *   spend 1 — script writes      DER        → continuation has NO length byte
 *   spend 2 — script reads  DER[0] as a length → 0x30 = "a 48-byte push"
 *
 * Deploy succeeds. The first spend succeeds. The UTXO that first spend creates
 * is unspendable. Straight fund loss, and invisible to any test that only
 * round-trips the compiler against itself.
 *
 * These tests run the whole cycle on the real `@bsv/sdk` Script VM with
 * `MockProvider.enableBroadcastValidation()` — a wrong framing fails the spend
 * outright rather than failing an equality check. They are the executed
 * companion to `packages/runar-compiler/src/__tests__/sig-state-varlen.test.ts`
 * (Stack-IR / hex assertions) and to the seven-tier byte-identity cases in
 * `packages/runar-compiler/src/__tests__/cross-compiler.test.ts`.
 *
 * Fixture values are REALISTIC DER signatures, because the leading `0x30` is
 * precisely the byte the broken reader mistook for a length: a 71-byte and a
 * 72-byte low-S/high-S shape, plus a degenerate 9-byte low-`r` signature whose
 * length is nothing like the fixed size any fixed-width read path would assume.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import {
  RunarContract,
  MockProvider,
  LocalSigner,
  findLastOpReturn,
} from 'runar-sdk';
import { PrivateKey } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

const PRIV = PrivateKey.fromString('b1'.repeat(32), 16);
const PKH = PRIV.toPublicKey().toHash('hex') as string;

function compileOrThrow(source: string, fileName: string): RunarArtifact {
  const r = compile(source, { fileName });
  if (!r.success || !r.artifact) {
    throw new Error(`compile failed: ${r.diagnostics.map((d) => d.message).join('; ')}`);
  }
  return r.artifact as RunarArtifact;
}

interface DeployAndCallResult {
  /** Full locking script hex as broadcast at DEPLOY time (before the call). */
  deployedScript: string;
  /** Full locking script hex of the continuation the CALL created. */
  postCallScript: string;
  /** Decoded state after the call, i.e. after a real Script VM spend. */
  postCallState: Record<string, unknown>;
  contract: RunarContract;
}

async function deployAndCall(
  source: string,
  fileName: string,
  constructorArgs: unknown[],
  method: string,
  args: unknown[],
): Promise<DeployAndCallResult> {
  const artifact = compileOrThrow(source, fileName);
  const signer = new LocalSigner(PRIV.toString());
  const provider = new MockProvider();
  provider.enableBroadcastValidation();
  provider.addUtxo(await signer.getAddress(), {
    txid: 'ee'.repeat(32),
    outputIndex: 0,
    satoshis: 1_000_000,
    script: '76a914' + PKH + '88ac',
  });
  const contract = new RunarContract(artifact, constructorArgs);
  contract.connect(provider, signer);
  await contract.deploy({ satoshis: 1000 });
  const deployedScript = contract.getUtxo()!.script;
  await contract.call(method, args, { satoshis: 60_000 });
  return {
    deployedScript,
    postCallScript: contract.getUtxo()?.script ?? '',
    postCallState: contract.state as Record<string, unknown>,
    contract,
  };
}

/**
 * Slice the raw state-section bytes out of a locking script, using the
 * compiler's own opcode-boundary walker (`findLastOpReturn` — structural, not
 * the encoder under test) to find where the executed code ends.
 */
function stateSectionHex(scriptHex: string): string {
  const pos = findLastOpReturn(scriptHex);
  if (pos === -1) throw new Error('stateSectionHex: no OP_RETURN in the script');
  return scriptHex.slice(pos + 2);
}

// ---------------------------------------------------------------------------
// Fixtures — real DER signature shapes. The leading 0x30 is the trap byte.
// ---------------------------------------------------------------------------

/** 71 bytes (0x47): 3044 || 0220 r || 0220 s || sighash. */
const DER_71 =
  '3044' +
  '0220' + '11'.repeat(32) +
  '0220' + '22'.repeat(32) +
  '41';

/** 72 bytes (0x48): 3045 || 0221 00r || 0220 s || sighash — the high-bit r form. */
const DER_72 =
  '3045' +
  '0221' + '00' + 'aa'.repeat(32) +
  '0220' + '7f'.repeat(32) +
  '41';

/** 9 bytes (0x09): degenerate low-r / low-s. Nothing like any fixed width. */
const DER_9 = '3006' + '020101' + '020101' + '41';

const DER_FIXTURES: Array<{ label: string; hex: string }> = [
  { label: '71-byte DER', hex: DER_71 },
  { label: '72-byte DER (high-bit r)', hex: DER_72 },
  { label: '9-byte degenerate low-r DER', hex: DER_9 },
];

// Sanity on the fixtures themselves: the lengths must be what the labels say,
// and the first byte must be the 0x30 that the broken reader mis-parsed.
for (const { label, hex } of DER_FIXTURES) {
  if (!hex.startsWith('30')) throw new Error(`${label}: fixture is not DER-shaped`);
}

/** `bigint` and `boolean` are language primitives, not importable named types. */
function typeImport(propType: string): string {
  return propType === 'bigint' || propType === 'boolean'
    ? ''
    : `import type { ${propType} } from 'runar-lang';\n`;
}

/**
 * Carries a caller-supplied signature through the continuation. `tail` sits
 * AFTER the variable-length field, so a missing (or wrong-width) length prefix
 * corrupts `tail` too, not just `sig` — an off-by-one cannot hide.
 */
function carrier(propType: string): string {
  return `import { StatefulSmartContract } from 'runar-lang';
${typeImport(propType)}
export class VarLenCarrier extends StatefulSmartContract {
  sig: ${propType};
  tail: bigint = 0n;
  constructor(sig: ${propType}) { super(sig); this.sig = sig; }
  public rotate(next: ${propType}, amount: bigint) {
    this.addOutput(amount, next, this.tail);
  }
}
`;
}

/**
 * Reads the mutable variable-length field and carries it forward unchanged.
 * The read is what `computeUsesCodePart` had to get right; the carry-forward
 * is what the writer had to frame.
 */
function reader(propType: string): string {
  return `import { StatefulSmartContract, assert, len } from 'runar-lang';
${typeImport(propType)}
export class VarLenReader extends StatefulSmartContract {
  sig: ${propType};
  tail: bigint = 0n;
  constructor(sig: ${propType}) { super(sig); this.sig = sig; }
  public prove(expected: bigint, amount: bigint) {
    assert(len(this.sig) === expected);
    this.addOutput(amount, this.sig, this.tail);
  }
}
`;
}

describe.each(['Sig', 'SigHashPreimage'] as const)(
  '%s state field — real Script VM deploy + spend',
  (propType) => {
    describe('deploy-time framing (SDK writer) is <len> || value', () => {
      for (const { label, hex } of DER_FIXTURES) {
        it(`${label}`, async () => {
          const lenByte = (hex.length / 2).toString(16).padStart(2, '0');
          const { deployedScript } = await deployAndCall(
            reader(propType),
            'VarLenReader.runar.ts',
            [hex],
            'prove',
            [BigInt(hex.length / 2), 60_000n],
          );
          // sig: <len><data>; tail: NUM2BIN-LE8(0). Hand-derived from the
          // framing rules in packages/runar-sdk/src/state.ts, NOT by calling
          // the serializer under test.
          expect(stateSectionHex(deployedScript)).toBe(
            lenByte + hex + '0000000000000000',
          );
        });
      }
    });

    describe('read path: the field is read from live state, then carried forward', () => {
      for (const { label, hex } of DER_FIXTURES) {
        it(`${label} reads back its own length on-chain`, async () => {
          const byteLen = BigInt(hex.length / 2);
          const lenByte = (hex.length / 2).toString(16).padStart(2, '0');
          const { postCallScript, postCallState } = await deployAndCall(
            reader(propType),
            'VarLenReader.runar.ts',
            [hex],
            'prove',
            [byteLen, 60_000n],
          );
          // `assert(len(this.sig) === expected)` executed on the VM against
          // the DESERIALIZED state — if the read path had fallen back to the
          // deploy-time placeholder or mis-split the field, this spend would
          // not have validated.
          expect(postCallState.sig).toBe(hex);
          expect(stateSectionHex(postCallScript)).toBe(
            lenByte + hex + '0000000000000000',
          );
        });
      }
    });
  },
);

/**
 * The strongest form of the write test: the new value crosses the UNLOCKING
 * script as a method argument, so the continuation the script builds is made
 * of bytes the compiler never saw at deploy time.
 *
 * `Sig` only. A `SigHashPreimage`-typed METHOD PARAMETER is indistinguishable,
 * in the SDK's call path, from the `txPreimage` the compiler injects into every
 * public method of a stateful contract: `RunarContract.prepareCall` strips
 * every SigHashPreimage param as implicit, so `rotate(next: SigHashPreimage,
 * amount: bigint)` is called with one user argument, not two. That is a
 * pre-existing convention of the SDK's ABI, not part of this fix;
 * `SigHashPreimage` state fields are covered above through the constructor and
 * the carry-forward path, and at the byte level in every tier by
 * `cross-compiler.test.ts`.
 */
describe('Sig state field — a NEW value supplied by the unlocking script', () => {
  for (const { label, hex } of DER_FIXTURES) {
    it(`${label} survives a spend and stays decodable`, async () => {
      const lenByte = (hex.length / 2).toString(16).padStart(2, '0');
      const { postCallScript, postCallState } = await deployAndCall(
        carrier('Sig'),
        'VarLenCarrier.runar.ts',
        ['00'],
        'rotate',
        [hex, 60_000n],
      );

      // The value the SDK decoded back out of the continuation.
      expect(postCallState.sig).toBe(hex);
      expect(postCallState.tail).toBe(0n);

      // And the framing the SCRIPT itself wrote must be the same shape the SDK
      // wrote at deploy time — this is the byte the next spend's reader parses
      // as a length. Pre-fix it was the DER `0x30`, i.e. "a 48-byte push".
      expect(stateSectionHex(postCallScript)).toBe(
        lenByte + hex + '0000000000000000',
      );
    });
  }
});

// ---------------------------------------------------------------------------
// Controls — the types this change must NOT touch.
// ---------------------------------------------------------------------------

describe('controls: fixed-width and numeric state framing is unchanged', () => {
  it('ByteString (the already-correct variable-length control) still round-trips', async () => {
    const { deployedScript, postCallState } = await deployAndCall(
      carrier('ByteString'),
      'VarLenCarrier.runar.ts',
      ['00'],
      'rotate',
      [DER_71, 60_000n],
    );
    expect(stateSectionHex(deployedScript)).toBe('01' + '00' + '0000000000000000');
    expect(postCallState.sig).toBe(DER_71);
  });

  it('the numeric state class stays a bare 8-byte NUM2BIN word — NOT push-data framed', async () => {
    // `bigint` stands in for the whole numeric class here, `RabinSig` and
    // `RabinPubKey` included — they are bigint aliases and share this exact
    // layout. (`RabinSig` itself cannot be driven end-to-end through the SDK:
    // `packages/runar-sdk/src/state.ts` has no `RabinSig` case in its arg
    // encoder, so a deploy with a RabinSig constructor arg splices a
    // non-hex placeholder and `LockingScript.fromHex` rejects it. That is a
    // pre-existing SDK gap, unrelated to this fix and out of its scope; the
    // seven compilers' RabinSig framing is pinned at the compile level by
    // `packages/runar-compiler/src/__tests__/sig-state-varlen.test.ts` and by
    // each tier's own regression test.)
    const { deployedScript, postCallScript, postCallState } = await deployAndCall(
      carrier('bigint'),
      'VarLenCarrier.runar.ts',
      [1n],
      'rotate',
      [255n, 60_000n],
    );
    expect(stateSectionHex(deployedScript)).toBe('0100000000000000' + '0000000000000000');
    expect(stateSectionHex(postCallScript)).toBe('ff00000000000000' + '0000000000000000');
    expect(postCallState.sig).toBe(255n);
    expect(postCallState.tail).toBe(0n);
  });

  it('PubKey stays 33 raw bytes — NOT push-data framed', async () => {
    const ownerHex = PRIV.toPublicKey().toDER('hex') as string;
    const { deployedScript, postCallState } = await deployAndCall(
      carrier('PubKey'),
      'VarLenCarrier.runar.ts',
      [ownerHex],
      'rotate',
      [ownerHex, 60_000n],
    );
    expect(stateSectionHex(deployedScript)).toBe(ownerHex + '0000000000000000');
    expect(postCallState.sig).toBe(ownerHex);
  });
});

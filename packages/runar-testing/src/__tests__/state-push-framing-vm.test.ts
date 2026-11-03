/**
 * The SDK's state-section serializer and the compiler's on-chain state
 * framing must be the same encoding.
 *
 * Reported privately (Ben Palmer, 2026-08-03) as "variable-length ByteString
 * state fields break the continuation output check". The actual trigger is
 * narrower: a ByteString state value of EXACTLY ONE byte whose value is in
 * {0x01..0x10, 0x81}. Multi-byte values, empty values, and 1-byte values
 * outside that set were always fine.
 *
 * Cause: #110 (4573b424 / bd7ec284) taught all seven SDKs' state serializers
 * the SCRIPT_VERIFY_MINIMALDATA rule — a 1-byte push in the OP_N range must
 * use OP_1..OP_16 / OP_1NEGATE. That rule is correct for UNLOCKING-script
 * pushes (`encodeArg`), which the interpreter executes. The state section is
 * not executed: it is raw data after OP_RETURN in the locking script, framed
 * as <len><data> by the compiler's on-chain writer (`emitPushDataEncode`,
 * 05-stack-lower.ts) and parsed as <len><data> by the on-chain reader. #110
 * changed only the seven SDKs, never the seven compilers, so from that
 * commit on the two sides disagreed:
 *
 *   value "05" -> SDK "55" (OP_5)   vs   on-chain "0105"
 *
 * Two faces, both fund-loss:
 *   - WRITE: the continuation the script rebuilds differs from the outputs
 *     the SDK actually serialised, so hashOutputs never matches;
 *   - READ: a contract DEPLOYED with such a value can't be spent at all —
 *     the on-chain reader takes 0x55 as a length-85 push and dies in
 *     OP_SPLIT on the first call.
 *
 * The fix restores <len><data> in the state serializer of all seven SDKs
 * (the pre-#110 encoding, which matched). `encodeArg` keeps the MINIMALDATA
 * rule — unlocking-script pushes really are executed.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import {
  RunarContract,
  MockProvider,
  LocalSigner,
  serializeState,
  deserializeState,
  findLastOpReturn,
} from 'runar-sdk';
import { PrivateKey } from '@bsv/sdk';
import type { RunarArtifact, StateField } from 'runar-ir-schema';

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
  /** Decoded state after the call, i.e. after a real Script VM spend. */
  postCallState: Record<string, unknown>;
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
  return { deployedScript, postCallState: contract.state as Record<string, unknown> };
}

/**
 * Slice the raw state-section bytes out of a compiled/deployed locking
 * script, using the compiler's own opcode-boundary walker (`findLastOpReturn`
 * — structural, not the encoder under test) to find where the executed code
 * ends and the state section begins.
 */
function stateSectionHex(scriptHex: string): string {
  const pos = findLastOpReturn(scriptHex);
  if (pos === -1) {
    throw new Error('stateSectionHex: no OP_RETURN found in the deployed script');
  }
  return scriptHex.slice(pos + 2);
}

/** Carries a caller-supplied ByteString through the continuation. */
const CARRIER = `import { StatefulSmartContract, assert } from 'runar-lang';
import type { ByteString } from 'runar-lang';

export class Carrier extends StatefulSmartContract {
  closed: bigint = 0n;
  handle: ByteString = "" as ByteString;
  tail: bigint = 0n;
  constructor(seed: bigint) { super(seed); this.closed = seed; }
  public put(h: ByteString, amount: bigint) {
    assert(this.closed == 0n);
    this.addOutput(amount, this.closed, h, this.tail);
  }
}
`;

/** Deployed with a 1-byte OP_N-range initial state value already in place. */
const PRESET = `import { StatefulSmartContract, assert } from 'runar-lang';
import type { ByteString } from 'runar-lang';

export class Preset extends StatefulSmartContract {
  closed: bigint = 0n;
  handle: ByteString = "05" as ByteString;
  constructor(seed: bigint) { super(seed); this.closed = seed; }
  public bump(amount: bigint) {
    assert(this.closed == 0n);
    this.addOutput(amount, this.closed, this.handle);
  }
}
`;

// Every 1-byte value the MINIMALDATA short-circuit touched, plus controls
// either side of it and multi-byte / empty cases.
const HANDLES = [
  '', '00', '01', '02', '05', '10', '11', '20', '7f', '80', '81', '82', 'ff',
  '0102', '0500', 'aabbcc', 'de'.repeat(40),
];

describe('state-section framing — SDK serializer vs on-chain reader/writer', () => {
  describe('write path: value survives the continuation on the real Script VM', () => {
    for (const handle of HANDLES) {
      const label = handle === '' ? '(empty)' : handle.length > 16 ? `${handle.slice(0, 8)}… (${handle.length / 2}B)` : handle;
      it(`handle=${label}`, async () => {
        const { postCallState } = await deployAndCall(CARRIER, 'Carrier.runar.ts', [0n], 'put', [handle, 60_000n]);
        expect(postCallState.handle).toBe(handle);
        expect(postCallState.tail).toBe(0n);
      });
    }
  });

  it('read path: a contract deployed with a 1-byte OP_N-range value is spendable', async () => {
    const { postCallState } = await deployAndCall(PRESET, 'Preset.runar.ts', [0n], 'bump', [60_000n]);
    expect(postCallState.handle).toBe('05');
  });

  describe('unit: serializeState frames ByteString as <len><data>, like the on-chain writer', () => {
    const fields: StateField[] = [{ name: 'b', type: 'ByteString', index: 0 }];

    it('1-byte values in the OP_N range are NOT collapsed to OP_1..OP_16', () => {
      for (let n = 1; n <= 16; n++) {
        const hex = n.toString(16).padStart(2, '0');
        expect(serializeState(fields, { b: hex })).toBe('01' + hex);
      }
    });

    it('0x81 is not collapsed to OP_1NEGATE', () => {
      expect(serializeState(fields, { b: '81' })).toBe('0181');
    });

    it('0x00 keeps the direct push (unchanged by this fix)', () => {
      expect(serializeState(fields, { b: '00' })).toBe('0100');
    });

    it('empty stays a zero-length push', () => {
      expect(serializeState(fields, { b: '' })).toBe('00');
    });

    it('values outside the OP_N range and multi-byte values are unchanged', () => {
      expect(serializeState(fields, { b: '11' })).toBe('0111');
      expect(serializeState(fields, { b: '0011' })).toBe('020011');
    });

    it('round-trips through deserializeState for every 1-byte value', () => {
      for (let byte = 0; byte <= 0xff; byte++) {
        const hex = byte.toString(16).padStart(2, '0');
        const blob = serializeState(fields, { b: hex });
        expect(deserializeState(fields, blob)).toEqual({ b: hex });
      }
    });

    // N-299: the round-trip test above can NEVER exercise decodePushData's
    // rejection of OP_N-range framing, because it only ever hands
    // deserializeState a blob serializeState just produced correctly
    // (<len><data>) -- the correct encoder never emits OP_1..OP_16 /
    // OP_1NEGATE for the state section. This is a direct, hand-written-bytes
    // decode case per P3 ("round-trip alone is never sufficient for a listed
    // wire primitive") so this file itself detects the PALMER-2 READ-face
    // regression (c28-state-strict.test.ts's `deserializeState(fields, '55')`
    // pin already catches it; this gives state-push-framing-vm the same
    // coverage across the whole OP_N range it was nominated, but not
    // measured, to catch).
    it('decodePushData rejects OP_N-range opcodes directly, independent of what the encoder would ever produce', () => {
      for (let n = 1; n <= 16; n++) {
        const opHex = (0x50 + n).toString(16); // OP_1 (0x51) .. OP_16 (0x60)
        expect(() => deserializeState(fields, opHex)).toThrow(/is not a push opcode/);
      }
      expect(() => deserializeState(fields, '4f')).toThrow(/is not a push opcode/); // OP_1NEGATE
    });
  });
});

// -----------------------------------------------------------------------------
// C1/C2 matrix — the remaining wire value classes.
//
// ByteString empty / 1-byte OP_N range / 1-byte 0x00 / 1-byte outside range /
// multi-byte are ALL already covered above by the HANDLES write-path loop and
// the PRESET read-path test — every one of those is a real deploy -> call
// through the real Script VM with broadcast validation enabled, which is
// STRONGER evidence than a static hex comparison (a wrong framing fails the
// spend outright, not just an equality check). Not duplicated here.
//
// The classes below (bigint edges including NEGATIVE and large magnitudes,
// bool, and a raw-fixed-width type) had no coverage in this file. Per plan
// principle P3, each one is checked TWO ways:
//   1. the raw state-section bytes of a REAL COMPILER-PRODUCED, DEPLOYED
//      locking script, compared against an expected hex string DERIVED BY
//      HAND from the framing rules documented in state.ts (never generated by
//      calling serializeState — that pins whatever serializeState does,
//      correct or not);
//   2. a real spend (call) through the Script VM with broadcast validation,
//      asserting the decoded post-call state.
// -----------------------------------------------------------------------------

/**
 * bigint state edges — hand-derived NUM2BIN-LE8 sign-magnitude words.
 *
 * Rule (state.ts encodeNum2Bin): 8 raw bytes, little-endian MAGNITUDE,
 * zero-padded; if negative, OR 0x80 into byte 7 (the sign lives in the
 * fixed-width word's top bit, never in two's complement). Computed by hand
 * per value below, then cross-checked against the independently-derived
 * conformance/sdk-output/tests/state-bigint-edges-large golden for the large
 * pair (9999999999 -> ffe30b5402000000; negated -> ffe30b5402000080) — the
 * two derivations agree, which is why they are safe to also use in a
 * compiler<->SDK vertical pin rather than only a unit KAT.
 */
const BIGINT_EDGES: Array<{ label: string; value: bigint; hex: string }> = [
  { label: '0', value: 0n, hex: '0000000000000000' },
  { label: '1', value: 1n, hex: '0100000000000000' },
  { label: '-1', value: -1n, hex: '0100000000000080' },
  { label: '127', value: 127n, hex: '7f00000000000000' },
  { label: '128 (magnitude byte 0x80, NOT the sign byte)', value: 128n, hex: '8000000000000000' },
  { label: '-128', value: -128n, hex: '8000000000000080' },
  { label: 'large positive (9999999999)', value: 9999999999n, hex: 'ffe30b5402000000' },
  { label: 'large negative (-9999999999)', value: -9999999999n, hex: 'ffe30b5402000080' },
];

/** A single bigint state field plus an untouched bigint tail (unwritten by bump). */
const BIGINT_CARRIER = `import { StatefulSmartContract } from 'runar-lang';

export class BigIntCarrier extends StatefulSmartContract {
  n: bigint;
  tail: bigint = 0n;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(amount: bigint) {
    this.addOutput(amount, this.n, this.tail);
  }
}
`;

describe('bigint state edges — NUM2BIN-LE8 sign-magnitude, hand-derived against the deployed script', () => {
  for (const { label, value, hex } of BIGINT_EDGES) {
    it(`n=${label}`, async () => {
      const { deployedScript, postCallState } = await deployAndCall(
        BIGINT_CARRIER,
        'BigIntCarrier.runar.ts',
        [value],
        'bump',
        [60_000n],
      );
      // n || tail(=0), each an 8-byte NUM2BIN-LE8 word — no push header.
      expect(stateSectionHex(deployedScript)).toBe(hex + '0000000000000000');

      expect(postCallState.n).toBe(value);
      expect(postCallState.tail).toBe(0n);
    });
  }
});

/**
 * bool state — 1 raw byte, no push header (state.ts encodeStateValue,
 * `case 'bool'/'boolean'`). The comment there records that a real boolean
 * state field once fell through to the push-data DEFAULT branch, which would
 * frame `true` as `0101` (a length-1 push of 0x01) instead of the correct
 * bare `01` — silently shifting every later field's offset by one byte.
 */
const BOOL_CARRIER = `import { StatefulSmartContract } from 'runar-lang';

export class BoolCarrier extends StatefulSmartContract {
  flag: boolean;
  tail: bigint = 0n;
  constructor(flag: boolean) { super(flag); this.flag = flag; }
  public flip(newFlag: boolean, amount: bigint) {
    this.addOutput(amount, newFlag, this.tail);
  }
}
`;

describe('bool state — 1 raw byte, no push header, hand-derived against the deployed script', () => {
  for (const flag of [true, false]) {
    it(`flag=${flag}`, async () => {
      const { deployedScript, postCallState } = await deployAndCall(
        BOOL_CARRIER,
        'BoolCarrier.runar.ts',
        [flag],
        'flip',
        [!flag, 60_000n],
      );
      // flag(1 byte, NOT a length-prefixed push) || tail(=0, 8 bytes).
      expect(stateSectionHex(deployedScript)).toBe((flag ? '01' : '00') + '0000000000000000');

      // WRITE path: flip() rewrites `flag` and must survive a real
      // continuation on the Script VM.
      expect(postCallState.flag).toBe(!flag);
      expect(postCallState.tail).toBe(0n);
    });
  }
});

/**
 * Raw-fixed state class (PubKey, 33 bytes) — raw fixed bytes, NO push header
 * and NO length prefix (state.ts encodeStateValue, `case 'PubKey'`/`'Addr'`/
 * `'Ripemd160'`/`'Sha256'`/`'Point'`). Distinguishes this class from
 * ByteString: a push-data framing bug on a fixed-width type would prepend a
 * length byte (0x21 = 33 for a PubKey) and shift every following field.
 */
const RAW_FIXED_CARRIER = `import { StatefulSmartContract } from 'runar-lang';
import type { PubKey } from 'runar-lang';

export class RawFixedCarrier extends StatefulSmartContract {
  owner: PubKey;
  tail: bigint = 0n;
  constructor(owner: PubKey) { super(owner); this.owner = owner; }
  public bump(amount: bigint) {
    this.addOutput(amount, this.owner, this.tail);
  }
}
`;

describe('raw-fixed state class (PubKey) — raw fixed bytes, no push header', () => {
  it('owner (33-byte compressed PubKey) frames as exactly its own bytes', async () => {
    const ownerHex = PRIV.toPublicKey().toDER('hex') as string;
    expect(ownerHex.length).toBe(66); // 33 bytes — sanity on the fixture itself

    const { deployedScript, postCallState } = await deployAndCall(
      RAW_FIXED_CARRIER,
      'RawFixedCarrier.runar.ts',
      [ownerHex],
      'bump',
      [60_000n],
    );
    // owner (33 raw bytes, no length byte) || tail(=0, 8 bytes).
    expect(stateSectionHex(deployedScript)).toBe(ownerHex + '0000000000000000');

    expect(postCallState.owner).toBe(ownerHex);
    expect(postCallState.tail).toBe(0n);
  });
});

/**
 * Mixed multi-field carrier: bigint + ByteString + bigint. A dangerous
 * OP_N-range ByteString value sandwiched between two signed NUM2BIN-LE8
 * fields, so an off-by-one in the middle field's push-data length would
 * corrupt the FOLLOWING field (`tail`), not just `handle` itself.
 */
const MIXED_CARRIER = `import { StatefulSmartContract } from 'runar-lang';
import type { ByteString } from 'runar-lang';

export class MixedCarrier extends StatefulSmartContract {
  head: bigint;
  handle: ByteString;
  tail: bigint;
  constructor(head: bigint, handle: ByteString, tail: bigint) {
    super(head, handle, tail);
    this.head = head;
    this.handle = handle;
    this.tail = tail;
  }
  public bump(amount: bigint) {
    this.addOutput(amount, this.head, this.handle, this.tail);
  }
}
`;

describe('mixed multi-field carrier — bigint + ByteString + bigint', () => {
  it('a dangerous OP_N-range ByteString sandwiched between two signed bigint fields', async () => {
    const head = -1n; // sign-magnitude 0100000000000080
    const handle = '05'; // the PALMER-2 value class
    const tail = 128n; // magnitude byte 0x80 lands in byte 0, not the sign byte (byte 7)

    const { deployedScript, postCallState } = await deployAndCall(
      MIXED_CARRIER,
      'MixedCarrier.runar.ts',
      [head, handle, tail],
      'bump',
      [60_000n],
    );
    // head: NUM2BIN-LE8(-1); handle: <len><data> (NOT OP_5 — this is the
    // state section, not an executed push); tail: NUM2BIN-LE8(128).
    expect(stateSectionHex(deployedScript)).toBe('0100000000000080' + '0105' + '8000000000000000');

    expect(postCallState.head).toBe(head);
    expect(postCallState.handle).toBe(handle);
    expect(postCallState.tail).toBe(tail);
  });
});

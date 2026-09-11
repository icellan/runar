// ---------------------------------------------------------------------------
// N-070 — `runar deploy --args` on a Rabin-typed constructor slot.
//
// FUNDS LOSS, reproduced end to end. The compiler stamped a `RabinPubKey`
// slot `valueEncoding: 'data'` (it special-cased only the spellings
// `int|bigint|bool|boolean`, and Rabin types are bigint ALIASES).
// `parseConstructorArgs` reads that descriptor and routes the modulus to the
// byte-string branch, which:
//
//   (1) SILENTLY REINTERPRETS a decimal modulus as hex whenever its digit
//       count is even — every decimal digit is also a hex digit. The operator
//       types the 20-digit `12345678901234567890`; the CLI splices the ten
//       bytes 0x12345678901234567890 and OP_MOD reads the modulus
//       682240594432271811228690. An odd digit count is rejected instead,
//       which is how this stayed hidden: the failure is data-dependent.
//
//   (2) ACCEPTS a big-endian hex modulus and pushes it verbatim, while
//       `emitVerifyRabinSig` consumes the slot with OP_MOD — little-endian.
//       `ab54a98ceb1f0ad2` deploys as the modulus 15134435188390955179.
//
// Either way the covenant can never verify and the output is unspendable.
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract, extractConstructorArgs } from 'runar-sdk';
import type { RunarArtifact } from 'runar-sdk';
import { parseConstructorArgs } from '../commands/deploy.js';

const PK = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const MODULUS = 12345678901234567890n;

const ORACLE_SOURCE = `
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

function oracleArtifact(): RunarArtifact {
  const result = compile(ORACLE_SOURCE, { fileName: 'OraclePriceFeed.runar.ts' });
  if (!result.artifact) {
    throw new Error(`fixture failed to compile: ${result.diagnostics.map(d => d.message).join('; ')}`);
  }
  return result.artifact;
}

/** Read the value the Script interpreter will see at a slot: LE sign-magnitude. */
function modulusAsScriptSees(script: string, byteOffset: number): bigint {
  const at = byteOffset * 2;
  const len = parseInt(script.slice(at, at + 2), 16);
  const le = script.slice(at + 2, at + 2 + len * 2);
  const bytes = le.match(/../g)!.map(h => parseInt(h, 16));
  let n = 0n;
  const negative = (bytes[bytes.length - 1]! & 0x80) !== 0;
  bytes[bytes.length - 1]! &= 0x7f;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!);
  return negative ? -n : n;
}

describe('N-070: runar deploy --args on a Rabin modulus', () => {
  it('accepts the decimal modulus a Rabin signer emits and splices what OP_MOD reads', () => {
    const artifact = oracleArtifact();
    const args = parseConstructorArgs(artifact, [MODULUS.toString(), PK]);
    expect(args[0]).toBe(MODULUS);

    const script = new RunarContract(artifact, args).getLockingScript();
    const slot = artifact.constructorSlots!.find(s => s.name === 'oraclePubKey')!;
    expect(modulusAsScriptSees(script, slot.byteOffset)).toBe(MODULUS);

    // Byte-for-byte identical to deploying through the SDK with the bigint.
    expect(script).toBe(new RunarContract(artifact, [MODULUS, PK]).getLockingScript());
  });

  it('an ODD-digit decimal modulus is accepted too (the old hex branch rejected it)', () => {
    const artifact = oracleArtifact();
    const odd = 1234567890123456789n;
    const args = parseConstructorArgs(artifact, [odd.toString(), PK]);
    expect(args[0]).toBe(odd);
    const script = new RunarContract(artifact, args).getLockingScript();
    const slot = artifact.constructorSlots!.find(s => s.name === 'oraclePubKey')!;
    expect(modulusAsScriptSees(script, slot.byteOffset)).toBe(odd);
  });

  it('a 128-byte modulus — the real Rabin size — survives the CLI intact', () => {
    const artifact = oracleArtifact();
    const big = (1n << 1023n) + 12345n;
    const args = parseConstructorArgs(artifact, [big.toString(), PK]);
    const script = new RunarContract(artifact, args).getLockingScript();
    const slot = artifact.constructorSlots!.find(s => s.name === 'oraclePubKey')!;
    const at = slot.byteOffset * 2;
    expect(script.slice(at, at + 4)).toBe('4c81'); // OP_PUSHDATA1 129
    const le = script.slice(at + 4, at + 4 + 129 * 2);
    const bytes = le.match(/../g)!.map(h => parseInt(h, 16));
    let n = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!);
    expect(n).toBe(big);
  });

  // -------------------------------------------------------------------------
  // The funds-loss half: a bare big-endian hex modulus must NOT be silently
  // byte-reversed. Chosen disposition: REJECT. A bare hex string is
  // indistinguishable from a decimal (`12345678901234567890` is valid hex),
  // so accepting it would mean guessing which the operator meant — and the
  // wrong guess is unrecoverable. `0x` makes the intent explicit, so that
  // form is accepted and parsed as a big-endian integer.
  // -------------------------------------------------------------------------
  it('rejects a bare big-endian hex modulus instead of reversing it', () => {
    const artifact = oracleArtifact();
    expect(() => parseConstructorArgs(artifact, ['ab54a98ceb1f0ad2', PK]))
      .toThrow(/oraclePubKey/);
  });

  it('accepts an explicit 0x big-endian modulus and encodes it byte-correctly', () => {
    const artifact = oracleArtifact();
    const args = parseConstructorArgs(artifact, ['0x' + MODULUS.toString(16), PK]);
    expect(args[0]).toBe(MODULUS);
    const script = new RunarContract(artifact, args).getLockingScript();
    expect(script).toBe(new RunarContract(artifact, [MODULUS, PK]).getLockingScript());
  });

  it('a deployed Rabin locking script round-trips back to a bigint', () => {
    const artifact = oracleArtifact();
    const args = parseConstructorArgs(artifact, [MODULUS.toString(), PK]);
    const script = new RunarContract(artifact, args).getLockingScript();
    const extracted = extractConstructorArgs(artifact, script);
    expect(extracted.oraclePubKey).toBe(MODULUS);
    expect(extracted.receiver).toBe(PK);
  });

  // -------------------------------------------------------------------------
  // Fail closed on a STALE artifact: one compiled before this fix carries
  // `valueEncoding: 'data'` on the Rabin slot. Trusting it is the funds bug;
  // the CLI must refuse rather than deploy the reversed modulus.
  // -------------------------------------------------------------------------
  it('refuses a stale artifact whose slot descriptor contradicts its ABI type', () => {
    const artifact = oracleArtifact();
    artifact.constructorSlots!.find(s => s.name === 'oraclePubKey')!.valueEncoding = 'data';
    expect(() => parseConstructorArgs(artifact, [MODULUS.toString(), PK]))
      .toThrow(/recompile/i);
  });

  // -------------------------------------------------------------------------
  // CONTROLS — every other arg form is byte-unchanged.
  // -------------------------------------------------------------------------
  it('CONTROL: a PubKey arg is still hex, and a decimal in its place still throws', () => {
    const artifact = oracleArtifact();
    const args = parseConstructorArgs(artifact, [MODULUS.toString(), PK]);
    expect(args[1]).toBe(PK);
    expect(() => parseConstructorArgs(artifact, [MODULUS.toString(), '12345'])).toThrow(/receiver/);
  });

  it('CONTROL: plain bigint / boolean / ByteString args are unchanged', () => {
    const artifact: RunarArtifact = {
      version: 'runar-v1.0.0-rc.1',
      compilerVersion: '1.0.0-rc.1',
      contractName: 'Mixed',
      parentClass: 'SmartContract',
      abi: {
        constructor: {
          params: [
            { name: 'n', type: 'bigint' },
            { name: 'flag', type: 'boolean' },
            { name: 'blob', type: 'ByteString' },
          ],
        },
        methods: [],
      },
      script: '000000',
      constructorSlots: [
        { paramIndex: 0, byteOffset: 0, name: 'n', type: 'bigint', valueEncoding: 'scriptnum' },
        { paramIndex: 1, byteOffset: 1, name: 'flag', type: 'boolean', valueEncoding: 'bool' },
        { paramIndex: 2, byteOffset: 2, name: 'blob', type: 'ByteString', valueEncoding: 'data' },
      ],
      buildTimestamp: '1970-01-01T00:00:00.000Z',
    } as unknown as RunarArtifact;

    expect(parseConstructorArgs(artifact, ['1000', 'true', 'deadbeef'])).toEqual([1000n, true, 'deadbeef']);
    expect(parseConstructorArgs(artifact, ['-1', 'false', '0xDEADBEEF'])).toEqual([-1n, false, 'deadbeef']);
    expect(() => parseConstructorArgs(artifact, ['1000', 'yes', 'deadbeef'])).toThrow(/flag/);
    expect(() => parseConstructorArgs(artifact, ['1000', 'true', 'zz'])).toThrow(/blob/);
    expect(() => parseConstructorArgs(artifact, ['1000', 'true', 'abc'])).toThrow(/even number of digits/);
  });
});

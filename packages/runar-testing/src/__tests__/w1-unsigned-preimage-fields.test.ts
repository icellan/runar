/**
 * W1 / FinalCountdown — the four unsigned 32-bit BIP-143 preimage fields were
 * decoded as SIGN-MAGNITUDE script numbers.
 *
 * `nVersion`, `nSequence`, `nLockTime` and the trailing sighash type are
 * unsigned 32-bit little-endian fields on the wire. Stack lowering split four
 * bytes off the preimage and ran a bare `OP_BIN2NUM`, and a Bitcoin script
 * number is sign-magnitude: the high bit of the last byte is the SIGN, not the
 * top value bit. So the two values contracts actually meet —
 *
 *     feffffff   0xfffffffe   the SDK's non-final default    read as -2147483646
 *     ffffffff   0xffffffff   the finality sentinel          read as -2147483647
 *
 * — both decoded NEGATIVE, and `extractSequence(p) < 0xffffffffn` (which
 * `02-validate.ts` #131 literally recommends to authors) is TRUE for the
 * sentinel it exists to exclude. A vault gated on
 * `extractLocktime >= deadline` plus that guard is spendable immediately: set
 * `nLockTime` to the deadline, set `nSequence = 0xffffffff`. Consensus ignores
 * `nLockTime` on a final input, and the script's own finality guard passes
 * because it is comparing a negative number.
 *
 * The fix is the pattern the file already used one case over, for varint
 * decoding: `push [0x00] OP_CAT OP_BIN2NUM`, so the four bytes are read as a
 * five-byte non-negative script number.
 *
 * ORACLE. Every claim here is `@bsv/sdk`'s `Spend` — the production script
 * interpreter — never `TestContract` and never the ANF interpreter. The
 * interpreter returns `_mockPreimage.sequence ?? 0xfffffffen` as an unsigned
 * bigint and cannot observe this defect at all; a test written against it
 * would have been green with the bug fully present.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import {
  LockingScript,
  UnlockingScript,
  Spend,
  PrivateKey,
  Hash,
  TransactionSignature,
} from '@bsv/sdk';
import { ScriptExecutionContract } from '../script-execution.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SCOPE = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID;

function bytesToHex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}

function pushDataHex(bytes: Uint8Array): string {
  const hex = bytesToHex(bytes);
  const n = bytes.length;
  if (n === 0) return '00';
  if (n < 0x4c) return n.toString(16).padStart(2, '0') + hex;
  if (n <= 0xff) return '4c' + n.toString(16).padStart(2, '0') + hex;
  if (n <= 0xffff) {
    const lo = (n & 0xff).toString(16).padStart(2, '0');
    const hi = ((n >> 8) & 0xff).toString(16).padStart(2, '0');
    return '4d' + lo + hi + hex;
  }
  throw new Error('push too large');
}

/** Write `v` as an unsigned 32-bit little-endian field at `off`. */
function putU32LE(buf: Uint8Array, off: number, v: number): void {
  buf[off] = v & 0xff;
  buf[off + 1] = (v >>> 8) & 0xff;
  buf[off + 2] = (v >>> 16) & 0xff;
  buf[off + 3] = (v >>> 24) & 0xff;
}

/**
 * What a BARE `OP_BIN2NUM` makes of four little-endian bytes: sign-magnitude,
 * high bit of the last byte is the sign. This is the value the pre-fix lowering
 * put on the stack, and asserting the script does NOT equal it is what keeps
 * these tests from passing for the wrong reason.
 */
function signMagnitude32(v: number): bigint {
  const negative = ((v >>> 24) & 0x80) !== 0;
  const magnitude = BigInt(v >>> 0) & 0x7fffffffn;
  return negative ? -magnitude : magnitude;
}

/**
 * A synthetic BIP-143 preimage. Only the fields these extractors read matter:
 * `nVersion` is the first 4 bytes and the other three are END-relative
 * (`nSequence` at len-44, `nLockTime` at len-8, sighash type at len-4), so the
 * variable-length `scriptCode` in the middle is irrelevant filler here.
 */
function synthPreimage(opts: {
  version: number;
  sequence: number;
  locktime: number;
  sighashType: number;
}): Uint8Array {
  const buf = new Uint8Array(181);
  for (let i = 0; i < buf.length; i++) buf[i] = (i * 7 + 3) & 0xff;
  putU32LE(buf, 0, opts.version);
  putU32LE(buf, buf.length - 44, opts.sequence);
  putU32LE(buf, buf.length - 8, opts.locktime);
  putU32LE(buf, buf.length - 4, opts.sighashType);
  return buf;
}

// ---------------------------------------------------------------------------
// Part A — differential decode of all four fields
// ---------------------------------------------------------------------------

const DECODE_SRC = `import {
  SmartContract, assert, SigHashPreimage,
  extractVersion, extractSequence, extractLocktime, extractSigHashType,
} from 'runar-lang';

export class W1Decode extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) { super(tag); this.tag = tag; }
  public ver(p: SigHashPreimage, n: bigint) { assert(extractVersion(p) === n); }
  public seq(p: SigHashPreimage, n: bigint) { assert(extractSequence(p) === n); }
  public lock(p: SigHashPreimage, n: bigint) { assert(extractLocktime(p) === n); }
  public sht(p: SigHashPreimage, n: bigint) { assert(extractSigHashType(p) === n); }
}
`;

/** The four boundary values: last signed-positive, first signed-negative, the
 *  SDK non-final default, and the finality sentinel. */
const PROBES = [0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff] as const;

type Field = 'ver' | 'seq' | 'lock' | 'sht';
const FIELDS: Field[] = ['ver', 'seq', 'lock', 'sht'];

describe('W1 — the four 32-bit preimage fields decode UNSIGNED', () => {
  const contract = ScriptExecutionContract.fromSource(DECODE_SRC, { tag: 1n }, 'W1Decode.runar.ts');

  /** Build a preimage whose `field` carries `v` and whose other three fields
   *  carry a benign value, so only the field under test can move the verdict. */
  function preimageFor(field: Field, v: number): Uint8Array {
    return synthPreimage({
      version: field === 'ver' ? v : 2,
      sequence: field === 'seq' ? v : 1,
      locktime: field === 'lock' ? v : 1,
      sighashType: field === 'sht' ? v : 0x41,
    });
  }

  for (const field of FIELDS) {
    for (const v of PROBES) {
      const label = `0x${v.toString(16).padStart(8, '0')}`;

      it(`${field}: ${label} decodes to ${v >>> 0}`, () => {
        const p = bytesToHex(preimageFor(field, v));
        const r = contract.execute(field, [p, BigInt(v >>> 0)]);
        expect(r.error, r.error).toBeUndefined();
        expect(r.success).toBe(true);
      });

      const signed = signMagnitude32(v);
      if (signed !== BigInt(v >>> 0)) {
        it(`${field}: ${label} does NOT decode to the sign-magnitude misread ${signed}`, () => {
          const p = bytesToHex(preimageFor(field, v));
          const r = contract.execute(field, [p, signed]);
          expect(r.success).toBe(false);
        });
      }
    }
  }
});

// ---------------------------------------------------------------------------
// Part B — the vault PoC on the real Spend interpreter
// ---------------------------------------------------------------------------

/**
 * The report's time-locked vault, verbatim, including the finality guard the
 * compiler's own #131 diagnostic recommends. `checkPreimage` binds `p` to the
 * spending transaction on chain (BUG-100 construction), so the locktime and
 * sequence the script reads are the ones the node will see.
 */
const VAULT_SRC = `import {
  SmartContract, assert, Sig, PubKey, SigHashPreimage,
  checkSig, checkPreimage, extractLocktime, extractSequence,
} from 'runar-lang';

export class W1Vault extends SmartContract {
  readonly beneficiary: PubKey;
  readonly deadline: bigint;
  constructor(beneficiary: PubKey, deadline: bigint) {
    super(beneficiary, deadline);
    this.beneficiary = beneficiary;
    this.deadline = deadline;
  }
  public claim(sig: Sig, p: SigHashPreimage) {
    assert(checkPreimage(p));
    assert(checkSig(sig, this.beneficiary));
    assert(extractLocktime(p) >= this.deadline);
    assert(extractSequence(p) < 0xffffffffn);
  }
}
`;

const DEADLINE = 2_000_000_000;

describe('W1 — FinalCountdown vault PoC (@bsv/sdk Spend.validate)', () => {
  const priv = PrivateKey.fromRandom();
  const pub = priv.toPublicKey();
  const pubHex = pub.encode(true, 'hex') as string;

  const compiled = compile(VAULT_SRC, {
    fileName: 'W1Vault.runar.ts',
    constructorArgs: { beneficiary: pubHex, deadline: BigInt(DEADLINE) },
  });
  if (!compiled.success || !compiled.scriptHex) {
    throw new Error(
      'vault compile failed: ' +
        compiled.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message).join('; '),
    );
  }
  const lockingHex = compiled.scriptHex;

  /**
   * Build and validate a real single-input spend of the vault.
   *
   * The emitter places `OP_CODESEPARATOR` at offset 1 of a preimage-verifying
   * script (`artifact.codeSeparatorIndex`), so BIP-143 `scriptCode` is the
   * locking script from offset 2 — the same subscript the node computes and
   * the same one `checkPreimage`'s on-chain `_codePart` reconstruction pins.
   */
  function spendVault(lockTime: number, inputSequence: number): { ok: boolean; err?: string } {
    const lockingScript = LockingScript.fromHex(lockingHex);
    const sepIndex = compiled.artifact?.codeSeparatorIndex ?? 1;
    const subscript = LockingScript.fromHex(lockingHex.slice((sepIndex + 1) * 2));

    const ctx = {
      sourceTXID: '00'.repeat(32),
      sourceOutputIndex: 0,
      sourceSatoshis: 100000,
      transactionVersion: 2,
      otherInputs: [] as never[],
      outputs: [] as never[],
      inputIndex: 0,
      inputSequence,
      lockTime,
    };

    const preimage = Uint8Array.from(
      TransactionSignature.formatBytes({ ...ctx, subscript, scope: SCOPE }) as unknown as number[],
    );

    // OP_CHECKSIG digests hash256(preimage); PrivateKey.sign() applies one
    // sha256 internally, so pre-hash once.
    const sig = priv.sign(Hash.sha256(Array.from(preimage)));
    const txSig = new TransactionSignature(sig.r, sig.s, SCOPE);
    const sigHex = bytesToHex(new Uint8Array(txSig.toChecksigFormat()));

    // claim(sig, p) — declared parameter order.
    const unlockingHex = pushDataHex(Buffer.from(sigHex, 'hex')) + pushDataHex(preimage);

    const spend = new Spend({
      ...ctx,
      lockingScript,
      unlockingScript: UnlockingScript.fromHex(unlockingHex),
    });
    try {
      return { ok: spend.validate() };
    } catch (e) {
      return { ok: false, err: e instanceof Error ? e.message : String(e) };
    }
  }

  it('HONEST CONTROL: non-final nSequence 0xfffffffe past the deadline still spends', () => {
    const r = spendVault(DEADLINE, 0xfffffffe);
    expect(r.err, r.err).toBeUndefined();
    expect(r.ok).toBe(true);
  });

  it('THEFT: nSequence 0xffffffff with nLockTime at the deadline is REJECTED', () => {
    // Consensus ignores nLockTime when every input is final, so this spend
    // confirms at any height. The script's finality guard must be what stops
    // it. Before the fix `Spend.validate()` returned true here.
    const r = spendVault(DEADLINE, 0xffffffff);
    expect(r.ok).toBe(false);
  });

  it('THEFT (any height): nSequence 0xffffffff with nLockTime 0 is REJECTED', () => {
    // Same spend with the locktime gate itself unsatisfied — belt and braces
    // that the sequence guard is not the only thing being exercised.
    const r = spendVault(0, 0xffffffff);
    expect(r.ok).toBe(false);
  });
});

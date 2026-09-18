/**
 * W3 / BoolBamboozle — a `boolean` parameter had no on-chain domain check.
 *
 * The source type `boolean` means `{true, false}`. Stack lowering loaded the
 * parameter straight off the unlocking stack and compared it with `OP_EQUAL`,
 * so an exhaustive-looking two-arm split
 *
 *     let authorized = true;
 *     if (useAlice === true)       authorized = checkSig(sigAlice, this.alice);
 *     else if (useAlice === false) authorized = checkSig(sigBob,   this.bob);
 *     assert(authorized);
 *
 * was NOT exhaustive on-chain. The SDK encodes `51` / `00`, but nothing stopped
 * a raw spender from pushing `OP_2` (`52`): it equals neither `OP_1` nor `OP_0`,
 * so NEITHER arm ran, `authorized` kept its stale `true` default, and both
 * `checkSig` calls were skipped. Empty signatures spent the vault.
 *
 * The fix gates every `boolean` parameter of a PUBLIC method once, at the
 * unlocking boundary, in the LOCKING script:
 *
 *     OP_DUP OP_0 OP_EQUAL OP_OVER OP_1 OP_EQUAL OP_BOOLOR OP_VERIFY
 *
 * Deliberately NOT `OP_0NOTEQUAL`: canonicalising to truthiness would turn `2`
 * into `1` and quietly take the Alice arm, which is a different contract than
 * the one the author wrote.
 *
 * ORACLE. `@bsv/sdk` `Spend.validate()` — the production script interpreter.
 * Never `TestContract` and never the ANF interpreter: both model a `boolean`
 * argument as a JS boolean and cannot represent `OP_2` at all, so a test
 * written against either would be green with the bug fully present.
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

// ---------------------------------------------------------------------------
// Contract under test
// ---------------------------------------------------------------------------

/**
 * The report's PoC. `useAlice` is the LAST parameter, so it is the LAST push in
 * the unlocking script and the hex literals below read left-to-right as
 * `<sigAlice> <sigBob> <useAlice>`.
 */
const BOOL_VAULT_SRC = `import { SmartContract, assert, PubKey, Sig, checkSig } from 'runar-lang';

class BoolVault extends SmartContract {
  readonly alice: PubKey;
  readonly bob: PubKey;

  constructor(alice: PubKey, bob: PubKey) {
    super(alice, bob);
    this.alice = alice;
    this.bob = bob;
  }

  public withdraw(sigAlice: Sig, sigBob: Sig, useAlice: boolean): void {
    let authorized: boolean = true;
    if (useAlice === true) {
      authorized = checkSig(sigAlice, this.alice);
    } else if (useAlice === false) {
      authorized = checkSig(sigBob, this.bob);
    }
    assert(authorized);
  }
}
`;

const SCOPE = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID;

const ALICE = PrivateKey.fromString(
  '1'.repeat(63) + '7',
  16,
);
const BOB = PrivateKey.fromString('2'.repeat(63) + '9', 16);

function bytesToHex(b: Uint8Array | number[]): string {
  return Buffer.from(b as number[]).toString('hex');
}

function pushHex(hex: string): string {
  const n = hex.length / 2;
  if (n === 0) return '00';
  if (n < 0x4c) return n.toString(16).padStart(2, '0') + hex;
  if (n <= 0xff) return '4c' + n.toString(16).padStart(2, '0') + hex;
  throw new Error('push too large');
}

function compileVault(): { scriptHex: string; scriptAsm: string } {
  const r = compile(BOOL_VAULT_SRC, {
    fileName: 'BoolVault.runar.ts',
    constructorArgs: {
      alice: ALICE.toPublicKey().encode(true, 'hex') as string,
      bob: BOB.toPublicKey().encode(true, 'hex') as string,
    },
  });
  if (!r.success || !r.scriptHex) {
    throw new Error(
      'compile failed: ' +
        r.diagnostics.filter(d => d.severity === 'error').map(d => d.message).join('; '),
    );
  }
  return { scriptHex: r.scriptHex, scriptAsm: r.scriptAsm ?? '' };
}

interface RunResult {
  success: boolean;
  error?: string;
}

function run(lockingHex: string, unlockingHex: string): RunResult {
  const spend = new Spend({
    sourceTXID: '00'.repeat(32),
    sourceOutputIndex: 0,
    sourceSatoshis: 100000,
    lockingScript: LockingScript.fromHex(lockingHex),
    transactionVersion: 2,
    otherInputs: [],
    outputs: [],
    unlockingScript: UnlockingScript.fromHex(unlockingHex),
    inputIndex: 0,
    inputSequence: 0xffffffff,
    lockTime: 0,
  });
  try {
    return { success: spend.validate() };
  } catch (e: unknown) {
    return { success: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/** A real DER signature over the sighash for `lockingHex`, as a hex push. */
function realSigHex(key: PrivateKey, lockingHex: string): string {
  const preimage = TransactionSignature.formatBytes({
    sourceTXID: '00'.repeat(32),
    sourceOutputIndex: 0,
    sourceSatoshis: 100000,
    transactionVersion: 2,
    otherInputs: [],
    outputs: [],
    inputIndex: 0,
    subscript: LockingScript.fromHex(lockingHex),
    inputSequence: 0xffffffff,
    lockTime: 0,
    scope: SCOPE,
  });
  const digest = Hash.sha256(Array.from(preimage));
  const sig = key.sign(digest);
  return bytesToHex(new TransactionSignature(sig.r, sig.s, SCOPE).toChecksigFormat());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('W3 / BoolBamboozle: boolean parameters are gated to {0, 1} on-chain', () => {
  it('rejects the raw OP_2 witness that skips BOTH arms of an exhaustive split', () => {
    const { scriptHex } = compileVault();

    // <empty sigAlice> <empty sigBob> <OP_2>
    const res = run(scriptHex, '000052');

    expect(res.success).toBe(false);
  });

  it('still rejects the honest-encoded witnesses with junk signatures', () => {
    const { scriptHex } = compileVault();

    // false → Bob arm → empty signature fails OP_CHECKSIG
    expect(run(scriptHex, '000000').success).toBe(false);
    // true → Alice arm → empty signature fails OP_CHECKSIG
    expect(run(scriptHex, '000051').success).toBe(false);
  });

  it('still accepts an honestly encoded boolean with a real signature', () => {
    const { scriptHex } = compileVault();

    // useAlice = true (OP_1) with a valid Alice signature.
    const aliceSig = realSigHex(ALICE, scriptHex);
    const unlockTrue = pushHex(aliceSig) + '00' + '51';
    expect(run(scriptHex, unlockTrue).success).toBe(true);

    // useAlice = false (OP_0) with a valid Bob signature.
    const bobSig = realSigHex(BOB, scriptHex);
    const unlockFalse = '00' + pushHex(bobSig) + '00';
    expect(run(scriptHex, unlockFalse).success).toBe(true);
  });

  it('rejects other non-{0,1} witnesses: -1, 0x00, 0x0001', () => {
    const { scriptHex } = compileVault();

    // OP_1NEGATE
    expect(run(scriptHex, '00004f').success).toBe(false);
    // non-minimal zero: a one-byte 0x00 push is NOT the empty item OP_0 pushes
    expect(run(scriptHex, '0000' + '0100').success).toBe(false);
    // non-minimal one: two-byte 0x0100 push
    expect(run(scriptHex, '0000' + '020100').success).toBe(false);
  });

  it('emits the domain gate in the locking script, not OP_0NOTEQUAL', () => {
    const { scriptAsm } = compileVault();

    expect(scriptAsm).toContain('OP_BOOLOR');
    // OP_0NOTEQUAL would canonicalise 2 -> 1 and silently take the true arm.
    expect(scriptAsm).not.toContain('OP_0NOTEQUAL');
  });
});

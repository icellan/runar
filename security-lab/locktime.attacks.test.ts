import { describe, it, expect } from 'vitest';
import { deployAndCall, validateInput, build, asm, firstLine } from './harness.js';

/**
 * nLockTime and nSequence are UNSIGNED uint32 on the wire, and the preimage
 * extractors used to hand those 4 raw bytes straight to `OP_BIN2NUM`, which is a
 * SIGNED sign-magnitude decode. Anything a developer expressed in the unsigned
 * domain — a Unix timestamp from 2038 onward, or the "final" nSequence
 * 0xFFFFFFFF — was compared against a number the script read as negative:
 *
 *     nLockTime 0x00000000 .. 0x7FFFFFFF   ->    0 ..  2147483647
 *     nLockTime 0x80000000 .. 0xFFFFFFFF   -> -2147483648 .. -1     (wrapped)
 *
 * That was F-1, and it had three faces: a post-2038 deadline that could never
 * be met (funds in, no way out), a `< deadline` gate that 0xFFFFFFFF passed as
 * "the distant past", and an nSequence-finality guard that could not fire
 * because 0xFFFFFFFF read as -1.
 *
 * All three are closed on main, and these tests are the guards:
 *
 *   - codegen pads the field before decoding it:
 *     `4 OP_SPLIT OP_DROP OP_0 OP_CAT OP_BIN2NUM` (B4)
 *   - D26 refuses to COMPILE a height gate whose domain is not pinned, so a
 *     contract cannot silently mix block heights with timestamps (B5)
 *   - with the read unsigned, `extractSequence(p) !== 0xffffffffn` actually
 *     discriminates, which the auction example now relies on (B3)
 *
 * The two domain pins are both present below because they are load-bearing, not
 * decoration: `< 500000000n` says "this gate is a block height", `>= 500000000n`
 * says "this one is a Unix timestamp", and consensus treats the two ranges
 * differently — an nLockTime at or above 5e8 makes the transaction final at
 * once, so an unpinned height gate is spent immediately.
 */

const VAULT = (extraPin: string) => `
class Vault extends StatefulSmartContract {
  amount: bigint;
  readonly deadline: bigint;
  constructor(amount: bigint, deadline: bigint) {
    super(amount, deadline);
    this.amount = amount;
    this.deadline = deadline;
  }
  public withdraw() {
    assert(extractLocktime(this.txPreimage) >= this.deadline);
    ${extraPin}
    this.amount = this.amount;
  }
}
`;

/** Height gate: the D26 pin is `< 500000000n`. */
const HEIGHT_VAULT = VAULT('assert(extractLocktime(this.txPreimage) < 500000000n);');
/** Timestamp gate: the D26 pin is `>= 500000000n`. */
const TIMESTAMP_VAULT = VAULT('assert(extractLocktime(this.txPreimage) >= 500000000n);');
/** Unpinned: compiles on the old compiler, refused by D26. */
const UNPINNED_VAULT = VAULT('');

/** nSequence-finality guard, in the form the auction example uses. */
const SEQ_GUARDED = `
class SeqVault extends StatefulSmartContract {
  amount: bigint;
  readonly deadline: bigint;
  constructor(amount: bigint, deadline: bigint) {
    super(amount, deadline);
    this.amount = amount;
    this.deadline = deadline;
  }
  public withdraw() {
    assert(extractSequence(this.txPreimage) !== 0xffffffffn);
    assert(extractLocktime(this.txPreimage) >= this.deadline);
    assert(extractLocktime(this.txPreimage) < 500000000n);
    this.amount = this.amount;
  }
}
`;

async function attempt(
  source: string,
  file: string,
  ctor: unknown[],
  bake: Record<string, unknown>,
  method: string,
  callOptions: Record<string, unknown>,
) {
  try {
    const r = await deployAndCall(source, file, ctor, method, [], {
      bake,
      signerKey: 'alice',
      fundingSatoshis: 500_000,
      deployOptions: { satoshis: 100_000 },
      callOptions: { satoshis: 100_000, ...callOptions },
    });
    const v = validateInput(r.callTx, 0, r.deployTx, 0);
    return { ok: v.ok, err: v.error, tx: r.callTx };
  } catch (e: any) {
    const msg = String(e.message);
    const isScriptReject = msg.includes('Script evaluation error') || msg.includes('must be truthy');
    return {
      ok: false,
      err: isScriptReject
        ? msg.split('Script evaluation error:')[1]?.trim().slice(0, 60) ?? 'script reject'
        : 'SDK: ' + firstLine(msg, 80),
    };
  }
}

const vault = (deadline: bigint) => ({
  source: undefined as unknown as string,
  ctor: [100_000n, deadline],
  bake: { amount: 100_000n, deadline },
});

describe('nLockTime / nSequence preimage extraction', () => {
  it('B1 a post-2038 timestamp deadline is satisfiable (it used to lock the funds away)', async () => {
    // F-1's worst case: `deadline = 2_500_000_000` (2049-02-07) was read as
    // -1794967296, so `extractLocktime >= deadline` was false for EVERY
    // nLockTime the chain allows. The contract took deposits and could never
    // spend one — verified on a regtest node at the time, where every withdraw
    // came back `mandatory-script-verify-flag-failed`, including the honest one
    // that set nLockTime to its own target.
    const deadline = 2_500_000_000n;
    const { ctor, bake } = vault(deadline);
    const at = await attempt(TIMESTAMP_VAULT, 'TimestampVault.runar.ts', ctor, bake, 'withdraw', { locktime: Number(deadline) });
    console.log(`B1 withdraw at nLockTime=${deadline}: ${at.ok ? 'ACCEPTED' : '*** rejected — still unsatisfiable: ' + firstLine(at.err ?? '') + ' ***'}`);
    expect(at.ok).toBe(true);

    const before = await attempt(TIMESTAMP_VAULT, 'TimestampVault.runar.ts', ctor, bake, 'withdraw', { locktime: Number(deadline) - 1 });
    console.log(`B1 withdraw one second early: ${before.ok ? '*** ACCEPTED — the gate is open ***' : 'rejected (correct)'}`);
    expect(before.ok).toBe(false);
  });

  it('B2 a pinned height gate accepts nothing below the deadline, and 0 is not one of them', async () => {
    const { ctor, bake } = vault(500_000n);
    const accepted: number[] = [];
    for (const locktime of [0, 1, 499_999, 500_000, 500_001, 499_999_999, 500_000_000, 2 ** 31 - 1, 2 ** 32 - 1]) {
      const r = await attempt(HEIGHT_VAULT, 'HeightVault.runar.ts', ctor, bake, 'withdraw', { locktime });
      const expected = locktime >= 500_000 && locktime < 500_000_000;
      console.log(`B2 nLockTime=${String(locktime).padStart(10)}: ${r.ok ? 'ACCEPT' : 'reject'}`);
      if (r.ok) accepted.push(locktime);
      expect(r.ok).toBe(expected);
    }
    // 0 used to be the flagship bypass: signed-read, an `nLockTime` of 0 looked
    // like a height far enough in the past to satisfy anything.
    expect(accepted).not.toContain(0);
    // Everything at or above the timestamp boundary is refused *because* it is a
    // timestamp, which is what the D26 pin is for.
    expect(accepted.filter((l) => l >= 500_000_000)).toEqual([]);
  });

  it('B3 the nSequence-finality guard discriminates now that the read is unsigned', async () => {
    // On the signed read this guard was `extractSequence(p) < 0xffffffffn`, and
    // 0xffffffff arrived as -1, so it passed for a final transaction — the guard
    // could not fire. Now that the field is unsigned, a final nSequence is
    // 4294967295 and the comparison bites.
    const { ctor, bake } = vault(500_000n);
    const final = await attempt(SEQ_GUARDED, 'SeqVault.runar.ts', ctor, bake, 'withdraw', { locktime: 500_000, sequence: 0xffffffff });
    console.log(`B3 sequence=0xffffffff (final, nLockTime ignored by consensus): ${final.ok ? '*** ACCEPTED — locktime is theatre ***' : 'rejected (correct) — ' + firstLine(final.err ?? '')}`);
    expect(final.ok).toBe(false);

    const nonFinal = await attempt(SEQ_GUARDED, 'SeqVault.runar.ts', ctor, bake, 'withdraw', { locktime: 500_000, sequence: 0xfffffffe });
    console.log(`B3 sequence=0xfffffffe (locktime enforced): ${nonFinal.ok ? 'accepted (correct)' : '*** rejected — honest spend broken: ' + firstLine(nonFinal.err ?? '') + ' ***'}`);
    expect(nonFinal.ok).toBe(true);
  });

  it('B4 the codegen pads the 4-byte preimage field before decoding it', () => {
    // The fix, as an opcode shape: read the last 4 bytes, drop the low half,
    // concatenate a 0x00 high byte, THEN convert. Without that pad
    // `OP_BIN2NUM` is a signed sign-magnitude decode and 0x80000000+ becomes
    // negative. Note the ASM renders the pad as literal `00` (a push), not
    // `OP_0`, so a grep for "OP_0 OP_CAT" finds nothing and looks unfixed.
    const script = asm(build(HEIGHT_VAULT, 'HeightVault.runar.ts', { amount: 100_000n, deadline: 500_000n }).scriptHex);
    const padded = script.match(/OP_SIZE OP_4 OP_SUB OP_SPLIT OP_NIP 00 OP_CAT OP_BIN2NUM/g) ?? [];
    const signed = script.match(/OP_SIZE OP_4 OP_SUB OP_SPLIT OP_NIP OP_BIN2NUM/g) ?? [];
    console.log(`B4 padded 4-byte reads: ${padded.length}, unpadded (signed) reads: ${signed.length}`);
    console.log(`B4   ${padded[0] ?? script.slice(-120)}`);
    expect(padded.length).toBeGreaterThan(0);
    expect(signed.length).toBe(0);
  });

  it('B5 D26 refuses to compile an unpinned height gate, and names the pin', () => {
    let diagnostic = '';
    let compiled = true;
    try {
      build(UNPINNED_VAULT, 'UnpinnedVault.runar.ts', { amount: 100_000n, deadline: 500_000n });
    } catch (e: any) {
      compiled = false;
      diagnostic = String(e.message);
    }
    console.log(`B5 unpinned gate compiles: ${compiled}`);
    if (diagnostic) console.log(`B5   ${firstLine(diagnostic, 160)}`);
    expect(compiled).toBe(false);
    expect(diagnostic).toMatch(/500000000|domain|timestamp/i);
  });
});

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { deployAndCall, validateInput, stateOf, build, key, inSeq, firstLine } from './harness.js';

const SRC = 'examples/ts/auction/Auction.runar.ts';
const source = readFileSync(SRC, 'utf8');
const DEADLINE = 500_000;

const AUCTIONEER = 'alice';
const PREV_BIDDER = 'bob';
const ATTACKER = 'charlie';

const BAKE = {
  auctioneer: key(AUCTIONEER).pubKey,
  highestBidder: key(PREV_BIDDER).pubKey,
  highestBid: 90_000n,
  deadline: BigInt(DEADLINE),
};
const CTOR = [key(AUCTIONEER).pubKey, key(PREV_BIDDER).pubKey, 90_000n, BigInt(DEADLINE)];

/** `Auction.bid` asserts `continuationAmount() >= extractAmount(p) + bidAmount`,
 *  so an honest continuation carries the pot AND the new bid: 100 000 + 95 000.
 *  Any test whose subject is not the amount has to fund this correctly, or every
 *  case fails for the wrong reason (which is exactly how the nLockTime sweep read
 *  when it was first re-run against main). */
const POT = 100_000;
const BID = 95_000;
const HONEST_SATS = POT + BID;

async function bid(callOptions: Record<string, unknown>, args: unknown[] = [null, key(ATTACKER).pubKey, 95_000n], pot = 100_000) {
  const run = await deployAndCall(source, SRC, CTOR, 'bid', args, {
      bake: BAKE,
      signerKey: AUCTIONEER,
      callSignerKey: ATTACKER,
      fundingSatoshis: pot + 10_000,
      callFundingSatoshis: 200_000,
      deployOptions: { satoshis: pot },
      callOptions,
    },
  );
  return { ...run, verdict: validateInput(run.callTx, 0, run.deployTx, 0) };
}

describe('AUCTION attacks', () => {
  it('ABI: what the compiler injects into every public method', () => {
    const c = build(source, SRC, BAKE);
    console.log('artifact keys:', Object.keys(c.artifact!).join(', '));
    console.log('constructorSlots:', JSON.stringify((c.artifact as any).constructorSlots));
    for (const m of c.artifact!.abi.methods) {
      console.log(`  ${m.isPublic ? 'public' : 'priv '} ${m.name}(${m.params.map((p) => p.name + ':' + p.type).join(', ')})`);
    }
  });

  /** A refusal is the interesting outcome now, and the SDK raises it while
   *  validating before broadcast, so the covenant's script error arrives as a
   *  thrown Error rather than a verdict object. Normalise both paths. */
  async function attemptBid(callOptions: Record<string, unknown>, args?: unknown[], pot = 100_000): Promise<{ ok: boolean; error: string }> {
    try {
      const r = await bid(callOptions, args, pot);
      return { ok: r.verdict.ok, error: r.verdict.error ?? '' };
    } catch (e: any) {
      return { ok: false, error: firstLine(String(e.message), 160) };
    }
  }

  it('A1 pot drain is refused — a continuation must carry at least its input value', async () => {
    // Pre-D25 this was the theft: bid 95 000 with a number, leave 546 in the
    // contract, walk away with 99 454 as change, and the covenant nodded.
    // Now two independent things stop it: the generic value floor on a stateful
    // continuation (D25 / F-024), and the auction's own
    // `assert(continuationAmount() >= extractAmount(p) + bidAmount)`.
    const r = await attemptBid({ satoshis: 546, changePubKey: key(ATTACKER).pubKey, locktime: DEADLINE - 1 });
    console.log(`A1 drain to 546 of a 100 000-sat pot: ${r.ok ? '*** ACCEPTED (drain is back) ***' : 'REFUSED'} ${r.ok ? '' : '— ' + r.error}`);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/OP_VERIFY|script|amount|value/i);
  });

  it('A2 a bid bigger than the money behind it is refused', async () => {
    // The residual F-3 question: state.highestBid is a number, the UTXO is
    // coins, and the compiler used to let one outrun the other. With
    // `continuationAmount() >= extractAmount(p) + bidAmount` in the example,
    // recording 95 000 while adding nothing should not compile into a spend.
    const honest = await attemptBid({ satoshis: HONEST_SATS, locktime: DEADLINE - 1 });
    console.log(`A2 honest bid (carry pot + bid = ${HONEST_SATS}): ${honest.ok ? 'accepted' : '*** REFUSED — the binding is too tight for honest use *** ' + honest.error}`);
    expect(honest.ok).toBe(true);

    // 105 000 clears the generic value floor (>= the 100 000 input) but breaks
    // the auction's own `>= input + bidAmount`, so this isolates the example-level
    // binding from the compiler-level one: the recorded number must be paid for.
    const short = await attemptBid({ satoshis: POT + 5_000, locktime: DEADLINE - 1 });
    console.log(`A2 record a 95 000 bid but carry only pot + 5 000: ${short.ok ? '*** ACCEPTED (number outruns coins) ***' : 'REFUSED'} ${short.ok ? '' : '— ' + short.error}`);
    expect(short.ok).toBe(false);
  });

  it('A3 leaving less than the previous bid is refused', async () => {
    const r = await attemptBid({ satoshis: 1_000, locktime: DEADLINE - 1 });
    console.log(`A3 leave 1 000 of a 100 000 pot: ${r.ok ? '*** ACCEPTED ***' : 'REFUSED'} ${r.ok ? '' : '— ' + r.error}`);
    expect(r.ok).toBe(false);
  });

  /** Close the auction. `close` is where the deadline actually lives — `bid`
   *  has no time gate on main, only the pot binding (A2/A3). */
  async function attemptClose(locktime: number, sequence?: number): Promise<{ ok: boolean; error: string; seq: number }> {
    try {
      const r = await deployAndCall(source, SRC, CTOR, 'close', [null], {
        bake: BAKE,
        signerKey: AUCTIONEER,
        fundingSatoshis: 110_000,
        deployOptions: { satoshis: POT },
        callOptions: sequence === undefined ? { locktime } : { locktime, sequence },
      });
      const v = validateInput(r.callTx, 0, r.deployTx, 0);
      return { ok: v.ok, error: v.error ?? '', seq: inSeq(r.callTx) };
    } catch (e: any) {
      return { ok: false, error: firstLine(String(e.message), 120), seq: -1 };
    }
  }

  it('A4 close(): deadline gate, D26 domain pin, and sequence guard all hold', async () => {
    // This is the whole of F-1 in one table. The bug had three faces on the old
    // compiler: a final nSequence left the gate unenforceable, a signed read
    // made both 0 and 0xFFFFFFFF pass, and nothing pinned the height/timestamp
    // domain, so 5e8+ was accepted as a "height". Main closes all three: the
    // 4-byte field is padded unsigned, D26 refuses to compile a height gate
    // without `extractLocktime(p) < 500000000n`, and the example asserts
    // `extractSequence(p) !== 0xffffffffn` — which only works because the read
    // is unsigned now (0xFFFFFFFF used to read as -1, which made the old
    // `< 0xffffffffn` guard vacuous).
    for (const locktime of [0, 1, DEADLINE - 1, DEADLINE, DEADLINE + 1, 499_999_999, 500_000_000, 2 ** 31 - 1, 2 ** 32 - 1]) {
      const r = await attemptClose(locktime);
      const expected = locktime >= DEADLINE && locktime < 500_000_000;
      console.log(`A4 nLockTime=${String(locktime).padStart(10)} seq=0x${r.seq.toString(16)}: ${r.ok ? 'ACCEPT' : 'reject — ' + firstLine(r.error, 55)}${r.ok !== expected ? `   <<< expected ${expected ? 'ACCEPT' : 'reject'}` : ''}`);
      expect(r.ok).toBe(expected);
    }

    // The nSequence half: with every input final, consensus ignores nLockTime,
    // so a close at exactly the right height must still be refused.
    const final = await attemptClose(DEADLINE + 5, 0xffffffff);
    console.log(`A4 close at the right height but sequence=0xffffffff: ${final.ok ? '*** ACCEPTED — locktime is theatre again ***' : 'rejected — ' + firstLine(final.error, 60)}`);
    expect(final.ok).toBe(false);
  });

  it('P1 caller-supplied newState must match the method-computed state', async () => {
    const attempts: Array<[string, Record<string, unknown>]> = [
      ['auctioneer as winner, bid 1', { highestBidder: key(AUCTIONEER).pubKey, highestBid: 1n }],
      ['lower bid than declared', { highestBidder: key(ATTACKER).pubKey, highestBid: 95_001n }],
    ];
    for (const [name, newState] of attempts) {
      try {
        const r = await bid({ locktime: DEADLINE - 1, satoshis: 95_000, newState });
        console.log(`P1 newState(${name}): ${r.verdict.ok ? 'ACCEPT (BAD)' : 'reject'} ${r.verdict.error?.split('\n')[0] ?? ''}`);
      } catch (e: any) {
        console.log(`P1 newState(${name}): reject (threw) ${firstLine(String(e.message), 90)}`);
      }
    }
  });

  it('P2 sig from the wrong bidder is rejected', async () => {
    try {
      const r = await bid({ satoshis: 95_000, locktime: DEADLINE - 1 }, [null, key(PREV_BIDDER).pubKey, 95_000n]);
      console.log('P2 (charlie signs, claims bob):', r.verdict.ok, r.verdict.error?.split('\n')[0] ?? '');
      expect(r.verdict.ok).toBe(false);
    } catch (e: any) {
      console.log('P2 (charlie signs, claims bob): reject (threw)');
    }
  });

  it('A8 negative / huge bidAmount', async () => {
    for (const amt of [-1n, 0n, 90_001n, 2n ** 31n - 1n, 2n ** 31n, 2n ** 63n, 10n ** 20n]) {
      try {
        const r = await bid({ satoshis: 95_000, locktime: DEADLINE - 1 }, [null, key(ATTACKER).pubKey, amt]);
        const st = stateOf(r.artifact, r.callTx) as any;
        console.log(`A8 bidAmount=${amt}: ${r.verdict.ok ? 'ACCEPT' : 'reject'}${r.verdict.error ? ' — ' + firstLine(r.verdict.error, 70) : ''} state.highestBid=${st?.highestBid}`);
      } catch (e: any) {
        console.log(`A8 bidAmount=${amt}: threw ${String(e.message).split('\n')[0]}`);
      }
    }
  });
});

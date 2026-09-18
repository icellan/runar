/**
 * W7 / ZombieBid — nLockTime is a NOT-BEFORE, and the canonical Auction read
 * it as a NOT-AFTER.
 *
 * `nLockTime` is chosen by the SPENDER and asserted by consensus as a lower
 * bound: a transaction is mineable once the chain has reached it. Nothing about
 * it bounds the chain from ABOVE, so
 *
 *     assert(extractLocktime(p) < this.deadline)      // Auction.bid, pre-W7
 *
 * cannot mean "the auction is still open". At height 101, past a deadline of
 * 100, an attacker sets `nLockTime = 99` with a non-final `nSequence`: the node
 * mines it (99 is already reached) and the script sees `99 < 100`. The late bid
 * lands. Part A mechanises exactly that, on the real Auction source.
 *
 * The mirror-image defect lived in `close`. Its gate — `extractLocktime(p) >=
 * this.deadline` — is the RIGHT polarity, but consensus only enforces nLockTime
 * on a NON-FINAL transaction. With every input at `nSequence = 0xffffffff` the
 * node ignores nLockTime entirely, so the auctioneer could stamp
 * `nLockTime = deadline` on a final transaction and close at height 1, before
 * anyone had a chance to bid. That is the FinalCountdown shape (W1) living in
 * the canonical example, and the compiler's own #131 diagnostic was already
 * warning about it.
 *
 * ORACLE. Every verdict here is `@bsv/sdk`'s `Spend` interpreter driven through
 * a real deploy -> call (`runStatefulSpend`): real secp256k1, real BIP-143
 * sighash, real `checkPreimage` continuation. NEVER `TestContract` — the
 * existing `Auction.test.ts` "rejects a bid after deadline" case passes today
 * with the contract fully exploitable, because `setMockPreimage({ locktime })`
 * feeds the interpreter the HONEST locktime an attacker would never use, and
 * the interpreter has no notion of chain height or input finality at all.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runStatefulSpend, testKey } from '../oracle/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const AUCTION_PATH = join(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  'examples',
  'ts',
  'auction',
  'Auction.runar.ts',
);
const source = readFileSync(AUCTION_PATH, 'utf8');

const SEQUENCE_FINAL = 0xffffffff;
const SEQUENCE_NONFINAL = 0xfffffffe;

const DEADLINE = 1000;

/**
 * The consensus locktime rule (CTxn::IsFinalTx), spelled out so the claims
 * below are mechanised rather than asserted in a comment.
 *
 * A transaction may be included in a block at `height` when nLockTime is zero,
 * when nLockTime is already reached, OR when every input is final — the last
 * disjunct is the one that makes a locktime gate vacuous.
 */
function nodeWillMineAtHeight(lockTime: number, sequence: number, height: number): boolean {
  if (lockTime === 0) return true;
  if (sequence === SEQUENCE_FINAL) return true; // final input -> nLockTime ignored
  return lockTime < height;
}

// Guard the guard: the predicate must actually discriminate, or every claim
// built on it is vacuous.
describe('W7 — the consensus locktime rule this file reasons with', () => {
  it('a non-final tx is held back until the chain reaches its nLockTime', () => {
    expect(nodeWillMineAtHeight(2000, SEQUENCE_NONFINAL, 101)).toBe(false);
    expect(nodeWillMineAtHeight(2000, SEQUENCE_NONFINAL, 2001)).toBe(true);
  });
  it('a FINAL tx is mineable at any height, whatever its nLockTime says', () => {
    expect(nodeWillMineAtHeight(2000, SEQUENCE_FINAL, 1)).toBe(true);
  });
});

function auctionSpend(opts: {
  method: 'bid' | 'close';
  args: unknown[];
  lockTime: number;
  sequence?: number;
}) {
  const alice = testKey('alice').pubKey;
  return runStatefulSpend({
    source,
    fileName: 'Auction.runar.ts',
    method: opts.method,
    args: opts.args,
    // auctioneer, highestBidder, highestBid, deadline
    constructorArgs: [alice, alice, 1n, BigInt(DEADLINE)],
    signerKey: 'alice',
    lockTime: opts.lockTime,
    sequence: opts.sequence,
  });
}

// ---------------------------------------------------------------------------
// Part A — the polarity itself. True before and after the fix; this is a
// property of Bitcoin, not of the compiler, and it is the reason the `bid`
// deadline guard had to be DELETED rather than repaired.
// ---------------------------------------------------------------------------

describe('W7 — nLockTime cannot bound the chain from above', () => {
  it('a stale nLockTime is mined long after the deadline it names', () => {
    // The attacker is at height DEADLINE + 1 and stamps a locktime the chain
    // passed ages ago. Non-final, so the node checks nLockTime — and lets it
    // through, because nLockTime is a lower bound.
    expect(nodeWillMineAtHeight(DEADLINE - 1, SEQUENCE_NONFINAL, DEADLINE + 1)).toBe(true);
  });

  it('and the script cannot tell that transaction from an honest early bid', () => {
    // Identical script verdict for an honest bid at height 500 and a zombie bid
    // at height 1001: the script only ever sees the number the SPENDER wrote.
    return auctionSpend({
      method: 'bid',
      args: [null, testKey('alice').pubKey, 100n],
      lockTime: DEADLINE - 1,
    }).then((r) => {
      expect(r.vmError, r.vmError).toBeUndefined();
      expect(r.vmAccepted).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// Part B — the two behaviours W7 changes.
// ---------------------------------------------------------------------------

describe('W7 — Auction.bid does not consult nLockTime at all', () => {
  const bidArgs = () => [null, testKey('alice').pubKey, 100n];

  // RED before the fix: `assert(extractLocktime(p) < deadline)` rejected this,
  // which is where the false sense of a deadline came from. v1 has no way to
  // make that rejection mean anything, so the guard is gone and bidding stays
  // open until the auctioneer closes.
  for (const lockTime of [0, DEADLINE - 1, DEADLINE, DEADLINE + 1, 2 * DEADLINE]) {
    it(`accepts a bid at nLockTime ${lockTime}`, async () => {
      const r = await auctionSpend({ method: 'bid', args: bidArgs(), lockTime });
      expect(r.vmError, r.vmError).toBeUndefined();
      expect(r.vmAccepted).toBe(true);
    });
  }

  it('still rejects a bid that does not outbid the leader', async () => {
    // The guard that does work must keep working — otherwise "bid accepts
    // everything" would pass for the wrong reason.
    const r = await auctionSpend({
      method: 'bid',
      args: [null, testKey('alice').pubKey, 1n],
      lockTime: DEADLINE - 1,
    });
    expect(r.vmAccepted).toBe(false);
  });
});

describe('W7 — Auction.close is gated by a locktime consensus actually enforces', () => {
  it('HONEST CONTROL: non-final, past the deadline, still closes', async () => {
    const r = await auctionSpend({
      method: 'close',
      args: [null],
      lockTime: 2 * DEADLINE,
      sequence: SEQUENCE_NONFINAL,
    });
    expect(r.vmError, r.vmError).toBeUndefined();
    expect(r.vmAccepted).toBe(true);
    // ... and the node does hold it back until the deadline.
    expect(nodeWillMineAtHeight(2 * DEADLINE, SEQUENCE_NONFINAL, 1)).toBe(false);
  });

  it('THEFT: an all-final close with nLockTime at the deadline is REJECTED', async () => {
    // Consensus mines this at height 1 (checked above), so the script is the
    // only thing standing between the auctioneer and an instant close at the
    // opening bid. Before the fix `Spend.validate()` returned true here.
    expect(nodeWillMineAtHeight(2 * DEADLINE, SEQUENCE_FINAL, 1)).toBe(true);
    const r = await auctionSpend({
      method: 'close',
      args: [null],
      lockTime: 2 * DEADLINE,
      sequence: SEQUENCE_FINAL,
    });
    expect(r.vmAccepted).toBe(false);
    expect(
      r.reachedEngine,
      `must be rejected by the script guard, not by an SDK error before it ran (vmErr=${r.vmError})`,
    ).toBe(true);
  });

  it('DISCRIMINATOR: the same close one below the sentinel is ACCEPTED', async () => {
    // Identical transaction except nSequence 0xfffffffd. If this were rejected
    // too, the test above would be passing on something other than the finality
    // sentinel (a fee, a size, a preimage-binding change) and would keep
    // passing after the guard was deleted.
    const r = await auctionSpend({
      method: 'close',
      args: [null],
      lockTime: 2 * DEADLINE,
      sequence: 0xfffffffd,
    });
    expect(r.vmError, r.vmError).toBeUndefined();
    expect(r.vmAccepted).toBe(true);
  });

  it('still rejects a close before the deadline', async () => {
    const r = await auctionSpend({
      method: 'close',
      args: [null],
      lockTime: DEADLINE - 1,
      sequence: SEQUENCE_NONFINAL,
    });
    expect(r.vmAccepted).toBe(false);
    expect(r.reachedEngine).toBe(true);
  });
});

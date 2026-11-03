import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, ALICE, BOB, CHARLIE, signTestMessage } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Auction.runar.sol'), 'utf8');
const FILE_NAME = 'Auction.runar.sol';

// ALICE = auctioneer, BOB = bidder A, CHARLIE = bidder B
const AUCTIONEER_SIG = signTestMessage(ALICE.privKey);
const BOB_SIG = signTestMessage(BOB.privKey);
const CHARLIE_SIG = signTestMessage(CHARLIE.privKey);
const DEADLINE = 500000n;
// N-027: the pot the contract UTXO holds before a bid (the mock preimage amount).
const POT = 10_000n;

describe('Auction (Solidity)', () => {
  function makeAuction(highestBid = 0n) {
    const auction = TestContract.fromSource(source, {
      auctioneer: ALICE.pubKey,
      highestBidder: BOB.pubKey,
      highestBid,
      deadline: DEADLINE,
    }, FILE_NAME);
    // Locktime only matters to close(); bid() does not read it (W7).
    auction.setMockPreimage({ locktime: DEADLINE - 1n, amount: POT });
    return auction;
  }

  it('accepts a valid bid above current highest', () => {
    const auction = makeAuction(100n);
    auction.setContinuationAmount(POT + 200n); // N-027: the bid is paid into the pot
    const result = auction.call('bid', { sig: CHARLIE_SIG, bidder: CHARLIE.pubKey, bidAmount: 200n });
    expect(result.success).toBe(true);
    expect(auction.state.highestBid).toBe(200n);
    expect(auction.state.highestBidder).toBe(CHARLIE.pubKey);
  });

  it('rejects a bid that is not paid into the pot (N-027)', () => {
    const auction = makeAuction(100n);
    // Carrying the pot forward unpaid passes F-024's `>= input` floor, not bid's rule.
    for (const continuation of [POT, POT + 199n]) {
      auction.setContinuationAmount(continuation);
      expect(auction.call('bid', { sig: CHARLIE_SIG, bidder: CHARLIE.pubKey, bidAmount: 200n }).success).toBe(false);
    }
    expect(auction.state.highestBid).toBe(100n);
    // The rule is a floor: paying more than the bid is allowed.
    auction.setContinuationAmount(POT + 201n);
    expect(auction.call('bid', { sig: CHARLIE_SIG, bidder: CHARLIE.pubKey, bidAmount: 200n }).success).toBe(true);
  });

  it('rejects a bid below current highest', () => {
    const auction = makeAuction(100n);
    const result = auction.call('bid', { sig: CHARLIE_SIG, bidder: CHARLIE.pubKey, bidAmount: 50n });
    expect(result.success).toBe(false);
  });

  // W7: this used to be "rejects a bid after deadline", asserted by putting
  // DEADLINE + 1 into the MOCK locktime. That test passed while the contract
  // was fully exploitable: nLockTime is a spender-chosen NOT-BEFORE (a late
  // bidder writes DEADLINE - 1 and the node mines it), and `TestContract` has
  // no notion of chain height or input finality. The guard is gone; bidding is
  // open until the auctioneer closes. Spend-level coverage lives in
  // packages/runar-testing/src/__tests__/w7-auction-locktime-polarity.test.ts.
  it('accepts a bid whatever the locktime says — v1 cannot close the window', () => {
    const auction = makeAuction(100n);
    auction.setMockPreimage({ locktime: DEADLINE + 1n });
    auction.setContinuationAmount(POT + 200n);
    const result = auction.call('bid', { sig: CHARLIE_SIG, bidder: CHARLIE.pubKey, bidAmount: 200n });
    expect(result.success).toBe(true);
    expect(auction.state.highestBid).toBe(200n);
  });

  it('allows close after deadline', () => {
    const auction = makeAuction(100n);
    auction.setMockPreimage({ locktime: DEADLINE });
    const result = auction.call('close', { sig: AUCTIONEER_SIG });
    expect(result.success).toBe(true);
  });

  it('rejects close before deadline', () => {
    const auction = makeAuction(100n);
    auction.setMockPreimage({ locktime: DEADLINE - 1n });
    const result = auction.call('close', { sig: AUCTIONEER_SIG });
    expect(result.success).toBe(false);
  });

  it('tracks multiple bids in sequence', () => {
    const auction = makeAuction(0n);

    // N-027: each bid adds itself to the pot; the next bid's input is that pot.
    auction.setContinuationAmount(POT + 100n);
    expect(auction.call('bid', { sig: BOB_SIG, bidder: BOB.pubKey, bidAmount: 100n }).success).toBe(true);
    expect(auction.state.highestBid).toBe(100n);

    auction.setMockPreimage({ amount: POT + 100n });
    auction.setContinuationAmount(POT + 100n + 200n);
    expect(auction.call('bid', { sig: CHARLIE_SIG, bidder: CHARLIE.pubKey, bidAmount: 200n }).success).toBe(true);
    expect(auction.state.highestBid).toBe(200n);
    expect(auction.state.highestBidder).toBe(CHARLIE.pubKey);
  });
});

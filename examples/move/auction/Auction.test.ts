import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, ALICE, BOB, CHARLIE, signTestMessage } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Auction.runar.move'), 'utf8');
const FILE_NAME = 'Auction.runar.move';

// ALICE = auctioneer, BOB = bidder A, CHARLIE = bidder B
const AUCTIONEER_SIG = signTestMessage(ALICE.privKey);
const BOB_SIG = signTestMessage(BOB.privKey);
const CHARLIE_SIG = signTestMessage(CHARLIE.privKey);
const DEADLINE = 500000n;

describe('Auction (Move)', () => {
  function makeAuction(highestBid = 0n) {
    const auction = TestContract.fromSource(source, {
      auctioneer: ALICE.pubKey,
      highestBidder: BOB.pubKey,
      highestBid,
      deadline: DEADLINE,
    }, FILE_NAME);
    // Set locktime before deadline (bidding is open)
    auction.setMockPreimage({ locktime: DEADLINE - 1n });
    return auction;
  }

  it('accepts a valid bid above current highest', () => {
    const auction = makeAuction(100n);
    const result = auction.call('bid', { sig: CHARLIE_SIG, bidder: CHARLIE.pubKey, bidAmount: 200n });
    expect(result.success).toBe(true);
    expect(auction.state.highestBid).toBe(200n);
    expect(auction.state.highestBidder).toBe(CHARLIE.pubKey);
  });

  it('rejects a bid below current highest', () => {
    const auction = makeAuction(100n);
    const result = auction.call('bid', { sig: CHARLIE_SIG, bidder: CHARLIE.pubKey, bidAmount: 50n });
    expect(result.success).toBe(false);
  });

  it('rejects a bid after deadline', () => {
    const auction = makeAuction(100n);
    auction.setMockPreimage({ locktime: DEADLINE + 1n });
    const result = auction.call('bid', { sig: CHARLIE_SIG, bidder: CHARLIE.pubKey, bidAmount: 200n });
    expect(result.success).toBe(false);
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

    auction.call('bid', { sig: BOB_SIG, bidder: BOB.pubKey, bidAmount: 100n });
    expect(auction.state.highestBid).toBe(100n);

    auction.call('bid', { sig: CHARLIE_SIG, bidder: CHARLIE.pubKey, bidAmount: 200n });
    expect(auction.state.highestBid).toBe(200n);
    expect(auction.state.highestBidder).toBe(CHARLIE.pubKey);
  });
});

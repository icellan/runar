import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Auction.runar.ts'), 'utf8');

const AUCTIONEER = '02' + 'aa'.repeat(32);
const BIDDER_A = '02' + 'bb'.repeat(32);
const BIDDER_B = '02' + 'cc'.repeat(32);
const MOCK_SIG = '30' + 'ff'.repeat(35);
const DEADLINE = 500000n;

describe('Auction', () => {
  function makeAuction(highestBid = 0n) {
    const auction = TestContract.fromSource(source, {
      auctioneer: AUCTIONEER,
      highestBidder: BIDDER_A,
      highestBid,
      deadline: DEADLINE,
    });
    // Set locktime before deadline (bidding is open)
    auction.setMockPreimage({ locktime: DEADLINE - 1n });
    return auction;
  }

  it('accepts a valid bid above current highest', () => {
    const auction = makeAuction(100n);
    const result = auction.call('bid', { sig: MOCK_SIG, bidder: BIDDER_B, bidAmount: 200n });
    expect(result.success).toBe(true);
    expect(auction.state.highestBid).toBe(200n);
    expect(auction.state.highestBidder).toBe(BIDDER_B);
  });

  it('rejects a bid below current highest', () => {
    const auction = makeAuction(100n);
    const result = auction.call('bid', { sig: MOCK_SIG, bidder: BIDDER_B, bidAmount: 50n });
    expect(result.success).toBe(false);
  });

  it('rejects a bid after deadline', () => {
    const auction = makeAuction(100n);
    auction.setMockPreimage({ locktime: DEADLINE + 1n });
    const result = auction.call('bid', { sig: MOCK_SIG, bidder: BIDDER_B, bidAmount: 200n });
    expect(result.success).toBe(false);
  });

  it('allows close after deadline', () => {
    const auction = makeAuction(100n);
    auction.setMockPreimage({ locktime: DEADLINE });
    const result = auction.call('close', { sig: MOCK_SIG });
    expect(result.success).toBe(true);
  });

  it('rejects close before deadline', () => {
    const auction = makeAuction(100n);
    auction.setMockPreimage({ locktime: DEADLINE - 1n });
    const result = auction.call('close', { sig: MOCK_SIG });
    expect(result.success).toBe(false);
  });

  it('tracks multiple bids in sequence', () => {
    const auction = makeAuction(0n);

    auction.call('bid', { sig: MOCK_SIG, bidder: BIDDER_A, bidAmount: 100n });
    expect(auction.state.highestBid).toBe(100n);

    auction.call('bid', { sig: MOCK_SIG, bidder: BIDDER_B, bidAmount: 200n });
    expect(auction.state.highestBid).toBe(200n);
    expect(auction.state.highestBidder).toBe(BIDDER_B);
  });
});

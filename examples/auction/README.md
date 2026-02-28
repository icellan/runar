# Auction

A stateful on-chain auction contract with time-locked bidding and closing phases.

## What it does

Implements a simple ascending-price auction. Funds are locked in the contract, and participants can place bids until a deadline. After the deadline, the auctioneer can close the auction.

- **Bid** -- anyone can place a bid that is higher than the current highest bid, as long as the deadline has not passed. The contract state updates with the new highest bidder and bid amount.
- **Close** -- only the auctioneer can close the auction, and only after the deadline has passed. No state continuation occurs; the auction is finalized.

## Design pattern

**Stateful contract with time locks** -- combines mutable state (`highestBidder`, `highestBid`) with locktime-based conditions extracted from the transaction preimage. The `extractLocktime()` function reads the nLockTime field from the spending transaction to enforce temporal constraints. Immutable fields (`auctioneer`, `deadline`) set the rules that govern the auction lifecycle.

## TSOP features demonstrated

- Time-lock enforcement via `extractLocktime(txPreimage)`
- Multiple stateful fields updated atomically
- Mixed `readonly` and mutable properties
- Two distinct spending paths with different authorization and timing rules
- OP_PUSH_TX for state continuity during bidding
- Terminal method (close) with no state continuation

## Compile and use

```bash
tsop compile Auction.tsop.ts
```

Deploy with the auctioneer's public key, an initial bidder/bid (can be zero), and a block height deadline. Bidders construct transactions with `nLockTime` set appropriately. The auctioneer closes after the deadline by providing a signature and a preimage from a transaction with `nLockTime >= deadline`.

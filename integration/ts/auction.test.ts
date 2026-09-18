/**
 * Auction integration test — stateful contract (SDK Deploy path).
 *
 * Auction is a StatefulSmartContract with properties:
 *   - auctioneer: PubKey (readonly)
 *   - highestBidder: PubKey (mutable)
 *   - highestBid: bigint (mutable)
 *   - deadline: bigint (readonly)
 *
 * Methods:
 *   - bid(sig: Sig, bidder: PubKey, bidAmount: bigint) — requires bidder's Sig
 *   - close(sig: Sig) — requires auctioneer's Sig + a consensus-enforced deadline
 *
 * The bid() method requires the bidder's signature (prevents griefing) and reads
 * no preimage field: nLockTime is a spender-chosen NOT-BEFORE and cannot bound
 * the chain from above, so v1 has no deadline on bidding (W7). The close()
 * method requires the auctioneer's Sig, `extractLocktime >= deadline`, and
 * `extractSequence !== 0xffffffff` — without the second the first is a no-op
 * on an all-final transaction. Both bid paths are complex enough to warrant raw
 * tx construction for spending. We test compile + deploy via the SDK. Full
 * spending tests are covered by the Go integration suite (auction_test.go and
 * auction_locktime_test.go).
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet, createWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

describe('Auction', () => {
  it('should compile the Auction contract', () => {
    const artifact = compileContract('examples/ts/auction/Auction.runar.ts');
    expect(artifact).toBeTruthy();
    expect(artifact.contractName).toBe('Auction');
  });

  it('should deploy with auctioneer, initial bidder, bid, and deadline', async () => {
    const artifact = compileContract('examples/ts/auction/Auction.runar.ts');

    const provider = createProvider();
    const auctioneer = createWallet();
    const initialBidder = createWallet();
    const { signer } = await createFundedWallet(provider);

    // Constructor: (auctioneer: PubKey, highestBidder: PubKey, highestBid: bigint, deadline: bigint)
    const contract = new RunarContract(artifact, [
      auctioneer.pubKeyHex,
      initialBidder.pubKeyHex,
      1000n,
      1000000n, // deadline far in the future
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();
    expect(typeof deployTxid).toBe('string');
    expect(deployTxid.length).toBe(64);
  });

  it('should deploy with zero initial bid', async () => {
    const artifact = compileContract('examples/ts/auction/Auction.runar.ts');

    const provider = createProvider();
    const auctioneer = createWallet();
    const initialBidder = createWallet();
    const { signer } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [
      auctioneer.pubKeyHex,
      initialBidder.pubKeyHex,
      0n,
      500000n,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();
  });

  it('should deploy with same key as auctioneer and initial bidder', async () => {
    const artifact = compileContract('examples/ts/auction/Auction.runar.ts');

    const provider = createProvider();
    const auctioneerAndBidder = createWallet();
    const { signer } = await createFundedWallet(provider);

    // Same key for both roles
    const contract = new RunarContract(artifact, [
      auctioneerAndBidder.pubKeyHex,
      auctioneerAndBidder.pubKeyHex,
      500n,
      999999n,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();
  });

  // NOTE: bid() spending tests require raw transaction construction. The Go
  // integration tests cover the bid scenario.

  it('should close the auction with auctioneer signature', async () => {
    const artifact = compileContract('examples/ts/auction/Auction.runar.ts');

    const provider = createProvider();
    const initialBidder = createWallet();
    const { signer, pubKeyHex } = await createFundedWallet(provider);

    // Auctioneer is the funded signer so null Sig auto-computes correctly.
    // G5: a REAL non-zero block-height deadline paired with a matching
    // CallOptions.locktime, mirroring integration/rust/tests/auction.rs. The old
    // deadline=0 + nLockTime=0 combination made
    // `extractLocktime(txPreimage) >= deadline` vacuously true, so a regression
    // in the SDK's locktime threading (or in extractLocktime codegen) would not
    // have been caught here. nLockTime=1 is safely in the past, so the tx is
    // immediately mineable — but if the SDK stopped writing the locktime into
    // the preimage, the preimage would carry 0 and `0 >= 1` would fail the spend.
    const DEADLINE = 1n;
    const contract = new RunarContract(artifact, [
      pubKeyHex,
      initialBidder.pubKeyHex,
      1000n,
      DEADLINE,
    ]);

    await contract.deploy(provider, signer, {});

    // null Sig is auto-computed from the signer (who is the auctioneer)
    // close() does not continue state, so no newState needed
    const { txid: callTxid } = await contract.call(
      'close', [null], provider, signer, { locktime: Number(DEADLINE) },
    );
    expect(callTxid).toBeTruthy();
    expect(callTxid.length).toBe(64);
  });

  it('should reject close with wrong signer', async () => {
    const artifact = compileContract('examples/ts/auction/Auction.runar.ts');

    const provider = createProvider();
    const initialBidder = createWallet();
    // Deploy with auctioneer=walletA
    const { signer: auctioneerSigner, pubKeyHex: auctioneerPubKey } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [
      auctioneerPubKey,
      initialBidder.pubKeyHex,
      1000n,
      1n, // non-zero block-height deadline (see the close test above)
    ]);

    await contract.deploy(provider, auctioneerSigner, {});

    // Call close with walletB — checkSig will fail on-chain. locktime is set so
    // the ONLY reason for rejection is the wrong signer, not an unsatisfied
    // deadline.
    const { signer: wrongSigner } = await createFundedWallet(provider);

    await expect(
      contract.call('close', [null], provider, wrongSigner, { locktime: 1 }),
    ).rejects.toThrow();
  });
});

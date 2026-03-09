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
 *   - bid(sig: Sig, bidder: PubKey, bidAmount: bigint) — requires bidder's Sig + extractLocktime
 *   - close(sig: Sig) — requires auctioneer's Sig
 *
 * The bid() method requires the bidder's signature (prevents griefing) and checks
 * extractLocktime(this.txPreimage) < this.deadline, which constrains the
 * transaction's nLockTime. The close() method requires the auctioneer's Sig. Both
 * bid paths are complex enough to warrant raw tx construction for spending. We test
 * compile + deploy via the SDK. Full spending tests are covered by the Go
 * integration suite (auction_test.go).
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

  // NOTE: bid() spending tests require raw transaction construction because
  // extractLocktime checks nLockTime against the deadline. The Go integration
  // tests cover the bid scenario.

  it('should close the auction with auctioneer signature', async () => {
    const artifact = compileContract('examples/ts/auction/Auction.runar.ts');

    const provider = createProvider();
    const initialBidder = createWallet();
    const { signer, pubKeyHex } = await createFundedWallet(provider);

    // Auctioneer is the funded signer so null Sig auto-computes correctly.
    // deadline=0 so extractLocktime(txPreimage) >= deadline passes with nLocktime=0
    const contract = new RunarContract(artifact, [
      pubKeyHex,
      initialBidder.pubKeyHex,
      1000n,
      0n,
    ]);

    await contract.deploy(provider, signer, {});

    // null Sig is auto-computed from the signer (who is the auctioneer)
    // close() does not continue state, so no newState needed
    const { txid: callTxid } = await contract.call(
      'close', [null], provider, signer,
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
      0n, // deadline=0 so extractLocktime passes
    ]);

    await contract.deploy(provider, auctioneerSigner, {});

    // Call close with walletB — checkSig will fail on-chain
    const { signer: wrongSigner } = await createFundedWallet(provider);

    await expect(
      contract.call('close', [null], provider, wrongSigner),
    ).rejects.toThrow();
  });
});

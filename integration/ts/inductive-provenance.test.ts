/**
 * InductiveSmartContract provenance integration test — on-chain regtest.
 *
 * Tests the core properties of inductive contracts:
 *
 *   Part 1 — Legitimate chain: Deploy → Tx1 (genesis) → Tx2 → Tx3
 *     Verifies that the SDK correctly manages the _genesisOutpoint field
 *     and that the real Bitcoin node accepts each transaction's script execution.
 *
 *   Part 2 — Forgery / rejection tests:
 *     - Tampered state (hashOutputs mismatch)
 *     - Wrong signer (checkSig failure)
 *     - Overspend (assert(amount <= balance) failure)
 *     - Independent lineage separation (two chains, same code, different genesis)
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet, createWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

// ---------------------------------------------------------------------------
// Zero sentinels for internal fields.
// The ABI requires 5 constructor args: 3 user + 2 internal fields.
// ---------------------------------------------------------------------------
const ZERO_SENTINEL = '00'.repeat(36);
const ZERO_PROOF = '00'.repeat(256);

/** Helper: create an InductiveToken RunarContract with proper constructor args. */
function createInductiveToken(
  artifact: ReturnType<typeof compileContract>,
  ownerPubKey: string,
  balance: bigint,
  tokenIdHex: string,
): InstanceType<typeof RunarContract> {
  // Constructor ABI: (owner, balance, tokenId, _genesisOutpoint, _proof)
  return new RunarContract(artifact, [
    ownerPubKey,
    balance,
    tokenIdHex,
    ZERO_SENTINEL,
    ZERO_PROOF,
  ]);
}

// Inductive scripts are ~75 KB. 500K sats covers script + fees comfortably.
const DEPLOY_SATS = 500_000;

describe('InductiveSmartContract — Provenance Security', () => {
  // =========================================================================
  // Part 1: Legitimate chain (must succeed)
  // =========================================================================
  describe('Part 1 — Legitimate chain: Deploy → Tx1 → Tx2 → Tx3', () => {
    it('should chain 4 sends (deploy + 3 spends), verifying lineage on-chain', async () => {
      const artifact = compileContract(
        'examples/ts/inductive-token/InductiveToken.runar.ts',
      );
      const provider = createProvider();
      const { signer, pubKeyHex } = await createFundedWallet(provider, 2.0);
      const tokenIdHex = Buffer.from('CHAIN-4-DEEP').toString('hex');

      const contract = createInductiveToken(artifact, pubKeyHex, 1000n, tokenIdHex);

      // --- Deploy (Genesis UTXO) ---
      const { txid: deployTxid } = await contract.deploy(provider, signer, {
        satoshis: DEPLOY_SATS,
      });
      expect(deployTxid).toBeTruthy();
      expect(deployTxid.length).toBe(64);

      // --- Tx1: First spend (genesis detection branch) ---
      // _genesisOutpoint == zero sentinel → genesis branch:
      //   _genesisOutpoint = extractOutpoint(txPreimage)
      const { txid: tx1id } = await contract.call(
        'send',
        [null, pubKeyHex, 1n],
        provider,
        signer,
        { newState: { owner: pubKeyHex }, satoshis: 1 },
      );
      expect(tx1id).toBeTruthy();
      expect(tx1id.length).toBe(64);

      // --- Tx2: Second spend (non-genesis branch) ---
      const { txid: tx2id } = await contract.call(
        'send',
        [null, pubKeyHex, 1n],
        provider,
        signer,
        { newState: { owner: pubKeyHex }, satoshis: 1 },
      );
      expect(tx2id).toBeTruthy();

      // --- Tx3: Third spend (depth 3) ---
      const { txid: tx3id } = await contract.call(
        'send',
        [null, pubKeyHex, 1n],
        provider,
        signer,
        { newState: { owner: pubKeyHex }, satoshis: 1 },
      );
      expect(tx3id).toBeTruthy();
    });

    it('should chain transfer (multi-output split) preserving lineage', async () => {
      const artifact = compileContract(
        'examples/ts/inductive-token/InductiveToken.runar.ts',
      );
      const provider = createProvider();
      const { signer, pubKeyHex } = await createFundedWallet(provider, 2.0);
      const recipient = createWallet();
      const tokenIdHex = Buffer.from('SPLIT-CHAIN').toString('hex');

      const contract = createInductiveToken(artifact, pubKeyHex, 1000n, tokenIdHex);
      await contract.deploy(provider, signer, { satoshis: DEPLOY_SATS });

      // Tx1: genesis — send to self
      await contract.call('send', [null, pubKeyHex, 1n], provider, signer, {
        newState: { owner: pubKeyHex },
        satoshis: 1,
      });

      // Tx2: transfer (multi-output split) — 300 to recipient, 700 to self.
      const { txid: splitTxid } = await contract.call(
        'transfer',
        [null, recipient.pubKeyHex, 300n, 1n],
        provider,
        signer,
        {
          outputs: [
            {
              satoshis: 1,
              state: { owner: recipient.pubKeyHex, balance: 300n },
            },
            { satoshis: 1, state: { owner: pubKeyHex, balance: 700n } },
          ],
          continuationOutputIndex: 1,
        },
      );
      expect(splitTxid).toBeTruthy();

      // Tx3: send from the 700-balance continuation (depth 3)
      const { txid: tx3id } = await contract.call(
        'send',
        [null, pubKeyHex, 1n],
        provider,
        signer,
        { newState: { owner: pubKeyHex }, satoshis: 1 },
      );
      expect(tx3id).toBeTruthy();
    });
  });

  // =========================================================================
  // Part 2: Forgery & rejection tests (must fail)
  // =========================================================================
  describe('Part 2 — Forgery and rejection tests', () => {
    /**
     * Tampered state test (hashOutputs mismatch).
     *
     * The internal lineage fields are part of the state in the UTXO's locking
     * script. The on-chain script hashes ALL outputs and compares against
     * extractOutputHash from the BIP-143 preimage. If ANY state field is
     * wrong — user field or internal field — the hash won't match.
     */
    it('should reject tampered state (hashOutputs mismatch)', async () => {
      const artifact = compileContract(
        'examples/ts/inductive-token/InductiveToken.runar.ts',
      );
      const provider = createProvider();
      const { signer, pubKeyHex } = await createFundedWallet(provider, 2.0);
      const tokenIdHex = Buffer.from('TAMPER-TEST').toString('hex');

      const contract = createInductiveToken(artifact, pubKeyHex, 1000n, tokenIdHex);
      await contract.deploy(provider, signer, { satoshis: DEPLOY_SATS });

      // Tx1: genesis
      await contract.call('send', [null, pubKeyHex, 1n], provider, signer, {
        newState: { owner: pubKeyHex },
        satoshis: 1,
      });

      // Tx2: claim balance=9999 instead of 1000 → hashOutputs mismatch
      await expect(
        contract.call('send', [null, pubKeyHex, 1n], provider, signer, {
          newState: { owner: pubKeyHex, balance: 9999n },
          satoshis: 1,
        }),
      ).rejects.toThrow();
    });

    /**
     * Wrong signer test: even with correct lineage, a wrong key cannot spend.
     * assert(checkSig(sig, this.owner)) will fail.
     */
    it('should reject a call with wrong signer (checkSig failure)', async () => {
      const artifact = compileContract(
        'examples/ts/inductive-token/InductiveToken.runar.ts',
      );
      const provider = createProvider();
      const { signer: ownerSigner, pubKeyHex: ownerPubKey } =
        await createFundedWallet(provider, 2.0);
      const { signer: attackerSigner } = await createFundedWallet(provider);
      const tokenIdHex = Buffer.from('SIGNER-TEST').toString('hex');

      const contract = createInductiveToken(artifact, ownerPubKey, 1000n, tokenIdHex);
      await contract.deploy(provider, ownerSigner, { satoshis: DEPLOY_SATS });

      // Tx1: genesis (legitimate owner signs)
      await contract.call(
        'send',
        [null, ownerPubKey, 1n],
        provider,
        ownerSigner,
        { newState: { owner: ownerPubKey }, satoshis: 1 },
      );

      // Tx2: attacker tries to spend with wrong key → checkSig fails
      await expect(
        contract.call(
          'send',
          [null, ownerPubKey, 1n],
          provider,
          attackerSigner,
          { newState: { owner: ownerPubKey }, satoshis: 1 },
        ),
      ).rejects.toThrow();
    });

    /**
     * Transfer amount validation: assert(amount <= this.balance) fails
     * when trying to transfer more than available.
     */
    it('should reject transfer of more than available balance', async () => {
      const artifact = compileContract(
        'examples/ts/inductive-token/InductiveToken.runar.ts',
      );
      const provider = createProvider();
      const { signer, pubKeyHex } = await createFundedWallet(provider, 2.0);
      const recipient = createWallet();
      const tokenIdHex = Buffer.from('OVERSPEND-TEST').toString('hex');

      const contract = createInductiveToken(artifact, pubKeyHex, 100n, tokenIdHex);
      await contract.deploy(provider, signer, { satoshis: DEPLOY_SATS });

      // Tx1: genesis
      await contract.call('send', [null, pubKeyHex, 1n], provider, signer, {
        newState: { owner: pubKeyHex },
        satoshis: 1,
      });

      // Tx2: try to transfer 200 when balance is only 100 → assert fails
      await expect(
        contract.call(
          'transfer',
          [null, recipient.pubKeyHex, 200n, 1n],
          provider,
          signer,
          {
            outputs: [
              {
                satoshis: 1,
                state: { owner: recipient.pubKeyHex, balance: 200n },
              },
              {
                satoshis: 1,
                state: { owner: pubKeyHex, balance: -100n },
              },
            ],
            continuationOutputIndex: 1,
          },
        ),
      ).rejects.toThrow();
    });

    /**
     * Cross-lineage test: two independent inductive chains with the same
     * contract code but different deployments have different genesis outpoints.
     */
    it('should maintain independent lineages for separate deployments', async () => {
      const artifact = compileContract(
        'examples/ts/inductive-token/InductiveToken.runar.ts',
      );
      const provider = createProvider();
      const { signer, pubKeyHex } = await createFundedWallet(provider, 3.0);
      const tokenIdHex = Buffer.from('LINEAGE-TEST').toString('hex');

      // Chain A
      const chainA = createInductiveToken(artifact, pubKeyHex, 500n, tokenIdHex);
      const { txid: deployA } = await chainA.deploy(provider, signer, {
        satoshis: DEPLOY_SATS,
      });

      // Chain B (same code, same tokenId, different deployment)
      const chainB = createInductiveToken(artifact, pubKeyHex, 500n, tokenIdHex);
      const { txid: deployB } = await chainB.deploy(provider, signer, {
        satoshis: DEPLOY_SATS,
      });

      expect(deployA).not.toBe(deployB);

      // Tx1 on each chain (genesis detection)
      const { txid: a1 } = await chainA.call(
        'send', [null, pubKeyHex, 1n], provider, signer,
        { newState: { owner: pubKeyHex }, satoshis: 1 },
      );

      const { txid: b1 } = await chainB.call(
        'send', [null, pubKeyHex, 1n], provider, signer,
        { newState: { owner: pubKeyHex }, satoshis: 1 },
      );

      // Tx2 on each chain (non-genesis — full parent verification)
      const { txid: a2 } = await chainA.call(
        'send', [null, pubKeyHex, 1n], provider, signer,
        { newState: { owner: pubKeyHex }, satoshis: 1 },
      );

      const { txid: b2 } = await chainB.call(
        'send', [null, pubKeyHex, 1n], provider, signer,
        { newState: { owner: pubKeyHex }, satoshis: 1 },
      );

      expect(a1).toBeTruthy();
      expect(b1).toBeTruthy();
      expect(a2).toBeTruthy();
      expect(b2).toBeTruthy();
    });

    /**
     * Depth-4 chain with ownership transfer at each step.
     * Tests that inductive verification works when owner changes between txs.
     */
    it('should verify lineage across ownership changes', async () => {
      const artifact = compileContract(
        'examples/ts/inductive-token/InductiveToken.runar.ts',
      );
      const provider = createProvider();

      const alice = await createFundedWallet(provider, 2.0);
      const bob = await createFundedWallet(provider, 1.0);
      const charlie = await createFundedWallet(provider, 1.0);
      const tokenIdHex = Buffer.from('TRANSFER-CHAIN').toString('hex');

      const contract = createInductiveToken(
        artifact, alice.pubKeyHex, 100n, tokenIdHex,
      );
      await contract.deploy(provider, alice.signer, { satoshis: DEPLOY_SATS });

      // Tx1: Alice sends to Bob (genesis)
      await contract.call(
        'send',
        [null, bob.pubKeyHex, 1n],
        provider,
        alice.signer,
        { newState: { owner: bob.pubKeyHex }, satoshis: 1 },
      );

      // Tx2: Bob sends to Charlie (non-genesis — verifies Tx1)
      await contract.call(
        'send',
        [null, charlie.pubKeyHex, 1n],
        provider,
        bob.signer,
        { newState: { owner: charlie.pubKeyHex }, satoshis: 1 },
      );

      // Tx3: Charlie sends back to Alice (depth 3 — verifies Tx2)
      const { txid: tx3id } = await contract.call(
        'send',
        [null, alice.pubKeyHex, 1n],
        provider,
        charlie.signer,
        { newState: { owner: alice.pubKeyHex }, satoshis: 1 },
      );
      expect(tx3id).toBeTruthy();
    });
  });
});

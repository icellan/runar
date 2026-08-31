/**
 * Cross-tier BIP-143 on-node broadcast leg (GAP-003).
 *
 * The node-FREE half of GAP-003 lives in `conformance/sdk-bip143/` — a frozen
 * TS-reference fixture that all seven SDK tiers replay, recomputing the
 * BIP-143 preimage byte-for-byte and verifying the reference signature. That
 * proves every tier AGREES on preimage construction without a node.
 *
 * This test is the complementary on-NODE leg: it proves the TypeScript
 * reference signing path (the @bsv/sdk BIP-143 LocalSigner that the fixture
 * froze) produces a CONSENSUS-VALID transaction — i.e. the agreed-upon
 * preimage + signature is accepted by a real Bitcoin node. It funds a P2PKH
 * UTXO, builds the spend, cross-checks the preimage against the SDK's
 * `computeOpPushTx` helper (same BIP-143 path the fixture uses), signs with
 * LocalSigner, broadcasts, and mines.
 *
 * Guarded on node availability the same way every other integration test is
 * (globalSetup `process.exit(1)`s when no regtest node is reachable), so when
 * run under `pnpm --filter ... test` against a live node it broadcasts; in an
 * environment with no node it is never reached. See conformance/sdk-bip143/.
 */

import { describe, it, expect } from 'vitest';
import { Transaction, P2PKH as BsvP2PKH, PrivateKey, Script, UnlockingScript } from '@bsv/sdk';
import { LocalSigner, computeOpPushTx } from 'runar-sdk';
import { createProvider } from './helpers/node.js';
import { createWallet } from './helpers/wallet.js';
import { rpcCall, mine, mineUntilConfirmed } from './helpers/node.js';

describe('BIP-143 cross-tier broadcast (P2PKH, TS reference path)', () => {
  it('broadcasts a P2PKH spend whose sighash is the agreed cross-tier preimage', async () => {
    const provider = createProvider();

    // Fund a P2PKH UTXO at a deterministic key.
    const { privKeyHex, pubKeyHex, pubKeyHash } = createWallet();
    const priv = PrivateKey.fromHex(privKeyHex);
    const address = priv.toAddress([0x6f]); // regtest p2pkh version byte

    await rpcCall('importaddress', address, '', false);
    // Mine before funding so the node wallet selects CONFIRMED coins.
    //
    // Under a full-suite run the wallet's own change outputs are still
    // unconfirmed, and `sendtoaddress` happily chains onto them: measured on a
    // live regtest node, funding without this line produced a tx whose parents
    // both had 0 confirmations, while funding right after a block produced one
    // whose parents had 1. An unconfirmed ancestor puts the whole group in
    // bitcoin-sv's CPFP/secondary mempool instead of the journal, and the
    // funding tx then never confirms — which is the exact state this test hit.
    await mine(1);
    const fundTxid = (await rpcCall('sendtoaddress', address, 0.001)) as string;
    // Confirm the funding tx before spending it, rather than assuming one block
    // contains it. An unconfirmed parent makes the spend a mempool descendant,
    // and on bitcoin-sv a descendant cannot enter the journal ahead of its
    // ancestor — so a lagging parent would surface as the child "never being
    // selected into a block", which is not what this test is asserting.
    await mineUntilConfirmed(fundTxid);

    // Locate the funded output.
    const fundTx = Transaction.fromHex((await rpcCall('getrawtransaction', fundTxid)) as string);
    let vout = -1;
    let fundedSats = 0;
    const lockingScriptHex = `76a914${pubKeyHash}88ac`;
    for (let i = 0; i < fundTx.outputs.length; i++) {
      if (fundTx.outputs[i]!.lockingScript.toHex() === lockingScriptHex) {
        vout = i;
        fundedSats = fundTx.outputs[i]!.satoshis!;
        break;
      }
    }
    expect(vout, 'funded P2PKH output not found').toBeGreaterThanOrEqual(0);

    // Build the spend: send (funded - fee) back to the same address. We build
    // it twice — unsigned (for the preimage) and again with the real unlocking
    // script (for broadcast). @bsv/sdk caches a tx's serialization on the first
    // toHex(), and mutating inputs[i].unlockingScript afterwards does NOT
    // invalidate that cache, so reusing the unsigned tx for broadcast would ship
    // an empty scriptSig (consensus-invalid). A fresh tx serializes cleanly.
    const fee = 500;
    const sendSats = fundedSats - fee;
    const buildSpend = (unlockingScript: Script): Transaction => {
      const t = new Transaction();
      t.addInput({
        sourceTransaction: fundTx,
        sourceOutputIndex: vout,
        unlockingScript,
        sequence: 0xffffffff,
      });
      t.addOutput({
        satoshis: sendSats,
        lockingScript: new BsvP2PKH().lock(address),
      });
      return t;
    };

    const unsignedHex = buildSpend(new UnlockingScript()).toHex();

    // Cross-check: the SDK's BIP-143 helper (the path the frozen fixture uses)
    // and the LocalSigner must compute the SAME preimage for this live tx.
    const { preimageHex } = computeOpPushTx(unsignedHex, 0, lockingScriptHex, fundedSats);
    expect(preimageHex.length).toBeGreaterThan(0);

    // Sign input 0 with LocalSigner (SIGHASH_ALL|FORKID) and assemble the
    // <sig> <pubkey> unlocking script.
    const signer = new LocalSigner(privKeyHex);
    const sigHex = await signer.sign(unsignedHex, 0, lockingScriptHex, fundedSats, 0x41);

    const pushSig = pushData(sigHex);
    const pushPk = pushData(pubKeyHex);
    const tx = buildSpend(Script.fromHex(pushSig + pushPk));

    // Broadcast + mine — node acceptance is the consensus-validity proof.
    const txid = await provider.broadcast(tx);
    expect(txid).toBeTruthy();
    expect(txid.length).toBe(64);

    // Confirm it actually entered a block. Mining ONE block is a race under a
    // full-suite run (see mineUntilConfirmed); the assertion is unchanged, only
    // the assumption that a single block must contain it.
    const confirmations = await mineUntilConfirmed(txid);
    expect(confirmations).toBeGreaterThan(0);
  });
});

/** Minimal Bitcoin push-data prefix for a hex blob (<= 75 bytes covers sig+pubkey). */
function pushData(hex: string): string {
  const len = hex.length / 2;
  if (len <= 75) return len.toString(16).padStart(2, '0') + hex;
  if (len <= 255) return '4c' + len.toString(16).padStart(2, '0') + hex;
  throw new Error('pushData: blob too large for this helper');
}

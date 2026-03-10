/**
 * Unit tests for OP_CODESEPARATOR signing behavior in the SDK.
 *
 * These tests were created to catch two bugs discovered in integration tests:
 *
 * 1. **Stateful terminal methods without terminalOutputs** pushed _codePart
 *    onto the stack even though the method doesn't consume it, causing
 *    CLEANSTACK violations.
 *
 * 2. **User Sig sighash scriptCode** was trimmed at OP_CODESEPARATOR for all
 *    contracts, but stateless contracts have checkSig BEFORE the separator,
 *    so the sighash must use the full locking script.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import type { RunarArtifact } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PROJECT_ROOT = resolve(import.meta.dirname, '..', '..', '..', '..');

function compileContract(sourcePath: string): RunarArtifact {
  const absPath = resolve(PROJECT_ROOT, sourcePath);
  const source = readFileSync(absPath, 'utf-8');
  const fileName = absPath.split('/').pop()!;
  const result = compile(source, { fileName });
  if (!result.artifact) {
    throw new Error(`Compile failed: ${JSON.stringify(result.errors)}`);
  }
  return result.artifact;
}

function compileSource(source: string, fileName: string): RunarArtifact {
  const result = compile(source, { fileName });
  if (!result.artifact) {
    throw new Error(`Compile failed: ${JSON.stringify(result.errors)}`);
  }
  return result.artifact;
}

const PRIV_KEY =
  '0000000000000000000000000000000000000000000000000000000000000001';

async function setupFundedProvider(
  satoshis: number,
): Promise<{ provider: MockProvider; signer: LocalSigner; address: string; pubKeyHex: string }> {
  const signer = new LocalSigner(PRIV_KEY);
  const address = await signer.getAddress();
  const pubKeyHex = await signer.getPublicKey();
  const provider = new MockProvider();
  provider.addUtxo(address, {
    txid: 'aa'.repeat(32),
    outputIndex: 0,
    satoshis,
    script: '76a914' + '00'.repeat(20) + '88ac',
  });
  return { provider, signer, address, pubKeyHex };
}

// Minimal tx hex parser — extracts unlocking scripts from inputs.
function parseUnlockingScripts(txHex: string): string[] {
  let offset = 0;
  function readHex(n: number): string {
    const s = txHex.slice(offset, offset + n * 2);
    offset += n * 2;
    return s;
  }
  function readUint32LE(): number {
    const h = readHex(4);
    const b = [];
    for (let i = 0; i < 8; i += 2) b.push(parseInt(h.slice(i, i + 2), 16));
    return (b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) >>> 0;
  }
  function readVarInt(): number {
    const first = parseInt(readHex(1), 16);
    if (first < 0xfd) return first;
    if (first === 0xfd) {
      const h = readHex(2);
      return parseInt(h.slice(0, 2), 16) | (parseInt(h.slice(2, 4), 16) << 8);
    }
    throw new Error('Unsupported varint');
  }

  readUint32LE(); // version
  const inputCount = readVarInt();
  const scripts: string[] = [];
  for (let i = 0; i < inputCount; i++) {
    readHex(32); // prevTxid
    readUint32LE(); // prevIndex
    const scriptLen = readVarInt();
    scripts.push(readHex(scriptLen));
    readUint32LE(); // sequence
  }
  return scripts;
}

// Count pushdata items in an unlocking script (rough: each pushdata opcode
// starts a new item).
function countPushdataItems(scriptHex: string): number {
  let count = 0;
  let i = 0;
  while (i < scriptHex.length) {
    const opcode = parseInt(scriptHex.slice(i, i + 2), 16);
    i += 2;
    if (opcode === 0) {
      count++;
    } else if (opcode >= 1 && opcode <= 75) {
      count++;
      i += opcode * 2;
    } else if (opcode === 76) { // OP_PUSHDATA1
      const len = parseInt(scriptHex.slice(i, i + 2), 16);
      i += 2;
      count++;
      i += len * 2;
    } else if (opcode === 77) { // OP_PUSHDATA2
      const lo = parseInt(scriptHex.slice(i, i + 2), 16);
      const hi = parseInt(scriptHex.slice(i + 2, i + 4), 16);
      i += 4;
      count++;
      i += (lo | (hi << 8)) * 2;
    } else if (opcode >= 79 && opcode <= 96) {
      // OP_1NEGATE, OP_1..OP_16
      count++;
    } else {
      // Non-push opcodes — shouldn't appear in unlocking script
      break;
    }
  }
  return count;
}

// ---------------------------------------------------------------------------
// Test: stateful terminal method without terminalOutputs
// ---------------------------------------------------------------------------

describe('OP_CODESEPARATOR: stateful terminal method without terminalOutputs', () => {
  it('should not push _codePart for terminal methods (close method)', async () => {
    // Auction has two methods: bid (non-terminal) and close (terminal).
    // Calling close without terminalOutputs goes through the non-terminal SDK
    // path. The SDK must NOT push _codePart for close because the compiled
    // script doesn't consume it (methodUsesCodePart returns false).
    const artifact = compileContract('examples/ts/auction/Auction.runar.ts');

    // Verify the artifact has OP_CODESEPARATOR
    expect(artifact.codeSeparatorIndex).toBeDefined();
    expect(artifact.codeSeparatorIndices).toBeDefined();

    const { provider, signer, pubKeyHex } = await setupFundedProvider(100_000);

    const otherWallet = new LocalSigner(
      '0000000000000000000000000000000000000000000000000000000000000002',
    );
    const otherPubKey = await otherWallet.getPublicKey();

    const contract = new RunarContract(artifact, [
      pubKeyHex,       // auctioneer
      otherPubKey,     // highestBidder
      1000n,           // highestBid
      0n,              // deadline=0 so extractLocktime check passes
    ]);

    await contract.deploy(provider, signer, { satoshis: 50_000 });

    // Call close WITHOUT terminalOutputs — this was the failing pattern.
    // Before the fix, this pushed _codePart causing CLEANSTACK.
    const result = await contract.call('close', [null], provider, signer);
    expect(result.txid).toBeTruthy();
    expect(result.txid.length).toBe(64);

    // Verify the unlocking script: should have the right number of items.
    // For close(sig) on a stateful contract with 2 methods:
    //   <opPushTxSig> <sig> <txPreimage> <methodSelector>
    // = 4 items. If _codePart were erroneously pushed, there would be 5.
    const broadcastedTxs = provider.getBroadcastedTxs();
    const callTx = broadcastedTxs[broadcastedTxs.length - 1]!;
    const unlocks = parseUnlockingScripts(callTx);
    // First input is the contract input
    const contractUnlock = unlocks[0]!;
    const itemCount = countPushdataItems(contractUnlock);
    // 4 items: opPushTxSig, sig, txPreimage, methodSelector
    expect(itemCount).toBe(4);
  });

  it('should push _codePart for non-terminal methods (bid method)', async () => {
    // bid() creates continuation outputs, so it DOES need _codePart.
    const artifact = compileContract('examples/ts/auction/Auction.runar.ts');

    const { provider, signer, pubKeyHex } = await setupFundedProvider(100_000);

    const bidderSigner = new LocalSigner(
      '0000000000000000000000000000000000000000000000000000000000000002',
    );
    const bidderPubKey = await bidderSigner.getPublicKey();

    const contract = new RunarContract(artifact, [
      pubKeyHex,       // auctioneer
      pubKeyHex,       // highestBidder (self initially)
      100n,            // highestBid
      999999999n,      // deadline far in the future
    ]);

    await contract.deploy(provider, signer, { satoshis: 50_000 });

    // bid(sig, bidder, bidAmount) — non-terminal, state-mutating
    const result = await contract.call(
      'bid',
      [null, bidderPubKey, 200n],
      provider, signer,
    );
    expect(result.txid).toBeTruthy();

    // Verify the unlocking script has _codePart.
    // For bid(sig, bidder, bidAmount) on a stateful contract with 2 methods:
    //   <codePart> <opPushTxSig> <sig> <bidder> <bidAmount> <changePKH> <changeAmount> <txPreimage> <methodSelector>
    // = 9 items.
    const broadcastedTxs = provider.getBroadcastedTxs();
    const callTx = broadcastedTxs[broadcastedTxs.length - 1]!;
    const unlocks = parseUnlockingScripts(callTx);
    const contractUnlock = unlocks[0]!;
    const itemCount = countPushdataItems(contractUnlock);
    // 10 items: codePart + opPushTxSig + sig + bidder + bidAmount + changePKH + changeAmount + newAmount + txPreimage + methodSelector
    expect(itemCount).toBe(10);
  });
});

// ---------------------------------------------------------------------------
// Test: NFT burn (stateful terminal) without terminalOutputs
// ---------------------------------------------------------------------------

describe('OP_CODESEPARATOR: NFT burn without terminalOutputs', () => {
  it('should not push _codePart for burn method', async () => {
    const artifact = compileContract('examples/ts/token-nft/NFTExample.runar.ts');

    expect(artifact.codeSeparatorIndex).toBeDefined();

    const { provider, signer, pubKeyHex } = await setupFundedProvider(100_000);

    const tokenIdHex = Buffer.from('NFT-TEST').toString('hex');
    const metadataHex = Buffer.from('Test NFT').toString('hex');

    const contract = new RunarContract(artifact, [
      pubKeyHex,
      tokenIdHex,
      metadataHex,
    ]);

    await contract.deploy(provider, signer, { satoshis: 50_000 });

    // burn(sig) — terminal method, no continuation output
    const result = await contract.call('burn', [null], provider, signer);
    expect(result.txid).toBeTruthy();
    expect(result.txid.length).toBe(64);
  });
});

// ---------------------------------------------------------------------------
// Test: stateless contract with checkSig + checkPreimage
// ---------------------------------------------------------------------------

describe('OP_CODESEPARATOR: stateless contract user sig scriptCode', () => {
  it('CovenantVault: user checkSig before OP_CODESEPARATOR uses full script', async () => {
    // CovenantVault is stateless. Its spend() method has:
    //   checkSig(sig, owner)   — BEFORE OP_CODESEPARATOR
    //   checkPreimage(preimage) — AFTER OP_CODESEPARATOR
    // The user's sig must be computed with the full locking script, not the
    // post-separator subscript.
    const artifact = compileContract(
      'examples/ts/covenant-vault/CovenantVault.runar.ts',
    );

    expect(artifact.codeSeparatorIndex).toBeDefined();
    // Verify OP_CODESEPARATOR (0xab) exists in the base script
    expect(artifact.script).toContain('ab');

    const { provider, signer, pubKeyHex } = await setupFundedProvider(100_000);

    const recipientSigner = new LocalSigner(
      '0000000000000000000000000000000000000000000000000000000000000002',
    );
    const recipientPubKey = await recipientSigner.getPublicKey();
    // hash160 of the recipient public key
    const { Hash, Utils } = await import('@bsv/sdk');
    const recipientPKH = Utils.toHex(
      Hash.hash160(Utils.toArray(recipientPubKey, 'hex')),
    );

    const contract = new RunarContract(artifact, [
      pubKeyHex,    // owner
      recipientPKH, // recipient (hash160)
      1000n,        // minAmount
    ]);

    await contract.deploy(provider, signer, { satoshis: 50_000 });

    // Build the expected P2PKH payout script for the recipient
    const payoutScript = '76a914' + recipientPKH + '88ac';

    // spend(sig, txPreimage) as terminal with correct output
    const result = await contract.call(
      'spend',
      [null, null],
      provider,
      signer,
      {
        terminalOutputs: [
          { scriptHex: payoutScript, satoshis: 1000 },
        ],
      },
    );
    expect(result.txid).toBeTruthy();
    expect(result.txid.length).toBe(64);
  });

  it('stateless checkSig is before OP_CODESEPARATOR in compiled script', () => {
    // Verify the script structure: checkSig (0xad = OP_CHECKSIGVERIFY)
    // appears before the OP_CODESEPARATOR (0xab).
    const artifact = compileContract(
      'examples/ts/covenant-vault/CovenantVault.runar.ts',
    );

    const script = artifact.script;
    const codeSepOffset = artifact.codeSeparatorIndex!;

    // The base script (before constructor substitution) has OP_CHECKSIGVERIFY
    // at a position before the code separator.
    const checksigPos = script.indexOf('ad'); // OP_CHECKSIGVERIFY
    expect(checksigPos).toBeLessThan(codeSepOffset * 2);
    expect(checksigPos).toBeGreaterThanOrEqual(0);
  });
});

// ---------------------------------------------------------------------------
// Test: inline stateful contract with single terminal method
// ---------------------------------------------------------------------------

describe('OP_CODESEPARATOR: single-method stateful terminal', () => {
  it('should work without terminalOutputs for a single-method terminal contract', async () => {
    // A minimal stateful contract with one terminal method (no addOutput).
    // This tests the simplest case: no method selector, no _codePart needed.
    const source = `
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class SimpleClose extends StatefulSmartContract {
  readonly owner: PubKey;
  counter: bigint;

  constructor(owner: PubKey, counter: bigint) {
    super(owner, counter);
    this.owner = owner;
    this.counter = counter;
  }

  public close(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }
}
`;
    const artifact = compileSource(source, 'SimpleClose.runar.ts');
    expect(artifact.codeSeparatorIndex).toBeDefined();

    const { provider, signer, pubKeyHex } = await setupFundedProvider(100_000);

    const contract = new RunarContract(artifact, [pubKeyHex, 0n]);
    await contract.deploy(provider, signer, { satoshis: 50_000 });

    // Call without terminalOutputs — SDK takes non-terminal path
    const result = await contract.call('close', [null], provider, signer);
    expect(result.txid).toBeTruthy();

    // Verify no _codePart in unlock (single method = no method selector either)
    // Expected items: <opPushTxSig> <sig> <txPreimage> = 3 items
    const broadcastedTxs = provider.getBroadcastedTxs();
    const callTx = broadcastedTxs[broadcastedTxs.length - 1]!;
    const unlocks = parseUnlockingScripts(callTx);
    const contractUnlock = unlocks[0]!;
    const itemCount = countPushdataItems(contractUnlock);
    expect(itemCount).toBe(3);
  });
});

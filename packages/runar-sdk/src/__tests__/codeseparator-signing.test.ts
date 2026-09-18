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
import { buildP2PKHScript } from '../script-utils.js';
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

// --- opcode-boundary scanning ----------------------------------------------
//
// Locating an opcode by `scriptHex.indexOf('ab')` is not locating an opcode.
// A hex substring search matches at ODD nibble offsets (the low nibble of one
// byte plus the high nibble of the next), and it matches PUSH DATA — a 33-byte
// PubKey constructor arg containing a 0xab byte is not an OP_CODESEPARATOR.
// Both failure modes are proved below in "RED-PROOF: hex-substring scanning".
//
// This walk is a deliberate minimal re-implementation. The fuller version in
// conformance/sdk-vertical/reference/script.ts is a REFERENCE implementation
// that imports nothing from packages/** on purpose; importing it here would
// invert that dependency.

const OP_PUSHDATA1 = 0x4c;
const OP_PUSHDATA2 = 0x4d;
const OP_PUSHDATA4 = 0x4e;
const OP_CODESEPARATOR = 0xab;
const OP_CHECKSIGVERIFY = 0xad;

/** Byte offset of every real opcode in `scriptHex`, in order. */
function opcodeOffsets(scriptHex: string): { offset: number; opcode: number }[] {
  if (scriptHex.length % 2 !== 0) {
    throw new Error(`script hex has odd length ${scriptHex.length}`);
  }
  const total = scriptHex.length / 2;
  const byteAt = (i: number): number => {
    if (i < 0 || i >= total) throw new Error(`script read past end at byte ${i} of ${total}`);
    return parseInt(scriptHex.slice(i * 2, i * 2 + 2), 16);
  };

  const ops: { offset: number; opcode: number }[] = [];
  let i = 0;
  while (i < total) {
    const opcode = byteAt(i);
    ops.push({ offset: i, opcode });
    if (opcode >= 0x01 && opcode <= 0x4b) i += 1 + opcode;
    else if (opcode === OP_PUSHDATA1) i += 2 + byteAt(i + 1);
    else if (opcode === OP_PUSHDATA2) i += 3 + (byteAt(i + 1) | (byteAt(i + 2) << 8));
    else if (opcode === OP_PUSHDATA4)
      i +=
        5 +
        (byteAt(i + 1) |
          (byteAt(i + 2) << 8) |
          (byteAt(i + 3) << 16) |
          byteAt(i + 4) * 0x1000000);
    else i += 1;
  }
  // A push whose length runs off the end leaves `i > total`. That is a
  // malformed script, not a script with no matches.
  if (i !== total) throw new Error(`script does not decode cleanly: ended at ${i} of ${total}`);
  return ops;
}

/** Byte offsets at which `opcode` appears as an OPCODE (never inside push data). */
function findOpcode(scriptHex: string, opcode: number): number[] {
  return opcodeOffsets(scriptHex)
    .filter((o) => o.opcode === opcode)
    .map((o) => o.offset);
}

const PRIV_KEY =
  '0000000000000000000000000000000000000000000000000000000000000001';

async function setupFundedProvider(
  satoshis: number,
): Promise<{ provider: MockProvider; signer: LocalSigner; address: string; pubKeyHex: string }> {
  const signer = new LocalSigner(PRIV_KEY);
  const address = await signer.getAddress();
  const pubKeyHex = await signer.getPublicKey();
  const provider = new MockProvider('testnet');
  provider.addUtxo(address, {
    txid: 'aa'.repeat(32),
    outputIndex: 0,
    satoshis,
    script: buildP2PKHScript(pubKeyHex),
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
// RED-PROOF: hex-substring scanning is not opcode scanning
// ---------------------------------------------------------------------------
//
// Two assertions in this file used to locate opcodes with a hex-STRING search:
//
//   expect(artifact.script).toContain('ab');   // "OP_CODESEPARATOR exists"
//   const checksigPos = script.indexOf('ad');  // "OP_CHECKSIGVERIFY is here"
//
// Neither locates an opcode. The tests below feed both the scripts they cannot
// tell apart: the old form PASSES on a script that contains no such opcode at
// all, while the opcode walk correctly reports none. That is what makes the
// replacement a real assertion rather than a reworded one.

describe('RED-PROOF: hex-substring scanning is not opcode scanning', () => {
  it('indexOf("ad") matches at an ODD NIBBLE offset, where no opcode begins', () => {
    // OP_1 OP_DROP <0xba> <0xda> OP_1 — bytes: 51 75 ba da 51. There is no
    // 0xad byte anywhere, yet 'ad' spans the low nibble of 0xba and the high
    // nibble of 0xda.
    const script = '5175bada51';

    // The OLD assertion is satisfied — it "found" OP_CHECKSIGVERIFY.
    expect(script.indexOf('ad')).toBeGreaterThanOrEqual(0);
    expect(script.indexOf('ad') % 2).toBe(1); // ...at an odd nibble: not a byte

    // The opcode walk knows better.
    expect(findOpcode(script, OP_CHECKSIGVERIFY)).toEqual([]);
  });

  it('toContain("ab") matches a 0xab byte INSIDE a push, which is data not an opcode', () => {
    // OP_PUSHDATA1 33 <33 bytes, one of them 0xab> — a PubKey constructor arg,
    // exactly the shape this suite's fixtures splice in. No OP_CODESEPARATOR.
    const pubkey = '02' + 'ab'.repeat(32); // 33 bytes: 0x02 then 32 x 0xab
    const script = '4c21' + pubkey + '75'; // PUSHDATA1 33 <pubkey> OP_DROP
    expect(pubkey.length / 2).toBe(33);

    // The OLD assertion is satisfied — it "found" OP_CODESEPARATOR.
    expect(script).toContain('ab');

    // The opcode walk knows better: every 0xab is push payload.
    expect(findOpcode(script, OP_CODESEPARATOR)).toEqual([]);
  });

  it('the walk still finds an opcode that IS at a byte boundary', () => {
    // Same push, now genuinely followed by OP_CODESEPARATOR OP_CHECKSIGVERIFY.
    const pubkey = '02' + 'ab'.repeat(32);
    const script = '4c21' + pubkey + 'ab' + 'ad';
    expect(findOpcode(script, OP_CODESEPARATOR)).toEqual([35]);
    expect(findOpcode(script, OP_CHECKSIGVERIFY)).toEqual([36]);
  });

  it('rejects a script whose push runs off the end instead of reporting "no matches"', () => {
    // PUSHDATA1 claiming 33 bytes with only 2 present. A silent decode would
    // report an empty match list, which reads identically to "opcode absent".
    expect(() => findOpcode('4c210102', OP_CODESEPARATOR)).toThrow(/does not decode cleanly|past end/);
  });
});

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
      1n,              // deadline: non-zero, so `extractLocktime >= deadline`
                       // is not vacuously true (W7 — the old deadline=0 made
                       // it pass whatever the SDK threaded).
    ]);

    await contract.deploy(provider, signer, { satoshis: 50_000 });

    // Call close WITHOUT terminalOutputs — this was the failing pattern.
    // Before the fix, this pushed _codePart causing CLEANSTACK.
    //
    // `locktime: 1` is load-bearing (W7): close() asserts
    // `extractSequence !== 0xffffffff`, and `resolveInputSequence` only
    // defaults the inputs to the non-final 0xfffffffe when a NON-ZERO locktime
    // is set. With no locktime the SDK emits an all-final tx, which is exactly
    // the spend the guard exists to refuse.
    const result = await contract.call('close', [null], provider, signer, { locktime: 1 });
    expect(result.txid).toBeTruthy();
    expect(result.txid.length).toBe(64);

    // Verify the unlocking script: should have the right number of items.
    // For close(sig) on a stateful contract with 2 methods (BUG-100 fix: the
    // OP_PUSH_TX signature is derived on-chain, so no _opPushTxSig is pushed):
    //   <sig> <txPreimage> <methodSelector>
    // = 3 items. If _codePart were erroneously pushed, there would be 4.
    const broadcastedTxs = provider.getBroadcastedTxs();
    const callTx = broadcastedTxs[broadcastedTxs.length - 1]!;
    const unlocks = parseUnlockingScripts(callTx);
    // First input is the contract input
    const contractUnlock = unlocks[0]!;
    const itemCount = countPushdataItems(contractUnlock);
    // 3 items: sig, txPreimage, methodSelector (opPushTxSig removed — derived on-chain)
    expect(itemCount).toBe(3);
  });

  it('should push _codePart for non-terminal methods (bid method)', async () => {
    // bid() creates continuation outputs, so it DOES need _codePart.
    const artifact = compileContract('examples/ts/auction/Auction.runar.ts');

    const { provider, signer, pubKeyHex } = await setupFundedProvider(100_000);

    const contract = new RunarContract(artifact, [
      pubKeyHex,       // auctioneer
      pubKeyHex,       // highestBidder (self initially)
      100n,            // highestBid
      999999999n,      // deadline far in the future
    ]);

    await contract.deploy(provider, signer, { satoshis: 50_000 });

    // bid(sig, bidder, bidAmount) — non-terminal, state-mutating. This test
    // only exercises _codePart pushdata bookkeeping, so `bidder` is the
    // connected signer's OWN key (self-bid) — the simple call() API only
    // ever auto-signs Sig params with the one connected signer, so `bidder`
    // must match it or checkSig(sig, bidder) genuinely fails on-chain.
    // (Pre-A1 finding: this test previously passed `bidder` = an unrelated
    // second key while auto-signing with the auctioneer's key, silently
    // broadcasting a script-invalid bid tx through the always-ack provider.)
    const result = await contract.call(
      'bid',
      [null, pubKeyHex, 200n],
      provider, signer,
    );
    expect(result.txid).toBeTruthy();

    // Verify the unlocking script has _codePart.
    // For bid(sig, bidder, bidAmount) on a stateful contract with 2 methods
    // (BUG-100 fix: OP_PUSH_TX signature derived on-chain, no _opPushTxSig):
    //   <codePart> <sig> <bidder> <bidAmount> <changePKH> <changeAmount> <newAmount> <txPreimage> <methodSelector>
    const broadcastedTxs = provider.getBroadcastedTxs();
    const callTx = broadcastedTxs[broadcastedTxs.length - 1]!;
    const unlocks = parseUnlockingScripts(callTx);
    const contractUnlock = unlocks[0]!;
    const itemCount = countPushdataItems(contractUnlock);
    // 9 items: codePart + sig + bidder + bidAmount + changePKH + changeAmount + newAmount + txPreimage + methodSelector (opPushTxSig removed)
    expect(itemCount).toBe(9);
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
    // OP_CODESEPARATOR (0xab) must be present AS AN OPCODE, at exactly the
    // offset the artifact advertises. `script.toContain('ab')` used to stand
    // in for this and is near-vacuous on a 795-byte script — see the RED-PROOF
    // block above.
    expect(findOpcode(artifact.script, OP_CODESEPARATOR)).toEqual([
      artifact.codeSeparatorIndex,
    ]);

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
    //
    // This used to be `script.indexOf('ad')` — a HEX-STRING search, which
    // matches at odd nibble offsets and inside push data, so it did not locate
    // the opcode at all. It also compared that hex index against
    // `codeSepOffset * 2`, mixing two coordinate systems. Both are now byte
    // offsets from a real opcode walk. See the RED-PROOF block above.
    const artifact = compileContract(
      'examples/ts/covenant-vault/CovenantVault.runar.ts',
    );

    const script = artifact.script;
    const codeSepOffset = artifact.codeSeparatorIndex!;

    const checksigOffsets = findOpcode(script, OP_CHECKSIGVERIFY);
    expect(checksigOffsets.length).toBeGreaterThan(0);
    // The user's checkSig is the FIRST OP_CHECKSIGVERIFY, and it is emitted
    // before the separator — which is why its sighash must use the FULL
    // locking script, not the post-separator subscript.
    expect(checksigOffsets[0]).toBeLessThan(codeSepOffset);
    // ...and the separator is a real opcode at the advertised offset, not a
    // stray 0xab byte inside a 33-byte PubKey push.
    expect(findOpcode(script, OP_CODESEPARATOR)).toEqual([codeSepOffset]);
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
    // (BUG-100 fix: OP_PUSH_TX signature derived on-chain, no _opPushTxSig)
    // Expected items: <sig> <txPreimage> = 2 items
    const broadcastedTxs = provider.getBroadcastedTxs();
    const callTx = broadcastedTxs[broadcastedTxs.length - 1]!;
    const unlocks = parseUnlockingScripts(callTx);
    const contractUnlock = unlocks[0]!;
    const itemCount = countPushdataItems(contractUnlock);
    expect(itemCount).toBe(2);
  });
});

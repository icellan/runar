import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { TestContract, ALICE, BOB } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'CovenantVault.runar.ts'), 'utf8');

const OWNER_PK = ALICE.pubKey;
const OWNER_SIG = ALICE.testSig;
const RECIPIENT_HEX = BOB.pubKeyHash;
const RECIPIENT = (() => {
  const b = new Uint8Array(20);
  for (let i = 0; i < 20; i++) b[i] = parseInt(BOB.pubKeyHash.substring(i*2, i*2+2), 16);
  return b;
})();
const MIN_AMOUNT = 5000n;
const MOCK_PREIMAGE = '00'.repeat(181);

function hash256(bytes: Uint8Array): Uint8Array {
  const a = createHash('sha256').update(bytes).digest();
  return new Uint8Array(createHash('sha256').update(a).digest());
}

/** Build a canonical 34-byte P2PKH output: 8-byte LE amount ‖ 1976a914 ‖ pkh ‖ 88ac. */
function p2pkhOutput(amount: bigint, pkh: Uint8Array): Uint8Array {
  if (pkh.length !== 20) throw new Error('pkh must be 20 bytes');
  const out = new Uint8Array(34);
  let a = amount;
  for (let i = 0; i < 8; i++) { out[i] = Number(a & 0xffn); a >>= 8n; }
  out.set([0x19, 0x76, 0xa9, 0x14], 8);
  out.set(pkh, 12);
  out.set([0x88, 0xac], 32);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

describe('CovenantVault', () => {
  function makeVault() {
    return TestContract.fromSource(source, {
      owner: OWNER_PK,
      recipient: RECIPIENT_HEX,
      minAmount: MIN_AMOUNT,
    });
  }

  it('accepts the canonical single-output transaction (happy path)', () => {
    const vault = makeVault();
    const expectedOutput = p2pkhOutput(MIN_AMOUNT, RECIPIENT);
    vault.setMockPreimageBytes({ outputHash: hash256(expectedOutput) });
    const result = vault.call('spend', {
      sig: OWNER_SIG,
      txPreimage: MOCK_PREIMAGE,
    });
    expect(result.success).toBe(true);
    expect(result.error).toBeUndefined();
  });

  // -- Adversarial: wrong output count ---------------------------------------

  it('rejects when the spending transaction commits zero outputs (n-1)', () => {
    const vault = makeVault();
    // Build a preimage whose hashOutputs commits to *no* outputs (empty bytes).
    vault.setMockPreimageBytes({ outputHash: hash256(new Uint8Array(0)) });
    const result = vault.call('spend', { sig: OWNER_SIG, txPreimage: MOCK_PREIMAGE });
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('rejects when the spending transaction commits an extra output (n+1)', () => {
    const vault = makeVault();
    // Two outputs concatenated: the required output plus an extra P2PKH to a
    // different address. Real Bitcoin hashOutputs is hash256(all_output_bytes).
    const required = p2pkhOutput(MIN_AMOUNT, RECIPIENT);
    const extraPkh = new Uint8Array(20).fill(0xcc);
    const extra = p2pkhOutput(1000n, extraPkh);
    vault.setMockPreimageBytes({ outputHash: hash256(concat(required, extra)) });
    const result = vault.call('spend', { sig: OWNER_SIG, txPreimage: MOCK_PREIMAGE });
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  // -- Adversarial: swapped output order -------------------------------------

  it('rejects when the required output is preceded by an unauthorised one', () => {
    const vault = makeVault();
    // Same total outputs as the n+1 case but with the *extra* output first
    // (reordered). The covenant constructs `<amount>‖<p2pkh(recipient)>` and
    // assumes it is the entire hashOutputs preimage; any other layout fails.
    const required = p2pkhOutput(MIN_AMOUNT, RECIPIENT);
    const otherPkh = new Uint8Array(20).fill(0xcc);
    const other = p2pkhOutput(MIN_AMOUNT, otherPkh);
    vault.setMockPreimageBytes({ outputHash: hash256(concat(other, required)) });
    const result = vault.call('spend', { sig: OWNER_SIG, txPreimage: MOCK_PREIMAGE });
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  // -- Adversarial: value at boundary ----------------------------------------

  it('rejects when the output amount is one satoshi below minAmount', () => {
    const vault = makeVault();
    const candidate = p2pkhOutput(MIN_AMOUNT - 1n, RECIPIENT);
    vault.setMockPreimageBytes({ outputHash: hash256(candidate) });
    const result = vault.call('spend', { sig: OWNER_SIG, txPreimage: MOCK_PREIMAGE });
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('rejects when the output amount is one satoshi above minAmount', () => {
    const vault = makeVault();
    const candidate = p2pkhOutput(MIN_AMOUNT + 1n, RECIPIENT);
    vault.setMockPreimageBytes({ outputHash: hash256(candidate) });
    const result = vault.call('spend', { sig: OWNER_SIG, txPreimage: MOCK_PREIMAGE });
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });
});

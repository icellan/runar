/**
 * W6 / GhostInput — `extractPrevOutputScript(i, hash)` does NOT verify input `i`.
 *
 * The name and the docs said it "extracts the previous-output locking script
 * for an arbitrary input of the spending transaction". It does nothing of the
 * kind. ANF lowering binds a hidden parameter named `_prevOutScript_<i>`,
 * asserts `hash256(param) === expectedHash`, and hands the bytes back. There is
 * no vin, no parent transaction, no outpoint, and no input-count check — `i` is
 * a label used to build the parameter name at compile time and nothing else.
 *
 * What the primitive actually proves is: *the spender knows a byte string whose
 * hash256 is `expectedHash`*. Locking scripts are public, so for any deployed
 * covenant that is free to satisfy, and a transaction with ONE input satisfies
 * a contract that claims to "verify input 1".
 *
 * V1 DECISION — option A: keep the primitive, fix every sentence that oversells
 * it. Actually binding vin[i] means parsing the authenticated current
 * transaction, selecting the input, fetching its parent tx, hashing it, matching
 * the outpoint txid, bounds-checking vout and extracting that output's script.
 * That construction already exists in this repo, written by hand and tested, as
 * `examples/ts/companion-verifier/` (`AttributedToken` + `CompanionVerifier`).
 * Promoting it to an intrinsic is a v2 item, not a drive-by.
 *
 * These tests PIN the weak behaviour so nobody mistakes it for the strong one,
 * and they pin the documentation so the claim cannot creep back in. The file is
 * named for what it proves — that this is NOT a co-spend.
 *
 * ORACLE. `@bsv/sdk` `Spend.validate()`. `TestContract` cannot see this at all:
 * its interpreter hands the intrinsic a mocked witness and never builds a
 * transaction, so an input-binding bug is invisible to it by construction.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { compile } from 'runar-compiler';
import { LockingScript, UnlockingScript, Spend, Hash } from '@bsv/sdk';

// ---------------------------------------------------------------------------
// Contract under test
// ---------------------------------------------------------------------------

/**
 * The shape a reader of the old docs would have written: "input 1 must be
 * spending the companion covenant".
 */
const GHOST_INPUT_SRC = `import { SmartContract, ByteString, assert, len, extractPrevOutputScript } from 'runar-lang';

class GhostInput extends SmartContract {
  readonly companionScriptHash: ByteString;

  constructor(companionScriptHash: ByteString) {
    super(companionScriptHash);
    this.companionScriptHash = companionScriptHash;
  }

  public spend() {
    const s = extractPrevOutputScript(1n, this.companionScriptHash);
    assert(len(s) > 0n);
  }
}
`;

/** The companion locking script whose bytes the covenant pins. `OP_TRUE`. */
const COMPANION_SCRIPT_HEX = '51';

function bytesToHex(b: number[] | Uint8Array): string {
  return Buffer.from(b as number[]).toString('hex');
}

function hexToBytes(h: string): number[] {
  return Array.from(Buffer.from(h, 'hex'));
}

/** hash256 = sha256(sha256(x)), the same digest the intrinsic emits. */
function hash256Hex(hex: string): string {
  return bytesToHex(Hash.hash256(hexToBytes(hex)) as number[]);
}

function compileGhost(): string {
  const r = compile(GHOST_INPUT_SRC, {
    fileName: 'GhostInput.runar.ts',
    constructorArgs: { companionScriptHash: hash256Hex(COMPANION_SCRIPT_HEX) },
  });
  if (!r.success || !r.scriptHex) {
    throw new Error(
      'compile failed: ' +
        r.diagnostics.filter(d => d.severity === 'error').map(d => d.message).join('; '),
    );
  }
  return r.scriptHex;
}

function pushHex(hex: string): string {
  const n = hex.length / 2;
  if (n === 0) return '00';
  if (n < 0x4c) return n.toString(16).padStart(2, '0') + hex;
  throw new Error('push too large for this test');
}

/**
 * Run the covenant in a transaction with EXACTLY ONE input — this contract's.
 * `otherInputs: []` is the whole point: there is no vin[1] for the intrinsic to
 * have read, and `Spend` is being told so explicitly.
 */
function runSingleInput(lockingHex: string, unlockingHex: string): { success: boolean; error?: string } {
  const spend = new Spend({
    sourceTXID: '11'.repeat(32),
    sourceOutputIndex: 0,
    sourceSatoshis: 100000,
    lockingScript: LockingScript.fromHex(lockingHex),
    transactionVersion: 2,
    otherInputs: [], // <-- a ONE-input transaction
    outputs: [],
    unlockingScript: UnlockingScript.fromHex(unlockingHex),
    inputIndex: 0,
    inputSequence: 0xffffffff,
    lockTime: 0,
  });
  try {
    return { success: spend.validate() };
  } catch (e: unknown) {
    return { success: false, error: e instanceof Error ? e.message : String(e) };
  }
}

// ---------------------------------------------------------------------------
// Behaviour: the weak property, pinned as weak
// ---------------------------------------------------------------------------

describe('W6 / GhostInput: extractPrevOutputScript proves knowledge of bytes, NOT that vin[i] spends them', () => {
  it('a ONE-input transaction satisfies a covenant that claims to verify input 1', () => {
    const scriptHex = compileGhost();

    // The spender simply copies the companion covenant's public locking script
    // into the witness slot. There is no second input anywhere.
    const res = runSingleInput(scriptHex, pushHex(COMPANION_SCRIPT_HEX));

    expect(res.success).toBe(true);
    expect(res.error).toBeUndefined();
  });

  it('the witness is unauthenticated: only the hash is checked, so any other preimage fails and no input is consulted', () => {
    const scriptHex = compileGhost();

    // Wrong bytes -> the hash assert is the ONLY thing standing in the way.
    expect(runSingleInput(scriptHex, pushHex('52')).success).toBe(false);

    // Right bytes -> accepted, with the transaction shape unchanged. Taken
    // together with the previous case this says exactly what the primitive is:
    // a hash preimage check on a caller-supplied string.
    expect(runSingleInput(scriptHex, pushHex(COMPANION_SCRIPT_HEX)).success).toBe(true);
  });

  it('the compiled script contains no outpoint, input-count or parent-tx machinery — just HASH256 + EQUALVERIFY', () => {
    const r = compile(GHOST_INPUT_SRC, {
      fileName: 'GhostInput.runar.ts',
      constructorArgs: { companionScriptHash: hash256Hex(COMPANION_SCRIPT_HEX) },
    });
    const asm = r.scriptAsm ?? '';

    expect(asm).toContain('OP_HASH256');
    expect(asm).toContain('OP_EQUALVERIFY');

    // `_prevOutScript_1` is an ordinary ABI parameter the SPENDER supplies.
    // If this ever stops being true, the primitive has changed shape and this
    // whole file needs rewriting rather than patching.
    const params = r.artifact?.abi.methods.find(m => m.name === 'spend')?.params ?? [];
    expect(params.map(p => p.name)).toEqual(['_prevOutScript_1']);
  });
});

// ---------------------------------------------------------------------------
// Documentation: the claim must not come back
// ---------------------------------------------------------------------------

const REPO_ROOT = join(__dirname, '..', '..', '..', '..');

/**
 * Every in-repo sentence about this intrinsic has to match the implementation.
 * These are the three places the v1 audit found overselling it.
 */
const DOC_FILES = [
  'packages/runar-lang/src/preimage.ts',
  'docs/cross-covenant-pattern.md',
  'spec/grammar.md',
];

/**
 * Phrases that assert input binding. Each is a sentence fragment that was
 * actually present before W6 and that a reader would take as "vin[i] was
 * checked". Matching is case-insensitive and whitespace-insensitive so a
 * reflow cannot smuggle one back.
 */
const FORBIDDEN_CLAIMS: Array<{ pattern: RegExp; why: string }> = [
  {
    pattern: /extract the previous-output locking script for an arbitrary input/i,
    why: 'claims the intrinsic reads an input of the spending transaction',
  },
  {
    pattern: /reads the previous-output locking script of input/i,
    why: 'claims the intrinsic reads a specific input',
  },
  {
    pattern: /returns the locking script of the\s+transaction's input/i,
    why: 'claims the return value came from a transaction input',
  },
  {
    pattern: /\bCoSpend\w*/,
    why: 'names the weak primitive as a co-spend, which it cannot perform',
  },
];

describe('W6 / GhostInput: no in-repo sentence claims this intrinsic reads an input', () => {
  for (const rel of DOC_FILES) {
    it(`${rel} does not oversell extractPrevOutputScript`, () => {
      const text = readFileSync(join(REPO_ROOT, rel), 'utf8');
      const normalized = text.replace(/\s+/g, ' ');
      const hits = FORBIDDEN_CLAIMS
        .filter(c => c.pattern.test(text) || c.pattern.test(normalized))
        .map(c => c.why);
      expect(hits, `${rel}: ${hits.join('; ')}`).toEqual([]);
    });

    it(`${rel} points at the companion-verifier example for the real construction`, () => {
      const text = readFileSync(join(REPO_ROOT, rel), 'utf8');
      expect(text).toContain('companion-verifier');
    });
  }
});

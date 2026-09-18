/**
 * W8 / SoloMerge — `token-ft`'s `merge` authenticates a companion via its
 * parent transaction. This file used to pin the hole as KNOWN-BROKEN
 * (one-token-input Spend accepted and minted `otherBalance` from nothing).
 * The protocol half inverted those expectations: do not delete this file.
 *
 * `merge(sig, otherBalance, allPrevouts, otherParentTx, outputSatoshis)`:
 *
 *   - `hash256(allPrevouts) === extractHashPrevouts(preimage)` still only
 *     proves `allPrevouts` is the real prevout list. Input count is not
 *     identity.
 *   - I am the first or second 36-byte outpoint; the other of those two is
 *     the companion; companion vout must be 0; `hash256(otherParentTx)`
 *     binds that parent.
 *   - The parent walk requires output 0's script varint to be 0xfd+LE16
 *     (token scripts are >252 B), so a P2PKH fee input cannot fill the
 *     companion slot even when `len(allPrevouts) === 72`.
 *   - Prefix `len-49` of that script must equal this input's scriptCode
 *     (after CompactSize / OP_CODESEPARATOR), and the state-tail balances
 *     must sum to `otherBalance`.
 *
 * ORACLE. `@bsv/sdk` `Spend.validate()`, via the real-crypto oracle's
 * `validateContractInput`. Never assert this family on `TestContract`.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Transaction, LockingScript, UnlockingScript } from '@bsv/sdk';
import {
  RunarContract,
  MockProvider,
  LocalSigner,
  extractStateFromScript,
  buildP2PKHScript,
  encodePushData,
} from 'runar-sdk';
import type { UTXO } from 'runar-sdk';
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

/**
 * MockProvider never drops spent coins from `getUtxos`. After deploy the
 * synthetic funding UTXO is still selectable, so coin-selection cannot be
 * trusted to pick a specific P2PKH parent. Replace the wallet contents.
 */
function replaceAddressUtxos(provider: MockProvider, address: string, next: UTXO[]): void {
  const bag = provider as unknown as { utxos: Map<string, UTXO[]> };
  bag.utxos.set(address, []);
  for (const u of next) provider.addUtxo(address, u);
}

/** Broadcast a 1-in/1-out tx whose output 0 is P2PKH (companion vout must be 0). */
async function broadcastVout0P2pkh(
  provider: MockProvider,
  signer: LocalSigner,
  seed: UTXO,
  destScript: string,
  destSats: number,
): Promise<{ parentHex: string; utxo: UTXO }> {
  const tx = new Transaction();
  tx.addInput({
    sourceTXID: seed.txid,
    sourceOutputIndex: seed.outputIndex,
    unlockingScript: new UnlockingScript(),
    sequence: 0xffffffff,
  });
  tx.addOutput({
    satoshis: destSats,
    lockingScript: LockingScript.fromHex(destScript),
  });
  const sig = await signer.sign(tx.toHex(), 0, seed.script, seed.satoshis);
  const pub = await signer.getPublicKey();
  tx.inputs[0]!.unlockingScript = UnlockingScript.fromHex(
    encodePushData(sig) + encodePushData(pub),
  );
  const txid = await provider.broadcast(tx);
  return {
    parentHex: tx.toHex(),
    utxo: { txid, outputIndex: 0, satoshis: destSats, script: destScript },
  };
}

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

  // `outputs` is stated explicitly because off-chain ANF uses dummy
  // extractors (the real prevouts/scriptCode do not exist yet during
  // `prepareCall`). The on-chain script recomputes the continuation itself;
  // a wrong successor here makes Spend REJECT rather than wave it through.
  const contract = new RunarContract(compiled.artifact, [
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
      [null, PHANTOM_BALANCE, null, deployTx.toHex(), 1n],
      provider,
      signer,
      {
        dryRun: true,
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

describe('W8 / SoloMerge: token-ft merge authenticates a companion parent', () => {
  it('a ONE-token-input transaction is rejected (supply is not inflated)', async () => {
    const res = await runSoloMerge();

    // Exactly one TOKEN input. The SDK may append a P2PKH fee input after it;
    // that is the token+P2PKH filling of two prevouts, and must also reject.
    expect(res.accepted, res.error).toBe(false);
    // If the SDK built a call tx (dry-run off the script failure), it still
    // has exactly one TOKEN input. A throw before broadcast is also a reject.
    if (res.tokenInputCount !== undefined) {
      expect(res.tokenInputCount, res.error).toBe(1);
      expect(res.inputCount, res.error).toBeGreaterThanOrEqual(1);
    }
  });

  it('a token + P2PKH fee input bound as the companion parent is rejected', async () => {
    // The attack YOINK named: two prevouts (token + P2PKH), `otherParentTx`
    // is the P2PKH's REAL parent so hash256 binds, then the walk must refuse
    // a 25-byte script (varint is not 0xfd+LE16). Binding the token parent
    // instead fails earlier at `hash256(otherParentTx) === companionTxid`
    // and never reaches that walk.
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
    const pkhScript = buildP2PKHScript(alice.pubKey);

    const parentSeed: UTXO = {
      txid: '11'.repeat(32),
      outputIndex: 0,
      satoshis: 100_000,
      script: pkhScript,
    };
    provider.addUtxo(address, parentSeed);
    const parent = await broadcastVout0P2pkh(provider, signer, parentSeed, pkhScript, 50_000);

    provider.addUtxo(address, {
      txid: '22'.repeat(32),
      outputIndex: 0,
      satoshis: 500_000,
      script: pkhScript,
    });

    const contract = new RunarContract(compiled.artifact, [
      alice.pubKey,
      REAL_BALANCE,
      0n,
      '01',
    ]);
    await contract.deploy(provider, signer, {});
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
    const spent = contract.getUtxo();
    if (!spent) throw new Error('deploy did not leave a tracked UTXO');

    replaceAddressUtxos(provider, address, [parent.utxo]);
    contract.connect(provider, signer);

    const prepared = await contract.prepareCall(
      'merge',
      [null, PHANTOM_BALANCE, null, parent.parentHex, 1n],
      {
        dryRun: true,
        outputs: [
          {
            satoshis: 1,
            state: {
              owner: alice.pubKey,
              balance: REAL_BALANCE,
              mergeBalance: PHANTOM_BALANCE,
            },
          },
        ],
      },
    );

    let mIdx = 0;
    if (prepared._parentStateful) {
      const pubMethods = compiled.artifact.abi.methods.filter(m => m.isPublic);
      if (pubMethods.length > 1) {
        const idx = pubMethods.findIndex(m => m.name === 'merge');
        if (idx >= 0) mIdx = idx;
      }
    }
    const sigSubscript = prepared._parentStateful
      ? contract.getSubscriptForSigning(prepared._contractUtxo.script, mIdx)
      : prepared._contractUtxo.script;
    const signatures: Record<number, string> = {};
    const txHex = prepared.tx.toHex();
    for (const idx of prepared.sigIndices) {
      signatures[idx] = await signer.sign(
        txHex, 0, sigSubscript, prepared._contractUtxo.satoshis,
      );
    }
    await expect(contract.finalizeCall(prepared, signatures)).rejects.toThrow();

    const callTx = prepared.tx;
    expect(callTx.inputs.length, 'token + P2PKH').toBe(2);
    expect(callTx.inputs[1]!.sourceOutputIndex).toBe(0);
    expect(callTx.inputs[1]!.sourceTXID).toBe(parent.utxo.txid);

    let accepted = false;
    try {
      accepted = validateContractInput(callTx, 0, deployTx, spent.outputIndex);
    } catch {
      accepted = false;
    }
    expect(accepted).toBe(false);
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

  it('two honest token inputs with agreeing balances still spend', async () => {
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

    const tokenId = '01';
    const balA = 400n;
    const balB = 600n;
    const contractA = new RunarContract(compiled.artifact, [alice.pubKey, balA, 0n, tokenId]);
    await contractA.deploy(provider, signer, {});
    const parentA = provider.getBroadcastedTxs()[0]!;
    const utxoA = contractA.getUtxo();
    if (!utxoA) throw new Error('deploy A did not leave a tracked UTXO');
    const deployTxA = Transaction.fromHex(parentA);

    const contractB = new RunarContract(compiled.artifact, [alice.pubKey, balB, 0n, tokenId]);
    await contractB.deploy(provider, signer, {});
    const parentB = provider.getBroadcastedTxs()[1]!;
    const utxoB = contractB.getUtxo();
    if (!utxoB) throw new Error('deploy B did not leave a tracked UTXO');

    try {
      await contractA.call(
        'merge',
        [null, balB, null, parentB, 1n],
        provider,
        signer,
        {
          dryRun: true,
          additionalContractInputs: [utxoB],
          additionalContractInputArgs: [[null, balA, null, parentA, 1n]],
          outputs: [
            {
              satoshis: 1,
              state: {
                owner: alice.pubKey,
                balance: balA,
                mergeBalance: balB,
              },
            },
          ],
        },
      );
    } catch (e) {
      expect.fail(e instanceof Error ? e.message : String(e));
    }

    const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[2]!);
    const accepted = validateContractInput(callTx, 0, deployTxA, utxoA.outputIndex);
    const acceptedB = validateContractInput(callTx, 1, Transaction.fromHex(parentB), utxoB.outputIndex);
    const state = extractStateFromScript(
      compiled.artifact,
      callTx.outputs[0]!.lockingScript.toHex(),
    ) as Record<string, unknown>;

    expect(accepted, 'input 0 Spend').toBe(true);
    expect(acceptedB, 'input 1 Spend').toBe(true);
    expect((state['balance'] as bigint) + (state['mergeBalance'] as bigint)).toBe(balA + balB);
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

    it(`${rel} describes the companion-parent merge`, () => {
      const text = readFileSync(join(REPO_ROOT, rel), 'utf8');
      expect(
        /otherParentTx|other_parent_tx|otherParentTx|companion-parent merge/i.test(text),
        `${rel}: expected otherParentTx / companion-parent wording`,
      ).toBe(true);
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

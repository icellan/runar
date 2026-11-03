/**
 * F-017 — two source identifiers that convert to one Rúnar name.
 *
 * On the `.runar.py` surface `tmp` and `tmp_` both convert to `tmp`. Before
 * the collision rule the reference compiler bound both spellings to ONE
 * variable, so
 *
 *     tmp = n + 1
 *     tmp_ = n + 2
 *     assert_(tmp == tmp_)          # ALWAYS false: the output is unspendable
 *
 * compiled to `OP_DUP OP_1ADD OP_SWAP OP_2 OP_ADD OP_DUP OP_DUP OP_NUMEQUAL …`
 * — the second binding compared with a copy of itself — and the guard ALWAYS
 * passed. `examples/python` runs contracts natively under CPython, so the
 * off-chain oracle saw the assertion fail while the deployed script accepted.
 *
 * The acceptance oracle is the real `@bsv/sdk` `Spend` engine: the artifact is
 * deployed and called through the TS SDK and the call's contract input is
 * replayed with `validateContractInput`. Expected verdicts are derived BY HAND
 * from the source (n+1 == n+2 is false for every n), never from compiler
 * output.
 *
 * What this proves: if the TS reference produces an artifact for the colliding
 * source, the real engine does not accept `unlock(5)` against it (pre-fix it
 * DID — that is the recorded failing run); and the reference refuses the
 * source with the shared collision diagnostic. The two controls show the same
 * harness rejects the always-false guard written with distinct names and
 * accepts a guard that is true, so neither verdict is vacuous.
 * What it does NOT prove: anything about the other six tiers (per-tier suites
 * and conformance/negatives/N46-N50 pin their refusal), or the `.runar.rs`,
 * `.runar.rb`, `.runar.move` and `.runar.go` surfaces (pinned at the compiler
 * level by packages/runar-compiler/src/__tests__/f017-identifier-collision.test.ts).
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner, buildP2PKHScript } from 'runar-sdk';
import { Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { testKey, validateContractInput } from '../oracle/real-crypto-execution.js';

const FILE = 'Trail.runar.py';

const src = (a: string, b: string, guard: string) => `from runar import SmartContract, Bigint, public, assert_


class Trail(SmartContract):
    def __init__(self):
        super().__init__()

    @public
    def unlock(self, n: Bigint):
        ${a} = n + 1
        ${b} = n + 2
        assert_(${guard})
`;

interface Verdict {
  accepted: boolean;
  reachedEngine: boolean;
  error?: string;
}

/** Deploy the artifact, call `unlock(n)`, and replay the contract input on
 *  the real Spend engine. */
async function spend(artifact: RunarArtifact, n: bigint): Promise<Verdict> {
  const key = testKey('alice');
  const signer = new LocalSigner(key.privKey);
  const provider = new MockProvider();
  provider.addUtxo(await signer.getAddress(), {
    txid: key.privKey.slice(0, 64),
    outputIndex: 0,
    satoshis: 500_000,
    script: buildP2PKHScript(key.pubKey),
  });
  const contract = new RunarContract(artifact, []);
  await contract.deploy(provider, signer, {});
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  try {
    await contract.call('unlock', [n], provider, signer, { dryRun: true });
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    return {
      accepted: false,
      reachedEngine: error.includes('local pre-broadcast dry-run rejected the primary contract input'),
      error,
    };
  }
  const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
  return { accepted: validateContractInput(callTx, 0, deployTx, 0), reachedEngine: true };
}

function compileRef(source: string) {
  return compile(source, { fileName: FILE, disableConstantFolding: true });
}

describe('F-017 — `tmp` and `tmp_` are never one binding in a deployed script', () => {
  it('ATTACK unlock(5) against the tmp / tmp_ always-false guard is not accepted; the source is refused', async () => {
    const r = compileRef(src('tmp', 'tmp_', 'tmp == tmp_'));
    if (r.success && r.artifact) {
      const v = await spend(r.artifact as unknown as RunarArtifact, 5n);
      expect(v.accepted, `an always-false guard accepted unlock(5): ${r.artifact.asm}`).toBe(false);
    }
    expect(r.success, 'the colliding source must be refused').toBe(false);
    expect(r.diagnostics.map((d) => d.message)).toContain(
      "identifier collision: 'tmp' and 'tmp_' both convert to 'tmp'; rename one of them",
    );
  });

  it('CONTROL the same always-false guard over distinct names x / y rejects unlock(5)', async () => {
    const r = compileRef(src('x', 'y', 'x == y'));
    expect(r.success).toBe(true);
    const v = await spend(r.artifact! as unknown as RunarArtifact, 5n);
    expect(v.reachedEngine, `never reached Spend: ${v.error ?? '(accepted)'}`).toBe(true);
    expect(v.accepted).toBe(false);
  });

  it('CONTROL a true guard over x / y accepts unlock(5) (the harness can say yes)', async () => {
    const r = compileRef(src('x', 'y', 'x + 1 == y'));
    expect(r.success).toBe(true);
    const v = await spend(r.artifact! as unknown as RunarArtifact, 5n);
    expect(v.accepted, v.error).toBe(true);
  });
});

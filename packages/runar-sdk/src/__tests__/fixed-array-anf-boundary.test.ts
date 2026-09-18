/**
 * FixedArray state across the ANF-interpreter boundary (call path).
 *
 * Pass `03b-expand-fixed-arrays` runs BEFORE ANF lowering, so the ANF program
 * has no property called `table` at all — it has `table__0`..`table__3`, and
 * every `load_prop` / `update_prop` in the method body names one of those. The
 * SDK's user-facing `_state`, by contrast, is keyed by the GROUPED name. Both
 * directions of that boundary have to be bridged (`flattenFixedArrayState` /
 * `regroupFixedArrayState`) or the continuation output commits a state the
 * method did not compute.
 *
 * The sharp probe is the RECONNECT path: `fromUtxo` sets `_state` to exactly
 * what `extractStateFromScript` decodes, which for a FixedArray field is the
 * grouped entry and nothing else — no synthetic leaves to mask an unbridged
 * inbound boundary. Because `this.table[i]++` at a runtime index lowers to a
 * per-leaf select, an absent property makes the interpreter fall back to each
 * leaf's ANF initialValue and rewrite ALL FOUR leaves from it, so the
 * continuation commits the deploy-time array and the covenant's hashOutputs
 * binding rejects the spend.
 *
 * Fixture: examples/ts/fixed-array-write/ArrayWrite.runar.ts, compiled here so
 * the artifact carries the ANF the call path needs.
 *
 * Every test runs on the DEFAULT validating MockProvider with a real
 * LocalSigner, so each broadcast replays input 0 through @bsv/sdk's Spend
 * interpreter: a second call has to satisfy the covenant the first call's
 * continuation committed.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import type { RunarArtifact } from 'runar-ir-schema';

const DEPLOYER_KEY = '0000000000000000000000000000000000000000000000000000000000000007';

const SOURCE_PATH = join(
  __dirname,
  '../../../../examples/ts/fixed-array-write/ArrayWrite.runar.ts',
);

let artifact: RunarArtifact;

beforeAll(() => {
  const source = readFileSync(SOURCE_PATH, 'utf8');
  const result = compile(source, { fileName: 'ArrayWrite.runar.ts' });
  if (!result.artifact) {
    throw new Error(
      `Compile failed: ${(result.diagnostics || [])
        .filter((d) => d.severity === 'error')
        .map((d) => d.message)
        .join('; ')}`,
    );
  }
  artifact = result.artifact;
  // Without ANF the call path never reaches the interpreter and this whole
  // file would be vacuous.
  expect(artifact.anf, 'ArrayWrite artifact carries no ANF').toBeTruthy();
});

/** Little-endian 8-byte words, one per leaf — the contract's state bytes.
 *  BigInt shifts: `>> 56n` on a JS number wraps to `>> 24`. */
function leHex(...vals: number[]): string {
  return vals
    .map((v) => {
      let out = '';
      for (let i = 0n; i < 8n; i++) out += Number((BigInt(v) >> (8n * i)) & 0xffn).toString(16).padStart(2, '0');
      return out;
    })
    .join('');
}

/** The 32-byte state section after the final OP_RETURN of a locking script. */
function stateTailHex(scriptHex: string): string {
  const nibbles = 4 * 8 * 2;
  expect(scriptHex.length).toBeGreaterThan(nibbles + 2);
  const sep = scriptHex.slice(-nibbles - 2, -nibbles);
  expect(sep, 'expected OP_RETURN (6a) before the 32-byte state section').toBe('6a');
  return scriptHex.slice(-nibbles);
}

function groupedTable(state: Record<string, unknown>): bigint[] {
  const raw = state['table'];
  expect(Array.isArray(raw), 'state has no grouped `table` array').toBe(true);
  return (raw as unknown[]).map((v) =>
    typeof v === 'string' ? BigInt(v.replace(/n$/, '')) : BigInt(v as bigint),
  );
}

async function deployArrayWrite() {
  const provider = new MockProvider('testnet');
  const signer = new LocalSigner(DEPLOYER_KEY);
  const address = await signer.getAddress();
  provider.addUtxo(address, {
    txid: 'aa'.repeat(32),
    outputIndex: 0,
    satoshis: 1_000_000,
    script: buildP2PKHScript(await signer.getPublicKey()),
  });
  const contract = new RunarContract(artifact, []);
  await contract.deploy(provider, signer, { satoshis: 50_000 });
  return { contract, provider, signer };
}

describe('FixedArray state across the ANF-interpreter boundary', () => {
  it('OUTBOUND: the continuation and the grouped entry both carry the computed state', async () => {
    const { contract, provider, signer } = await deployArrayWrite();

    expect(stateTailHex(contract.getUtxo()!.script)).toBe(leHex(0, 0, 0, 0));

    await contract.call('bump', [0n], provider, signer);

    expect(stateTailHex(contract.getUtxo()!.script)).toBe(leHex(1, 0, 0, 0));
    expect(groupedTable(contract.state)).toEqual([1n, 0n, 0n, 0n]);
  });

  it('INBOUND: repeated bumps of one slot accumulate', async () => {
    const { contract, provider, signer } = await deployArrayWrite();

    for (let n = 1; n <= 3; n++) {
      await contract.call('bump', [0n], provider, signer);
      expect(stateTailHex(contract.getUtxo()!.script)).toBe(leHex(n, 0, 0, 0));
      expect(groupedTable(contract.state)).toEqual([BigInt(n), 0n, 0n, 0n]);
    }
  });

  it('INBOUND: a contract reconnected with fromUtxo can still spend its own UTXO', async () => {
    const { contract, provider, signer } = await deployArrayWrite();

    // Real on-chain history: table -> [0,2,0,0].
    await contract.call('bump', [1n], provider, signer);
    await contract.call('bump', [1n], provider, signer);
    const onChain = { ...contract.getUtxo()! };
    expect(stateTailHex(onChain.script)).toBe(leHex(0, 2, 0, 0));

    // A fresh process that only ever sees the deployed script.
    const restored = RunarContract.fromUtxo(artifact, onChain);
    expect(
      'table__1' in restored.state,
      'fromUtxo leaked a synthetic leaf; this test no longer probes the grouped-only restore path',
    ).toBe(false);
    expect(groupedTable(restored.state)).toEqual([0n, 2n, 0n, 0n]);

    await restored.call('bump', [1n], provider, signer);

    expect(stateTailHex(restored.getUtxo()!.script)).toBe(leHex(0, 3, 0, 0));
    expect(groupedTable(restored.state)).toEqual([0n, 3n, 0n, 0n]);
  });
});

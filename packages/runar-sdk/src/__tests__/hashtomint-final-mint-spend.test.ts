/**
 * compilers/zig/examples/HashToMint.runar.zig after D18 (per path): the
 * example used to write `supply` and then call `addOutput` only when supply
 * stayed positive, so the final mint's path wrote state and reached no
 * addOutput, which every compiler now refuses. It now computes the remainder
 * in a local and carries it in `addOutput(1, rest)` on the continuing branch
 * only. It also reads the outpoint txid through extractOutpoint instead of a
 * raw substr of the preimage (same bytes on chain: BIP-143 offset 68), since
 * the SDK's off-chain derivation cannot evaluate a raw preimage substr and
 * the example could not be called through the SDK at all before. This test
 * drives both mints under @bsv/sdk Spend (difficulty 0, so the
 * proof-of-work gates pass for any nonce):
 *  - a non-final mint (supply 2 * reward) is accepted and continues the
 *    covenant with supply = reward in a 1-sat contract output, after the
 *    reward inscription output;
 *  - the final mint (supply == reward) is accepted and creates NO contract
 *    output: the covenant ends, as the example intends.
 * Does not prove: the proof-of-work gates (difficulty 0 here) or other tiers'
 * bytes (the example compiles to the same hex in every tier).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { Spend, LockingScript, Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

const SRC = readFileSync(join(__dirname, '../../../../compilers/zig/examples/HashToMint.runar.zig'), 'utf8');
const DEPLOYER_KEY = '0000000000000000000000000000000000000000000000000000000000000003';
const MINER_KEY = '0000000000000000000000000000000000000000000000000000000000000005';
const REWARD = 100n;
const INSCRIPTION = '0063036f7264'; // any reward-inscription prefix bytes
const PKH = 'ab'.repeat(20);
const DEPLOY_SATS = 10_000;

function artifact(): RunarArtifact {
  const r = compile(SRC, { fileName: 'HashToMint.runar.zig' });
  if (!r.success || !r.artifact) {
    throw new Error(r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message).join('; '));
  }
  return r.artifact as unknown as RunarArtifact;
}

async function funded(provider: MockProvider, key: string): Promise<LocalSigner> {
  const s = new LocalSigner(key);
  provider.addUtxo(await s.getAddress(), {
    txid: key.slice(0, 64),
    outputIndex: 0,
    satoshis: 500_000,
    script: buildP2PKHScript(await s.getPublicKey()),
  });
  return s;
}

function validateSpend(tx: Transaction, inputIdx: number, sourceTx: Transaction, sourceOutputIdx: number): boolean {
  const input = tx.inputs[inputIdx]!;
  const src = sourceTx.outputs[sourceOutputIdx]!;
  return new Spend({
    sourceTXID: input.sourceTXID!,
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: src.satoshis!,
    lockingScript: src.lockingScript,
    transactionVersion: tx.version,
    otherInputs: tx.inputs
      .filter((_: unknown, i: number) => i !== inputIdx)
      .map((inp, idx) => ({
        inputIndex: idx >= inputIdx ? idx + 1 : idx,
        sourceOutputIndex: inp.sourceOutputIndex,
        sourceTXID: inp.sourceTXID!,
        sequence: inp.sequence,
        unlockingScript: undefined as never,
        sourceSatoshis: 0,
        lockingScript: LockingScript.fromHex(''),
      })),
    outputs: tx.outputs.map((o) => ({ lockingScript: o.lockingScript, satoshis: o.satoshis })),
    unlockingScript: input.unlockingScript,
    inputIndex: inputIdx,
    inputSequence: input.sequence,
    lockTime: tx.lockTime,
  }).validate();
}

async function mint(supply: bigint) {
  const provider = new MockProvider('testnet');
  const deployer = await funded(provider, DEPLOYER_KEY);
  const miner = await funded(provider, MINER_KEY);
  // supply, total_supply, reward, starting_difficulty, difficulty_range, reward_inscription
  const c = new RunarContract(artifact(), [supply, 10n * REWARD, REWARD, 0n, 0n, INSCRIPTION]);
  await c.deploy(provider, deployer, { satoshis: DEPLOY_SATS });
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  await c.call('redeem', ['00'.repeat(8), PKH], provider, miner);
  const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
  const contractPrefix = deployTx.outputs[0]!.lockingScript.toHex().slice(0, 200);
  const continuations = callTx.outputs.filter((o) => o.lockingScript.toHex().startsWith(contractPrefix));
  return { c, deployTx, callTx, continuations };
}

describe('HashToMint: a non-final mint continues, the final mint ends the covenant', () => {
  it('non-final mint: accepted, continues with supply = reward', async () => {
    const { c, deployTx, callTx, continuations } = await mint(2n * REWARD);
    expect(validateSpend(callTx, 0, deployTx, 0)).toBe(true);
    expect(continuations).toHaveLength(1);
    expect(continuations[0]!.satoshis).toBe(1);
    expect(c.state.supply).toBe(REWARD);
    const raw = callTx.outputs.find((o) => o.lockingScript.toHex() === `${INSCRIPTION}76a914${PKH}88ac`);
    expect(raw?.satoshis).toBe(1);
  }, 120_000);

  it('final mint: accepted, and no output carries the contract', async () => {
    const { deployTx, callTx, continuations } = await mint(REWARD);
    expect(validateSpend(callTx, 0, deployTx, 0)).toBe(true);
    expect(continuations).toHaveLength(0);
    expect(callTx.outputs.some((o) => o.lockingScript.toHex() === `${INSCRIPTION}76a914${PKH}88ac`)).toBe(true);
  }, 120_000);
});

#!/usr/bin/env npx tsx
/**
 * N-412 cross-SDK call vector: a STATELESS contract whose public methods take
 * the auto-injected intent witness `_prevOutScript_0`.
 *
 * `StatelessWitness.runar.ts` has two public methods, both calling
 * `extractPrevOutputScript(0n, expectedHash)`, so the ABI of each ends with a
 * hidden `_prevOutScript_0` ByteString. The compiled script reads it directly
 * beneath the method selector, so a stateless spend must push
 * `<declared args> <witness> <selector>` — the same "witness after the
 * declared args, before the selector" order the stateful path uses.
 *
 * Three scenarios, each on a fresh contract + provider:
 *   - `peek`: `call('peek', [5])` — no Sig, no preimage; selector 1.
 *   - `spend`: `call('spend', [null, pubKey])` — the stateless Sig branch;
 *     the Sig is signed by the connected LocalSigner (RFC 6979, so every tier
 *     derives the same bytes); selector 0.
 *   - `spendPrepared`: `prepareCall('spend', [null, pubKey])`, then
 *     `finalizeCall` with `expected.spend.signatureHex` at sig index 0 —
 *     must broadcast the same tx as `spend`.
 *
 * Acceptance oracle: MockProvider's default broadcast validation runs @bsv/sdk
 * Spend on every input, so a recorded tx exists only if it is consensus-valid;
 * `stateless-witness.test.ts` re-checks it with Spend directly and shows a
 * tampered witness push is rejected.
 *
 * Run: `cd conformance && npx tsx sdk-call/generate-stateless-witness.ts`
 * (`--check` re-derives and fails on drift without rewriting).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Hash, Transaction, UnlockingScript, Utils } from '@bsv/sdk';
import { compile } from '../../packages/runar-compiler/src/index.js';
import { serializeArtifact } from '../../packages/runar-compiler/src/artifact/assembler.js';
import { RunarContract } from '../../packages/runar-sdk/src/contract.js';
import { MockProvider } from '../../packages/runar-sdk/src/providers/mock.js';
import { LocalSigner } from '../../packages/runar-sdk/src/signers/local.js';
import { buildP2PKHScript } from '../../packages/runar-sdk/src/script-utils.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..', '..');
export const STATELESS_WITNESS_VECTOR_PATH = join(__dirname, 'stateless-witness.json');

const SOURCE = 'conformance/sdk-call/StatelessWitness.runar.ts';
const PRIV = '0000000000000000000000000000000000000000000000000000000000000001';
const CONTRACT_TXID = 'aa'.repeat(32);
const FUNDING_TXID = 'bb'.repeat(32);
const CONTRACT_SATS = 10_000;
const FUNDING_SATS = 100_000;

export async function buildStatelessWitnessVector(): Promise<Record<string, unknown>> {
  const src = readFileSync(join(ROOT, SOURCE), 'utf8');
  const r = compile(src, { fileName: 'StatelessWitness.runar.ts' });
  if (!r.artifact) throw new Error('compile failed');
  const artifact = JSON.parse(serializeArtifact(r.artifact));
  artifact.buildTimestamp = '1970-01-01T00:00:00.000Z';

  const signer = new LocalSigner(PRIV);
  const pubKey = await signer.getPublicKey();
  const address = await signer.getAddress();
  const pubKeyHash = Utils.toHex(Hash.hash160(Utils.toArray(pubKey, 'hex')));
  // Any bytes do; the contract pins them by hash256. A P2PKH script is a
  // realistic "previous output script".
  const prevOutScriptHex = buildP2PKHScript(pubKey);
  const expectedHash = Utils.toHex(Hash.hash256(Utils.toArray(prevOutScriptHex, 'hex')));
  const lockingHex = new RunarContract(r.artifact, [pubKeyHash, expectedHash]).getLockingScript();
  const contractUtxo = { txid: CONTRACT_TXID, outputIndex: 0, satoshis: CONTRACT_SATS, script: lockingHex };
  const fundingUtxo = { txid: FUNDING_TXID, outputIndex: 1, satoshis: FUNDING_SATS, script: buildP2PKHScript(pubKey) };

  const fresh = (): { contract: RunarContract; provider: MockProvider } => {
    // Default MockProvider: Spend-validates every input of a broadcast tx.
    const provider = new MockProvider('testnet');
    provider.addUtxo(address, fundingUtxo);
    provider.addContractUtxo(lockingHex, contractUtxo);
    const contract = RunarContract.fromUtxo(r.artifact!, contractUtxo);
    contract.connect(provider, signer);
    contract.setPrevOutScript(0, prevOutScriptHex);
    return { contract, provider };
  };
  const onlyBroadcast = (provider: MockProvider): Transaction => {
    const txs = provider.getBroadcastedTxs();
    if (txs.length !== 1) throw new Error(`expected 1 broadcast, got ${txs.length}`);
    if (provider.getValidationStats().validated !== 2) {
      throw new Error(`expected Spend validation of 2 inputs, got ${provider.getValidationStats().validated}`);
    }
    return Transaction.fromHex(txs[0]!);
  };

  // peek(5)
  const a = fresh();
  await a.contract.call('peek', [5n]);
  const peekTx = onlyBroadcast(a.provider);

  // spend(<auto Sig>, pubKey)
  const b = fresh();
  await b.contract.call('spend', [null, pubKey]);
  const spendTx = onlyBroadcast(b.provider);
  const spendChunks = UnlockingScript.fromHex(spendTx.inputs[0]!.unlockingScript!.toHex()).chunks;
  const signatureHex = Utils.toHex(spendChunks[0]!.data!);

  // prepareCall + finalizeCall(spend) with the recorded signature.
  const c = fresh();
  const prepared = await c.contract.prepareCall('spend', [null, pubKey]);
  if (prepared.sigIndices.length !== 1 || prepared.sigIndices[0] !== 0) {
    throw new Error(`unexpected sigIndices ${JSON.stringify(prepared.sigIndices)}`);
  }
  await c.contract.finalizeCall(prepared, { 0: signatureHex });
  const preparedTx = onlyBroadcast(c.provider);
  if (preparedTx.toHex() !== spendTx.toHex()) {
    throw new Error('prepareCall/finalizeCall broadcast differs from call()');
  }

  return {
    vector_version: 1,
    notes:
      'N-412 cross-SDK vector: a stateless contract whose methods take the auto-injected intent witness ' +
      '_prevOutScript_0. For each scenario, load the artifact, build the contract from contractUtxo, connect a ' +
      'provider holding fundingUtxo for the privKeyHex address, setPrevOutScript(0, prevOutScriptHex), then: ' +
      '(peek) call peek with args [5]; (spend) call spend with args [null (auto-sign), pubKeyHex]; ' +
      '(spendPrepared) prepareCall spend with the same args, assert sig indices == [0], finalizeCall with ' +
      'expected.spend.signatureHex at index 0. Assert input 0 unlocking script == expected.<scenario>.input0UnlockingHex ' +
      '(<declared args> <witness push> <selector>) and the broadcast tx hex == expected.<scenario>.referenceTxHex ' +
      '(spendPrepared reuses expected.spend). Generated by conformance/sdk-call/generate-stateless-witness.ts ' +
      '(MockProvider Spend-validated both inputs); replayed through @bsv/sdk Spend by ' +
      'conformance/sdk-call/stateless-witness.test.ts.',
    source: SOURCE,
    artifact,
    constructorArgs: { pubKeyHash, expectedHash },
    privKeyHex: PRIV,
    pubKeyHex: pubKey,
    prevOutScriptHex,
    contractUtxo,
    fundingUtxo,
    expected: {
      peek: {
        method: 'peek',
        args: ['5'],
        input0UnlockingHex: peekTx.inputs[0]!.unlockingScript!.toHex(),
        referenceTxHex: peekTx.toHex(),
      },
      spend: {
        method: 'spend',
        sigIndices: [0],
        signatureHex,
        input0UnlockingHex: spendTx.inputs[0]!.unlockingScript!.toHex(),
        referenceTxHex: spendTx.toHex(),
      },
    },
  };
}

async function main(): Promise<void> {
  const want = JSON.stringify(await buildStatelessWitnessVector(), null, 2) + '\n';
  if (process.argv.includes('--check')) {
    if (readFileSync(STATELESS_WITNESS_VECTOR_PATH, 'utf8') !== want) {
      console.error(`drift: ${STATELESS_WITNESS_VECTOR_PATH} differs from a fresh derivation`);
      process.exit(1);
    }
    console.log('stateless-witness vector up to date');
    return;
  }
  writeFileSync(STATELESS_WITNESS_VECTOR_PATH, want);
  console.log(`wrote ${STATELESS_WITNESS_VECTOR_PATH}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  void main();
}

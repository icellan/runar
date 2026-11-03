#!/usr/bin/env npx tsx
/**
 * N-286 cross-SDK call vector: a stateful merge through the two-phase API.
 *
 * `prepareCall('increment', [null], { additionalContractInputs: [extra] })`
 * on MergeCounter spends TWO contract UTXOs (same locking script, same state,
 * same satoshis) plus one P2PKH funding UTXO. Per the TS reference:
 *   - the extra contract input (input 1) gets its own OP_PUSH_TX preimage and
 *     its Sig signed by the connected signer DURING prepareCall;
 *   - only input 0's Sig is left as a placeholder; `prepared.sighash` is its
 *     BIP-143 digest, and `finalizeCall` rewrites input 0 only.
 *
 * The scenario is deterministic (fixed key, outpoints, amounts, MockProvider's
 * default fee rate), so every SDK given the same artifact, UTXOs, key and new
 * state must produce the same sighash and, after splicing the recorded
 * primary signature, byte-identical tx hex. The vector also records the
 * primary signature so no tier needs a digest-signing API: each tier asserts
 * its prepared sighash equals `expected.sighash`, finalizes with
 * `expected.primarySignatureHex`, and compares the broadcast hex to
 * `expected.referenceTxHex`.
 *
 * Acceptance oracle: MockProvider's default broadcast validation runs @bsv/sdk
 * Spend on EVERY input (all three outpoints are registered), so the recorded
 * tx is consensus-valid on both contract inputs and the funding input;
 * `stateful-merge.test.ts` re-checks that with Spend directly.
 *
 * Run: `cd conformance && npx tsx sdk-call/generate-stateful-merge.ts`
 * (`--check` re-derives and fails on drift without rewriting).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Hash, PrivateKey, Transaction, Utils } from '@bsv/sdk';
import { compile } from '../../packages/runar-compiler/src/index.js';
import { serializeArtifact } from '../../packages/runar-compiler/src/artifact/assembler.js';
import { RunarContract } from '../../packages/runar-sdk/src/contract.js';
import { MockProvider } from '../../packages/runar-sdk/src/providers/mock.js';
import { LocalSigner } from '../../packages/runar-sdk/src/signers/local.js';
import { buildP2PKHScript } from '../../packages/runar-sdk/src/script-utils.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..', '..');
export const MERGE_VECTOR_PATH = join(__dirname, 'stateful-merge-prepared.json');

const SOURCE = 'conformance/sdk-call/MergeCounter.runar.ts';
const PRIV = '0000000000000000000000000000000000000000000000000000000000000001';
const CONTRACT_TXID = 'aa'.repeat(32);
const EXTRA_TXID = 'cc'.repeat(32);
const FUNDING_TXID = 'bb'.repeat(32);
const CONTRACT_SATS = 10_000;
const FUNDING_SATS = 100_000;

export async function buildMergeVector(): Promise<Record<string, unknown>> {
  const src = readFileSync(join(ROOT, SOURCE), 'utf8');
  const r = compile(src, { fileName: 'MergeCounter.runar.ts' });
  if (!r.artifact) throw new Error('compile failed');
  const artifact = JSON.parse(serializeArtifact(r.artifact));
  artifact.buildTimestamp = '1970-01-01T00:00:00.000Z';

  const signer = new LocalSigner(PRIV);
  const pubKey = await signer.getPublicKey();
  const address = await signer.getAddress();
  const lockingHex = new RunarContract(r.artifact, [0n, pubKey]).getLockingScript();
  const contractUtxo = { txid: CONTRACT_TXID, outputIndex: 0, satoshis: CONTRACT_SATS, script: lockingHex };
  const extraContractUtxo = { txid: EXTRA_TXID, outputIndex: 1, satoshis: CONTRACT_SATS, script: lockingHex };
  const fundingUtxo = { txid: FUNDING_TXID, outputIndex: 0, satoshis: FUNDING_SATS, script: buildP2PKHScript(pubKey) };

  // Default MockProvider: Spend-validates every input of a broadcast tx,
  // refuses unknown outpoints, enforces the fee floor.
  const provider = new MockProvider('testnet');
  provider.addUtxo(address, fundingUtxo);
  provider.addContractUtxo(lockingHex, contractUtxo);
  provider.addContractUtxo(lockingHex + ':extra', extraContractUtxo);

  const contract = RunarContract.fromUtxo(r.artifact, contractUtxo);
  contract.connect(provider, signer);
  const prepared = await contract.prepareCall('increment', [null], {
    additionalContractInputs: [extraContractUtxo],
  });
  if (prepared.sigIndices.length !== 1 || prepared.sigIndices[0] !== 0) {
    throw new Error(`unexpected sigIndices ${JSON.stringify(prepared.sigIndices)}`);
  }
  // The external signer's job: ECDSA over the BIP-143 digest, exactly as
  // LocalSigner.sign does (PrivateKey.sign sha256-hashes its input once more,
  // so pass sha256(preimage) to land on hash256(preimage)).
  if (prepared.sighash !== Utils.toHex(Hash.hash256(Utils.toArray(prepared.preimage, 'hex')))) {
    throw new Error('prepared.sighash is not hash256(prepared.preimage)');
  }
  const primarySignatureHex =
    (PrivateKey.fromHex(PRIV).sign(Hash.sha256(Utils.toArray(prepared.preimage, 'hex'))).toDER('hex') as string) + '41';
  const preparedTxHex = prepared.tx.toHex();
  await contract.finalizeCall(prepared, { 0: primarySignatureHex });

  const broadcast = provider.getBroadcastedTxs();
  if (broadcast.length !== 1) throw new Error(`expected 1 broadcast, got ${broadcast.length}`);
  if (provider.getValidationStats().validated !== 3) {
    throw new Error(`expected Spend validation of 3 inputs, got ${provider.getValidationStats().validated}`);
  }
  const tx = Transaction.fromHex(broadcast[0]!);

  return {
    vector_version: 1,
    notes:
      'N-286 cross-SDK vector: a stateful merge through prepareCall/finalizeCall. Load the artifact, build the ' +
      'contract from contractUtxo (constructorArgs), connect a provider holding fundingUtxo for the privKeyHex ' +
      'address, and prepareCall `increment` with a null Sig (auto-sign placeholder) and additional contract input ' +
      'extraContractUtxo (tiers that do not auto-compute state in prepareCall pass newState). Assert: ' +
      'prepared sighash == expected.sighash and sig indices == [0]; finalizeCall with expected.primarySignatureHex at ' +
      'sig index 0; the broadcast tx hex == expected.referenceTxHex. Input 1 (the extra contract input) is fully ' +
      'built and signed by the connected signer inside prepareCall; finalizeCall rewrites input 0 only. ' +
      'Generated by conformance/sdk-call/generate-stateful-merge.ts (MockProvider Spend-validated all 3 inputs); ' +
      'replayed through @bsv/sdk Spend by conformance/sdk-call/stateful-merge.test.ts.',
    source: SOURCE,
    artifact,
    constructorArgs: { count: '0', owner: pubKey },
    newState: { count: '1' },
    privKeyHex: PRIV,
    pubKeyHex: pubKey,
    contractUtxo,
    extraContractUtxo,
    fundingUtxo,
    method: 'increment',
    expected: {
      sigIndices: [0],
      sighash: prepared.sighash,
      preimageHex: prepared.preimage,
      primarySignatureHex,
      preparedTxHex,
      inputCount: tx.inputs.length,
      outputCount: tx.outputs.length,
      referenceTxHex: tx.toHex(),
    },
  };
}

async function main(): Promise<void> {
  const want = JSON.stringify(await buildMergeVector(), null, 2) + '\n';
  if (process.argv.includes('--check')) {
    if (readFileSync(MERGE_VECTOR_PATH, 'utf8') !== want) {
      console.error(`drift: ${MERGE_VECTOR_PATH} differs from a fresh derivation`);
      process.exit(1);
    }
    console.log('stateful-merge vector up to date');
    return;
  }
  writeFileSync(MERGE_VECTOR_PATH, want);
  console.log(`wrote ${MERGE_VECTOR_PATH}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  void main();
}

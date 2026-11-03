/**
 * N-042 — TokenWallet drives a SHIPPED example contract end to end.
 *
 * TokenWallet is written against one ABI: state `supply` + `holder`,
 * `transfer(sig, to: Addr)` and `merge(sig, otherSupply, otherHolder)`. No
 * contract in the repo had that ABI — `examples/ts/token-ft` has
 * `transfer(sig, to: PubKey, amount, outputSatoshis)` and runar-lang's
 * `FungibleToken` is stateless — so the wallet could only ever be exercised
 * against a fixture inlined in its own test (F-045). User decision R86: ship a
 * matching example, `examples/ts/token-wallet-naive-INSECURE/WalletToken.runar.ts`,
 * and run TokenWallet against THAT file.
 *
 * Oracle: MockProvider's default broadcast validation (@bsv/sdk `Spend`), plus
 * an explicit `Spend.validate()` replay of every input of every broadcast tx —
 * real ECDSA, real BIP-143. Never TestContract / the ANF interpreter.
 *
 * What this proves: the shipped example compiles, deploys, and TokenWallet's
 * getBalance / transfer / merge produce transactions whose every input passes
 * Spend.validate; the signature check is real (a non-holder wallet is
 * refused); merge spends both token outpoints into one continuation holding
 * the summed supply.
 * What it does NOT prove: node acceptance, the other SDKs (see their own
 * N-042 tests), or that the example is a sound token. It is not: `transfer`
 * cannot reassign the PubKey holder to an Addr, and `merge` cannot
 * authenticate its companion input, so the holder can inflate supply with a
 * single-input merge. Both limits are inherent to the ABI and are documented
 * in the example's header.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';
import { Spend, LockingScript, Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { TokenWallet } from '../tokens.js';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';

const EXAMPLE_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '../../../../examples/ts/token-wallet-naive-INSECURE/WalletToken.runar.ts',
);

const HOLDER_KEY = '0000000000000000000000000000000000000000000000000000000000000142';
const DEPLOYER_KEY = '0000000000000000000000000000000000000000000000000000000000000143';
const OTHER_KEY = '0000000000000000000000000000000000000000000000000000000000000144';

function compileExample(): RunarArtifact {
  const source = readFileSync(EXAMPLE_PATH, 'utf8');
  const r = compile(source, { fileName: 'WalletToken.runar.ts' });
  if (!r.success || !r.artifact) {
    throw new Error(r.diagnostics.map((d) => d.message).join('; '));
  }
  return r.artifact as unknown as RunarArtifact;
}

type Known = Map<string, { script: string; satoshis: number }>;

/** Presents a fixed UTXO list for getUtxos so each deploy spends its own coin. */
class FundingView {
  constructor(private readonly inner: MockProvider, private readonly coins: unknown[]) {}
  getUtxos = async () => this.coins as never;
  broadcast = (tx: Transaction) => this.inner.broadcast(tx);
  getTransaction = (txid: string) => this.inner.getTransaction(txid);
  getRawTransaction = (txid: string) => this.inner.getRawTransaction(txid);
  getFeeRate = () => this.inner.getFeeRate();
  getNetwork = () => this.inner.getNetwork();
  getContractUtxo = (h: string) => this.inner.getContractUtxo(h);
}

async function setup(artifact: RunarArtifact, supplies: bigint[], walletKey?: string) {
  const provider = new MockProvider();
  const holder = new LocalSigner(HOLDER_KEY);
  const holderAddr = await holder.getAddress();
  const holderPub = await holder.getPublicKey();
  const deployer = new LocalSigner(DEPLOYER_KEY);
  const known: Known = new Map();

  const tokenUtxos = [];
  for (let i = 0; i < supplies.length; i++) {
    const deployFunding = {
      txid: (i + 0x42).toString(16).padStart(2, '0').repeat(32),
      outputIndex: 0,
      satoshis: 1_000_000,
      script: buildP2PKHScript(await deployer.getPublicKey()),
    };
    provider.addUtxo(`deployer-${i}`, deployFunding);
    const token = new RunarContract(artifact, [supplies[i]!, holderPub]);
    await token.deploy(new FundingView(provider, [deployFunding]), deployer, { satoshis: 5_000 });
    const u = token.getUtxo()!;
    provider.addUtxo(holderAddr, u);
    known.set(`${u.txid}:${u.outputIndex}`, { script: u.script, satoshis: u.satoshis });
    tokenUtxos.push(u);
  }

  const funding = {
    txid: 'fd'.repeat(32),
    outputIndex: 0,
    satoshis: 200_000,
    script: buildP2PKHScript(holderPub),
  };
  provider.addUtxo(holderAddr, funding);
  known.set(`${funding.txid}:0`, { script: funding.script, satoshis: funding.satoshis });

  const walletSigner = walletKey ? new LocalSigner(walletKey) : holder;
  if (walletKey) {
    for (const u of [...tokenUtxos, funding]) provider.addUtxo(await walletSigner.getAddress(), u);
  }
  return { provider, wallet: new TokenWallet(artifact, provider, walletSigner), tokenUtxos, known };
}

/** Replay every input of `txHex` through @bsv/sdk's Spend; throws on failure. */
function spendValidateAll(txHex: string, known: Known): void {
  const tx = Transaction.fromHex(txHex);
  tx.inputs.forEach((input, i) => {
    const key = `${input.sourceTXID}:${input.sourceOutputIndex}`;
    const prev = known.get(key);
    if (!prev) throw new Error(`input ${i} spends unknown outpoint ${key}`);
    const spend = new Spend({
      sourceTXID: input.sourceTXID!,
      sourceOutputIndex: input.sourceOutputIndex,
      sourceSatoshis: prev.satoshis,
      lockingScript: LockingScript.fromHex(prev.script),
      transactionVersion: tx.version,
      otherInputs: tx.inputs.filter((_, j) => j !== i),
      outputs: tx.outputs,
      inputIndex: i,
      unlockingScript: input.unlockingScript!,
      inputSequence: input.sequence ?? 0xffffffff,
      lockTime: tx.lockTime,
    });
    expect(spend.validate()).toBe(true);
  });
}

function lastBroadcast(provider: MockProvider): string {
  const txs = provider.getBroadcastedTxs();
  return txs[txs.length - 1]!;
}

describe('N-042 TokenWallet against the shipped WalletToken example', () => {
  it('getBalance + transfer: the broadcast tx validates on every input', async () => {
    const artifact = compileExample();
    const { provider, wallet, tokenUtxos, known } = await setup(artifact, [100n]);
    expect(await wallet.getBalance()).toBe(100n);

    const txid = await wallet.transfer(await new LocalSigner(OTHER_KEY).getAddress(), 100n);

    const txHex = lastBroadcast(provider);
    const tx = Transaction.fromHex(txHex);
    expect(tx.id('hex')).toBe(txid);
    expect(`${tx.inputs[0]!.sourceTXID}:${tx.inputs[0]!.sourceOutputIndex}`).toBe(
      `${tokenUtxos[0]!.txid}:${tokenUtxos[0]!.outputIndex}`,
    );
    spendValidateAll(txHex, known);
  });

  it('transfer from a wallet that is not the holder is refused (checkSig is real)', async () => {
    const artifact = compileExample();
    const { wallet } = await setup(artifact, [100n], OTHER_KEY);
    await expect(wallet.transfer(await new LocalSigner(OTHER_KEY).getAddress(), 100n))
      .rejects.toThrow(/refusing to broadcast invalid transaction/);
  });

  it('merge: spends both token outpoints once, every input validates, supply is summed', async () => {
    const artifact = compileExample();
    const { provider, wallet, tokenUtxos, known } = await setup(artifact, [100n, 250n]);
    expect(await wallet.getBalance()).toBe(350n);

    const txid = await wallet.merge();

    const txHex = lastBroadcast(provider);
    const tx = Transaction.fromHex(txHex);
    expect(tx.id('hex')).toBe(txid);
    const spent = tx.inputs.map((inp) => `${inp.sourceTXID}:${inp.sourceOutputIndex}`);
    for (const u of tokenUtxos) expect(spent).toContain(`${u.txid}:${u.outputIndex}`);
    expect(new Set(spent).size).toBe(spent.length);
    spendValidateAll(txHex, known);
    const merged = await RunarContract.fromTxId(artifact, txid, 0, provider);
    expect(merged.state['supply']).toBe(350n);
  });
});

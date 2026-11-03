/**
 * F-045 — TokenWallet.transfer / .merge must sign the transaction that is
 * actually broadcast.
 *
 * The defect: both helpers built a throwaway `prelimTx` locally, BIP-143-signed
 * input 0 of THAT tx, and handed the concrete signature to `contract.call`. A
 * non-null Sig arg skips call()'s auto-signing, and prepareCall builds a
 * different transaction (its own coin selection, real unlock size, change
 * output, and — for a stateful contract — the OP_CODESEPARATOR-trimmed
 * subscript), so the embedded signature never covers the broadcast tx.
 * `merge` also never passed the second token UTXO as an input, so it was read
 * for its supply and left unspent.
 *
 * Oracle: @bsv/sdk `Spend.validate()` (real ECDSA, real BIP-143) replayed on
 * every input of the broadcast tx — never TestContract / the ANF interpreter.
 * MockProvider's own broadcast validation (also `Spend`) is on by default, so
 * pre-fix the call throws before anything is broadcast.
 *
 * The token contract is compiled here from source against the ABI TokenWallet
 * is written for: state field `supply`, `holder: PubKey`,
 * `transfer(sig: Sig, to: Addr)`, `merge(sig: Sig, otherSupply: bigint,
 * otherHolder: PubKey)`. (`examples/ts/token-ft` has a different ABI —
 * transfer(sig, to: PubKey, amount, outputSatoshis) — that TokenWallet cannot
 * call at all.)
 *
 * What this proves: every input of the tx TokenWallet broadcasts passes
 * Spend.validate, the signature check is real (a wrong-holder wallet is
 * refused), and merge spends BOTH token outpoints into one continuation
 * holding the summed supply.
 * What it does NOT prove: mainnet acceptance (no node here), the other six
 * SDKs, or any token semantics beyond this test fixture (its `transfer` does
 * not reassign the holder — it only exercises the signing path).
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { Spend, LockingScript, Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { TokenWallet } from '../tokens.js';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript, pubkeyToPKH } from '../script-utils.js';

const WALLET_TOKEN = `
import { StatefulSmartContract, assert, checkSig, len } from 'runar-lang';
import type { PubKey, Sig, Addr } from 'runar-lang';

class WalletToken extends StatefulSmartContract {
  supply: bigint;
  holder: PubKey;

  constructor(supply: bigint, holder: PubKey) {
    super(supply, holder);
    this.supply = supply;
    this.holder = holder;
  }

  public transfer(sig: Sig, to: Addr) {
    assert(checkSig(sig, this.holder));
    assert(len(to) === 20n);
  }

  public merge(sig: Sig, otherSupply: bigint, otherHolder: PubKey) {
    assert(checkSig(sig, this.holder));
    assert(otherHolder === this.holder);
    assert(otherSupply >= 0n);
    this.supply = this.supply + otherSupply;
  }
}
`;

const HOLDER_KEY = '0000000000000000000000000000000000000000000000000000000000000045';
const DEPLOYER_KEY = '0000000000000000000000000000000000000000000000000000000000000046';
const OTHER_KEY = '0000000000000000000000000000000000000000000000000000000000000047';

function compileToken(): RunarArtifact {
  const r = compile(WALLET_TOKEN, { fileName: 'WalletToken.runar.ts' });
  if (!r.success || !r.artifact) {
    throw new Error(r.diagnostics.map((d) => d.message).join('; '));
  }
  return r.artifact as unknown as RunarArtifact;
}

const artifact = compileToken();

/** Outpoint -> the output it spends, for every coin this test created. */
type Known = Map<string, { script: string; satoshis: number }>;

/**
 * Deploy token UTXOs (from a separate deployer wallet) holding `supplies`, all
 * owned by `holderSigner`, and credit them plus one P2PKH funding coin to the
 * holder's address — what a WhatsOnChain-backed wallet would list.
 */
async function setup(
  supplies: bigint[],
  opts: { tokenSats?: number; fundingSats?: number; walletKey?: string } = {},
) {
  const provider = new MockProvider();
  const holder = new LocalSigner(HOLDER_KEY);
  const holderAddr = await holder.getAddress();
  const holderPub = await holder.getPublicKey();
  const deployer = new LocalSigner(DEPLOYER_KEY);
  const known: Known = new Map();

  const tokenUtxos = [];
  for (let i = 0; i < supplies.length; i++) {
    const deployFunding = {
      txid: (i + 1).toString(16).padStart(2, '0').repeat(32),
      outputIndex: 0,
      satoshis: 1_000_000,
      script: buildP2PKHScript(await deployer.getPublicKey()),
    };
    provider.addUtxo(`deployer-${i}`, deployFunding);
    const token = new RunarContract(artifact, [supplies[i]!, holderPub]);
    // Each deploy spends only its own funding coin.
    await token.deploy(
      new FundingView(provider, [deployFunding]),
      deployer,
      { satoshis: opts.tokenSats ?? 5_000 },
    );
    const u = token.getUtxo()!;
    provider.addUtxo(holderAddr, u);
    known.set(`${u.txid}:${u.outputIndex}`, { script: u.script, satoshis: u.satoshis });
    tokenUtxos.push(u);
  }

  const funding = {
    txid: 'fe'.repeat(32),
    outputIndex: 0,
    satoshis: opts.fundingSats ?? 200_000,
    script: buildP2PKHScript(holderPub),
  };
  provider.addUtxo(holderAddr, funding);
  known.set(`${funding.txid}:0`, { script: funding.script, satoshis: funding.satoshis });

  const walletSigner = opts.walletKey ? new LocalSigner(opts.walletKey) : holder;
  if (opts.walletKey) {
    // A wallet whose key is NOT the holder, listing the holder's coins.
    for (const u of [...tokenUtxos, funding]) provider.addUtxo(await walletSigner.getAddress(), u);
  }
  const wallet = new TokenWallet(artifact, provider, walletSigner);
  return { provider, wallet, tokenUtxos, funding, known, holderPub };
}

/**
 * Presents `provider` with a fixed UTXO list for getUtxos, so each deploy
 * spends only its own funding coin. Everything else delegates.
 */
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

/** Replay input `i` of `txHex` through @bsv/sdk's Spend; throws on failure. */
function spendValidate(txHex: string, i: number, known: Known): true {
  const tx = Transaction.fromHex(txHex);
  const input = tx.inputs[i]!;
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
  return spend.validate() as true;
}

function lastBroadcast(provider: MockProvider): string {
  const txs = provider.getBroadcastedTxs();
  return txs[txs.length - 1]!;
}

describe('F-045 TokenWallet signs the transaction it broadcasts', () => {
  it('transfer: input 0 of the broadcast tx passes Spend.validate', async () => {
    const { provider, wallet, tokenUtxos, known } = await setup([100n]);
    // An Addr is a hash160; pass it raw here so this test isolates signing.
    const recipient = pubkeyToPKH(await new LocalSigner(OTHER_KEY).getPublicKey());

    const txid = await wallet.transfer(recipient, 100n);

    const txHex = lastBroadcast(provider);
    const tx = Transaction.fromHex(txHex);
    expect(tx.id('hex')).toBe(txid);
    expect(tx.inputs[0]!.sourceTXID).toBe(tokenUtxos[0]!.txid);
    expect(tx.inputs[0]!.sourceOutputIndex).toBe(tokenUtxos[0]!.outputIndex);
    for (let i = 0; i < tx.inputs.length; i++) {
      expect(spendValidate(txHex, i, known)).toBe(true);
    }
  });

  it('transfer: accepts the documented Base58 recipient address', async () => {
    const { provider, wallet, known } = await setup([100n]);
    const txid = await wallet.transfer(await new LocalSigner(OTHER_KEY).getAddress(), 100n);
    const txHex = lastBroadcast(provider);
    expect(Transaction.fromHex(txHex).id('hex')).toBe(txid);
    expect(spendValidate(txHex, 0, known)).toBe(true);
  });

  it('transfer: a wallet whose key is not the holder is refused (the checkSig is real)', async () => {
    const { wallet } = await setup([100n], { walletKey: OTHER_KEY });
    const recipient = pubkeyToPKH(await new LocalSigner(OTHER_KEY).getPublicKey());
    await expect(wallet.transfer(recipient, 100n))
      .rejects.toThrow(/refusing to broadcast invalid transaction/);
  });

  it('merge: spends BOTH token outpoints, every input validates, supply is summed', async () => {
    const { provider, wallet, tokenUtxos, known } = await setup([100n, 250n]);

    const txid = await wallet.merge();

    const txHex = lastBroadcast(provider);
    const tx = Transaction.fromHex(txHex);
    expect(tx.id('hex')).toBe(txid);
    const spent = tx.inputs.map((inp) => `${inp.sourceTXID}:${inp.sourceOutputIndex}`);
    for (const u of tokenUtxos) {
      expect(spent).toContain(`${u.txid}:${u.outputIndex}`);
    }
    // Each outpoint exactly once — a token UTXO must not double as a funding input.
    expect(new Set(spent).size).toBe(spent.length);
    for (let i = 0; i < tx.inputs.length; i++) {
      expect(spendValidate(txHex, i, known)).toBe(true);
    }
    const merged = await RunarContract.fromTxId(artifact, txid, 0, provider);
    expect(merged.state['supply']).toBe(350n);
  });

  it('merge: a token UTXO larger than the funding coin is still spent as a contract input, not as funding', async () => {
    // Largest-first funding selection would otherwise pick the second token
    // UTXO (listed at the same address) as a P2PKH funding input as well.
    const { provider, wallet, tokenUtxos, known } = await setup([100n, 250n], {
      tokenSats: 300_000,
      fundingSats: 50_000,
    });

    const txid = await wallet.merge();

    const txHex = lastBroadcast(provider);
    const tx = Transaction.fromHex(txHex);
    expect(tx.id('hex')).toBe(txid);
    const spent = tx.inputs.map((inp) => `${inp.sourceTXID}:${inp.sourceOutputIndex}`);
    for (const u of tokenUtxos) {
      expect(spent).toContain(`${u.txid}:${u.outputIndex}`);
    }
    expect(new Set(spent).size).toBe(spent.length);
    for (let i = 0; i < tx.inputs.length; i++) {
      expect(spendValidate(txHex, i, known)).toBe(true);
    }
  });
});

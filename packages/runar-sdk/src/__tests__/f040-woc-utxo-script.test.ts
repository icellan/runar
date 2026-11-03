// F-040: WhatsOnChainProvider.getUtxos returned `script: ''` for every UTXO,
// because WoC's GET /address/{a}/unspent listing carries no locking script.
// That empty string became the BIP-143 scriptCode in LocalSigner.sign, so
// every funding signature was computed over a zero-length scriptCode, which
// no real P2PKH OP_CHECKSIG accepts.
//
// Proves:
//   - with the shared recorded responses (conformance/sdk-woc/vectors.json),
//     getUtxos fetches GET /tx/{txid}/hex for each UTXO and returns the real
//     locking script and satoshis;
//   - it fails loudly when the tx body hashes to another txid, when tx_pos is
//     not an output, when the listed value disagrees with the tx, when the tx
//     is unavailable, and when the output script is empty;
//   - LocalSigner and WalletSigner refuse an empty subscript;
//   - by execution under @bsv/sdk Spend.validate: a signature over an empty
//     scriptCode does not unlock a real P2PKH output, while the fixed
//     getUtxos -> LocalSigner.sign flow's signature does.
// Does NOT prove: that the live WoC API still serves these shapes (vectors
// recorded 2026-09-29), nor anything about getContractUtxo, which is not
// changed by F-040.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  PrivateKey,
  P2PKH,
  Transaction,
  TransactionSignature,
  Script,
  UnlockingScript,
  LockingScript,
  Spend,
  Hash,
  Utils,
  type SecurityLevel,
} from '@bsv/sdk';
import { WhatsOnChainProvider } from '../providers/woc.js';
import { LocalSigner } from '../signers/local.js';
import { WalletSigner } from '../signers/wallet.js';

interface WocRejection {
  name: string;
  unspentBody: string;
  rawTxHex: Record<string, string>;
  error: string;
}
interface WocVectorFile {
  address: string;
  unspentBody: string;
  rawTxHex: Record<string, string>;
  expected: { txid: string; outputIndex: number; satoshis: number; script: string }[];
  rejection_vectors: WocRejection[];
}

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(join(here, '..', '..', '..', '..', 'conformance', 'sdk-woc', 'vectors.json'), 'utf8'),
) as WocVectorFile;

const BASE = 'https://api.whatsonchain.com/v1/bsv/main';

/** Serve `unspentBody` at the address listing and each raw tx at /tx/{txid}/hex; 404 elsewhere. */
function serveWoc(address: string, unspentBody: string, rawTxHex: Record<string, string>) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url === `${BASE}/address/${address}/unspent`) {
      return new Response(unspentBody, { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const m = /^.*\/tx\/([0-9a-f]{64})\/hex$/.exec(url);
    if (m && rawTxHex[m[1]!] !== undefined) {
      return new Response(rawTxHex[m[1]!], { status: 200, headers: { 'content-type': 'text/plain' } });
    }
    return new Response('Not Found', { status: 404 });
  });
}

afterEach(() => vi.restoreAllMocks());

describe('F-040 WhatsOnChainProvider.getUtxos returns the real locking script', () => {
  it('recorded listing: every UTXO carries its output script and value', async () => {
    serveWoc(vectors.address, vectors.unspentBody, vectors.rawTxHex);
    const utxos = await new WhatsOnChainProvider('mainnet').getUtxos(vectors.address);
    expect(utxos).toEqual(vectors.expected);
  });

  for (const rv of vectors.rejection_vectors) {
    it(`rejects ${rv.name}`, async () => {
      serveWoc(vectors.address, rv.unspentBody, rv.rawTxHex);
      await expect(new WhatsOnChainProvider('mainnet').getUtxos(vectors.address)).rejects.toThrow(rv.error);
    });
  }
});

// A 1-in/1-out tx spending `fundingTxid:vout`.
function spendingTxHex(fundingTxid: string, vout: number): string {
  const tx = new Transaction();
  tx.addInput({
    sourceTXID: fundingTxid,
    sourceOutputIndex: vout,
    unlockingScript: new UnlockingScript(),
    sequence: 0xffffffff,
  });
  tx.addOutput({ satoshis: 900, lockingScript: new P2PKH().lock(PrivateKey.fromRandom().toAddress()) });
  return tx.toHex();
}

describe('F-040 signers refuse an empty subscript', () => {
  const txHex = spendingTxHex('11'.repeat(32), 0);

  it('LocalSigner.sign(tx, 0, "", sats) throws', async () => {
    const signer = new LocalSigner('01'.repeat(32));
    await expect(signer.sign(txHex, 0, '', 1000)).rejects.toThrow(/empty subscript/);
  });

  it('WalletSigner.sign(tx, 0, "", sats) throws before asking the wallet', async () => {
    const wallet = {
      getPublicKey: vi.fn(),
      createSignature: vi.fn(),
    };
    const signer = new WalletSigner({
      protocolID: [2 as SecurityLevel, 'test app'],
      keyID: '1',
      wallet: wallet as never,
    });
    await expect(signer.sign(txHex, 0, '', 1000)).rejects.toThrow(/empty subscript/);
    expect(wallet.createSignature).not.toHaveBeenCalled();
  });
});

describe('F-040 harm, by execution under @bsv/sdk Spend.validate', () => {
  const key = PrivateKey.fromHex('5c'.repeat(32));
  const pubKeyHex = key.toPublicKey().toDER('hex') as string;
  const address = key.toAddress();
  const lock = new P2PKH().lock(address);

  // A funding tx paying 1000 sats to `key` at output 0.
  const funding = new Transaction();
  funding.addInput({
    sourceTXID: '22'.repeat(32),
    sourceOutputIndex: 0,
    unlockingScript: new UnlockingScript(),
    sequence: 0xffffffff,
  });
  funding.addOutput({ satoshis: 1000, lockingScript: lock });
  const fundingHex = funding.toHex();
  const fundingTxid = funding.id('hex') as string;

  function validates(spendHex: string, sigHex: string): boolean {
    const tx = Transaction.fromHex(spendHex);
    const unlocking = new UnlockingScript([
      { op: sigHex.length / 2, data: Utils.toArray(sigHex, 'hex') },
      { op: pubKeyHex.length / 2, data: Utils.toArray(pubKeyHex, 'hex') },
    ]);
    const spend = new Spend({
      sourceTXID: fundingTxid,
      sourceOutputIndex: 0,
      sourceSatoshis: 1000,
      lockingScript: LockingScript.fromHex(lock.toHex()),
      transactionVersion: tx.version,
      otherInputs: [],
      outputs: tx.outputs,
      unlockingScript: unlocking,
      inputIndex: 0,
      inputSequence: 0xffffffff,
      lockTime: tx.lockTime,
    });
    try {
      return spend.validate();
    } catch {
      return false;
    }
  }

  it('a signature over an empty scriptCode (the pre-fix flow) is rejected', () => {
    const spendHex = spendingTxHex(fundingTxid, 0);
    const tx = Transaction.fromHex(spendHex);
    // Exactly what LocalSigner computed before F-040 when handed script ''.
    const preimage = TransactionSignature.format({
      sourceTXID: fundingTxid,
      sourceOutputIndex: 0,
      sourceSatoshis: 1000,
      transactionVersion: tx.version,
      otherInputs: [],
      outputs: tx.outputs,
      inputIndex: 0,
      subscript: Script.fromHex('') as never,
      inputSequence: 0xffffffff,
      lockTime: tx.lockTime,
      scope: 0x41,
    });
    const sigHex = (key.sign(Hash.sha256(preimage)).toDER('hex') as string) + '41';
    expect(validates(spendHex, sigHex)).toBe(false);
  });

  it('the fixed getUtxos -> LocalSigner.sign flow produces a signature that is accepted', async () => {
    const listing = JSON.stringify([{ height: 1, tx_pos: 0, tx_hash: fundingTxid, value: 1000 }]);
    serveWoc(address, listing, { [fundingTxid]: fundingHex });
    const [utxo] = await new WhatsOnChainProvider('mainnet').getUtxos(address);
    expect(utxo!.script).toBe(lock.toHex());

    const spendHex = spendingTxHex(utxo!.txid, utxo!.outputIndex);
    const sigHex = await new LocalSigner('5c'.repeat(32)).sign(spendHex, 0, utxo!.script, utxo!.satoshis);
    expect(validates(spendHex, sigHex)).toBe(true);
  });
});

/**
 * Regtest integration test for `assembleMultiContractCall` — the on-chain
 * counterpart of multi-contract-call.test.ts.
 *
 * Two DIFFERENT artifacts are deployed as real UTXOs and consumed by ONE
 * spending tx assembled via the new surface:
 *   input 0: OutputBinder.release (terminal, binds outputs via hashOutputs)
 *   input 1: BumpToken.bump      (stateful continuation + P2PKH change)
 *
 * The real node accepting that tx is the proof; a wrong-owner assembly must be
 * rejected BY THE NODE. Suite skips gracefully when no regtest node is up.
 *
 * Node defaults match integration/regtest.sh (RPC_URL / RPC_USER / RPC_PASS
 * env overrides supported).
 */

import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { assembleMultiContractCall, dryRunMultiContractInput } from '../multi-contract.js';
import { RPCProvider } from '../providers/rpc-provider.js';
import { LocalSigner } from '../signers/local.js';
import { ExternalSigner } from '../signers/external.js';
import { Hash, Utils } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Regtest RPC helpers (self-contained)
// ---------------------------------------------------------------------------

const RPC_URL = process.env.RPC_URL ?? 'http://localhost:18332';
const RPC_USER = process.env.RPC_USER ?? 'bitcoin';
const RPC_PASS = process.env.RPC_PASS ?? 'bitcoin';

async function rpcCall(method: string, ...params: unknown[]): Promise<unknown> {
  const auth = Buffer.from(`${RPC_USER}:${RPC_PASS}`).toString('base64');
  const response = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Basic ${auth}` },
    body: JSON.stringify({ jsonrpc: '1.0', id: 'multi-contract', method, params }),
    signal: AbortSignal.timeout(120_000),
  });
  const json = (await response.json()) as { result: unknown; error: unknown };
  if (json.error) {
    throw new Error(`RPC ${method}: ${(json.error as { message?: string }).message ?? JSON.stringify(json.error)}`);
  }
  return json.result;
}

async function mine(blocks: number): Promise<void> {
  try {
    await rpcCall('generate', blocks);
  } catch {
    const addr = (await rpcCall('getnewaddress')) as string;
    await rpcCall('generatetoaddress', blocks, addr);
  }
}

async function isNodeAvailable(): Promise<boolean> {
  try {
    await rpcCall('getblockcount');
    return true;
  } catch {
    return false;
  }
}

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Encode(buffer: Buffer): string {
  let num = BigInt('0x' + buffer.toString('hex'));
  let result = '';
  while (num > 0n) { result = BASE58[Number(num % 58n)] + result; num /= 58n; }
  for (const byte of buffer) { if (byte === 0) result = '1' + result; else break; }
  return result;
}
function regtestAddress(pubKeyHash: string): string {
  const payload = Buffer.concat([Buffer.from([0x6f]), Buffer.from(pubKeyHash, 'hex')]);
  const h1 = createHash('sha256').update(payload).digest();
  const h2 = createHash('sha256').update(h1).digest();
  return base58Encode(Buffer.concat([payload, h2.subarray(0, 4)]));
}

const hash160hex = (pubKeyHex: string): string =>
  Utils.toHex(Hash.hash160(Utils.toArray(pubKeyHex, 'hex')));
const hash256hex = (hex: string): string => {
  const f = createHash('sha256').update(Buffer.from(hex, 'hex')).digest();
  return createHash('sha256').update(f).digest('hex');
};
const u64le = (n: bigint): string => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n);
  return b.toString('hex');
};
const varintHex = (n: number): string => {
  if (n < 0xfd) return n.toString(16).padStart(2, '0');
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n);
  return 'fd' + b.toString('hex');
};

interface TestWallet { pubKeyHex: string; local: LocalSigner; signer: ExternalSigner }

async function createFundedWallet(btcAmount = 0.05): Promise<TestWallet> {
  const local = new LocalSigner(
    createHash('sha256').update(`multi-contract-${Date.now()}-${Math.random()}`).digest('hex'),
  );
  const pubKeyHex = await local.getPublicKey();
  const address = regtestAddress(hash160hex(pubKeyHex));
  await rpcCall('importaddress', address, '', false);
  try {
    await rpcCall('sendtoaddress', address, btcAmount);
  } catch {
    await mine(101);
    await rpcCall('sendtoaddress', address, btcAmount);
  }
  await mine(1);
  const signer = new ExternalSigner(
    pubKeyHex, address,
    async (txHex, inputIndex, subscript, satoshis, sigHashType) =>
      local.sign(txHex, inputIndex, subscript, satoshis, sigHashType ?? 0x41),
  );
  return { pubKeyHex, local, signer };
}

// ---------------------------------------------------------------------------
// Contracts — same neutral pair as the unit suite
// ---------------------------------------------------------------------------

const TOKEN_SOURCE = `
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class BumpToken extends StatefulSmartContract {
  owner: PubKey;
  value: bigint;

  constructor(owner: PubKey, value: bigint) {
    super(owner, value);
    this.owner = owner;
    this.value = value;
  }

  public bump(sig: Sig, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    this.addOutput(outputSatoshis, this.owner, this.value + 1n);
  }

  public freeze(sig: Sig, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    this.addOutput(outputSatoshis, this.owner, this.value);
  }
}
`;

const BINDER_SOURCE = `
import { StatefulSmartContract, assert, checkSig, hash256, extractOutputHash } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class OutputBinder extends StatefulSmartContract {
  owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public release(sig: Sig, expectedOutputs: ByteString) {
    assert(checkSig(sig, this.owner));
    assert(hash256(expectedOutputs) === extractOutputHash(this.txPreimage));
  }
}
`;

function compileSource(source: string, fileName: string): RunarArtifact {
  const result = compile(source, { fileName });
  if (!result.artifact) {
    throw new Error(`compile failed for ${fileName}: ${JSON.stringify(result.diagnostics)}`);
  }
  return result.artifact;
}

const tokenArtifact = compileSource(TOKEN_SOURCE, 'BumpToken.runar.ts');
const binderArtifact = compileSource(BINDER_SOURCE, 'OutputBinder.runar.ts');

const nodeUp = await isNodeAvailable();

// ---------------------------------------------------------------------------
// Shared assembly for both cases
// ---------------------------------------------------------------------------

async function deployPairAndAssemble(wallet: TestWallet, sigWallet: TestWallet) {
  const provider = new RPCProvider(RPC_URL, RPC_USER, RPC_PASS, { autoMine: true, network: 'testnet' });

  const token = new RunarContract(tokenArtifact, [wallet.pubKeyHex, 5n]);
  await token.deploy(provider, wallet.signer, { satoshis: 3000 });
  const binder = new RunarContract(binderArtifact, [wallet.pubKeyHex]);
  await binder.deploy(provider, wallet.signer, { satoshis: 3000 });

  const tokenNext = new RunarContract(tokenArtifact, [wallet.pubKeyHex, 5n]);
  tokenNext.setState({ owner: wallet.pubKeyHex, value: 6n });
  const contScript = tokenNext.getLockingScript();
  const changePKH = hash160hex(wallet.pubKeyHex);
  const changeScript = '76a914' + changePKH + '88ac';
  const outputs = [
    { satoshis: 1500, script: contScript },
    { satoshis: 1000, script: changeScript },
  ];
  const expectedOutputs =
    u64le(1500n) + varintHex(contScript.length / 2) + contScript +
    u64le(1000n) + varintHex(changeScript.length / 2) + changeScript;

  const assembled = await assembleMultiContractCall(
    [
      {
        contract: binder, method: 'release',
        args: [null, expectedOutputs], signer: sigWallet.local,
      },
      {
        contract: token, method: 'bump',
        args: [null, 1500n], signer: sigWallet.local,
        changePKH, changeAmount: 1000n,
      },
    ],
    outputs,
    { dryRun: false }, // validated explicitly per-case below
  );
  return { assembled, token, binder };
}

// ---------------------------------------------------------------------------
// The suite
// ---------------------------------------------------------------------------

describe.skipIf(!nodeUp)('assembleMultiContractCall — regtest integration', () => {
  it('ACCEPT: a tx with two different-artifact covenant inputs is accepted and confirmed', async () => {
    const wallet = await createFundedWallet();
    const { assembled, token, binder } = await deployPairAndAssemble(wallet, wallet);

    // Offline gate first (ladder discipline: local-before-chain).
    const bU = binder.getUtxo()!;
    const tU = token.getUtxo()!;
    expect(dryRunMultiContractInput(assembled.txHex, 0, bU.script, bU.satoshis).valid).toBe(true);
    expect(dryRunMultiContractInput(assembled.txHex, 1, tU.script, tU.satoshis).valid).toBe(true);

    const txid = (await rpcCall('sendrawtransaction', assembled.txHex)) as string;
    expect(txid).toMatch(/^[0-9a-f]{64}$/);
    expect(txid).toBe(hash256hex(assembled.txHex).match(/.{2}/g)!.reverse().join(''));

    await mine(1);
    const verbose = (await rpcCall('getrawtransaction', txid, true)) as { confirmations?: number };
    expect(verbose.confirmations ?? 0).toBeGreaterThanOrEqual(1);
  }, 120_000);

  it('REJECT: the same assembly signed by a non-owner is rejected by the node', async () => {
    const wallet = await createFundedWallet();
    const stranger = await createFundedWallet(0.01);
    const { assembled } = await deployPairAndAssemble(wallet, stranger);

    let rejection = '';
    try {
      await rpcCall('sendrawtransaction', assembled.txHex);
    } catch (e) {
      rejection = e instanceof Error ? e.message : String(e);
    }
    expect(rejection).toMatch(/mandatory-script-verify-flag-failed|Script failed|non-mandatory/i);
  }, 120_000);
});

if (!nodeUp) {
  console.warn(`[multi-contract regtest] node not reachable at ${RPC_URL} — suite skipped`);
}

// N-474: CI's integration job starts a regtest node and runs this file with
// RUNAR_INTEGRATION_STRICT=1. There, an unreachable node is a failure, not a
// skip — otherwise a node that failed to start turns the step back into the
// green two-skip run every other job already produces. Outside strict mode
// this asserts nothing (and is not a skip either).
it('a regtest node answers when RUNAR_INTEGRATION_STRICT=1', () => {
  if (process.env.RUNAR_INTEGRATION_STRICT === '1') {
    expect(nodeUp, `RUNAR_INTEGRATION_STRICT=1 but no regtest node answered at ${RPC_URL}`).toBe(true);
  }
});

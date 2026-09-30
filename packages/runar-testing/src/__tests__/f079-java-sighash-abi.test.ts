/**
 * F-079 (GK-BUG-015) — the Java tier dropped `abi.methods[].sigHashType`.
 *
 * A public method declaring `/** @sighash SINGLE|FORKID *\/` compiles to a
 * covenant whose OP_PUSH_TX binding appends flag 0x43 to the derived signature
 * and asserts `extractSigHashType(txPreimage) == 0x43`. The SDK learns that
 * mode ONLY from `abi.methods[].sigHashType`; absent, it builds the BIP-143
 * preimage under ALL|FORKID (0x41). Java's `AnfMethod` carried no sighash, so
 * its artifact omitted the field and every call the SDK built for such a method
 * was a spend the script rejects.
 *
 * The Java artifact is produced by the Java CLI (`--emit-artifact`), the call
 * is built by the shipped TS SDK, and the verdict comes from `@bsv/sdk`'s
 * `Spend` interpreter on the serialized call tx (`validateContractInput`). No
 * TestContract, no ANF interpreter.
 *
 * What this proves:
 *  - the Java ABI equals the TS reference ABI (and Go's, when its binary is
 *    built) for a contract mixing a SINGLE|FORKID method and a default one;
 *  - the Java artifact, spent through the SDK, is ACCEPTED and the preimage's
 *    sighash byte is 0x43;
 *  - the same Java artifact with `sigHashType` removed (the pre-fix shape) is
 *    REJECTED by the script, with the SDK having signed under 0x41 — so the ABI
 *    field is load-bearing, not decorative.
 *
 * What this does NOT prove: anything about the soundness of SINGLE itself (the
 * compiler warns that the single same-index output must carry the full value;
 * that is SighashValidate's job), nor any `--ir`-path artifact (the ANF IR JSON
 * carries no per-method sighash in any tier, so an IR-built artifact omits it
 * exactly as Go's CompileFromIR does).
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner, buildP2PKHScript } from 'runar-sdk';
import { Transaction, UnlockingScript } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { testKey, validateContractInput } from '../oracle/real-crypto-execution.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-f079-'));

const FILE = 'Pair.runar.ts';
const SRC = `
class Pair extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  /** @sighash SINGLE|FORKID */
  public bump(amount: bigint): void {
    this.addOutput(amount, this.n + 1n);
  }
  public plain(): void {
    this.n = this.n + 1n;
  }
}
`;

const CONTRACT_SATS = 10_000;

function run(cmd: string, args: string[]): string {
  const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: 120_000, maxBuffer: 32 * 1024 * 1024 });
  if (r.error) throw new Error(`${cmd} failed to start: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} exited ${r.status}: ${r.stderr}`);
  return r.stdout;
}

let seq = 0;
function writeTmp(fileName: string, src: string): string {
  const dir = join(TMP, String(seq++));
  mkdirSync(dir);
  const p = join(dir, fileName);
  writeFileSync(p, src);
  return p;
}

function javaArtifact(): RunarArtifact {
  const libs = join(REPO, 'compilers', 'java', 'build', 'libs');
  const jar = existsSync(libs) ? readdirSync(libs).find((f) => f.endsWith('.jar')) : undefined;
  if (!jar) throw new Error('Java jar missing — run `gradle jar` in compilers/java');
  const out = writeTmp('artifact.json', '');
  run('java', ['-jar', join(libs, jar), '--source', writeTmp(FILE, SRC), '--emit-artifact', out]);
  return JSON.parse(readFileSync(out, 'utf8'));
}

function tsArtifact(): RunarArtifact {
  const r = compile(SRC, { fileName: FILE });
  if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
  return r.artifact as unknown as RunarArtifact;
}

/** MockProvider (broadcast validation ON) that remembers the last tx it was handed. */
class RecordingProvider extends MockProvider {
  lastAttempt: Transaction | undefined;
  override async broadcast(tx: Transaction): Promise<string> {
    this.lastAttempt = tx;
    return super.broadcast(tx);
  }
}

/**
 * Deploy Pair(5) with CONTRACT_SATS, then a caller calls `bump(CONTRACT_SATS)`:
 * the single continuation output (full value, n = 6) lands at index 0 — the
 * same index as the contract input, which is the only output SINGLE commits to.
 *
 * The caller owns no UTXOs (the #116 exact-cover shape used by
 * runar-sdk's sighash-exec.test.ts): change clamps to 0, so the continuation is
 * the SOLE output. A change output would sit at index 1, outside SINGLE's
 * hashOutputs, while the covenant hashes continuation‖change — the spend would
 * fail for a reason unrelated to this item. Zero fee, hence enforceFeeFloor off
 * (Spend validation on broadcast stays ON).
 */
async function callBump(artifact: RunarArtifact) {
  const alice = testKey('alice');
  const eve = testKey('eve');
  const deployer = new LocalSigner(alice.privKey);
  const caller = new LocalSigner(eve.privKey);
  const provider = new RecordingProvider('testnet', { enforceFeeFloor: false });
  provider.addUtxo(await deployer.getAddress(), {
    txid: alice.privKey.slice(0, 64), outputIndex: 0, satoshis: 500_000,
    script: buildP2PKHScript(alice.pubKey),
  });
  const contract = new RunarContract(artifact, [5n]);
  await contract.deploy(provider, deployer, { satoshis: CONTRACT_SATS });
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

  provider.lastAttempt = undefined;
  let error: string | undefined;
  try {
    await contract.call('bump', [BigInt(CONTRACT_SATS)], provider, caller, {
      outputs: [{ satoshis: CONTRACT_SATS, state: { n: 6n } }],
    });
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }
  const attempted = provider.lastAttempt as Transaction | undefined;
  if (!attempted) throw new Error(`no call tx was built: ${error}`);
  const callTx = Transaction.fromHex(attempted.toHex());

  // Largest push of the contract input's unlocking script = the preimage; its
  // last 4 bytes are the LE sighashType.
  let preimage: number[] = [];
  for (const c of UnlockingScript.fromHex(callTx.inputs[0]!.unlockingScript!.toHex()).chunks) {
    if (c.data && c.data.length > preimage.length) preimage = c.data;
  }
  let accepted: boolean;
  let scriptError: string | undefined;
  try {
    accepted = validateContractInput(callTx, 0, deployTx, 0);
  } catch (e) {
    accepted = false;
    scriptError = e instanceof Error ? e.message.split('\n')[0] : String(e);
  }
  return { accepted, scriptError, error, callTx, sighashByte: preimage[preimage.length - 4] };
}

describe('F-079 — Java artifact publishes the @sighash mode', () => {
  const java = javaArtifact();

  it('Java abi equals the TS reference abi (sigHashType 67 on bump only)', () => {
    const bump = java.abi.methods.find((m) => m.name === 'bump')!;
    const plain = java.abi.methods.find((m) => m.name === 'plain')!;
    expect(bump.sigHashType).toBe(0x43);
    expect('sigHashType' in plain).toBe(false);
    expect('sigHashType' in java.abi.constructor).toBe(false);
    expect(java.abi).toEqual(tsArtifact().abi);
  });

  it('Java abi equals the Go tier abi (when compilers/go/runar-go is built)', () => {
    const goBin = join(REPO, 'compilers', 'go', 'runar-go');
    if (!existsSync(goBin)) return; // ts parity above is the hard gate
    const go = JSON.parse(run(goBin, ['--source', writeTmp(FILE, SRC)])) as RunarArtifact;
    expect(java.abi).toEqual(go.abi);
  });

  it('the Java artifact spent through the SDK is ACCEPTED under SINGLE|FORKID', async () => {
    const v = await callBump(java);
    expect(v.error, v.error).toBeUndefined();
    expect(v.sighashByte).toBe(0x43);
    expect(v.callTx.inputs.length).toBe(1);
    expect(v.callTx.outputs.length).toBe(1);
    expect(v.callTx.outputs[0]!.satoshis).toBe(CONTRACT_SATS);
    expect(v.accepted, v.scriptError).toBe(true);
  });

  it('control: the same artifact WITHOUT sigHashType (pre-fix shape) is REJECTED', async () => {
    const stripped = JSON.parse(JSON.stringify(java)) as RunarArtifact;
    for (const m of stripped.abi.methods) delete (m as { sigHashType?: number }).sigHashType;
    const v = await callBump(stripped);
    expect(v.sighashByte, 'SDK falls back to ALL|FORKID').toBe(0x41);
    expect(v.accepted).toBe(false);
    // Rejected at the OP_PUSH_TX signature check: the script derives its
    // signature with flag 0x43 over a preimage the SDK built under 0x41.
    expect(v.scriptError).toMatch(/OP_CHECKSIGVERIFY requires that a valid signature/);
  });
});

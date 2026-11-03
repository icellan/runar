/**
 * F-016 — Python tier: which class in a `.runar.ts` file is the contract.
 *
 * The TS reference parser keeps only the class whose `extends` names a valid
 * base (`SmartContract` / `StatefulSmartContract` / `UnsafeSmartContract`) and
 * ignores every other class. Python's `parser_ts.py` compiled the FIRST class
 * in the file, defaulting a missing `extends` to `SmartContract`. A decoy
 * helper placed ahead of the real contract, with the same ABI, was therefore
 * compiled in its place with zero diagnostics:
 *
 *     class Helper {                       // no extends: TS ignores it
 *       public unlock(preimage: ByteString) { assert(sha256(preimage) !== this.hashValue); }
 *     }
 *     export class HashLock extends SmartContract {
 *       public unlock(preimage: ByteString) { assert(sha256(preimage) === this.hashValue); }
 *     }
 *
 * The source's contract is `HashLock`: only the hash preimage may spend. The
 * pre-fix Python artifact compiled `Helper` instead, which lets EVERY preimage
 * except the real one spend it (and locks the owner out).
 *
 * The acceptance oracle is the real `@bsv/sdk` `Spend` engine: the Python
 * CLI's artifact is deployed and called through the TS SDK, and the call's
 * contract input is replayed with `validateContractInput`. Expected verdicts
 * are derived BY HAND from the source, never from compiler output. The
 * byte-identity check compares against the TS reference compiler.
 *
 * What this proves: the Python-compiled artifact for a decoy-first file is the
 * TS reference's `HashLock` bytes, rejects a spend with a wrong preimage and
 * accepts the real preimage.
 * What it does NOT prove: anything about the other tiers' parsers, or about
 * the non-TS `.runar.*` surfaces of the Python tier.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner, buildP2PKHScript } from 'runar-sdk';
import { Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { testKey, validateContractInput } from '../oracle/real-crypto-execution.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const FILE = 'HashLock.runar.ts';

const SRC = `import { SmartContract, assert, ByteString, Sha256, sha256 } from 'runar-lang';

class Helper {
  readonly hashValue: Sha256;

  constructor(hashValue: Sha256) {
    super(hashValue);
    this.hashValue = hashValue;
  }

  public unlock(preimage: ByteString) {
    assert(sha256(preimage) !== this.hashValue);
  }
}

export class HashLock extends SmartContract {
  readonly hashValue: Sha256;

  constructor(hashValue: Sha256) {
    super(hashValue);
    this.hashValue = hashValue;
  }

  public unlock(preimage: ByteString) {
    assert(sha256(preimage) === this.hashValue);
  }
}
`;

const SECRET = Buffer.from('open sesame', 'utf8').toString('hex');
const WRONG = Buffer.from('let me in', 'utf8').toString('hex');
const HASH = createHash('sha256').update(Buffer.from(SECRET, 'hex')).digest('hex');

function compileWithPython(source: string): RunarArtifact {
  const dir = mkdtempSync(join(tmpdir(), 'runar-f016-'));
  const path = join(dir, FILE);
  writeFileSync(path, source);
  const r = spawnSync('python3', ['-m', 'runar_compiler', '--source', path], {
    cwd: join(REPO, 'compilers', 'python'),
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 32 * 1024 * 1024,
  });
  if (r.error) throw new Error(`python3 failed to start: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`python compile failed (${r.status}): ${r.stderr}`);
  return JSON.parse(r.stdout) as RunarArtifact;
}

interface Verdict {
  accepted: boolean;
  reachedEngine: boolean;
  error?: string;
}

/** Deploy the artifact locked to HASH, call `unlock(preimage)`, and replay the
 *  contract input on the real Spend engine. */
async function spend(artifact: RunarArtifact, preimage: string): Promise<Verdict> {
  const key = testKey('alice');
  const signer = new LocalSigner(key.privKey);
  const provider = new MockProvider();
  provider.addUtxo(await signer.getAddress(), {
    txid: key.privKey.slice(0, 64),
    outputIndex: 0,
    satoshis: 500_000,
    script: buildP2PKHScript(key.pubKey),
  });
  const contract = new RunarContract(artifact, [HASH]);
  await contract.deploy(provider, signer, {});
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  try {
    // dryRun: the SDK replays the contract input on the real Spend engine
    // before broadcast and throws a message unique to a script rejection.
    await contract.call('unlock', [preimage], provider, signer, { dryRun: true });
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

describe('F-016 — Python: a decoy class ahead of the contract is not compiled as the contract', () => {
  const artifact = compileWithPython(SRC);

  it('compiles the class that extends SmartContract, byte-identical to the TS reference', () => {
    const ref = compile(SRC, { fileName: FILE });
    expect(ref.success).toBe(true);
    expect(artifact.contractName).toBe('HashLock');
    expect(artifact.script).toBe(ref.scriptHex);
  });

  it('ATTACK unlock(wrong preimage) is REJECTED by the Spend engine', async () => {
    const v = await spend(artifact, WRONG);
    expect(v.reachedEngine, `never reached Spend: ${v.error ?? '(accepted)'}`).toBe(true);
    expect(v.accepted, 'a non-preimage spent the hash lock').toBe(false);
  });

  it('CONTROL unlock(real preimage) is ACCEPTED', async () => {
    const v = await spend(artifact, SECRET);
    expect(v.accepted, v.error).toBe(true);
  });
});

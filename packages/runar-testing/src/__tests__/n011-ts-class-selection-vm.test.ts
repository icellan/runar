/**
 * N-011 — every tier: which class in a `.runar.ts` file is the contract.
 *
 * The TS reference (`01-parse.ts`) keeps only the class whose `extends` names a
 * valid base (`SmartContract` / `StatefulSmartContract` / `UnsafeSmartContract`)
 * and ignores every other class. It reports "Only one SmartContract subclass is
 * allowed per file" at each extra valid class, and "No class extending
 * SmartContract, StatefulSmartContract, or UnsafeSmartContract found" when
 * there is none. F-016 ported that rule to Python. Zig, Ruby and Java still
 * compiled the FIRST class in the file, defaulting a missing `extends` to
 * `SmartContract`, so a decoy helper placed ahead of the real contract, with
 * the same ABI, was compiled in its place with zero diagnostics:
 *
 *     class Helper {                       // no extends: TS ignores it
 *       public unlock(preimage: ByteString) { assert(sha256(preimage) !== this.hashValue); }
 *     }
 *     export class HashLock extends SmartContract {
 *       public unlock(preimage: ByteString) { assert(sha256(preimage) === this.hashValue); }
 *     }
 *
 * The source's contract is `HashLock`: only the hash preimage may spend. The
 * pre-fix Zig / Ruby / Java artifact (a8008791) compiled `Helper` instead, which
 * lets EVERY preimage except the real one spend it. The same tiers also
 * compiled a lone non-extending class, silently took the first of several
 * valid classes, and Zig refused a foreign-base helper ahead of the contract
 * that TS accepts. Go selected correctly but worded both diagnostics
 * differently from TS.
 *
 * The acceptance oracle is the real `@bsv/sdk` `Spend` engine: each tier's
 * artifact is deployed and called through the TS SDK, and the call's contract
 * input is replayed with `validateContractInput`. Expected verdicts are derived
 * BY HAND from the source, never from compiler output.
 *
 * What this proves: for each of the seven tiers, the decoy-first file compiles
 * to the TS reference's `HashLock` bytes, the crafted wrong-preimage spend is
 * rejected and the real preimage accepted; and on the seven F-016 shapes, plus
 * a substring-named base, every tier accepts exactly the files TS accepts (same
 * bytes) and refuses the rest with the TS diagnostic text.
 * What it does NOT prove: diagnostic LOCATIONS (the per-tier parser tests pin
 * those), or class selection on the other eight `.runar.*` surfaces.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner, buildP2PKHScript } from 'runar-sdk';
import { Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { testKey, validateContractInput } from '../oracle/real-crypto-execution.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-n011-'));
const FILE = 'HashLock.runar.ts';

const NO_CLASS = 'No class extending SmartContract, StatefulSmartContract, or UnsafeSmartContract found';
const ONLY_ONE = 'Only one SmartContract subclass is allowed per file';

const IMPORTS = "import { SmartContract, assert, ByteString, Sha256, sha256 } from 'runar-lang';\n\n";

const HASHLOCK = `export class HashLock extends SmartContract {
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

// Same ABI as HashLock, but `unlock` accepts any preimage EXCEPT the real one.
const DECOY = `class Helper {
  readonly hashValue: Sha256;

  constructor(hashValue: Sha256) {
    super(hashValue);
    this.hashValue = hashValue;
  }

  public unlock(preimage: ByteString) {
    assert(sha256(preimage) !== this.hashValue);
  }
}
`;
const FOREIGN = DECOY.replace('class Helper {', 'class Helper extends Base {');

const DECOY_FIRST = IMPORTS + DECOY + '\n' + HASHLOCK;

/** The seven F-016 shapes plus SUBSTRING_BASE_ONLY. `reject` is the TS reference's diagnostic text. */
const SHAPES: { name: string; src: string; reject?: string }[] = [
  { name: 'DECOY_FIRST', src: DECOY_FIRST },
  { name: 'FOREIGN_BASE_FIRST', src: IMPORTS + FOREIGN + '\n' + HASHLOCK },
  { name: 'CONTRACT_FIRST', src: IMPORTS + HASHLOCK + '\n' + DECOY },
  { name: 'NO_EXTENDS_ONLY', src: IMPORTS + DECOY, reject: NO_CLASS },
  { name: 'FOREIGN_BASE_ONLY', src: IMPORTS + FOREIGN, reject: NO_CLASS },
  // The base must be EXACTLY a valid name: Go matched it by substring.
  {
    name: 'SUBSTRING_BASE_ONLY',
    src: IMPORTS + DECOY.replace('class Helper {', 'class Helper extends NotSmartContract {'),
    reject: NO_CLASS,
  },
  {
    name: 'TWO_VALID',
    src: IMPORTS + `export class First extends SmartContract {
  constructor() {
    super();
  }

  public unlock(preimage: ByteString) {
    assert(true);
  }
}

` + HASHLOCK,
    reject: ONLY_ONE,
  },
  {
    name: 'THREE_VALID',
    src: `import { SmartContract, assert } from 'runar-lang';

export class A extends SmartContract {
  constructor() { super(); }
  public unlock(x: bigint) { assert(x === 1n); }
}
export class B extends SmartContract {
  constructor() { super(); }
  public unlock(x: bigint) { assert(x === 2n); }
}
export class C extends SmartContract {
  constructor() { super(); }
  public unlock(x: bigint) { assert(x === 3n); }
}
`,
    reject: ONLY_ONE,
  },
];

const SECRET = Buffer.from('open sesame', 'utf8').toString('hex');
const WRONG = Buffer.from('let me in', 'utf8').toString('hex');
const HASH = createHash('sha256').update(Buffer.from(SECRET, 'hex')).digest('hex');

function requireBin(p: string, how: string): string {
  if (!existsSync(p)) throw new Error(`missing compiler binary ${p} — build it with: ${how}`);
  return p;
}

function javaJar(): string {
  const libs = join(REPO, 'compilers', 'java', 'build', 'libs');
  const jar = existsSync(libs) ? readdirSync(libs).find((f) => f.endsWith('.jar')) : undefined;
  if (!jar) throw new Error('Java jar missing — run `gradle jar` in compilers/java');
  return join(libs, jar);
}

interface Run { status: number; stdout: string; out: string }

/** Run a CLI to completion. A spawn error or signal is a broken harness, never a verdict. */
function run(cmd: string, args: string[], cwd?: string): Run {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 120_000, maxBuffer: 32 * 1024 * 1024 });
  if (r.error) throw new Error(`${cmd} failed to start: ${r.error.message}`);
  if (r.status === null) throw new Error(`${cmd} ${args.join(' ')} killed by ${r.signal}`);
  return { status: r.status, stdout: r.stdout, out: r.stdout + r.stderr };
}

let seq = 0;
function writeTmp(fileName: string, src: string): string {
  const dir = join(TMP, String(seq++));
  mkdirSync(dir);
  const p = join(dir, fileName);
  writeFileSync(p, src);
  return p;
}

/** Each native tier's `compile <src>` -> artifact JSON (or its refusal). */
const NATIVE: { name: string; compile: (src: string) => { artifact?: RunarArtifact; out: string } }[] = [
  {
    name: 'go',
    compile: (src) => {
      const r = run(
        requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'),
        ['--source', writeTmp(FILE, src)],
      );
      return r.status === 0 ? { artifact: JSON.parse(r.stdout), out: r.out } : { out: r.out };
    },
  },
  {
    name: 'rust',
    compile: (src) => {
      const r = run(
        requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'),
        ['--source', writeTmp(FILE, src)],
      );
      return r.status === 0 ? { artifact: JSON.parse(r.stdout), out: r.out } : { out: r.out };
    },
  },
  {
    name: 'python',
    compile: (src) => {
      const r = run('python3', ['-m', 'runar_compiler', '--source', writeTmp(FILE, src)], join(REPO, 'compilers', 'python'));
      return r.status === 0 ? { artifact: JSON.parse(r.stdout), out: r.out } : { out: r.out };
    },
  },
  {
    name: 'zig',
    compile: (src) => {
      const r = run(
        requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'),
        ['--source', writeTmp(FILE, src)],
      );
      return r.status === 0 ? { artifact: JSON.parse(r.stdout), out: r.out } : { out: r.out };
    },
  },
  {
    name: 'ruby',
    compile: (src) => {
      const r = run('ruby', [
        '-I', join(REPO, 'compilers', 'ruby', 'lib'),
        join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby'),
        '--source', writeTmp(FILE, src),
      ]);
      return r.status === 0 ? { artifact: JSON.parse(r.stdout), out: r.out } : { out: r.out };
    },
  },
  {
    name: 'java',
    compile: (src) => {
      const outPath = writeTmp('artifact.json', '');
      const r = run('java', ['-jar', javaJar(), '--source', writeTmp(FILE, src), '--emit-artifact', outPath]);
      return r.status === 0 ? { artifact: JSON.parse(readFileSync(outPath, 'utf8')), out: r.out } : { out: r.out };
    },
  },
];

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

const ref = compile(DECOY_FIRST, { fileName: FILE });
if (!ref.success || !ref.artifact) throw new Error(`TS reference refused DECOY_FIRST: ${JSON.stringify(ref.diagnostics)}`);
const tsArtifact = ref.artifact as unknown as RunarArtifact;

describe('N-011 — the TS reference itself', () => {
  it('compiles HashLock (not the decoy) and its bytes are the hash lock a80087', () => {
    expect(tsArtifact.contractName).toBe('HashLock');
    expect(tsArtifact.script).toBe('a80087');
  });

  for (const shape of SHAPES) {
    it(`${shape.name}: ${shape.reject ? `refuses with "${shape.reject}"` : 'compiles HashLock'}`, () => {
      const r = compile(shape.src, { fileName: FILE });
      if (shape.reject) {
        expect(r.success).toBe(false);
        expect(r.diagnostics.map((d) => d.message)).toContain(shape.reject);
      } else {
        expect(r.success, JSON.stringify(r.diagnostics)).toBe(true);
        expect(r.scriptHex).toBe('a80087');
      }
    });
  }
});

for (const tier of NATIVE) {
  describe(`N-011 [${tier.name}] — the class extending a valid base is the contract`, () => {
    for (const shape of SHAPES) {
      it(`${shape.name}: same verdict and ${shape.reject ? 'diagnostic' : 'bytes'} as the TS reference`, () => {
        const got = tier.compile(shape.src);
        if (shape.reject) {
          expect(got.artifact, `${tier.name} compiled a file TS refuses`).toBeUndefined();
          expect(got.out).toContain(shape.reject);
        } else {
          expect(got.artifact, `${tier.name} refused a file TS accepts: ${got.out}`).toBeDefined();
          expect(got.artifact!.contractName).toBe('HashLock');
          expect(got.artifact!.script).toBe(tsArtifact.script);
        }
      });
    }

    it('ATTACK DECOY_FIRST unlock(wrong preimage) is REJECTED by the Spend engine', async () => {
      const got = tier.compile(DECOY_FIRST);
      expect(got.artifact, got.out).toBeDefined();
      const v = await spend(got.artifact!, WRONG);
      expect(v.reachedEngine, `never reached Spend: ${v.error ?? '(accepted)'}`).toBe(true);
      expect(v.accepted, 'a non-preimage spent the hash lock').toBe(false);
    });

    it('CONTROL DECOY_FIRST unlock(real preimage) is ACCEPTED', async () => {
      const got = tier.compile(DECOY_FIRST);
      expect(got.artifact, got.out).toBeDefined();
      const v = await spend(got.artifact!, SECRET);
      expect(v.accepted, v.error).toBe(true);
    });
  });
}

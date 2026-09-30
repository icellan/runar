/**
 * N-046 (ScopeSnatcher) + N-047 (ShadowGoblin) — execution proof, all seven
 * tiers: a block-scoped re-declaration, or an inlined helper's local, no longer
 * overwrites the enclosing variable it shadows (user decision R24:
 * alpha-rename).
 *
 *     let authorized = checkSig(sig, this.owner);
 *     if (trigger) { let authorized = true; }   // a NEW, block-scoped variable
 *     assert(authorized);                       // still the checkSig result
 *
 * Pre-fix every tier bound the inner `let` under the name `authorized`, the
 * if-arm reconciliation took it for a reassignment of the outer local, and
 * `spend(<attacker's signature>, true)` unlocked the coins. The if/else variant
 * (both arms re-declare `ok`) was accepted the same way. ShadowGoblin: an
 * inlined output-emitting helper's `const valid = len(destination) > 0n`
 * replaced the caller's `const valid = checkSig(…)`, so a stranger's
 * signature drained the contract to an address of their choosing.
 *
 * Oracle: the real `@bsv/sdk` Spend engine. Each tier's CLI artifact is
 * deployed and called through the TS SDK with broadcast validation on (the
 * MockProvider replays every input on Spend before accepting a broadcast); an
 * accepted call is re-checked with `validateContractInput`. The attacker's
 * input is crafted, not random: a well-formed signature by a key that is not
 * the owner's (bob vs alice), on the exact spend the report used. Expected
 * verdicts are derived BY HAND from the source, never from compiler output.
 *
 * What this proves: for each of the seven tiers, the compiled ScopeSnatcher,
 * its if/else variant and ShadowGoblin scripts reject the stranger's spend
 * that the pre-fix scripts accepted, and accept the owner's.
 * The last block pins the ANF naming scheme cross-tier: all seven tiers emit
 * identical canonical ANF for the three probes, binding the shadowing
 * declarations as `authorized@1`, `ok@1` / `ok@2` and `valid@1`.
 * What it does NOT prove: the other shadowing shapes (nested if, loop body,
 * loop variable, parameter shadow, helper local vs caller parameter) on chain
 * — each tier's n046 unit test pins those byte-for-byte against their renamed
 * spellings; nor hostile `--ir` JSON, which carries its own binding names.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner, buildP2PKHScript } from 'runar-sdk';
import { Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { testKey, validateContractInput } from '../oracle/real-crypto-execution.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-n046-'));

const SCOPE_SNATCHER = `import { SmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class ShadowVault extends SmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public spend(sig: Sig, trigger: boolean) {
    let authorized = checkSig(sig, this.owner);
    if (trigger) {
      let authorized = true;
    }
    assert(authorized);
  }
}
`;

const SCOPE_SNATCHER_IF_ELSE = `import { SmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class ShadowVaultIfElse extends SmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public spend(sig: Sig, x: bigint) {
    let ok = checkSig(sig, this.owner);
    if (x > 0n) {
      const ok = true;
      assert(ok);
    } else {
      const ok = true;
      assert(ok);
    }
    assert(ok);
  }
}
`;

const SHADOW_GOBLIN = `import { StatefulSmartContract, ByteString, PubKey, Sig, assert, checkSig, len } from 'runar-lang';

class OwnerPayout extends StatefulSmartContract {
  nonce: bigint;
  readonly owner: PubKey;

  constructor(nonce: bigint, owner: PubKey) {
    super(nonce, owner);
    this.nonce = nonce;
    this.owner = owner;
  }

  public withdraw(sig: Sig, destination: ByteString) {
    const valid = checkSig(sig, this.owner);
    this.pay(destination);
    assert(valid);
  }

  private pay(destination: ByteString) {
    const valid = len(destination) > 0n;
    assert(valid);
    this.addRawOutput(50000n, destination);
  }
}
`;

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

function run(cmd: string, args: string[], cwd?: string): string {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 120_000, maxBuffer: 32 * 1024 * 1024 });
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

const TIERS: { name: string; artifact: (src: string, fileName: string) => RunarArtifact }[] = [
  {
    name: 'ts',
    artifact: (src, fileName) => {
      const r = compile(src, { fileName });
      if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
      return r.artifact as unknown as RunarArtifact;
    },
  },
  {
    name: 'go',
    artifact: (src, f) => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'),
      ['--source', writeTmp(f, src)],
    )),
  },
  {
    name: 'rust',
    artifact: (src, f) => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'),
      ['--source', writeTmp(f, src)],
    )),
  },
  {
    name: 'python',
    artifact: (src, f) => JSON.parse(run('python3', ['-m', 'runar_compiler', '--source', writeTmp(f, src)], join(REPO, 'compilers', 'python'))),
  },
  {
    name: 'zig',
    artifact: (src, f) => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'),
      ['--source', writeTmp(f, src)],
    )),
  },
  {
    name: 'ruby',
    artifact: (src, f) => JSON.parse(run('ruby', [
      '-I', join(REPO, 'compilers', 'ruby', 'lib'),
      join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby'),
      '--source', writeTmp(f, src),
    ])),
  },
  {
    name: 'java',
    artifact: (src, f) => {
      const out = writeTmp('artifact.json', '');
      run('java', ['-jar', javaJar(), '--source', writeTmp(f, src), '--emit-artifact', out]);
      return JSON.parse(readFileSync(out, 'utf8'));
    },
  },
];

const OWNER = testKey('alice');
const ATTACKER = testKey('bob');

interface Verdict {
  accepted: boolean;
  reachedEngine: boolean;
  error?: string;
}

/**
 * Deploy `artifact` (owner = alice), then call `method(args)` signed by
 * `caller`. `null` Sig args are signed by `caller`'s key, so the attacker's
 * call carries a well-formed signature by the WRONG key.
 */
async function spend(
  artifact: RunarArtifact,
  ctorArgs: unknown[],
  method: string,
  args: unknown[],
  caller: { privKey: string; pubKey: string },
  terminal: boolean,
): Promise<Verdict> {
  const ownerSigner = new LocalSigner(OWNER.privKey);
  const provider = new MockProvider();
  provider.enableBroadcastValidation();
  provider.addUtxo(await ownerSigner.getAddress(), {
    txid: OWNER.privKey.slice(0, 64),
    outputIndex: 0,
    satoshis: 1_000_000,
    script: buildP2PKHScript(OWNER.pubKey),
  });
  const contract = new RunarContract(artifact, ctorArgs);
  contract.connect(provider, ownerSigner);
  await contract.deploy({ satoshis: 200_000 });
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  const callerSigner = new LocalSigner(caller.privKey);
  contract.connect(provider, callerSigner);
  try {
    await contract.call(
      method,
      args,
      terminal ? { terminalOutputs: [{ scriptHex: buildP2PKHScript(caller.pubKey), satoshis: 199_000 }] } : undefined,
    );
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    return { accepted: false, reachedEngine: error.includes('refusing to broadcast invalid transaction'), error };
  }
  const txs = provider.getBroadcastedTxs();
  const callTx = Transaction.fromHex(txs[txs.length - 1]!);
  return { accepted: validateContractInput(callTx, 0, deployTx, 0), reachedEngine: true };
}

for (const tier of TIERS) {
  describe(`N-046 / N-047 [${tier.name}] — a shadowing declaration never overwrites the outer variable`, () => {
    const vault = tier.artifact(SCOPE_SNATCHER, 'ShadowVault.runar.ts');
    const vaultIfElse = tier.artifact(SCOPE_SNATCHER_IF_ELSE, 'ShadowVaultIfElse.runar.ts');
    const payout = tier.artifact(SHADOW_GOBLIN, 'OwnerPayout.runar.ts');

    it('ScopeSnatcher ATTACK spend(<bob sig>, true) against owner alice is REJECTED', async () => {
      const v = await spend(vault, [OWNER.pubKey], 'spend', [null, true], ATTACKER, true);
      expect(v.reachedEngine, `never reached Spend: ${v.error ?? '(accepted)'}`).toBe(true);
      expect(v.accepted, 'the inner `let authorized = true` overwrote the checkSig result').toBe(false);
    });

    it('ScopeSnatcher honest spend(<alice sig>, true) is ACCEPTED', async () => {
      const v = await spend(vault, [OWNER.pubKey], 'spend', [null, true], OWNER, true);
      expect(v.accepted, v.error).toBe(true);
    });

    it('ScopeSnatcher if/else ATTACK spend(<bob sig>, 1) is REJECTED', async () => {
      const v = await spend(vaultIfElse, [OWNER.pubKey], 'spend', [null, 1n], ATTACKER, true);
      expect(v.reachedEngine, `never reached Spend: ${v.error ?? '(accepted)'}`).toBe(true);
      expect(v.accepted, 'an arm-local `const ok = true` overwrote the checkSig result').toBe(false);
    });

    it('ScopeSnatcher if/else honest spend(<alice sig>, 1) is ACCEPTED', async () => {
      const v = await spend(vaultIfElse, [OWNER.pubKey], 'spend', [null, 1n], OWNER, true);
      expect(v.accepted, v.error).toBe(true);
    });

    it('ShadowGoblin ATTACK withdraw(<bob sig>, <bob p2pkh>) is REJECTED', async () => {
      const v = await spend(payout, [0n, OWNER.pubKey], 'withdraw', [null, buildP2PKHScript(ATTACKER.pubKey)], ATTACKER, false);
      expect(v.reachedEngine, `never reached Spend: ${v.error ?? '(accepted)'}`).toBe(true);
      expect(v.accepted, "the helper's `const valid` overwrote the caller's checkSig result").toBe(false);
    });

    it('ShadowGoblin honest withdraw(<alice sig>, <alice p2pkh>) is ACCEPTED', async () => {
      const v = await spend(payout, [0n, OWNER.pubKey], 'withdraw', [null, buildP2PKHScript(OWNER.pubKey)], OWNER, false);
      expect(v.accepted, v.error).toBe(true);
    });
  });
}

// ---------------------------------------------------------------------------
// Cross-tier ANF parity: the `<name>@<n>` scheme is identical in every tier.
// ---------------------------------------------------------------------------

const NATIVE_IR: Record<string, () => { cmd: string; pre: string[]; cwd?: string }> = {
  go: () => ({ cmd: requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'), pre: [] }),
  rust: () => ({ cmd: requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'), pre: [] }),
  python: () => ({ cmd: 'python3', pre: ['-m', 'runar_compiler'], cwd: join(REPO, 'compilers', 'python') }),
  zig: () => ({ cmd: requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'), pre: [] }),
  ruby: () => ({ cmd: 'ruby', pre: ['-I', join(REPO, 'compilers', 'ruby', 'lib'), join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby')] }),
  java: () => ({ cmd: 'java', pre: ['-jar', javaJar()] }),
};

/** Sorted keys, no `sourceLoc`, integers as plain numbers (the conformance
 *  runner's canonical form). */
function canonical(value: unknown): unknown {
  if (typeof value === 'bigint') return Number(value);
  if (typeof value === 'string' && /^-?\d+n$/.test(value)) return Number(value.slice(0, -1));
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as object).sort()) {
      if (k === 'sourceLoc') continue;
      out[k] = canonical((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}

describe('N-046 / N-047 — seven-tier ANF parity of the alpha-renamed bindings', () => {
  const probes: [string, string, string[]][] = [
    [SCOPE_SNATCHER, 'ShadowVault.runar.ts', ['"name":"authorized"', '"name":"authorized@1"']],
    [SCOPE_SNATCHER_IF_ELSE, 'ShadowVaultIfElse.runar.ts', ['"name":"ok"', '"name":"ok@1"', '"name":"ok@2"']],
    [SHADOW_GOBLIN, 'OwnerPayout.runar.ts', ['"name":"valid"', '"name":"valid@1"']],
  ];
  for (const [src, file, names] of probes) {
    it(`${file}: every tier emits the TS canonical ANF (fold off)`, () => {
      const ts = compile(src, { fileName: file, disableConstantFolding: true });
      expect(ts.success, JSON.stringify(ts.diagnostics)).toBe(true);
      const tsAnf = JSON.stringify(canonical(ts.anf));
      for (const n of names) expect(tsAnf).toContain(n);
      for (const tier of Object.keys(NATIVE_IR)) {
        const { cmd, pre, cwd } = NATIVE_IR[tier]!();
        const out = run(cmd, [...pre, '--source', writeTmp(file, src), '--emit-ir', '--disable-constant-folding'], cwd);
        expect(JSON.stringify(canonical(JSON.parse(out))), `${tier} ANF diverges from ts`).toBe(tsAnf);
      }
    });
  }
});

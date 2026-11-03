/**
 * N-045 (EXT-2 WideHash) — execution proof, all seven tiers, both
 * constant-folding modes: a continuation never commits a fixed-width state
 * field (Sha256, PubKey, Addr, Ripemd160, Point, P256Point, P384Point) whose
 * value has the wrong width.
 *
 *     root: Sha256;  owner: PubKey;  memo: ByteString;
 *     public updateRoot(nextRoot: Sha256) { this.root = nextRoot; }   // anyone
 *     public withdraw(sig: Sig) { assert(checkSig(sig, this.owner)); }
 *
 * The state section is `root(32) || owner(33) || frame(memo)`. The reader takes
 * the declared width of each fixed-width field. Before the fix the writer
 * copied a fixed-width value as it was, so a stranger calling `updateRoot` with
 * the 66-byte root
 *
 *     R(32) || strangerPubKey(33) || 0x22
 *
 * committed `R || strangerPK || 22 || ownerPK || 00`, which the next spend
 * reads as root = R, owner = strangerPK, memo = ownerPK || 00 (a 34-byte push,
 * consumed exactly, so N-044's exact-consumption check is satisfied). The
 * stranger then withdraws. A 31- or 33-byte root shifts every later field and
 * bricks the UTXO instead. The fix emits `OP_SIZE <width> OP_NUMEQUALVERIFY`
 * for every fixed-width mutable field before every continuation commit
 * (auto-continuation / getStateScript and addOutput).
 *
 * Oracle: @bsv/sdk's production Spend with strict consensus flags
 * (`validateContractInput` -> `newConsensusSpend`, and the SDK's `dryRun`
 * replay of input 0), on each tier's own CLI artifact deployed and called
 * through the TS SDK. Every expected verdict is derived BY HAND from the
 * source above, never from compiler output.
 *
 * THE ATTACKER'S SDK. After this item the TS SDK itself refuses to encode a
 * wrong-width Sha256 argument or state value (defence in depth). An attacker is
 * not bound by our SDK, so each attack spend is built by an "attacker SDK": the
 * same SDK with the shared `STATE_FIELD_WIDTHS.Sha256` entry temporarily set to
 * the attack width, which is the only thing those refusals consult. The bytes it
 * builds are exactly the bytes a hand-built transaction would carry; the
 * on-chain script is the only thing judging them.
 *
 * What this proves: for each of the seven tiers and both folding modes, through
 * BOTH continuation writers (auto-continuation and an explicit addOutput), the
 * compiled covenant (a) rejects a stranger's 66-byte root that would otherwise
 * hand them `owner`, (b) rejects a 31- and a 33-byte root that would otherwise
 * brick the UTXO, (c) still accepts an honest 32-byte update, after which the
 * stranger's withdraw is rejected and the owner's is accepted with state
 * carried through; and (d) every tier emits `OP_SIZE <w> OP_NUMEQUALVERIFY`
 * for each of the seven fixed-width types when it is a mutable field.
 * What it does NOT prove: (d) is a static byte-pattern check for the six types
 * other than Sha256 (their rejection is not executed here); and nothing about
 * a deployer who publishes a wrong-width INITIAL state (the deployer chooses
 * the code too).
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner, buildP2PKHScript } from 'runar-sdk';
import { STATE_FIELD_WIDTHS } from 'runar-ir-schema';
import { Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { testKey, validateContractInput } from '../oracle/real-crypto-execution.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-n045-'));

const HEADER = `import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { ByteString, PubKey, Sha256, Sig } from 'runar-lang';
`;

const PROPS = `  root: Sha256;
  owner: PubKey;
  memo: ByteString;

  constructor(root: Sha256, owner: PubKey, memo: ByteString) {
    super(root, owner, memo);
    this.root = root;
    this.owner = owner;
    this.memo = memo;
  }

  public withdraw(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }
`;

/** The two continuation writers, each with the same `updateRoot` surface. */
const CONTRACTS: { label: string; src: string; extraArgs: unknown[] }[] = [
  {
    label: 'auto-continuation',
    src: `${HEADER}
class RootVault extends StatefulSmartContract {
${PROPS}
  public updateRoot(nextRoot: Sha256) {
    this.root = nextRoot;
  }
}
`,
    extraArgs: [],
  },
  {
    label: 'addOutput',
    src: `${HEADER}
class RootVault extends StatefulSmartContract {
${PROPS}
  public updateRoot(nextRoot: Sha256, outputSatoshis: bigint) {
    assert(outputSatoshis >= 1n);
    this.addOutput(outputSatoshis, nextRoot, this.owner, this.memo);
  }
}
`,
    extraArgs: [100_000n],
  },
];
const FILE = 'RootVault.runar.ts';

const OWNER = testKey('alice');
const STRANGER = testKey('bob');
const ROOT0 = '11'.repeat(32);
const DEPLOY_SATS = 100_000;

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
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 180_000, maxBuffer: 64 * 1024 * 1024 });
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

/** Native-tier CLI invocation (everything but the source path and flags). */
const NATIVE: Record<string, () => { cmd: string; pre: string[]; cwd?: string }> = {
  go: () => ({ cmd: requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'), pre: [] }),
  rust: () => ({ cmd: requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'), pre: [] }),
  python: () => ({ cmd: 'python3', pre: ['-m', 'runar_compiler'], cwd: join(REPO, 'compilers', 'python') }),
  zig: () => ({ cmd: requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'), pre: [] }),
  ruby: () => ({ cmd: 'ruby', pre: ['-I', join(REPO, 'compilers', 'ruby', 'lib'), join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby')] }),
  java: () => ({ cmd: 'java', pre: ['-jar', javaJar()] }),
};

function artifactFor(tier: string, src: string, fileName: string, disableFold: boolean): RunarArtifact {
  if (tier === 'ts') {
    const r = compile(src, { fileName, disableConstantFolding: disableFold });
    if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
    return r.artifact as unknown as RunarArtifact;
  }
  const { cmd, pre, cwd } = NATIVE[tier]!();
  const fold = disableFold ? ['--disable-constant-folding'] : [];
  const p = writeTmp(fileName, src);
  if (tier === 'java') {
    const out = writeTmp('artifact.json', '');
    run(cmd, [...pre, '--source', p, '--emit-artifact', out, ...fold], cwd);
    return JSON.parse(readFileSync(out, 'utf8'));
  }
  return JSON.parse(run(cmd, [...pre, '--source', p, ...fold], cwd));
}

interface Step {
  accepted: boolean;
  reachedEngine: boolean;
  error?: string;
}

interface Session {
  provider: MockProvider;
  contract: RunarContract;
  prevTx: Transaction;
}

async function deploy(artifact: RunarArtifact): Promise<Session> {
  const provider = new MockProvider();
  for (const k of [OWNER, STRANGER]) {
    const s = new LocalSigner(k.privKey);
    provider.addUtxo(await s.getAddress(), {
      txid: k.privKey.slice(0, 64),
      outputIndex: 0,
      satoshis: 5_000_000,
      script: buildP2PKHScript(k.pubKey),
    });
  }
  const contract = new RunarContract(artifact, [ROOT0, OWNER.pubKey, '']);
  await contract.deploy(provider, new LocalSigner(OWNER.privKey), { satoshis: DEPLOY_SATS });
  const prevTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  return { provider, contract, prevTx };
}

/**
 * The attacker's SDK (see the header): the shared width table believes a
 * Sha256 is `width` bytes for the duration of `fn`.
 */
async function asAttackerWithSha256Width<T>(width: number, fn: () => Promise<T>): Promise<T> {
  const table = STATE_FIELD_WIDTHS as Record<string, { size: number; encoding: string }>;
  const original = table.Sha256!;
  table.Sha256 = { size: width, encoding: original.encoding };
  try {
    return await fn();
  } finally {
    table.Sha256 = original;
  }
}

async function call(s: Session, method: string, args: unknown[], who: { privKey: string }, satoshis?: number): Promise<Step> {
  const before = s.provider.getBroadcastedTxs().length;
  try {
    // dryRun: the SDK replays the contract input on the real Spend engine
    // before broadcast and throws a message unique to a script rejection.
    await s.contract.call(method, args, s.provider, new LocalSigner(who.privKey), {
      dryRun: true,
      ...(satoshis !== undefined ? { satoshis } : {}),
    });
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    return {
      accepted: false,
      reachedEngine: error.includes('local pre-broadcast dry-run rejected the primary contract input'),
      error: error.slice(0, 400),
    };
  }
  const tx = Transaction.fromHex(s.provider.getBroadcastedTxs()[before]!);
  const accepted = validateContractInput(tx, 0, s.prevTx, 0);
  s.prevTx = tx;
  return { accepted, reachedEngine: true };
}

const TIERS = ['ts', ...Object.keys(NATIVE)];

/** R || strangerPK || 0x22: the next reader takes owner = strangerPK. */
const HIJACK_ROOT = '22'.repeat(32) + STRANGER.pubKey + '22';

for (const tier of TIERS) {
  for (const disableFold of [true, false]) {
    for (const c of CONTRACTS) {
      describe(`N-045 [${tier}, fold ${disableFold ? 'off' : 'on'}, ${c.label}] — fixed-width state is width-checked`, () => {
        const artifact = artifactFor(tier, c.src, FILE, disableFold);

        it('ATTACK: a stranger\'s 66-byte root (R || strangerPK || 22) -> updateRoot REJECTED', async () => {
          const s = await deploy(artifact);
          const u = await asAttackerWithSha256Width(66, () =>
            call(s, 'updateRoot', [HIJACK_ROOT, ...c.extraArgs], STRANGER, DEPLOY_SATS));
          let consequence = '';
          if (u.accepted) {
            // Show what the accepted update bought the stranger.
            const w = await asAttackerWithSha256Width(66, () =>
              call(s, 'withdraw', [null], STRANGER, DEPLOY_SATS));
            consequence = ` — and the stranger's withdraw was then ${w.accepted ? 'ACCEPTED (owner hijacked)' : `rejected: ${w.error}`}`;
          }
          expect(u.reachedEngine, `never reached Spend: ${u.error ?? '(accepted)'}`).toBe(true);
          expect(u.accepted, `wrong-width root committed${consequence}`).toBe(false);
        }, 120_000);

        for (const width of [31, 33]) {
          it(`ATTACK: a ${width}-byte root (would brick the UTXO) -> updateRoot REJECTED`, async () => {
            const s = await deploy(artifact);
            const u = await asAttackerWithSha256Width(width, () =>
              call(s, 'updateRoot', ['33'.repeat(width), ...c.extraArgs], STRANGER, DEPLOY_SATS));
            expect(u.reachedEngine, `never reached Spend: ${u.error ?? '(accepted)'}`).toBe(true);
            expect(u.accepted).toBe(false);
          }, 120_000);
        }

        it('honest 32-byte update ACCEPTED; then stranger withdraw REJECTED, owner withdraw ACCEPTED', async () => {
          const s = await deploy(artifact);
          const next = '44'.repeat(32);
          const u = await call(s, 'updateRoot', [next, ...c.extraArgs], STRANGER, DEPLOY_SATS);
          expect(u.accepted, `honest update must be accepted: ${u.error}`).toBe(true);
          expect(s.contract.state).toEqual({ root: next, owner: OWNER.pubKey, memo: '' });

          const sw = await call(s, 'withdraw', [null], STRANGER, DEPLOY_SATS);
          expect(sw.reachedEngine, `never reached Spend: ${sw.error ?? '(accepted)'}`).toBe(true);
          expect(sw.accepted).toBe(false);

          const ow = await call(s, 'withdraw', [null], OWNER, DEPLOY_SATS);
          expect(ow.accepted, `owner's withdraw must be accepted: ${ow.error}`).toBe(true);
          expect(s.contract.state).toEqual({ root: next, owner: OWNER.pubKey, memo: '' });
        }, 120_000);
      });
    }
  }
}

// (d) Every fixed-width type gets `OP_SIZE <w> OP_NUMEQUALVERIFY` before its
// continuation commit. `<w>` is a 1-byte script number push (`01 <w>`).
const FIXED_WIDTH_TYPES: [string, number][] = [
  ['Sha256', 32], ['PubKey', 33], ['Addr', 20], ['Ripemd160', 20],
  ['Point', 64], ['P256Point', 64], ['P384Point', 96],
];

function widthProbeSource(type: string): string {
  return `import { StatefulSmartContract } from 'runar-lang';
import type { ${type} } from 'runar-lang';

class WidthProbe extends StatefulSmartContract {
  v: ${type};

  constructor(v: ${type}) {
    super(v);
    this.v = v;
  }

  public set(next: ${type}) {
    this.v = next;
  }
}
`;
}

describe('N-045 — every tier width-checks every fixed-width mutable field', () => {
  for (const tier of TIERS) {
    for (const [type, width] of FIXED_WIDTH_TYPES) {
      it(`[${tier}] ${type}: OP_SIZE ${width} OP_NUMEQUALVERIFY before the continuation`, () => {
        const a = artifactFor(tier, widthProbeSource(type), 'WidthProbe.runar.ts', true);
        const pattern = '8201' + width.toString(16).padStart(2, '0') + '9d';
        // Byte-aligned occurrences only (an odd hex offset is not an opcode).
        const hits = [...a.script.matchAll(new RegExp(pattern, 'g'))].filter((m) => m.index! % 2 === 0);
        expect(hits.length, `${tier} ${type}: no ${pattern} in ${a.script.length / 2}-byte script`).toBeGreaterThan(0);
      }, 120_000);
    }
  }
});

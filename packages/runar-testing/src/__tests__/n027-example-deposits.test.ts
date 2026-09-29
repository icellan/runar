/**
 * N-027 — the TicTacToe and Auction examples enforce their deposit on-chain.
 *
 * F-024 gave every default state continuation a `>= input` floor and the
 * read-only builtin `continuationAmount()`. The floor stops a drain, but it
 * does not make a joiner pay the bet or a bidder pay the bid: a `join` or a
 * `bid` whose continuation just carries the input forward passes it. The
 * examples now state the rule themselves:
 *
 *   TicTacToe.join:  continuationAmount() == extractAmount(txPreimage) + betAmount
 *   Auction.bid:     continuationAmount() >= extractAmount(txPreimage) + bidAmount
 *
 * What this proves:
 *   1. Every shipped source of each example (TicTacToe and TicTacToe.v2 on
 *      their 9 / 8 surfaces, Auction on its 9) compiles in each of the seven
 *      tiers to ONE locking script per example, so the verdicts below hold for
 *      every tier's bytes.
 *   2. Under `@bsv/sdk` Spend on a real BIP-143 preimage, with the transaction
 *      built by the TS SDK: an honest join / bid (paid by the caller's funding
 *      input) is ACCEPTED; a join / bid that does not pay (continuation = the
 *      input, which F-024's floor alone accepts) is REJECTED; a join short by
 *      one satoshi is REJECTED; a join that overpays by one is REJECTED (the
 *      TicTacToe rule is exact); a bid that overpays is ACCEPTED (the Auction
 *      rule is a floor).
 * What this does NOT prove: that the deploy itself is funded with `betAmount`
 * (nothing on-chain checks a deploy), that the payout methods are correct, or
 * anything about refunds — this Auction does not refund an outbid bidder, and
 * the pot is the deposit plus every bid (see the contract's comment).
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner, buildP2PKHScript } from 'runar-sdk';
import { Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { testKey, validateContractInput } from '../oracle/real-crypto-execution.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const EX = join(REPO, 'examples');
const TMP = mkdtempSync(join(tmpdir(), 'runar-n027-'));

const SURFACE_DIRS: [string, string][] = [
  ['ts', 'ts'], ['sol', 'sol'], ['move', 'move'], ['go', 'go'], ['rust', 'rs'],
  ['python', 'py'], ['zig', 'zig'], ['ruby', 'rb'],
];

function sources(sub: string, stem: string, java: boolean): string[] {
  const out = SURFACE_DIRS.map(([dir, ext]) => join(EX, dir, sub, `${stem}.runar.${ext}`));
  if (java) out.push(join(EX, 'java', 'src', 'main', 'java', 'runar', 'examples', sub, `${stem}.runar.java`));
  for (const p of out) if (!existsSync(p)) throw new Error(`missing example source ${p}`);
  return out;
}

const EXAMPLES: Record<string, string[]> = {
  TicTacToe: sources('tic-tac-toe', 'TicTacToe', true),
  'TicTacToe.v2': sources('tic-tac-toe', 'TicTacToe.v2', false),
  Auction: sources('auction', 'Auction', true),
};

let seq = 0;
function copyToTmp(path: string): string {
  const dir = join(TMP, String(seq++));
  mkdirSync(dir);
  const p = join(dir, basename(path));
  writeFileSync(p, readFileSync(path, 'utf8'));
  return p;
}

function javaJar(): string {
  const libs = join(REPO, 'compilers', 'java', 'build', 'libs');
  const jar = existsSync(libs) ? readdirSync(libs).find((f) => f.endsWith('.jar')) : undefined;
  if (!jar) throw new Error('Java jar missing — run `gradle jar` in compilers/java');
  return join(libs, jar);
}

function requireBin(p: string, how: string): string {
  if (!existsSync(p)) throw new Error(`missing compiler binary ${p} — build it with: ${how}`);
  return p;
}

function run(cmd: string, args: string[], cwd?: string): string {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 300_000, maxBuffer: 64 * 1024 * 1024 });
  if (r.error) throw new Error(`${cmd} failed to start: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`${cmd} exited ${r.status}: ${`${r.stderr}${r.stdout}`.trim()}`);
  return r.stdout;
}

const scriptOf = (stdout: string): string => (JSON.parse(stdout) as { script: string }).script;

const TIERS: Record<string, (path: string) => string> = {
  ts: (path) => {
    const r = compile(readFileSync(path, 'utf8'), { fileName: basename(path) });
    if (!r.success || !r.artifact) throw new Error(r.diagnostics.map((d) => d.message).join(' | '));
    return r.artifact.script;
  },
  go: (path) => scriptOf(run(
    requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'),
    ['--source', copyToTmp(path)],
  )),
  rust: (path) => scriptOf(run(
    requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'),
    ['--source', copyToTmp(path)],
  )),
  python: (path) => scriptOf(run('python3', ['-m', 'runar_compiler', '--source', copyToTmp(path)], join(REPO, 'compilers', 'python'))),
  zig: (path) => scriptOf(run(
    requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'),
    ['--source', copyToTmp(path)],
  )),
  ruby: (path) => scriptOf(run('ruby', [
    '-I', join(REPO, 'compilers', 'ruby', 'lib'),
    join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby'),
    '--source', copyToTmp(path),
  ])),
  java: (path) => {
    const out = join(TMP, `artifact-${seq++}.json`);
    run('java', ['-jar', javaJar(), '--source', copyToTmp(path), '--emit-artifact', out]);
    return scriptOf(readFileSync(out, 'utf8'));
  },
};

function tsArtifact(example: string): RunarArtifact {
  const path = EXAMPLES[example]![0]!;
  const r = compile(readFileSync(path, 'utf8'), { fileName: basename(path) });
  if (!r.artifact) throw new Error(`reference compile of ${path} failed`);
  return r.artifact as unknown as RunarArtifact;
}

// Pre-existing and outside N-027: the Zig surface of TicTacToe v1 declares
// `p2pkhPrefix: ... = runar.hexToBytes("1976a914")`, and the Go, Rust, Python,
// Ruby and Java Zig parsers refuse that initializer ("initializer must be a
// literal value") while the TS and Zig tiers accept it. That is a Zig-surface
// literal-parser gap tracked separately. Those five compiles must either match
// the reference (once the parsers are fixed) or refuse with exactly that
// diagnostic; anything else fails.
const KNOWN_ZIG_HEX_INITIALIZER_GAP = /initializer must be a literal value/;
function knownGap(example: string, path: string, tier: string): boolean {
  return example === 'TicTacToe' && path.endsWith('.runar.zig') && tier !== 'ts' && tier !== 'zig';
}

describe('N-027 — every shipped source, in every tier, is one script per example', () => {
  for (const [example, paths] of Object.entries(EXAMPLES)) {
    const reference = tsArtifact(example).script;
    for (const path of paths) {
      for (const [tier, compileIn] of Object.entries(TIERS)) {
        it(`${example}: ${basename(path)} in ${tier}`, () => {
          if (knownGap(example, path, tier)) {
            let script: string | undefined;
            try {
              script = compileIn(path);
            } catch (e) {
              expect(String(e)).toMatch(KNOWN_ZIG_HEX_INITIALIZER_GAP);
              return;
            }
            expect(script).toBe(reference);
            return;
          }
          expect(compileIn(path)).toBe(reference);
        }, 300_000);
      }
    }
  }
});

/**
 * Deploy `example` with `deploySats`, then have `callerKey` call `method` with
 * the continuation holding `newSatoshis`, funded by a UTXO of the caller's so
 * the continuation can grow. The verdict is `@bsv/sdk` Spend on the bytes the
 * SDK built; a broadcast the MockProvider refuses is recorded and replayed.
 */
async function spend(
  example: string,
  ctorArgs: (bigint | string)[],
  deploySats: number,
  method: string,
  args: unknown[],
  callerKey: string,
  newSatoshis: number,
): Promise<boolean> {
  const artifact = tsArtifact(example);
  const owner = testKey('alice');
  const caller = testKey(callerKey);
  let last: Transaction | undefined;
  class Recording extends MockProvider {
    override async broadcast(tx: Transaction): Promise<string> {
      last = tx;
      return super.broadcast(tx);
    }
  }
  const provider = new Recording();
  provider.addUtxo(await new LocalSigner(owner.privKey).getAddress(), {
    txid: owner.privKey.slice(0, 64), outputIndex: 0, satoshis: 500_000, script: buildP2PKHScript(owner.pubKey),
  });
  const contract = new RunarContract(artifact, ctorArgs);
  await contract.deploy(provider, new LocalSigner(owner.privKey), { satoshis: deploySats });
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  const signer = new LocalSigner(caller.privKey);
  provider.addUtxo(await signer.getAddress(), {
    txid: caller.privKey.slice(0, 64), outputIndex: 0, satoshis: 200_000, script: buildP2PKHScript(caller.pubKey),
  });
  try {
    await contract.call(method, args, provider, signer, { satoshis: newSatoshis, changeAddress: caller.pubKeyHash });
  } catch {
    // replayed below
  }
  if (!last || last === deployTx) throw new Error('no call tx was built');
  const tx = Transaction.fromHex(last.toHex());
  expect(tx.outputs[0]!.satoshis).toBe(newSatoshis);
  try {
    return validateContractInput(tx, 0, deployTx, 0);
  } catch {
    return false;
  }
}

const BET = 5_000;

for (const example of ['TicTacToe', 'TicTacToe.v2']) {
  const joinWith = (newSatoshis: number): Promise<boolean> => spend(
    example, [testKey('alice').pubKey, BigInt(BET)], BET, 'join', [testKey('eve').pubKey, null], 'eve', newSatoshis,
  );
  describe(`N-027 ${example}.join pays exactly the bet (@bsv/sdk Spend)`, () => {
    it('honest join: continuation = input + bet is ACCEPTED', async () => {
      expect(await joinWith(BET + BET)).toBe(true);
    });
    it('join that pays nothing (continuation = input) is REJECTED', async () => {
      expect(await joinWith(BET)).toBe(false);
    });
    it('join short by one satoshi is REJECTED', async () => {
      expect(await joinWith(BET + BET - 1)).toBe(false);
    });
    it('join that overpays by one satoshi is REJECTED (the rule is exact)', async () => {
      expect(await joinWith(BET + BET + 1)).toBe(false);
    });
  });
}

describe('N-027 Auction.bid adds the bid to the pot (@bsv/sdk Spend)', () => {
  const POT = 1_000;
  const BID = 5_000;
  const bid = (newSatoshis: number): Promise<boolean> => spend(
    'Auction',
    [testKey('alice').pubKey, testKey('alice').pubKey, 1n, 1_000n],
    POT, 'bid', [null, testKey('eve').pubKey, BigInt(BID)], 'eve', newSatoshis,
  );
  it('honest bid: continuation = prior pot + bid is ACCEPTED', async () => {
    expect(await bid(POT + BID)).toBe(true);
  });
  it('bid that pays nothing (continuation = prior pot) is REJECTED', async () => {
    expect(await bid(POT)).toBe(false);
  });
  it('bid short by one satoshi is REJECTED', async () => {
    expect(await bid(POT + BID - 1)).toBe(false);
  });
  it('bid that pays more than it declares is ACCEPTED (the rule is a floor)', async () => {
    expect(await bid(POT + BID + 1)).toBe(true);
  });
});

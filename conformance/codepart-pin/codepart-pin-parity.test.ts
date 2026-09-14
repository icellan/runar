/**
 * R-095 — every tier's `verify_code_part_len` pin must equal the byte length
 * the SDK actually deploys.
 *
 * The pin is `emittedTemplateLength + growth`, where `growth` is what the
 * OP_0 constructor-arg placeholders turn into once the SDK splices real
 * values in. `packages/runar-sdk/src/__tests__/codepart-length-pin.test.ts`
 * is the same oracle for the TypeScript tier alone. This file is its
 * seven-tier mirror, and it exists because the derivation it checks is
 * duplicated seven times and no parity gate can see a shared error:
 *
 *   all seven compilers hardcoded a 1-byte push header for every fixed-width
 *   constructor type. `P384Point` is 96 bytes, past the 75-byte direct-push
 *   ceiling, so the SDK bakes it as `4c 60 || <96 bytes>` — 98 bytes over a
 *   1-byte placeholder, a growth of 97. All seven agreed on 96. Cross-tier
 *   hex parity was perfect and every honest spend of such a contract aborted
 *   at OP_VERIFY with the funds already locked.
 *
 * So the assertion here is deliberately NOT "the tiers agree". It is "each
 * tier's pin equals the length the SDK will really deploy for that tier's own
 * template" — an absolute oracle, measured against `getCodePartHex()` rather
 * than against another compiler's opinion.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { compile } from 'runar-compiler';
import { RunarContract } from 'runar-sdk';
import {
  findGoBinary,
  findJavaJarPath,
  findPythonBinary,
  findRubyBinary,
  findRustBinary,
  findZigBinary,
} from '../runner/runner.js';

const REPO = resolve(__dirname, '../..');
const FIXTURE = join(__dirname, 'VarLenP384Ctor.runar.ts');

/** The seven tiers, by id. A tier silently vanishing fails the guard below. */
const ALL_TIER_IDS = ['go', 'java', 'python', 'ruby', 'rust', 'ts', 'zig'] as const;

/** A 96-byte P-384 point. Only its LENGTH matters to the pin. */
const ANCHOR = 'ab'.repeat(96);
/** Any ByteString: `memo` is the variable-length state field, not a slot. */
const MEMO = '48656c6c6f';

interface Tier {
  id: string;
  /** null when the toolchain is not built on this machine. */
  cmd: string | null;
  prefix: string[];
  argsFor: (src: string) => string[];
  cwd: string;
}

/** Split a runner finder's `"ruby /path/to/script"` into cmd + args. */
function splitCmd(s: string | null): { cmd: string | null; args: string[] } {
  if (s === null) return { cmd: null, args: [] };
  const parts = s.trim().split(/\s+/);
  return { cmd: parts[0] ?? null, args: parts.slice(1) };
}

/** Mirrors `resolveTsxLoader` in go-only-parity.test.ts (runner-private). */
function resolveTsxLoader(): string | null {
  for (const p of [
    join(REPO, 'conformance/node_modules/tsx/dist/loader.mjs'),
    join(REPO, 'node_modules/tsx/dist/loader.mjs'),
    join(REPO, 'integration/ts/node_modules/tsx/dist/loader.mjs'),
  ]) {
    if (existsSync(p)) return pathToFileURL(p).href;
  }
  return null;
}

const TIMEOUT_MS = 120_000;

function buildTiers(): Tier[] {
  const go = splitCmd(findGoBinary());
  const rust = splitCmd(findRustBinary());
  const zig = splitCmd(findZigBinary());
  const ruby = splitCmd(findRubyBinary());
  const python = splitCmd(findPythonBinary());
  const jar = findJavaJarPath();
  const tsxLoader = resolveTsxLoader();
  const tsCli = join(REPO, 'packages/runar-cli/src/bin.ts');

  return [
    {
      id: 'ts',
      cmd: tsxLoader && existsSync(tsCli) ? process.execPath : null,
      prefix: tsxLoader ? ['--import', tsxLoader, tsCli, 'compile'] : [],
      argsFor: (s) => [s, '--hex'],
      cwd: REPO,
    },
    { id: 'go', cmd: go.cmd, prefix: go.args, argsFor: (s) => ['--source', s, '--hex'], cwd: join(REPO, 'compilers/go') },
    { id: 'rust', cmd: rust.cmd, prefix: rust.args, argsFor: (s) => ['--source', s, '--hex'], cwd: join(REPO, 'compilers/rust') },
    { id: 'python', cmd: python.cmd, prefix: python.args, argsFor: (s) => ['--source', s, '--hex'], cwd: join(REPO, 'compilers/python') },
    { id: 'zig', cmd: zig.cmd, prefix: zig.args, argsFor: (s) => ['compile', s, '--hex'], cwd: join(REPO, 'compilers/zig') },
    { id: 'ruby', cmd: ruby.cmd, prefix: ruby.args, argsFor: (s) => ['--source', s, '--hex'], cwd: join(REPO, 'compilers/ruby') },
    { id: 'java', cmd: jar ? 'java' : null, prefix: jar ? ['-jar', jar] : [], argsFor: (s) => ['--source', s, '--hex'], cwd: REPO },
  ];
}

const TIERS = buildTiers();
const AVAILABLE = TIERS.filter((t) => t.cmd !== null);

const USAGE_ERROR_RE =
  /flag provided but not defined|unexpected argument|unrecognized argument|unrecognized option|invalid option|unknown flag|unknown option|no such option|usage: |error: unexpected|too many arguments/i;
const LAUNCH_ERROR_RE =
  /unable to access jarfile|no main manifest attribute|could not find or load main class|cannot find module|modulenotfounderror|no such file or directory|command not found|permission denied|is a directory/i;

/**
 * Compile the fixture with one tier and return its script hex.
 *
 * Throws rather than returning a verdict when the process produced no compile
 * result at all — a spawn error, a signal, a usage complaint, a launcher
 * failure, or an exit-0 with no hex on stdout. Scoring any of those as a
 * result is how a tier drops silently out of a parity matrix.
 */
function compileWith(tier: Tier): string {
  if (tier.cmd === null) throw new Error(`${tier.id}: no toolchain`);
  const argv = [...tier.prefix, ...tier.argsFor(FIXTURE)];
  const res = spawnSync(tier.cmd, argv, {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: TIMEOUT_MS,
    maxBuffer: 64 * 1024 * 1024,
  });

  const where = `${tier.id} (${tier.cmd} ${argv.join(' ')})`;
  if (res.error) throw new Error(`${where} could not run: ${res.error.message}`);
  if (res.signal !== null) {
    throw new Error(`${where} was killed by ${res.signal}; a signalled child has no verdict`);
  }
  if (res.status === null) throw new Error(`${where} could not run: no exit status`);

  const diag = `${res.stderr ?? ''}\n${res.stdout ?? ''}`.trim();
  if (res.status !== 0) {
    if (USAGE_ERROR_RE.test(diag)) {
      throw new Error(`${where} exited ${res.status} with a USAGE error — the harness is mis-driving this CLI:\n${diag.slice(0, 600)}`);
    }
    if (LAUNCH_ERROR_RE.test(diag)) {
      throw new Error(`${where} exited ${res.status} with a LAUNCHER error — the compiler never started:\n${diag.slice(0, 600)}`);
    }
    // Every tier must ACCEPT this contract. A refusal is a finding, not a skip.
    throw new Error(`${where} refused the fixture (exit ${res.status}):\n${diag.slice(0, 600)}`);
  }

  const hex = (res.stdout ?? '').replace(/\s+/g, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex)) {
    throw new Error(`${where} exited 0 but printed no script hex:\n${diag.slice(0, 600)}`);
  }
  return hex;
}

/** One decoded pin: `76 | 04 LL LL LL LL | 81 | (9c|a2) | 69`. */
interface DecodedPin {
  exact: boolean;
  value: number;
}

function decodePins(scriptHex: string): DecodedPin[] {
  const pins: DecodedPin[] = [];
  for (let i = 0; i + 18 <= scriptHex.length; i += 2) {
    const seq = scriptHex.slice(i, i + 18);
    if (!seq.startsWith('7604')) continue;
    if (seq.slice(12, 14) !== '81') continue;
    const cmp = seq.slice(14, 16);
    if (cmp !== '9c' && cmp !== 'a2') continue;
    if (seq.slice(16, 18) !== '69') continue;
    const le = seq.slice(4, 12);
    pins.push({ exact: cmp === '9c', value: parseInt(le.match(/../g)!.reverse().join(''), 16) });
  }
  return pins;
}

/**
 * The deploy-time growth of the fixture's single P384Point slot, MEASURED
 * through the SDK's own encoder rather than restated as a constant: build the
 * code part with a real 96-byte anchor and subtract the template it was built
 * from. Everything below is relative to this number, so if the SDK's push
 * encoding ever changes, this test moves with it instead of going stale.
 */
function measuredSlotGrowth(): number {
  const source = require('node:fs').readFileSync(FIXTURE, 'utf-8') as string;
  const r = compile(source, { fileName: 'VarLenP384Ctor.runar.ts' });
  if (!r.artifact || !r.scriptHex) {
    throw new Error(`reference compile failed: ${JSON.stringify(r.diagnostics)}`);
  }
  const deployed = new RunarContract(r.artifact, [MEMO, ANCHOR]).getCodePartHex();
  return deployed.length / 2 - r.scriptHex.length / 2;
}

describe('R-095: the code-part length pin equals the deployed length, in every tier', () => {
  it('the matrix names all seven tiers (a silently dropped tier fails here)', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...ALL_TIER_IDS]);
  });

  it('every tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (process.env.CI === 'true') {
      expect(missing, `CI=true but these tiers have no toolchain: ${missing.join(', ')}`).toEqual([]);
    }
    expect(AVAILABLE.length).toBeGreaterThanOrEqual(2);
  });

  it('a 96-byte P384Point slot really grows the deployed script by 97 bytes', () => {
    // 96 > 75, so OP_PUSHDATA1: `4c 60` + 96 bytes = 98, over a 1-byte OP_0.
    expect(measuredSlotGrowth()).toBe(97);
  });

  for (const tier of TIERS) {
    const run = tier.cmd === null ? it.skip : it;
    run(`${tier.id}: the exact pin equals template + measured growth`, () => {
      const growth = measuredSlotGrowth();
      const hex = compileWith(tier);
      const pins = decodePins(hex);
      expect(pins.length, `${tier.id} emitted no verify_code_part_len pin`).toBe(1);
      const pin = pins[0]!;
      // Variable-length state + a fully fixed-width slot set: the compiler
      // knows the growth exactly, so this must be an equality pin.
      expect(pin.exact, `${tier.id} degraded the pin to a lower bound`).toBe(true);
      // One byte off and every honest spend fails OP_VERIFY.
      expect(pin.value, `${tier.id} pinned ${pin.value}, SDK deploys ${hex.length / 2 + growth}`)
        .toBe(hex.length / 2 + growth);
    }, TIMEOUT_MS + 30_000);
  }
});

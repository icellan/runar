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

// ---------------------------------------------------------------------------
// R-010 — clauses 8a/8b must constrain the remainder the SDK actually deploys.
//
// The pin above rides on the CODE part's length. Clauses 8a/8b ride on the
// REMAINDER: everything the deployed locking script carries after the code
// part. For a StatefulSmartContract with zero mutable properties there is no
// state section at all — no separator, no payload — so the remainder is empty.
// `fixedStateSectionLength()` nonetheless summed to 0 in all seven tiers,
// which read as "a fixed section of length zero" and emitted
// `SIZE(rest) == 1 + 0` plus a demand for a trailing `0x6a`. Same shape of
// defect as R-095, same consequence: every honest spend aborts and the funds
// are locked.
//
// The assertion is again absolute, not cross-tier: each tier's own clause is
// checked against the remainder the SDK really writes.
// ---------------------------------------------------------------------------

const ZERO_MUTABLE_FIXTURE = join(__dirname, 'ZeroMutableContinuation.runar.ts');

/** A compressed secp256k1 point. Only its LENGTH matters to the layout. */
const ZM_OWNER = '02' + '11'.repeat(32);

/** Push2 OP_SUB OP_ROT OP_SWAP OP_SPLIT — step 8's split, right before 8a. */
const SPLIT_ANCHOR = '52947b7c7f';

interface AuthClause {
  /** Length clause 8a demands of the remainder, or null when 8a is absent. */
  demandedRestLen: number | null;
  /** Whether clause 8b demands a leading OP_RETURN byte in the remainder. */
  demandsSeparator: boolean;
}

/** Decode a minimally-encoded numeric push at `i`; returns [value, nextIndex]. */
function readPush(bytes: number[], i: number): [number, number] {
  const op = bytes[i]!;
  if (op === 0x00) return [0, i + 1];
  if (op >= 0x51 && op <= 0x60) return [op - 0x50, i + 1];
  if (op >= 0x01 && op <= 0x4b) {
    let v = 0;
    for (let k = op - 1; k >= 0; k--) v = (v << 8) | bytes[i + 1 + k]!;
    return [v, i + 1 + op];
  }
  throw new Error(`not a numeric push at ${i}: 0x${op.toString(16)}`);
}

function decodeAuthClause(scriptHex: string): AuthClause {
  const at = scriptHex.indexOf(SPLIT_ANCHOR);
  if (at < 0) throw new Error('no code-part authentication clause in this script');
  if (scriptHex.indexOf(SPLIT_ANCHOR, at + 2) >= 0) {
    throw new Error('ambiguous: more than one split anchor');
  }
  const bytes = scriptHex.match(/../g)!.map((b) => parseInt(b, 16));
  let i = at / 2 + SPLIT_ANCHOR.length / 2;

  let demandedRestLen: number | null = null;
  if (bytes[i] === 0x82) {
    const [n, next] = readPush(bytes, i + 1);
    if (bytes[next] !== 0x9d) throw new Error('clause 8a is not OP_NUMEQUALVERIFY-terminated');
    demandedRestLen = n;
    i = next + 1;
  }
  const demandsSeparator =
    bytes[i] === 0x51 && bytes[i + 1] === 0x7f && bytes[i + 2] === 0x75 &&
    bytes[i + 3] === 0x01 && bytes[i + 4] === 0x6a && bytes[i + 5] === 0x88;

  return { demandedRestLen, demandsSeparator };
}

/**
 * The remainder the SDK really deploys for the zero-mutable fixture, MEASURED
 * through the SDK rather than restated as a constant: everything
 * `getLockingScript()` puts after `getCodePartHex()`. A `stateFields`-less
 * artifact writes nothing there, and this is the number clauses 8a/8b have to
 * agree with.
 */
function measuredZeroMutableRest(): string {
  const source = require('node:fs').readFileSync(ZERO_MUTABLE_FIXTURE, 'utf-8') as string;
  const r = compile(source, { fileName: 'ZeroMutableContinuation.runar.ts' });
  if (!r.artifact || !r.scriptHex) {
    throw new Error(`reference compile failed: ${JSON.stringify(r.diagnostics)}`);
  }
  const c = new RunarContract(r.artifact, [ZM_OWNER]);
  const code = c.getCodePartHex();
  const locking = c.getLockingScript();
  if (!locking.startsWith(code)) {
    throw new Error('getLockingScript() does not begin with getCodePartHex()');
  }
  return locking.slice(code.length);
}

/** Compile an arbitrary fixture with one tier. Mirrors `compileWith`. */
function compileFixtureWith(tier: Tier, fixture: string): string {
  if (tier.cmd === null) throw new Error(`${tier.id}: no toolchain`);
  const argv = [...tier.prefix, ...tier.argsFor(fixture)];
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
      throw new Error(`${where} exited ${res.status} with a USAGE error:\n${diag.slice(0, 600)}`);
    }
    if (LAUNCH_ERROR_RE.test(diag)) {
      throw new Error(`${where} exited ${res.status} with a LAUNCHER error:\n${diag.slice(0, 600)}`);
    }
    throw new Error(`${where} refused the fixture (exit ${res.status}):\n${diag.slice(0, 600)}`);
  }

  const hex = (res.stdout ?? '').replace(/\s+/g, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex)) {
    throw new Error(`${where} exited 0 but printed no script hex:\n${diag.slice(0, 600)}`);
  }
  return hex;
}

describe('R-010: clauses 8a/8b match the deployed remainder, in every tier', () => {
  it('the zero-mutable artifact really has no state section', () => {
    // If this ever stops holding, the oracle below is measuring the wrong
    // thing and the per-tier assertions become vacuous.
    expect(measuredZeroMutableRest()).toBe('');
  });

  for (const tier of TIERS) {
    const run = tier.cmd === null ? it.skip : it;
    run(`${tier.id}: demands exactly the remainder the SDK writes`, () => {
      const rest = measuredZeroMutableRest();
      const hex = compileFixtureWith(tier, ZERO_MUTABLE_FIXTURE);
      const clause = decodeAuthClause(hex);

      expect(
        clause.demandedRestLen,
        `${tier.id} clause 8a demands SIZE(rest)==${clause.demandedRestLen}, ` +
          `SDK deploys ${rest.length / 2} — every honest spend aborts`,
      ).toBe(rest.length / 2);

      expect(
        clause.demandsSeparator,
        `${tier.id} clause 8b demands an OP_RETURN the SDK never writes`,
      ).toBe(rest.startsWith('6a'));
    }, TIMEOUT_MS + 30_000);
  }

  it('all available tiers agree byte for byte on this fixture', () => {
    // Parity is not the oracle, but a split here would mean one tier took a
    // different branch through the fix.
    const byTier = AVAILABLE.map((t) => [t.id, compileFixtureWith(t, ZERO_MUTABLE_FIXTURE)] as const);
    const distinct = new Set(byTier.map(([, hex]) => hex));
    expect(
      distinct.size,
      `tiers diverged: ${byTier.map(([id, hex]) => `${id}=${hex.length / 2}B`).join(' ')}`,
    ).toBe(1);
  }, TIMEOUT_MS * 2);
});

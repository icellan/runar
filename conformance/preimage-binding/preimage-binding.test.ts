/**
 * R-105 — forged-preimage rejection was proven in ONE tier. This makes that
 * proof cover all seven.
 *
 * The single most security-critical behaviour in the language is that a forged
 * OP_PUSH_TX preimage is rejected — it is the BUG-100 exploit, and it is what
 * makes a stateful contract a covenant rather than a suggestion. It IS proven,
 * thoroughly: `packages/runar-testing/src/__tests__/oppushtx-binding.test.ts`
 * drives the real @bsv/sdk `Spend` interpreter across a 60-context sighash
 * sweep plus DER/low-S edge cases, and requires the genuine preimage to be
 * ACCEPTED and forged, decoupled and zeroed preimages to be REJECTED.
 *
 * It proves it about `CHECK_PREIMAGE_BINDING_HEX` — the TypeScript tier's
 * constant. The other six tiers emit their own copy of that blob, and nothing
 * asserted the copies were the same bytes. Six tiers' covenant binding was
 * argued by resemblance.
 *
 * The link is cheap and total: if every tier's compiled stateful contract
 * contains that exact 428-byte blob, verbatim, then the execution proof
 * transfers by construction. That is what this file asserts, and it is a
 * stronger statement than "the scripts agree" — it names the security-bearing
 * substring and requires it to be present, so a tier that agreed on a
 * DIFFERENT-but-identical-looking blob would still fail here.
 *
 * What this deliberately does NOT do is re-execute the sweep in six tiers.
 * Three of them ship no Script VM at all (CLAUDE.md: Zig, Ruby and Java have no
 * canonical upstream interpreter), so that is not available; the byte-identity
 * of the blob is.
 */
import { describe, it, expect } from 'vitest';
import { CHECK_PREIMAGE_BINDING_HEX } from '../../packages/runar-compiler/src/index.js';
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  findGoBinary,
  findJavaJarPath,
  findPythonBinary,
  findRubyBinary,
  findRustBinary,
  findZigBinary,
} from '../runner/runner.js';

/**
 * Cross-tier ACCEPTANCE parity. Started as the subtype-lattice gate (N-104) and
 * is now the repo's general corpus for "every tier must accept this, and agree
 * on the bytes" — the directory name is narrower than its contents.
 *
 * `conformance/negatives/rejection-parity.test.ts` gates what the seven tiers
 * must REFUSE. This file is its mirror: a small corpus that every tier must
 * ACCEPT, and — because a compiler that accepts a program and emits different
 * bytes for it is a worse failure than one that refuses it — must compile to
 * BYTE-IDENTICAL script hex.
 *
 * It exists because `isSubtype` had diverged along two independent axes, and
 * neither axis was visible to any existing gate. Both were measured as a full
 * 14x14 bidirectional matrix (every ordered pair of every family member, plus
 * the `Sha256Digest` alias) driven through real compiles in all seven tiers:
 *
 *   axis 1 — the family lattice.  ts / rust / zig treat the ByteString and
 *   bigint families as bidirectionally assignable; go / python / ruby / java
 *   carried only the `subtype -> base` direction. 85 of 196 cells disagreed.
 *   Fixture: FamilyWidening.runar.ts.
 *
 *   axis 2 — the `Sha256Digest` alias.  ts / zig / python / ruby / java
 *   normalise it to `Sha256` in their `.runar.ts` frontend; go and rust only
 *   did so in their OTHER surface parsers, so on a `.runar.ts` source the name
 *   stayed opaque and matched nothing.
 *   Fixture: Sha256DigestAlias.runar.ts, landing with the alias fix — the two
 *   axes are independent defects and are fixed one commit apart.
 *
 * The two axes are why two separate single-pair probes reached two different
 * "the split is N-vs-M" answers and both were right: `const h: Sha256 = pkh`
 * lands on axis 1 alone (3-vs-4), `const h: Sha256Digest = pkh` needs both
 * axes permissive (2-vs-5). A cell-by-cell matrix was the only thing that
 * separated them, and this corpus is the regression gate for the result.
 *
 * Beyond the lattice, the corpus now also holds FixedArrayOutputShape.runar.ts
 * (N-106 / N-107): the `addOutput` arity rule must count the state slots that
 * exist AFTER `expandFixedArrays`, not the declared properties. That was an
 * acceptance divergence of exactly the shape this file was built for — the
 * reference tier alone refused a contract the other six compiled — and
 * `conformance/negatives/N26` and `N27` are its two rejection halves.
 *
 * Vacuity: every tier must be OBSERVED accepting each fixture. The failure
 * this guards against is a tier silently dropping out of the matrix — the same
 * shape rejection-parity.test.ts documents at length — so a tier with no
 * toolchain is named, not skipped, and `verdict` refuses to score a run that
 * never produced a compiler diagnostic.
 */

const REPO = resolve(__dirname, '../..');
const DIR = __dirname;

/** The seven tiers, by id. A tier silently vanishing fails the guard below. */
const ALL_TIER_IDS = ['go', 'java', 'python', 'ruby', 'rust', 'ts', 'zig'] as const;

interface Tier {
  id: string;
  /** null when the toolchain is not built on this machine. */
  cmd: string | null;
  prefix: string[];
  argsFor: (src: string) => string[];
  cwd: string;
  timeoutMs: number;
}

/** Split a runner finder's `"ruby /path/to/script"` into cmd + args. */
function splitCmd(s: string | null): { cmd: string | null; args: string[] } {
  if (s === null) return { cmd: null, args: [] };
  const parts = s.trim().split(/\s+/);
  return { cmd: parts[0] ?? null, args: parts.slice(1) };
}

/** Mirrors `resolveTsxLoader` in rejection-parity.test.ts (runner-private). */
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

const NATIVE_TIMEOUT = 120_000;
const TS_TIMEOUT = 180_000;

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
      timeoutMs: TS_TIMEOUT,
    },
    {
      id: 'go',
      cmd: go.cmd,
      prefix: go.args,
      argsFor: (s) => ['--source', s, '--hex'],
      cwd: join(REPO, 'compilers/go'),
      timeoutMs: NATIVE_TIMEOUT,
    },
    {
      id: 'rust',
      cmd: rust.cmd,
      prefix: rust.args,
      argsFor: (s) => ['--source', s, '--hex'],
      cwd: join(REPO, 'compilers/rust'),
      timeoutMs: NATIVE_TIMEOUT,
    },
    {
      id: 'python',
      cmd: python.cmd,
      prefix: python.args,
      argsFor: (s) => ['--source', s, '--hex'],
      cwd: join(REPO, 'compilers/python'),
      timeoutMs: NATIVE_TIMEOUT,
    },
    {
      id: 'zig',
      cmd: zig.cmd,
      prefix: zig.args,
      argsFor: (s) => ['compile', s, '--hex'],
      cwd: join(REPO, 'compilers/zig'),
      timeoutMs: NATIVE_TIMEOUT,
    },
    {
      id: 'ruby',
      cmd: ruby.cmd,
      prefix: ruby.args,
      argsFor: (s) => ['--source', s, '--hex'],
      cwd: join(REPO, 'compilers/ruby'),
      timeoutMs: NATIVE_TIMEOUT,
    },
    {
      id: 'java',
      cmd: jar ? 'java' : null,
      prefix: jar ? ['-jar', jar] : [],
      argsFor: (s) => ['--source', s, '--hex'],
      cwd: REPO,
      timeoutMs: NATIVE_TIMEOUT,
    },
  ];
}

const TIERS: Tier[] = buildTiers();

function missingTierIds(tiers: Tier[]): string[] {
  return tiers.filter((t) => t.cmd === null).map((t) => t.id);
}

/** Same classifiers as rejection-parity.test.ts: a non-zero exit that came
 *  from the launcher or the argv parser is not the language's opinion. */
const USAGE_ERROR_RE =
  /flag provided but not defined|unexpected argument|unrecognized argument|unrecognized option|invalid option|unknown flag|unknown option|no such option|usage: |error: unexpected|too many arguments/i;
const LAUNCH_ERROR_RE =
  /unable to access jarfile|no main manifest attribute|could not find or load main class|cannot find module|modulenotfounderror|no such file or directory|command not found|permission denied|is a directory/i;

class BrokenTier extends Error {}

interface Accepted {
  ok: true;
  /** Lowercased script hex, whitespace-stripped. */
  hex: string;
}
interface Rejected {
  ok: false;
  diag: string;
}
type Verdict = Accepted | Rejected;

/**
 * Compile one source with one tier. On success the script hex is returned so
 * the corpus can assert byte-identity, not merely "seven exit codes were 0".
 *
 * Throws `BrokenTier` when the process produced no verdict at all — a spawn
 * error, a signal, an empty diagnostic, a usage complaint, or a launcher
 * failure. Scoring any of those as a result is the bare-catch bug that made
 * two tiers of rejection-parity vacuous before R-100.
 */
function verdict(tier: Tier, src: string): Verdict {
  if (tier.cmd === null) throw new BrokenTier(`${tier.id}: no toolchain`);
  const argv = [...tier.prefix, ...tier.argsFor(src)];
  const res = spawnSync(tier.cmd, argv, {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });

  const where = `${tier.id} (${tier.cmd} ${argv.join(' ')})`;
  if (res.error) throw new BrokenTier(`${where} could not run: ${res.error.message}`);
  if (res.signal !== null) {
    throw new BrokenTier(
      `${where} could not run to completion: killed by ${res.signal} ` +
        `(timeout is ${tier.timeoutMs}ms). A signalled child has no verdict.`,
    );
  }
  if (res.status === null) throw new BrokenTier(`${where} could not run: no exit status`);

  const diag = `${res.stderr ?? ''}\n${res.stdout ?? ''}`.trim();
  if (res.status === 0) {
    const hex = (res.stdout ?? '').replace(/\s+/g, '').toLowerCase();
    if (!/^[0-9a-f]+$/.test(hex)) {
      throw new BrokenTier(
        `${where} exited 0 but did not print script hex — an "acceptance" ` +
          `with no artifact proves nothing:\n${diag.slice(0, 600)}`,
      );
    }
    return { ok: true, hex };
  }
  if (diag === '') {
    throw new BrokenTier(
      `${where} exited ${res.status} with an EMPTY diagnostic. A silent ` +
        `non-zero exit is a crash or a lost pipe, not a rejection.`,
    );
  }
  if (USAGE_ERROR_RE.test(diag)) {
    throw new BrokenTier(
      `${where} exited ${res.status} with a USAGE error, not a compile ` +
        `diagnostic — the harness is mis-driving this CLI:\n${diag.slice(0, 600)}`,
    );
  }
  if (LAUNCH_ERROR_RE.test(diag)) {
    throw new BrokenTier(
      `${where} exited ${res.status} with a LAUNCHER error — the compiler ` +
        `never started, so it has no opinion about this source:\n${diag.slice(0, 600)}`,
    );
  }
  return { ok: false, diag };
}


const PROBE = 'StatefulBinding.runar.ts';
const available = TIERS.filter((t) => t.cmd !== null);

describe('R-105: every tier emits the exact preimage-binding blob that was exploit-tested', () => {
  it('the matrix names all seven tiers (a silently dropped tier fails here)', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...ALL_TIER_IDS]);
  });

  it('every tier is built (strict in CI, ">=2" locally)', () => {
    const missing = missingTierIds(TIERS);
    if (process.env.CI === 'true') {
      expect(missing, `CI=true but these tiers have no toolchain: ${missing.join(', ')}`).toEqual([]);
    }
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  it('the blob under test is non-trivial — a short or empty constant would make every case below vacuous', () => {
    expect(CHECK_PREIMAGE_BINDING_HEX.length % 2).toBe(0);
    expect(
      CHECK_PREIMAGE_BINDING_HEX.length / 2,
      'the OP_PUSH_TX binding blob is 428 bytes since the Any-S construction; a ' +
        'sudden change in size means the thing being transferred is not the thing ' +
        'oppushtx-binding.test.ts exploit-tested',
    ).toBe(428);
    expect(/^[0-9a-f]+$/.test(CHECK_PREIMAGE_BINDING_HEX)).toBe(true);
  });

  for (const tier of available) {
    it(`${tier.id} emits the blob verbatim`, () => {
      const v = verdict(tier, join(__dirname, PROBE));
      expect(v.ok, v.ok ? '' : `${tier.id} refused the probe contract:\n${v.diag.slice(0, 600)}`).toBe(true);

      const hex = (v as { ok: true; hex: string }).hex;
      expect(
        hex.includes(CHECK_PREIMAGE_BINDING_HEX),
        `${tier.id}'s stateful contract does NOT contain the exact binding blob that ` +
          `oppushtx-binding.test.ts proved rejects forged, decoupled and zeroed ` +
          `preimages. Whatever this tier emits for checkPreimage, the BUG-100 exploit ` +
          `proof does not cover it.\n` +
          `  tier script: ${hex.length / 2} bytes\n` +
          `  blob:        ${CHECK_PREIMAGE_BINDING_HEX.length / 2} bytes`,
      ).toBe(true);
    });
  }

  it('the blob appears exactly once — a second copy would mean two bindings to reason about', () => {
    for (const tier of available) {
      const v = verdict(tier, join(__dirname, PROBE));
      expect(v.ok).toBe(true);
      const hex = (v as { ok: true; hex: string }).hex;
      const count = hex.split(CHECK_PREIMAGE_BINDING_HEX).length - 1;
      expect(count, `${tier.id} emits the binding blob ${count} times`).toBe(1);
    }
  });
});

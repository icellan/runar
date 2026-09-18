/**
 * R-037 — the Go-only crypto families, and what the other six tiers do with them.
 *
 * CLAUDE.md scopes seven families to the Go tier by policy: BabyBear,
 * KoalaBear, Poseidon2 (KoalaBear + Merkle), BN254 + Groth16, Merkle /
 * `merkleRootSha256`, the SP1 FRI verifier, and FiatShamir-KB. The finding's
 * objection is that the policy and the code disagree: five non-Go tiers ship
 * LIVE, DISPATCHED codegen for these families with zero test references, while
 * the Java tier ships stubs that throw. A family that is "not a conformance
 * target" but is nonetheless compiled by six tiers is exempt from the parity
 * check and still carries the divergence risk.
 *
 * This file does not pick the policy — that is a project decision, and the
 * remediation note frames it as one (delete the untested ports, or promote the
 * families to real conformance targets). It asserts the property that must hold
 * under EITHER choice, which is the finding's own testable assertion:
 *
 *   for each family, every non-Go tier must either REFUSE the contract with a
 *   real diagnostic, or produce hex BYTE-IDENTICAL to Go's.
 *
 * The state it forbids is the third one: a tier that compiles the family and
 * emits DIFFERENT bytes. Nothing else in the repository would catch that — the
 * fixtures carrying these builtins all declare `"compilers": ["go"]`, so the
 * other six tiers are never compared on them.
 *
 * Measured when this file was written: for all four families below, the five
 * non-Go non-Java tiers produce byte-identical hex to Go, and Java refuses with
 * its "Java tier carries partial port only" diagnostic. So the ports are
 * consistent today — the gap was that nobody was checking.
 */
import { describe, it, expect } from 'vitest';
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


/** One probe contract per Go-only family, beside this file. */
const FAMILIES = [
  { file: 'GoOnlyBabyBear.runar.ts', family: 'BabyBear', builtin: 'bbFieldMul' },
  { file: 'GoOnlyKoalaBear.runar.ts', family: 'KoalaBear', builtin: 'kbFieldMul' },
  { file: 'GoOnlyBn254.runar.ts', family: 'BN254', builtin: 'bn254FieldMul' },
  { file: 'GoOnlyMerkle.runar.ts', family: 'Merkle', builtin: 'merkleRootSha256' },
  // R-141 added this one: the field probe above never touched the G1 POINT
  // surface, so the coordinate-canonicity and OP_SIZE-64 gates on
  // bn254G1OnCurve / bn254G1Negate had no cross-tier gate at all.
  { file: 'GoOnlyBn254G1.runar.ts', family: 'BN254 G1', builtin: 'bn254G1OnCurve' },
] as const;

const available = TIERS.filter((t) => t.cmd !== null);
const goTier = TIERS.find((t) => t.id === 'go')!;

describe('R-037: Go-only families — refuse, or match Go byte for byte', () => {
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

  it('the Go tier — the reference for these families — is available', () => {
    expect(
      goTier.cmd,
      'every assertion here is relative to Go\'s output; without it there is nothing to compare against',
    ).not.toBeNull();
  });

  for (const { file, family, builtin } of FAMILIES) {
    const src = join(__dirname, file);

    describe(`${family} (${builtin})`, () => {
      it('Go compiles it — the reference must exist', () => {
        const v = verdict(goTier, src);
        expect(
          v.ok,
          `Go is the reference tier for ${family}; if IT refuses, the probe contract ` +
            `is wrong rather than the tiers:\n${v.ok ? '' : v.diag.slice(0, 600)}`,
        ).toBe(true);
      });

      for (const tier of available.filter((t) => t.id !== 'go')) {
        it(`${tier.id} refuses it, or matches Go exactly`, () => {
          const goResult = verdict(goTier, src);
          expect(goResult.ok, 'Go must compile the probe').toBe(true);
          const goHex = (goResult as { ok: true; hex: string }).hex;

          const v = verdict(tier, src);

          if (!v.ok) {
            // Refusal is a legitimate answer — it is what the Java tier does.
            // It must be a REAL diagnostic, which `verdict` already guarantees
            // (an empty, usage or launcher error throws BrokenTier), and it
            // must mention the builtin or the family so a reader can tell why.
            const mentions =
              v.diag.includes(builtin) ||
              v.diag.toLowerCase().includes(family.toLowerCase()) ||
              /go-only|partial port|not supported|unsupported/i.test(v.diag);
            expect(
              mentions,
              `${tier.id} refused ${family}, which is allowed, but the diagnostic ` +
                `does not say what was refused — a contributor cannot tell a policy ` +
                `refusal from a bug:\n${v.diag.slice(0, 600)}`,
            ).toBe(true);
            return;
          }

          expect(
            v.hex,
            `${tier.id} COMPILES ${family} and emits different bytes than Go.\n` +
              `This is the state the policy leaves unguarded: the fixtures using these ` +
              `builtins all declare "compilers": ["go"], so nothing else compares the ` +
              `other six tiers on them. Either make this tier match Go, or make it ` +
              `refuse like the Java tier does.\n` +
              `  go:   ${goHex.slice(0, 60)}... (${goHex.length / 2} bytes)\n` +
              `  ${tier.id}: ${v.hex.slice(0, 60)}... (${v.hex.length / 2} bytes)`,
          ).toBe(goHex);
        });
      }
    });
  }
});

/**
 * Regression pins for findings that were fixed WITHOUT their own assertion test.
 *
 * Seven reviewer findings were closed by earlier commits in this remediation —
 * the code was changed and the change was verified by hand — but each one's
 * `testable_assertion` was never encoded anywhere. A fix with no test is a fix
 * until someone refactors near it.
 *
 * This file encodes those assertions verbatim, one describe block per finding,
 * against every built tier. It fixes nothing: every case here passes at the
 * commit that adds it. What it buys is that the seven cannot silently reopen.
 *
 * Measured when the file was written:
 *
 *   R-050  nested output-emitting helper      7 tiers byte-identical, 1530 hexchars
 *   R-070  reverseBytes in Ruby               7 tiers byte-identical, 11450 hexchars
 *   R-076  FixedArray + @sighash SINGLE|FORKID 7 tiers identical, script pushes 0x43
 *   R-077  mutation through a local (Ruby)    7 tiers identical, 1374 hexchars
 *   R-078  mutation through a local (Java)    same probe — one shape, two tiers
 *   R-080  addRawOutput() with no arguments   located diagnostic in every tier
 *   R-083  `i += 2n` loop update              refused before ANF lowering
 *   R-085  undeclared identifier (Java)       located diagnostic, not acceptance
 *   N-134  256-bit hex literal                 7 tiers identical; hex spelling ==
 *                                              decimal spelling, in every tier
 *   R-114  .runar.sol with no constructor      7 tiers accept and agree (was 4/3)
 *   R-197  bitwise ops on ByteString           7 tiers accept and agree; the
 *                                              documented claim had no fixture
 *
 * R-076 deserves a note: it is only TESTABLE at all since N-124 taught the Zig
 * tier to compile `this.arr[i]++`. Before that, the probe could not reach the
 * sighash question in that tier.
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


/** Contracts every tier must COMPILE, and agree on byte for byte. */
const MUST_COMPILE = [
  {
    file: 'NestedHelper.runar.ts',
    finding: 'R-050',
    what: 'a stateful method calling a private output-emitting helper inside an `if`',
  },
  {
    file: 'RevBytes.runar.ts',
    finding: 'R-070',
    what: 'reverseBytes — it crashed the Ruby compiler',
  },
  {
    file: 'SighashArr.runar.ts',
    finding: 'R-076',
    what: 'a FixedArray stateful contract carrying @sighash SINGLE|FORKID',
  },
  {
    file: 'MutLocal.runar.ts',
    finding: 'R-077 / R-078',
    what: 'a method whose only mutation is through a local binding',
  },
  {
    file: 'NoCtorSol.runar.sol',
    finding: 'R-114',
    what: 'a `.runar.sol` contract with no constructor — four tiers synthesised one, three refused',
  },
  {
    file: 'BitwiseBytes.runar.ts',
    finding: 'R-197',
    what: 'bitwise &, |, ^, ~ with ByteString operands — the half the bitwise-ops fixture never covered',
  },
  {
    file: 'HexBigLiteral.runar.ts',
    finding: 'N-134',
    what: "a 256-bit integer literal written in hex — the Zig tier's parsers refused it",
  },
  {
    file: 'DecBigLiteral.runar.ts',
    finding: 'N-134',
    what: 'the same number in decimal — the spelling that always worked',
  },
  {
    file: 'NegLoopStart.runar.ts',
    finding: 'N-138',
    what: 'a for-loop starting at a NEGATIVE literal — the Zig tier unrolled from 0 on all nine surfaces',
  },
  {
    file: 'BytesInit.runar.ts',
    finding: 'R-204',
    what: 'a ByteString-literal property initializer — the one documented initializer type the property-initializers fixture never covered',
  },
] as const;

/** Contracts every tier must REFUSE, with a real located diagnostic. */
const MUST_REFUSE = [
  {
    file: 'BadArity.runar.ts',
    finding: 'R-080',
    what: 'addRawOutput() with no arguments',
    expect: /addRawOutput/i,
  },
  {
    file: 'BadUpdate.runar.ts',
    finding: 'R-083',
    what: 'a for-loop updated by `i += 2n`',
    // Every tier refuses it; they do not agree on WHY, and two of the wordings
    // never mention the loop:
    //
    //   ts/zig/go/java/python/ruby  "Unsupported binary operator: '+='" or a
    //                               loop-update message naming the unit step
    //   rust                        "Assignment expressions in expression
    //                               context are not recommended" — a parse-level
    //                               refusal of the compound assignment
    //
    // R-083's assertion is "rejected before ANF lowering", which Rust satisfies.
    // The wording gap is filed as its own item rather than hidden by loosening
    // this to /./.
    expect: /\+=|loop update|unit step|unsupported binary|assignment expression/i,
  },
  {
    file: 'Undeclared.runar.java',
    finding: 'R-085',
    what: 'a condition using an undeclared identifier',
    expect: /notDeclaredAnywhere|unknown|undefined|unresolved|bigint/i,
  },
] as const;

const available = TIERS.filter((t) => t.cmd !== null);

describe('regression pins for previously-closed findings', () => {
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

  for (const { file, finding, what } of MUST_COMPILE) {
    const src = join(__dirname, file);

    describe(`${finding} — ${what}`, () => {
      for (const tier of available) {
        it(`${tier.id} compiles it`, () => {
          const v = verdict(tier, src);
          expect(
            v.ok,
            v.ok ? '' : `${tier.id} REFUSED a contract ${finding} closed:\n${v.diag.slice(0, 700)}`,
          ).toBe(true);
        });
      }

      it('all tiers emit byte-identical script', () => {
        const byTier = new Map<string, string>();
        const refused: string[] = [];
        for (const tier of available) {
          const v = verdict(tier, src);
          if (v.ok) byTier.set(tier.id, v.hex);
          else refused.push(tier.id);
        }
        expect(refused, `these tiers refused, so byte-identity over the rest is vacuous`).toEqual([]);
        const values = [...new Set(byTier.values())];
        expect(
          values.length,
          `tiers disagree on ${file}:\n` +
            [...byTier.entries()].map(([k, v]) => `  ${k}: ${v.slice(0, 48)}… (${v.length / 2} bytes)`).join('\n'),
        ).toBe(1);
      });
    });
  }

  // N-134's assertion is not "each spelling is self-consistent across tiers" —
  // that would pass if every tier compiled the hex form to something wrong in
  // the same way. It is that the two SPELLINGS are one number.
  it('N-134 — the hex and decimal spellings of one number compile to one script', () => {
    const hexSrc = join(__dirname, 'HexBigLiteral.runar.ts');
    const decSrc = join(__dirname, 'DecBigLiteral.runar.ts');
    for (const tier of available) {
      const h = verdict(tier, hexSrc);
      const d = verdict(tier, decSrc);
      expect(h.ok, `${tier.id} refused the hex spelling`).toBe(true);
      expect(d.ok, `${tier.id} refused the decimal spelling`).toBe(true);
      expect(
        (h as { ok: true; hex: string }).hex,
        `${tier.id} compiles 0xFFFF…41n and its decimal equal to DIFFERENT scripts`,
      ).toBe((d as { ok: true; hex: string }).hex);
    }
  });

  // R-076's assertion is not just "they agree" — it is that the DECLARED sighash
  // flag survives FixedArray expansion. Agreement on a wrong flag would pass the
  // block above and miss the finding entirely.
  it('R-076 — the emitted script still pushes the declared sighash flag 0x43', () => {
    const src = join(__dirname, 'SighashArr.runar.ts');
    for (const tier of available) {
      const v = verdict(tier, src);
      expect(v.ok, `${tier.id} refused the @sighash probe`).toBe(true);
      expect(
        (v as { ok: true; hex: string }).hex.includes('0143'),
        `${tier.id} compiled the contract but its script never pushes 0x43 ` +
          `(SINGLE|FORKID). Zeroing the mode during FixedArray expansion is R-076.`,
      ).toBe(true);
    }
  });

  for (const { file, finding, what, expect: pattern } of MUST_REFUSE) {
    const src = join(__dirname, file);

    describe(`${finding} — ${what} (must be refused)`, () => {
      for (const tier of available) {
        it(`${tier.id} refuses it with a diagnostic that says why`, () => {
          const v = verdict(tier, src);
          expect(
            v.ok,
            v.ok
              ? `${tier.id} ACCEPTED a contract ${finding} says must be refused. ` +
                `It compiled to ${(v as { ok: true; hex: string }).hex.slice(0, 48)}…`
              : '',
          ).toBe(false);
          expect(
            pattern.test((v as { ok: false; diag: string }).diag),
            `${tier.id} refused, but the diagnostic does not name the problem — a ` +
              `reader cannot tell a real rejection from an unrelated failure:\n` +
              `${(v as { ok: false; diag: string }).diag.slice(0, 700)}`,
          ).toBe(true);
        });
      }
    });
  }
});

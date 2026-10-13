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
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import {
  CONSENSUS_SPEND_CONTEXT,
  newConsensusSpend,
} from '../../packages/runar-testing/src/consensus-spend.js';
import {
  findGoBinary,
  findJavaJarPath,
  findPythonBinary,
  findRubyBinary,
  findRustBinary,
  findZigBinary,
} from '../runner/runner.js';
import { isCiEnv } from '../anf-interpreter/driver-gate.js';

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
  // F-091: the G1 ADD surface, which neither probe above reaches. Its
  // execution leg is the describe block at the bottom of this file.
  { file: 'GoOnlyBn254G1Add.runar.ts', family: 'BN254 G1 add', builtin: 'bn254G1Add' },
  // F-092: every non-Go tier refuses this one on source; its `--ir` leg — where
  // the Python port used to compile it with 7 of 8 root limbs dropped — is the
  // describe block below.
  { file: 'GoOnlyPoseidon2Merkle.runar.ts', family: 'Poseidon2 Merkle', builtin: 'merkleRootPoseidon2KB' },
  // F-196: all five scalar-field entry points, which GoOnlyBn254 (Mul only)
  // does not reach. Its execution leg is the F-196 describe block below.
  { file: 'GoOnlyBn254Field.runar.ts', family: 'BN254 field', builtin: 'bn254FieldAdd' },
] as const;

const available = TIERS.filter((t) => t.cmd !== null);
const goTier = TIERS.find((t) => t.id === 'go')!;

describe('R-037: Go-only families — refuse, or match Go byte for byte', () => {
  it('the matrix names all seven tiers (a silently dropped tier fails here)', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...ALL_TIER_IDS]);
  });

  it('every tier is built (strict in CI, ">=2" locally)', () => {
    const missing = missingTierIds(TIERS);
    if (isCiEnv(process.env)) {
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

/**
 * F-092 — merkleRootPoseidon2KB through the `--ir` entry point.
 *
 * The source leg above cannot see this: every non-Go tier refuses the builtin
 * in its typechecker. But `--ir` runs no frontend, and the Python tier's stack
 * lowering carried a live port that reconciled the eight root limbs with seven
 * OP_NIPs — keeping root_7 alone, so `merkleRootPoseidon2KB(...) === expected`
 * authenticated one ~31-bit field element. Go had fixed the same truncation in
 * R-056 (EmitPoseidon2RootPack).
 *
 * What this proves: on Go's own ANF IR for the probe, every tier either refuses
 * (a real diagnostic, per `verdict`) or emits hex byte-identical to Go's.
 * Execution of the Python script against Plonky3 vectors lives in
 * compilers/python/tests/test_f092_poseidon2_merkle_root_binds_every_limb.py;
 * Go's in compilers/go/compiler/poseidon2_merkle_root_binding_test.go.
 * What it does not prove: that a refusing tier's diagnostic names the builtin
 * (the Ruby and Zig `--ir` refusals today are an internal error and a bare
 * `InvalidBuiltin`), nor depths other than 1.
 */
describe('F-092: merkleRootPoseidon2KB via --ir — refuse, or match Go byte for byte', () => {
  const src = join(DIR, 'GoOnlyPoseidon2Merkle.runar.ts');
  const irArgs = (id: string, f: string): string[] =>
    id === 'ts' ? ['--from-ir', f, '--hex'] : id === 'zig' ? ['compile-ir', f, '--hex'] : ['--ir', f, '--hex'];

  for (const tier of available.filter((t) => t.id !== 'go')) {
    it(`${tier.id} refuses Go's IR, or matches Go exactly`, () => {
      const dir = mkdtempSync(join(tmpdir(), 'f092-p2kb-ir-'));
      try {
        const emitted = spawnSync(goTier.cmd!, [...goTier.prefix, '--source', src, '--emit-ir'], {
          cwd: goTier.cwd,
          encoding: 'utf-8',
          timeout: goTier.timeoutMs,
          maxBuffer: 64 * 1024 * 1024,
        });
        expect(emitted.status, `go --emit-ir failed:\n${emitted.stderr}`).toBe(0);
        const irFile = join(dir, 'GoOnlyPoseidon2Merkle.anf.json');
        writeFileSync(irFile, emitted.stdout);

        const goResult = verdict({ ...goTier, argsFor: () => irArgs('go', irFile) }, src);
        expect(goResult.ok, 'Go must compile its own IR').toBe(true);
        const goHex = (goResult as Accepted).hex;

        const v = verdict({ ...tier, argsFor: () => irArgs(tier.id, irFile) }, src);
        if (!v.ok) return; // a refusal is allowed; `verdict` already rejected a crash-less silence
        expect(
          v.hex,
          `${tier.id} COMPILES merkleRootPoseidon2KB from IR and emits different bytes than Go ` +
            `(${v.hex.length / 2} vs ${goHex.length / 2} bytes). Either match Go or refuse.`,
        ).toBe(goHex);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

/**
 * F-091 — bn254G1Add on the omega-partner pair, EXECUTED in every tier.
 *
 * BN254 has j-invariant 0 and p = 1 mod 3, so for P = (x, y) the points
 * (w*x, -y) and (w^2*x, -y) are on the curve, have px != qx, and zero the
 * unified slope's denominator py + qy. The slope is then 0/0, Fermat gives
 * inv(0) = 0, and every tier's script used to return (-(px+qx), -py): an
 * ON-curve point that is NOT P + Q. Measured before the fix on @bsv/sdk's
 * Spend: `bn254G1Add(G, (w, -2)) === (w^2, -2)` was ACCEPTED and the true sum
 * was REJECTED, byte-identically in go / python / rust / zig / ruby / ts.
 *
 * What this proves: for each tier that compiles the probe, the omega case
 * ABORTS inside the builtin (an OP_VERIFY failure, not a mismatch on the final
 * equality) whatever `expected` the spender supplies — including the old wrong
 * answer and the true sum from an independent chord/tangent reference below —
 * while general addition, doubling and P + (-P) -> all-zero O are ACCEPTED
 * against that same reference. What it does not prove: anything about the
 * Groth16 MSM path, which shares the affine adder and is deliberately left
 * unchanged; nor about tiers that refuse the probe (Java), which the parity
 * leg above already scores.
 */
describe('F-091: bn254G1Add omega-partner pair — executed on @bsv/sdk Spend', () => {
  const P: bigint = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n;
  const W: bigint = 0x30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd48n;
  const mod = (a: bigint) => ((a % P) + P) % P;
  const inv = (a: bigint) => {
    // Extended Euclid — deliberately NOT Fermat, so a zero input throws.
    let [r0, r1, s0, s1] = [mod(a), P, 1n, 0n];
    if (r0 === 0n) throw new Error('inverse of 0');
    while (r1 !== 0n) {
      const q = r0 / r1;
      [r0, r1] = [r1, r0 - q * r1];
      [s0, s1] = [s1, s0 - q * s1];
    }
    return mod(s0);
  };
  type Pt = [bigint, bigint] | null; // null = point at infinity
  /** Independent chord/tangent reference. */
  const add = (a: Pt, b: Pt): Pt => {
    if (a === null) return b;
    if (b === null) return a;
    const [x1, y1] = a;
    const [x2, y2] = b;
    let l: bigint;
    if (x1 === x2) {
      if (mod(y1 + y2) === 0n) return null;
      l = mod(3n * x1 * x1 * inv(2n * y1));
    } else {
      l = mod((y2 - y1) * inv(x2 - x1));
    }
    const x3 = mod(l * l - x1 - x2);
    return [x3, mod(l * (x1 - x3) - y1)];
  };
  const onCurve = ([x, y]: [bigint, bigint]) => mod(y * y - x * x * x - 3n) === 0n;
  const hex32 = (v: bigint) => v.toString(16).padStart(64, '0');
  const blob = (pt: Pt) => (pt === null ? '00'.repeat(64) : hex32(pt[0]) + hex32(pt[1]));
  const push64 = (h: string) => '40' + h;

  const G: [bigint, bigint] = [1n, 2n];
  const G2 = add(G, G) as [bigint, bigint];
  const G3 = add(G, G2) as [bigint, bigint];
  const neg = ([x, y]: [bigint, bigint]): [bigint, bigint] => [x, mod(-y)];
  const omegaQ = (pt: [bigint, bigint], c: bigint): [bigint, bigint] => [mod(c * pt[0]), mod(-pt[1])];
  const W2 = mod(W * W);

  function spend(lockHex: string, a: Pt, b: Pt, expected: Pt): { ok: boolean; err: string } {
    try {
      const ok = newConsensusSpend({
        ...CONSENSUS_SPEND_CONTEXT,
        lockingScript: LockingScript.fromHex(lockHex),
        unlockingScript: UnlockingScript.fromHex(push64(blob(a)) + push64(blob(b)) + push64(blob(expected))),
        otherInputs: [],
        outputs: [],
      }).validate();
      return { ok, err: '' };
    } catch (e) {
      return { ok: false, err: String((e as Error).message) };
    }
  }

  it('the witness is what it claims: on-curve, px != qx, py + qy == 0, and the old answer is wrong', () => {
    expect(W !== 1n && mod(W * W * W) === 1n).toBe(true);
    const Q = omegaQ(G, W);
    expect(onCurve(Q)).toBe(true);
    expect(Q[0]).not.toBe(G[0]);
    expect(mod(G[1] + Q[1])).toBe(0n);
    const oldAnswer: [bigint, bigint] = [mod(-(G[0] + Q[0])), mod(-G[1])];
    expect(onCurve(oldAnswer)).toBe(true);
    expect(blob(oldAnswer)).not.toBe(blob(add(G, Q)));
  });

  const src = join(DIR, 'GoOnlyBn254G1Add.runar.ts');
  for (const tier of available) {
    it(`${tier.id}: omega pairs abort, legitimate sums are accepted`, () => {
      const v = verdict(tier, src);
      if (!v.ok) {
        // A refusal is scored by the parity leg above. Only Java refuses
        // today; any other tier refusing would make this leg vacuous for it.
        expect(tier.id, `${tier.id} refused the probe:\n${v.diag.slice(0, 600)}`).toBe('java');
        return;
      }
      const lock = v.hex;

      const accepted: Array<[string, Pt, Pt]> = [
        ['G+2G=3G', G, G2],
        ['G+G=2G', G, G],
        ['G+(-G)=O', G, neg(G)],
        ['2G+(-2G)=O', G2, neg(G2)],
        ['3G+G', G3, G],
      ];
      for (const [name, a, b] of accepted) {
        const r = spend(lock, a, b, add(a, b));
        expect(r.ok, `${tier.id} ${name} must be accepted: ${r.err}`).toBe(true);
      }

      const omega: Array<[string, [bigint, bigint], [bigint, bigint]]> = [
        ['G+(wG.x,-G.y)', G, omegaQ(G, W)],
        ['G+(w^2G.x,-G.y)', G, omegaQ(G, W2)],
        ['(wG.x,-G.y)+G', omegaQ(G, W), G],
        ['2G+(w*2G.x,-2G.y)', G2, omegaQ(G2, W)],
      ];
      for (const [name, a, b] of omega) {
        const oldAnswer: [bigint, bigint] = [mod(-(a[0] + b[0])), mod(-a[1])];
        for (const [label, expected] of [['old wrong answer', oldAnswer], ['true sum', add(a, b)]] as const) {
          const r = spend(lock, a, b, expected);
          expect(r.ok, `${tier.id} ${name} == ${label} must be REJECTED`).toBe(false);
          expect(r.err, `${tier.id} ${name} == ${label}: the builtin must abort, not mismatch`).toMatch(/OP_VERIFY/);
        }
      }
    });
  }
});

/**
 * F-196 — operand canonicity of the five raw BN254 scalar-field builtins,
 * EXECUTED in every tier.
 *
 * Their operands are unlock arguments. Before the gate, every tier fed them
 * straight into OP_ADD / OP_MUL and a bare OP_MOD — which keeps the sign of the
 * dividend — so `bn254FieldAdd(-1, 0) === -1` SPENT, and `bn254FieldAdd(p, 0)
 * === 0` spent as a second spelling of 0. Each entry point now runs
 * `<0> <p> OP_WITHIN OP_VERIFY` on every operand first.
 *
 * What this proves: for each tier that compiles the probe, on @bsv/sdk's Spend,
 * an operand of -1, of exactly p, or of 5+p in ANY position of ANY of the five
 * builtins ABORTS inside the builtin (OP_VERIFY, not a mismatch on the final
 * equality), whatever `expected` the spender supplies — the escaped value or
 * the reduced residue; and canonical operands up to p-1 are ACCEPTED against
 * results computed here with bigint arithmetic, so an over-strict gate reddens.
 * What it does not prove: anything about the Groth16 / pairing paths, which use
 * the internal field helpers and are deliberately left ungated; nor tiers that
 * refuse the probe (Java), which the parity leg above scores.
 */
describe('F-196: bn254Field* operand canonicity — executed on @bsv/sdk Spend', () => {
  const P: bigint = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n;
  const mod = (a: bigint) => ((a % P) + P) % P;
  const pow = (b: bigint, e: bigint): bigint => {
    let r = 1n;
    let x = mod(b);
    while (e > 0n) {
      if (e & 1n) r = (r * x) % P;
      x = (x * x) % P;
      e >>= 1n;
    }
    return r;
  };

  /** Minimal-push encoding of a script number (push-only, minimal pushes). */
  const pushNum = (n: bigint): string => {
    if (n === 0n) return '00';
    if (n === -1n) return '4f';
    if (n >= 1n && n <= 16n) return (0x50 + Number(n)).toString(16);
    const neg = n < 0n;
    let abs = neg ? -n : n;
    const bytes: number[] = [];
    while (abs > 0n) {
      bytes.push(Number(abs & 0xffn));
      abs >>= 8n;
    }
    if (bytes[bytes.length - 1]! & 0x80) bytes.push(neg ? 0x80 : 0x00);
    else if (neg) bytes[bytes.length - 1]! |= 0x80;
    if (bytes.length >= 0x4c) throw new Error('pushNum: test values stay below 76 bytes');
    return bytes.length.toString(16).padStart(2, '0') + bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
  };

  // Public methods in declaration order — the dispatch index.
  const M = { add: 0, sub: 1, mul: 2, inv: 3, neg: 4 } as const;
  type Op = keyof typeof M;
  const ref: Record<Op, (...a: bigint[]) => bigint> = {
    add: (a, b) => mod(a! + b!),
    sub: (a, b) => mod(a! - b!),
    mul: (a, b) => mod(a! * b!),
    inv: (a) => pow(a!, P - 2n),
    neg: (a) => mod(-a!),
  };

  function spend(lockHex: string, op: Op, args: bigint[], expected: bigint): { ok: boolean; err: string } {
    const unlock = [...args, expected].map(pushNum).join('') + pushNum(BigInt(M[op]));
    try {
      const ok = newConsensusSpend({
        ...CONSENSUS_SPEND_CONTEXT,
        lockingScript: LockingScript.fromHex(lockHex),
        unlockingScript: UnlockingScript.fromHex(unlock),
        otherInputs: [],
        outputs: [],
      }).validate();
      return { ok, err: '' };
    } catch (e) {
      return { ok: false, err: String((e as Error).message) };
    }
  }

  const PM1 = P - 1n;
  const BAD: Array<[string, bigint]> = [['-1', -1n], ['p', P], ['5+p', P + 5n]];

  const src = join(DIR, 'GoOnlyBn254Field.runar.ts');
  for (const tier of available) {
    it(`${tier.id}: non-canonical operands abort, canonical operands near p are accepted`, () => {
      const v = verdict(tier, src);
      if (!v.ok) {
        expect(tier.id, `${tier.id} refused the probe:\n${v.diag.slice(0, 600)}`).toBe('java');
        return;
      }
      const lock = v.hex;

      // CONTROL WITH TEETH: honest spends against independently computed results.
      const accepted: Array<[Op, bigint[]]> = [
        ['add', [PM1, PM1]], ['add', [PM1, 1n]], ['add', [0n, 0n]],
        ['sub', [0n, PM1]], ['sub', [0n, 1n]], ['sub', [PM1, PM1]],
        ['mul', [PM1, PM1]], ['mul', [PM1, 2n]], ['mul', [P - 2n, P - 3n]],
        ['inv', [PM1]], ['inv', [2n]],
        ['neg', [0n]], ['neg', [1n]], ['neg', [PM1]],
      ];
      for (const [op, args] of accepted) {
        const r = spend(lock, op, args, ref[op](...args));
        expect(r.ok, `${tier.id} ${op}(${args.join(', ')}) must be accepted: ${r.err}`).toBe(true);
      }

      // The finding, verbatim: bn254FieldAdd(-1, 0) used to return -1.
      for (const expected of [-1n, PM1]) {
        const r = spend(lock, 'add', [-1n, 0n], expected);
        expect(r.ok, `${tier.id} add(-1, 0) == ${expected} must be REJECTED`).toBe(false);
        expect(r.err, `${tier.id} add(-1, 0): the builtin must abort`).toMatch(/OP_VERIFY/);
      }

      for (const op of ['add', 'sub', 'mul', 'inv', 'neg'] as const) {
        const arity = op === 'inv' || op === 'neg' ? 1 : 2;
        for (let pos = 0; pos < arity; pos++) {
          for (const [label, bad] of BAD) {
            const args = arity === 1 ? [bad] : pos === 0 ? [bad, 3n] : [3n, bad];
            // Offer both the reduced residue and, for add / mul, the value the
            // ungated bare OP_MOD returned (sign of the dividend, which is JS
            // bigint `%`); the gate must abort either way.
            const escaped =
              op === 'add' ? (args[0]! + args[1]!) % P : op === 'mul' ? (args[0]! * args[1]!) % P : ref[op](...args);
            for (const expected of [ref[op](...args), escaped]) {
              const r = spend(lock, op, args, expected);
              expect(r.ok, `${tier.id} ${op} with operand ${pos} = ${label} must be REJECTED`).toBe(false);
              expect(r.err, `${tier.id} ${op} operand ${pos} = ${label}: must abort in the gate`).toMatch(/OP_VERIFY/);
            }
          }
        }
      }
    });
  }
});

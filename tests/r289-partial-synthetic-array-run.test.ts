/**
 * R-289 (CL-GAP-081): the FixedArray re-grouper silently emits a partial or
 * broken synthetic-array run as independent scalars — a wrong ABI shape handed
 * to the SDK with no diagnostic.
 *
 * Pass 3b expands `table: FixedArray<bigint, 4>` into four scalar siblings
 * `table__0..table__3`, each carrying a `syntheticArrayChain` marker
 * `{base, index, length}`. For the artifact's ABI and `stateFields`, the
 * re-grouper collapses those siblings back into one array-shaped entry so the
 * SDK can present the array API.
 *
 * It has two silent early-outs. When the innermost marker's `index` is not 0,
 * and when a run declaring length N does not yield N contiguous siblings, the
 * entry is pushed through as a plain scalar and compilation continues:
 *
 *     // Partial or broken run — defensive. A well-formed expansion
 *     // always emits all N siblings contiguously, so this only
 *     // fires on bugs/malformed inputs.
 *
 * "Only on malformed inputs" is true and is not reassuring, because the `--ir`
 * mode accepts ANF IR JSON from whoever hands it over. Editing ONE field — the
 * first sibling's declared `length`, 4 -> 5 — makes every native tier exit 0 and
 * emit an artifact whose `stateFields` reads
 *
 *     table__0, table__1, table__2, table__3     (four independent bigints)
 *
 * where the same contract compiled from source reads
 *
 *     table   FixedArray<bigint, 4>, syntheticNames [table__0 .. table__3]
 *
 * The SDK serialises and deserialises state from `stateFields`, so it builds
 * the wrong layout from an artifact the compiler called valid.
 *
 * SAFE TO REFUSE: both early-outs are unreachable from valid source. All 174
 * in-repo `.runar.ts` contracts were compiled in both fold modes with each path
 * instrumented; neither fired once. So turning them into refusals cannot
 * reject a contract that compiles today.
 *
 * Each tier is driven through ITS OWN `--emit-ir` so no tier is graded against
 * another's IR schema, and the control case runs first so a tier that cannot
 * produce the grouped entry at all fails loudly instead of passing vacuously.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  findGoBinary,
  findRustBinary,
  findPythonBinary,
  findZigBinary,
  findRubyBinary,
  findJavaBinary,
} from '../conformance/runner/runner.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** A stateful contract whose only state is a FixedArray — the grouped entry. */
const SOURCE = `import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

export class ArrayWrite extends StatefulSmartContract {
  table: FixedArray<bigint, 4> = [0n, 0n, 0n, 0n];

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.table[i]++;
    assert(true);
  }
}
`;

function splitCmd(s: string | null): { cmd: string | null; args: string[] } {
  if (s === null) return { cmd: null, args: [] };
  const parts = s.trim().split(/\s+/);
  return { cmd: parts[0] ?? null, args: parts.slice(1) };
}

interface Run {
  code: number | null;
  stdout: string;
  stderr: string;
}

interface Tier {
  id: string;
  binary: string | null;
  cwd: string;
  /** argv that writes the ANF IR for `src`; `null` when the IR goes to stdout. */
  emitIr: (src: string, irPath: string) => { argv: string[]; toStdout: boolean };
  /** argv that compiles `irPath` to an artifact; `null` when it goes to stdout. */
  fromIr: (irPath: string, artPath: string) => { argv: string[]; toStdout: boolean };
}

const TIERS: Tier[] = [
  {
    id: 'go',
    binary: findGoBinary(),
    cwd: join(ROOT, 'compilers/go'),
    emitIr: (src, ir) => ({ argv: ['--source', src, '--emit-ir-to', ir, '--hex'], toStdout: false }),
    fromIr: (ir, art) => ({ argv: ['--ir', ir, '--output', art], toStdout: false }),
  },
  {
    id: 'rust',
    binary: findRustBinary(),
    cwd: join(ROOT, 'compilers/rust'),
    emitIr: (src, ir) => ({ argv: ['--source', src, '--emit-ir-to', ir, '--hex'], toStdout: false }),
    fromIr: (ir, art) => ({ argv: ['--ir', ir, '--output', art], toStdout: false }),
  },
  {
    id: 'python',
    binary: findPythonBinary(),
    cwd: join(ROOT, 'compilers/python'),
    emitIr: (src, ir) => ({ argv: ['--source', src, '--emit-ir-to', ir, '--hex'], toStdout: false }),
    fromIr: (ir, art) => ({ argv: ['--ir', ir, '--output', art], toStdout: false }),
  },
  {
    id: 'ruby',
    binary: findRubyBinary(),
    cwd: join(ROOT, 'compilers/ruby'),
    emitIr: (src, ir) => ({ argv: ['--source', src, '--emit-ir-to', ir, '--hex'], toStdout: false }),
    fromIr: (ir, art) => ({ argv: ['--ir', ir, '--output', art], toStdout: false }),
  },
  {
    id: 'zig',
    binary: findZigBinary(),
    cwd: join(ROOT, 'compilers/zig'),
    emitIr: (src) => ({ argv: ['--source', src, '--emit-ir'], toStdout: true }),
    fromIr: (ir) => ({ argv: ['compile-ir', ir], toStdout: true }),
  },
  {
    // N-086/N-229 gave Java a FixedArray re-grouper (StateFieldRegroup.java),
    // and the shared IR-loader syntheticArrayChain rule (N-096,
    // AnfLoader -> SyntheticArrayChain.check) refuses a malformed run before
    // the regrouper ever sees it — same diagnostic shape as every other tier.
    // Java has no `--output` flag; `--emit-artifact` is its equivalent.
    id: 'java',
    binary: findJavaBinary(),
    cwd: join(ROOT, 'compilers/java'),
    emitIr: (src, ir) => ({ argv: ['--source', src, '--emit-ir-to', ir, '--hex'], toStdout: false }),
    fromIr: (ir, art) => ({ argv: ['--ir', ir, '--emit-artifact', art], toStdout: false }),
  },
];

function run(tier: Tier, argv: string[]): Run {
  const { cmd, args } = splitCmd(tier.binary);
  const res = spawnSync(cmd!, [...args, ...argv], {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: 300_000,
    maxBuffer: 64 * 1024 * 1024,
  });
  return { code: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

/** `stateFields` entry names, or null when no artifact was produced. */
function stateFieldNames(json: string): string[] | null {
  try {
    const a = JSON.parse(json) as { stateFields?: Array<{ name?: string }> };
    return (a.stateFields ?? []).map((f) => f.name ?? '');
  } catch {
    return null;
  }
}

const available = TIERS.filter((t) => t.binary !== null && existsSync(t.cwd));

describe('R-289: a malformed synthetic-array run is refused, not silently ungrouped', () => {
  it('at least two tiers are built (a one-tier run proves nothing)', () => {
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  for (const tier of TIERS) {
    const maybe = available.includes(tier) ? it : it.skip;

    maybe(`${tier.id}: refuses an IR whose array run is short by one`, () => {
      const dir = mkdtempSync(join(tmpdir(), `r289-${tier.id}-`));
      try {
        const src = join(dir, 'ArrayWrite.runar.ts');
        writeFileSync(src, SOURCE);
        const irPath = join(dir, 'program.ir.json');

        // 1. This tier's own IR.
        const emit = tier.emitIr(src, irPath);
        const emitted = run(tier, emit.argv);
        expect(emitted.code, `${tier.id} --emit-ir failed: ${emitted.stderr.slice(0, 400)}`).toBe(0);
        const irText = emit.toStdout ? emitted.stdout : readFileSync(irPath, 'utf-8');
        if (emit.toStdout) writeFileSync(irPath, irText);

        // 2. CONTROL: the well-formed IR must produce the GROUPED entry. A tier
        //    that cannot would make the malformed case meaningless.
        const goodArt = join(dir, 'good.json');
        const good = tier.fromIr(irPath, goodArt);
        const goodRun = run(tier, good.argv);
        expect(goodRun.code, `${tier.id} rejected its own IR: ${goodRun.stderr.slice(0, 400)}`).toBe(0);
        const goodJson = good.toStdout ? goodRun.stdout : readFileSync(goodArt, 'utf-8');
        expect(stateFieldNames(goodJson), `${tier.id} control`).toEqual(['table']);

        // 3. The adversarial edit: ONE field. The first sibling declares a run
        //    of 5 where only 4 siblings exist, so the run is short by one.
        const ir = JSON.parse(irText) as {
          properties: Array<{ name: string; syntheticArrayChain?: Array<{ length: number }> }>;
        };
        const head = ir.properties.find((p) => p.name === 'table__0');
        expect(head?.syntheticArrayChain?.[0], `${tier.id}: no chain marker to corrupt`).toBeDefined();
        head!.syntheticArrayChain![0]!.length = 5;
        const badIr = join(dir, 'program-bad.ir.json');
        writeFileSync(badIr, JSON.stringify(ir, null, 1));

        // 4. The assertion: refuse. Not "exit 0 with four scalars".
        const badArt = join(dir, 'bad.json');
        const bad = tier.fromIr(badIr, badArt);
        const badRun = run(tier, bad.argv);
        const badJson = bad.toStdout
          ? badRun.stdout
          : existsSync(badArt)
            ? readFileSync(badArt, 'utf-8')
            : '';
        const names = stateFieldNames(badJson);

        expect(
          badRun.code === 0 ? `exit 0 with stateFields ${JSON.stringify(names)}` : 'refused',
          `${tier.id} accepted a malformed synthetic-array run and emitted the wrong ABI shape`,
        ).toBe('refused');

        // And it must refuse for THIS reason. Several guards would catch this
        // input, so a bare "it refused" assertion passes with the one it is
        // built for deleted. Pinning the wording keeps that guard under test.
        //
        // N-096: since the shared syntheticArrayChain rule, the IR loader
        // refuses this input before the regrouper sees it — the head declares
        // 5 elements, so the next sibling (length 4) does not continue the
        // expansion. The regrouper's own short-run guard ("declares 5 elements
        // but the contiguous run has 1") is still there, now behind it.
        const said = `${badRun.stderr}\n${badRun.stdout}`;
        expect(
          said,
          `${tier.id} refused, but not with the short-run diagnostic this input is built to trigger`,
        ).toContain(
          "IR validation: malformed syntheticArrayChain on property 'table__1': " +
            "'table' expects its element 'table__1' here (type bigint, level lengths [5])",
        );
        expect(said, `${tier.id} refused without naming the array`).toMatch(/table/);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }, 300_000);
  }

});

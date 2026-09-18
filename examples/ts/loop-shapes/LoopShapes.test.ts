import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, runDifferentialExecution } from 'runar-testing';
import { compile } from 'runar-compiler';

/**
 * R-102 — the loop shape the corpus never had.
 *
 * Two `for` loops existed repo-wide before this example, both zero-start and
 * incrementing, so the ANF `loop` node's `start` field was exercised by
 * nothing. Two wrong-value miscompiles were living behind that gap — Go's
 * constant folder dropping Start and Step (N-128), and Zig's `.runar.go` /
 * `.runar.java` parsers dropping the init value (N-129).
 *
 * Both produced a script that computes a different number than the source says,
 * and both were invisible to a corpus of zero-start loops. The assertions below
 * therefore pin the SUM, and name the two wrong answers so a regression says
 * which bug came back.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'LoopShapes.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

const SUM = 3n + 4n + 5n + 6n; // 18

describe('LoopShapes (a non-zero loop start)', () => {
  it('the loop really does start at 3 and run four times', () => {
    expect(SUM).toBe(18n);
  });

  it('accepts seed + 18', () => {
    const c = TestContract.fromSource(source, { target: SUM }, FILE);
    const r = c.call('verify', { seed: 0n });
    expect(r.success, r.error).toBe(true);
  });

  it('accepts a shifted seed with the matching target', () => {
    const c = TestContract.fromSource(source, { target: 100n + SUM }, FILE);
    expect(c.call('verify', { seed: 100n }).success).toBe(true);
  });

  it('REJECTS 6 — the sum of 0+1+2+3, which is what a dropped start gives', () => {
    const c = TestContract.fromSource(source, { target: 6n }, FILE);
    expect(
      c.call('verify', { seed: 0n }).success,
      'N-128: Go folded the loop as zero-start step-1 and produced exactly this',
    ).toBe(false);
  });

  it('REJECTS 21 — the sum of 0..6, which is what a dropped init gives', () => {
    const c = TestContract.fromSource(source, { target: 21n }, FILE);
    expect(
      c.call('verify', { seed: 0n }).success,
      "N-129: Zig's .runar.go / .runar.java parsers unrolled 0..bound and " +
        'produced exactly this',
    ).toBe(false);
  });

  it('the ANF carries the start, not just the count', () => {
    const r = compile(source, { fileName: FILE });
    expect(r.success, r.diagnostics.map((d) => d.message).join('\n')).toBe(true);
    const loops = r
      .anf!.methods.flatMap((m) => m.body)
      .map((b) => b.value)
      .filter((v): v is Extract<typeof v, { kind: 'loop' }> => v.kind === 'loop');
    expect(loops.length, 'the fixture must still contain a loop').toBe(1);
    expect(loops[0]!.start, 'a start of 0 here means the shape stopped being tested').toBe(3n);
    expect(loops[0]!.count).toBe(4);
  });

  it('the interpreter and the ScriptVM agree', () => {
    const r = runDifferentialExecution({
      source,
      fileName: FILE,
      method: 'verify',
      args: [0n],
      constructorArgs: { target: SUM },
    });
    expect(r.agrees, `interpreter=${r.interpreterAccepted} vm=${r.vmAccepted}`).toBe(true);
  });
});

/**
 * R-102 guard — the docstring's arithmetic must equal what the code computes.
 *
 * The docstring shipped claiming a second, descending loop and a total of
 * `seed + 32`; the contract has always had one ascending loop worth 18. Nobody
 * noticed because no test ever read the prose. These assertions do: they parse
 * the ledger out of the contract's own docstring and check it against the ANF
 * of all nine surface ports and against the interpreter, so the prose cannot
 * drift from the code again without a red test.
 *
 * The parser is deliberately anchored — a ledger row must begin `loop <n> (…):`
 * at the start of a JSDoc line, and the total must be a whole `so …` line — so
 * that a sentence quoting the old wording inside a paragraph is inert. That is
 * asserted below, not assumed.
 */

const PORTS: ReadonlyArray<readonly [string, string]> = [
  ['LoopShapes.runar.ts', 'LoopShapes.runar.ts'],
  ['LoopShapes.runar.sol', '../../sol/loop-shapes/LoopShapes.runar.sol'],
  ['LoopShapes.runar.move', '../../move/loop-shapes/LoopShapes.runar.move'],
  ['LoopShapes.runar.go', '../../go/loop-shapes/LoopShapes.runar.go'],
  ['LoopShapes.runar.rs', '../../rust/loop-shapes/LoopShapes.runar.rs'],
  ['LoopShapes.runar.py', '../../python/loop-shapes/LoopShapes.runar.py'],
  ['LoopShapes.runar.zig', '../../zig/loop-shapes/LoopShapes.runar.zig'],
  ['LoopShapes.runar.rb', '../../ruby/loop-shapes/LoopShapes.runar.rb'],
  [
    'LoopShapes.runar.java',
    '../../java/src/main/java/runar/examples/loop-shapes/LoopShapes.runar.java',
  ],
];

interface LedgerRow {
  readonly label: string;
  readonly terms: bigint[];
  readonly stated: bigint;
}
interface Ledger {
  readonly rows: LedgerRow[];
  readonly total: bigint;
}

/** A ledger row: ` *   loop 1 (i = 3n; i < 7n; i++):  3 + 4 + 5 + 6 = 18` */
const ROW_RE = /^[ \t]*\*[ \t]+loop[ \t]+\d+[ \t]*\(([^)]*)\):[ \t]+(\d+(?:[ \t]*\+[ \t]*\d+)*)[ \t]*=[ \t]*(\d+)[ \t]*$/;
/** The total, as a whole line: ` * so \`verify(seed)\` asserts \`seed + 18\`.` */
const TOTAL_RE = /^[ \t]*\*[ \t]+so[ \t]+`verify\(seed\)`[ \t]+asserts[ \t]+`seed[ \t]*\+[ \t]*(\d+)`\.[ \t]*$/;

function docBlockOf(src: string): string {
  const m = /\/\*\*([\s\S]*?)\*\/\s*export class LoopShapes\b/.exec(src);
  if (!m) throw new Error('no JSDoc block immediately precedes `export class LoopShapes`');
  return m[0]!;
}

function parseLedger(doc: string): Ledger {
  const rows: LedgerRow[] = [];
  const totals: bigint[] = [];
  for (const line of doc.split('\n')) {
    const r = ROW_RE.exec(line);
    if (r) {
      rows.push({
        label: r[1]!.trim(),
        terms: r[2]!.split('+').map((t) => BigInt(t.trim())),
        stated: BigInt(r[3]!),
      });
      continue;
    }
    const t = TOTAL_RE.exec(line);
    if (t) totals.push(BigInt(t[1]!));
  }
  if (totals.length !== 1) {
    throw new Error(`the docstring must state exactly one total; found ${totals.length}`);
  }
  return { rows, total: totals[0]! };
}

function loopsOf(src: string, fileName: string) {
  const r = compile(src, { fileName });
  expect(r.success, `${fileName}: ${r.diagnostics.map((d) => d.message).join('\n')}`).toBe(true);
  return r
    .anf!.methods.flatMap((m) => m.body)
    .map((b) => b.value)
    .filter((v): v is Extract<typeof v, { kind: 'loop' }> => v.kind === 'loop');
}

describe('LoopShapes docstring vs code (R-102 guard)', () => {
  const ledger = parseLedger(docBlockOf(source));

  it('the docstring states a ledger at all', () => {
    expect(ledger.rows.length, 'no `loop N (...): a + b = c` row in the docstring').toBeGreaterThan(
      0,
    );
  });

  it('each documented row adds up to the number it claims', () => {
    for (const row of ledger.rows) {
      const actual = row.terms.reduce((a, b) => a + b, 0n);
      expect(actual, `row "${row.label}": ${row.terms.join(' + ')}`).toBe(row.stated);
    }
  });

  it('the documented rows add up to the documented total', () => {
    const sum = ledger.rows.reduce((a, r) => a + r.stated, 0n);
    expect(sum, 'the ledger rows and the `seed + N` line disagree').toBe(ledger.total);
    expect(ledger.total, 'the total drifted from the sibling SUM constant').toBe(SUM);
  });

  it.each(PORTS)('%s computes exactly the documented ledger', (fileName, relPath) => {
    const portSrc = readFileSync(join(__dirname, relPath), 'utf8');
    const loops = loopsOf(portSrc, fileName);
    expect(loops.length, `${fileName} has ${loops.length} loops, docstring documents ${ledger.rows.length}`).toBe(
      ledger.rows.length,
    );
    loops.forEach((loop, idx) => {
      const row = ledger.rows[idx]!;
      const step = BigInt(loop.step);
      const expected = row.terms.map((_, i) => loop.start + BigInt(i) * step);
      expect(
        expected,
        `${fileName} loop ${idx + 1} runs ${expected.join(', ')}; docstring says ${row.terms.join(', ')}`,
      ).toEqual(row.terms);
      expect(loop.count, `${fileName} loop ${idx + 1} iteration count`).toBe(row.terms.length);
    });
  });

  it('the contract accepts the documented total and nothing else', () => {
    const ok = TestContract.fromSource(source, { target: ledger.total }, FILE);
    expect(ok.call('verify', { seed: 0n }).success, 'documented total rejected').toBe(true);
    for (const off of [-1n, 1n]) {
      const bad = TestContract.fromSource(source, { target: ledger.total + off }, FILE);
      expect(
        bad.call('verify', { seed: 0n }).success,
        `target ${ledger.total + off} accepted; the assert is not pinning the sum`,
      ).toBe(false);
    }
  });

  it('a paragraph quoting the OLD wording does not feed the parser', () => {
    const historical = [
      '/**',
      ' * LoopShapes.',
      ' *',
      ' * An earlier revision of this note invented a second, descending loop:',
      ' * it wrote "countdown: 5 + 4 + 3 + 2 = 14" and concluded that',
      ' * so `verify(seed)` asserts `seed + 32`. The code never had that loop.',
      ' *',
      ' *   loop 1 (i = 3n; i < 7n; i++):  3 + 4 + 5 + 6 = 18',
      ' *',
      ' * so `verify(seed)` asserts `seed + 18`.',
      ' */',
    ].join('\n');
    const parsed = parseLedger(historical);
    expect(parsed.rows.length, 'the historical prose was read as a ledger row').toBe(1);
    expect(parsed.rows[0]!.stated).toBe(18n);
    expect(parsed.total, 'the historical prose was read as the total').toBe(18n);
  });
});

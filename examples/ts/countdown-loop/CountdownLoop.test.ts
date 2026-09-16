import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, runDifferentialExecution } from 'runar-testing';
import { compile } from 'runar-compiler';

/**
 * R-102 — the descending half of the loop shape.
 *
 * `loop-shapes` covers a non-zero START; every loop in the corpus before this
 * one ascended, so `step = -1` shipped in all seven tiers and cross-tier
 * parity was never once measured on it. Three defects were living in that gap:
 *
 *   * the Move `while`-fold matched `i = i + …` only, so a counting-down Move
 *     loop unrolled ZERO times — the body, and every assertion in it, absent
 *     from the locking script, exit 0, no diagnostic;
 *   * the `.runar.zig` surface never set `descending` from its comparison in
 *     the Zig tier, so the same source compiled to a real countdown in six
 *     tiers and to nothing in the seventh;
 *   * `range(a, b, -1)`, `n.downto(m)` and `(a..b).rev()` did not parse, so
 *     three of the nine surfaces could not spell a countdown at all.
 *
 * The assertions below pin the SUM rather than the trip count, and name the
 * wrong answers so a regression says which defect came back.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'CountdownLoop.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

const SUM = 5n + 4n + 3n + 2n; // 14

describe('CountdownLoop (step = -1)', () => {
  it('the loop really does start at 5 and descend four times', () => {
    expect(SUM).toBe(14n);
  });

  it('accepts seed + 14', () => {
    const c = TestContract.fromSource(source, { target: SUM }, FILE);
    const r = c.call('verify', { seed: 0n });
    expect(r.success, r.error).toBe(true);
  });

  it('accepts a shifted seed with the matching target', () => {
    const c = TestContract.fromSource(source, { target: 100n + SUM }, FILE);
    expect(c.call('verify', { seed: 100n }).success).toBe(true);
  });

  it('REJECTS 0 — what a DROPPED LOOP BODY gives', () => {
    const c = TestContract.fromSource(source, { target: 0n }, FILE);
    expect(
      c.call('verify', { seed: 0n }).success,
      'the Move fold and the Zig surface both produced a zero-trip loop, ' +
        'which leaves acc at seed and accepts exactly this',
    ).toBe(false);
  });

  it('REJECTS 6 — the sum of 0+1+2+3, which is what an ASCENDING iterator gives', () => {
    const c = TestContract.fromSource(source, { target: 6n }, FILE);
    expect(
      c.call('verify', { seed: 0n }).success,
      'a step read as +1 from a start of 0 produces exactly this',
    ).toBe(false);
  });

  it('the ANF carries a NEGATIVE step and the real start', () => {
    const r = compile(source, { fileName: FILE });
    expect(r.success, r.diagnostics.map((d) => d.message).join('\n')).toBe(true);
    const loops = r
      .anf!.methods.flatMap((m) => m.body)
      .map((b) => b.value)
      .filter((v): v is Extract<typeof v, { kind: 'loop' }> => v.kind === 'loop');
    expect(loops.length, 'the fixture must still contain a loop').toBe(1);
    expect(loops[0]!.step, 'a step of +1 here means the descending shape stopped being tested').toBe(
      -1,
    );
    expect(loops[0]!.start, 'a start of 0 here means the start was dropped').toBe(5n);
    expect(loops[0]!.count, 'a count of 0 is the dropped-body defect').toBe(4);
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
 * R-102 guard — the docstring's arithmetic must equal what the code computes,
 * on all nine surfaces.
 *
 * Same shape as the `loop-shapes` guard, and here it carries more weight: the
 * nine ports spell the same loop five different ways (`i--`, a Move
 * `while`-fold, `range(5, 1, -1)`, `5.downto(2)`, `(2..6).rev()`), and three of
 * those spellings did not exist before this fixture. Reading the ITERATOR
 * VALUES out of each port's ANF is what says they all mean 5, 4, 3, 2 — a
 * matching trip count would not.
 */

const PORTS: ReadonlyArray<readonly [string, string]> = [
  ['CountdownLoop.runar.ts', 'CountdownLoop.runar.ts'],
  ['CountdownLoop.runar.sol', '../../sol/countdown-loop/CountdownLoop.runar.sol'],
  ['CountdownLoop.runar.move', '../../move/countdown-loop/CountdownLoop.runar.move'],
  ['CountdownLoop.runar.go', '../../go/countdown-loop/CountdownLoop.runar.go'],
  ['CountdownLoop.runar.rs', '../../rust/countdown-loop/CountdownLoop.runar.rs'],
  ['CountdownLoop.runar.py', '../../python/countdown-loop/CountdownLoop.runar.py'],
  ['CountdownLoop.runar.zig', '../../zig/countdown-loop/CountdownLoop.runar.zig'],
  ['CountdownLoop.runar.rb', '../../ruby/countdown-loop/CountdownLoop.runar.rb'],
  [
    'CountdownLoop.runar.java',
    '../../java/src/main/java/runar/examples/countdown-loop/CountdownLoop.runar.java',
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

/** A ledger row: ` *   loop 1 (i = 5n; i > 1n; i--):  5 + 4 + 3 + 2 = 14` */
const ROW_RE =
  /^[ \t]*\*[ \t]+loop[ \t]+\d+[ \t]*\(([^)]*)\):[ \t]+(\d+(?:[ \t]*\+[ \t]*\d+)*)[ \t]*=[ \t]*(\d+)[ \t]*$/;
/** The total, as a whole line: ` * so \`verify(seed)\` asserts \`seed + 14\`.` */
const TOTAL_RE =
  /^[ \t]*\*[ \t]+so[ \t]+`verify\(seed\)`[ \t]+asserts[ \t]+`seed[ \t]*\+[ \t]*(\d+)`\.[ \t]*$/;

function docBlockOf(src: string): string {
  const m = /\/\*\*([\s\S]*?)\*\/\s*export class CountdownLoop\b/.exec(src);
  if (!m) throw new Error('no JSDoc block immediately precedes `export class CountdownLoop`');
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

describe('CountdownLoop docstring vs code (R-102 guard)', () => {
  const ledger = parseLedger(docBlockOf(source));

  it('the docstring states a ledger at all', () => {
    expect(
      ledger.rows.length,
      'no `loop N (...): a + b = c` row in the docstring',
    ).toBeGreaterThan(0);
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

  it('the ledger actually descends (a guard that would pass on an ascending row is no guard)', () => {
    const terms = ledger.rows[0]!.terms;
    expect(terms.length, 'the ledger row must have more than one term to have a direction')
      .toBeGreaterThan(1);
    expect(terms[1]! - terms[0]!, 'the documented iterator ascends; this fixture is the DESCENDING one')
      .toBe(-1n);
  });

  it.each(PORTS)('%s computes exactly the documented ledger', (fileName, relPath) => {
    const portSrc = readFileSync(join(__dirname, relPath), 'utf8');
    const loops = loopsOf(portSrc, fileName);
    expect(
      loops.length,
      `${fileName} has ${loops.length} loops, docstring documents ${ledger.rows.length}`,
    ).toBe(ledger.rows.length);
    loops.forEach((loop, idx) => {
      const row = ledger.rows[idx]!;
      const step = BigInt(loop.step);
      const expected = row.terms.map((_, i) => loop.start + BigInt(i) * step);
      expect(
        expected,
        `${fileName} loop ${idx + 1} runs ${expected.join(', ')}; docstring says ${row.terms.join(', ')}`,
      ).toEqual(row.terms);
      expect(loop.count, `${fileName} loop ${idx + 1} iteration count`).toBe(row.terms.length);
      expect(loop.step, `${fileName} loop ${idx + 1} must descend`).toBe(-1);
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
});

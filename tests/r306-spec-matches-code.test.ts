/**
 * Spec claims that name a checkable property of the compiler must be checked
 * against the compiler.
 *
 * `spec/README.md` says "The specification is authoritative. If a compiler's
 * behavior contradicts the spec, the compiler has a bug." The round-three
 * audit found several places where taking that literally would have been
 * catastrophic, because the spec was the stale half:
 *
 *   - `semantics.md` §8.4/§8.5 and `opcodes.md` §12.2/§12.3 described the EC
 *     ladder as a 256-iteration loop. Every tier runs 257, over `k + 3n`. A
 *     256-iteration ladder over `k + 3n` misses the top set bit and returns a
 *     DIFFERENT multiple of `P` for roughly half of all scalars, silently —
 *     a tier built from §8.4 would have reproduced a fund-loss bug the TS
 *     comment at `ec-codegen.ts` records as already fixed once.
 *   - `stack-ir.md` §3.5 claimed the StackOp union has "exactly 13 variants".
 *     It has 16. One of the three missing ones, `raw_bytes`, carries the
 *     428-byte checkPreimage blob that binds a spend to its transaction and
 *     is present in EVERY stateful contract; a validator derived from the
 *     spec would reject every stateful artifact or drop that binding.
 *   - `opcodes.md` §12.2's script-size column was out by 4x-12x on the
 *     primitives that actually dominate a script.
 *
 * So: read the number out of the document, compute it from the code, compare.
 * Where a claim cannot be computed (prose about intent, roadmap items), it is
 * not in here — see the report for what was left un-mechanised and why.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from '../packages/runar-compiler/src/index.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p: string) => readFileSync(join(repoRoot, p), 'utf8');

// ---------------------------------------------------------------------------
// The EC ladder's iteration count
// ---------------------------------------------------------------------------

/** `for (let bit = N; bit >= 0; bit--)` / `for bit := N; bit >= 0; bit--` → N+1. */
function ladderIterations(file: string, re: RegExp): number {
  const m = read(file).match(re);
  expect(m, `the scalar-multiply ladder loop was not found in ${file}`).not.toBeNull();
  return Number(m![1]) + 1;
}

describe('R-306: the documented EC ladder length matches the emitted one', () => {
  const tsIterations = () =>
    ladderIterations(
      'packages/runar-compiler/src/passes/ec-codegen.ts',
      /\/\/ 257 iterations[\s\S]{0,80}?for \(let bit = (\d+); bit >= 0; bit--\)/,
    );

  it('TypeScript and Go emit the same number of ladder steps', () => {
    const go = ladderIterations(
      'compilers/go/codegen/ec.go',
      /for bit := (\d+); bit >= 0; bit-- \{/,
    );
    expect(tsIterations()).toBe(go);
    // Anti-vacuity: a regex that matched some unrelated loop would not land on
    // 257, which is the whole point of the +3n offset.
    expect(go).toBe(257);
  });

  for (const [file, re] of [
    ['spec/semantics.md', /result = double_and_add\(x, y, k \+ 3n, (\d+) iterations\)/],
    ['spec/semantics.md', /result = double_and_add\(Gx, Gy, k \+ 3n, (\d+) iterations\)/],
    ['spec/semantics.md', /The loop therefore runs \*\*(\d+) iterations\*\*/],
    ['spec/opcodes.md', /\| `ecMul\(p, k\)` \| (\d+)-iteration double-and-add loop/],
    ['spec/opcodes.md', /\| `ecMul\(p, k\)` \| Synthesized \((\d+)-iter double-and-add\)/],
    ['spec/opcodes.md', /\| `ecMulGen\(k\)` \| Synthesized \((\d+)-iter double-and-add\)/],
    ['spec/opcodes.md', /The loop runs \*\*(\d+)\*\*/],
  ] as const) {
    it(`${file} — ${re.source.slice(0, 44)}…`, () => {
      const m = read(file).match(re);
      expect(m, `the ladder-length claim has moved or changed shape in ${file}`).not.toBeNull();
      expect(
        Number(m![1]),
        `${file} documents a ${m![1]}-iteration ladder; the compilers emit ${tsIterations()}`,
      ).toBe(tsIterations());
    });
  }
});

// ---------------------------------------------------------------------------
// opcodes.md §12.2 — approximate script sizes
// ---------------------------------------------------------------------------

/** Compile a one-assert contract and return its locking-script byte length. */
function scriptBytes(imports: string, expr: string): number {
  const src =
    `import { SmartContract, assert, ByteString${imports ? ', ' + imports : ''} } from 'runar-lang';\n` +
    `export class SizeProbe extends SmartContract {\n` +
    `  constructor() { super(); }\n` +
    `  public unlock(p: ByteString, k: bigint, x: bigint, expected: ByteString): void {\n` +
    `    assert(${expr});\n` +
    `  }\n` +
    `}\n`;
  const r = compile(src, { fileName: 'SizeProbe.runar.ts' });
  expect(r.diagnostics, `size probe for ${expr} did not compile`).toEqual([]);
  return r.artifact!.script.length / 2;
}

/** `~24.6 KB` / `~800 B` → bytes. KB is 1000 here, as the table uses it. */
function parseSize(s: string, unit: string): number {
  return Number(s) * (unit === 'KB' ? 1000 : 1);
}

const SIZE_PROBES: Array<[fn: string, imports: string, expr: string]> = [
  ['ecAdd(a, b)', 'ecAdd', 'ecAdd(p, expected) === expected'],
  ['ecMul(p, k)', 'ecMul', 'ecMul(p, k) === expected'],
  ['ecMulGen(k)', 'ecMulGen', 'ecMulGen(k) === expected'],
  ['ecNegate(p)', 'ecNegate', 'ecNegate(p) === expected'],
  ['ecOnCurve(p)', 'ecOnCurve', 'ecOnCurve(p)'],
  ['ecMakePoint(x, y)', 'ecMakePoint', 'ecMakePoint(k, x) === expected'],
  ['ecPointX(p)', 'ecPointX', 'ecPointX(p) === x'],
  ['ecPointY(p)', 'ecPointY', 'ecPointY(p) === x'],
];

describe('R-306: opcodes.md §12.2 script sizes are within an order of the real ones', () => {
  const table = read('spec/opcodes.md');

  // A ±35% band: the column says "Approximate", and the point of the guard is
  // to catch the 4x-12x drift the audit found, not to pin codegen byte-exact.
  const TOLERANCE = 0.35;

  for (const [fn, imports, expr] of SIZE_PROBES) {
    it(`${fn}`, { timeout: 60_000 }, () => {
      const escaped = fn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const m = table.match(
        new RegExp(`\\| \`${escaped}\` \\|[^|]*\\| ~([\\d.]+) (KB|B) \\|`),
      );
      expect(m, `no §12.2 size row found for ${fn}`).not.toBeNull();

      const documented = parseSize(m![1]!, m![2]!);
      const measured = scriptBytes(imports, expr);
      const ratio = documented / measured;
      expect(
        Math.abs(ratio - 1),
        `${fn}: §12.2 says ~${m![1]} ${m![2]} (${documented} B); ` +
          `compiling it measures ${measured} B (${ratio.toFixed(2)}x)`,
      ).toBeLessThan(TOLERANCE);
    });
  }

  it('anti-vacuity: the probes really do produce wildly different sizes', () => {
    // If every probe compiled to the same stub, every row above would agree
    // with whatever the table happened to say.
    const add = scriptBytes('ecAdd', 'ecAdd(p, expected) === expected');
    const pointX = scriptBytes('ecPointX', 'ecPointX(p) === x');
    expect(add).toBeGreaterThan(pointX * 10);
  }, 60_000);
});

// ---------------------------------------------------------------------------
// stack-ir.md §3.5 — the StackOp union
// ---------------------------------------------------------------------------

describe('R-306: stack-ir.md documents every StackOp variant', () => {
  const src = read('packages/runar-compiler/src/ir/stack-ir.ts');
  const spec = read('spec/stack-ir.md');

  /** Members of `export type StackOp = | A | B | ...`. */
  function unionMembers(): string[] {
    const m = src.match(/export type StackOp =\s*([\s\S]*?);/);
    expect(m, 'the StackOp union declaration has moved').not.toBeNull();
    return m![1]!
      .split('|')
      .map((s) => s.trim())
      .filter(Boolean);
  }

  /** The `op` tag each variant interface declares. */
  function opTag(iface: string): string {
    const m = src.match(new RegExp(`interface ${iface} \\{[\\s\\S]*?op: '([a-z_]+)'`));
    expect(m, `interface ${iface} declares no literal op tag`).not.toBeNull();
    return m![1]!;
  }

  it('the stated variant count matches the union', () => {
    const stated = spec.match(/discriminated union with exactly \*\*(\d+) variants\*\*/);
    expect(stated, 'the variant-count sentence has moved or changed shape').not.toBeNull();
    expect(
      Number(stated![1]),
      `stack-ir.md says ${stated![1]} variants; stack-ir.ts declares ${unionMembers().length}`,
    ).toBe(unionMembers().length);
  });

  it('every variant has a row in the §3.5 table', () => {
    const missing = unionMembers().filter((v) => !spec.includes(`\`${v}\``));
    expect(
      missing,
      `stack-ir.md §3.5 omits ${missing.length} StackOp variant(s): ${missing.join(', ')}`,
    ).toEqual([]);
  });

  it("every variant's op tag appears in the spec", () => {
    const missing = unionMembers()
      .map((v) => opTag(v))
      .filter((tag) => !spec.includes(`'${tag}'`));
    expect(
      missing,
      `stack-ir.md names no op tag for: ${missing.join(', ')}`,
    ).toEqual([]);
  });

  it('anti-vacuity: the union parsed into a plausible set', () => {
    const members = unionMembers();
    expect(members.length).toBeGreaterThan(10);
    expect(members).toContain('PushOp');
    expect(members.every((m) => /^[A-Z]\w+Op$/.test(m))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// The `loop` node: iteration variable, and the on-the-wire field set
// ---------------------------------------------------------------------------

describe('R-306: the documented for-loop iteration variable is the emitted one', () => {
  /** Compile a loop that accumulates `i` and return the folded constant. */
  function unrolledOps(header: string, body: string): string {
    const src =
      `import { SmartContract, assert } from 'runar-lang';\n` +
      `export class LoopProbe extends SmartContract {\n` +
      `  constructor() { super(); }\n` +
      `  public unlock(x: bigint): void {\n` +
      `    let acc: bigint = 0n;\n` +
      `    ${header} { ${body} }\n` +
      `    assert(acc === x);\n` +
      `  }\n` +
      `}\n`;
    const r = compile(src, { fileName: 'LoopProbe.runar.ts' });
    expect(r.diagnostics, 'loop probe did not compile').toEqual([]);
    return r.artifact!.asm;
  }

  /** The `i` of each unrolled `OP_<i> OP_10` pair, in emission order. */
  function iterationValues(asm: string): string[] {
    return [...asm.matchAll(/OP_(\d+) OP_10\b/g)].map((x) => x[1]!);
  }

  it('semantics.md §4.4 counting-up example emits the values it documents', () => {
    // "for (let i = 3n; i < 6n; i++) ... the emitted script pushes OP_3 OP_4 OP_5"
    const doc = read('spec/semantics.md');
    const m = doc.match(
      /`for \(let i = 3n; i < 6n; i\+\+\)`[^.]*?`i` bound to `(\d+)`, `(\d+)`, `(\d+)`/,
    );
    expect(m, 'the counting-up example has moved or changed shape').not.toBeNull();

    // `acc = acc * 10n + i` makes the ORDER observable, not just the sum: each
    // unrolled copy emits `OP_<i> OP_10`, so the digit before each OP_10 is
    // that iteration's value.
    const asm = unrolledOps('for (let i = 3n; i < 6n; i++)', 'acc = acc * 10n + i;');
    expect(iterationValues(asm), `emitted ${asm}`).toEqual([m![1], m![2], m![3]]);
  }, 30_000);

  it('semantics.md §4.4 counting-down example emits the values it documents', () => {
    const doc = read('spec/semantics.md');
    const m = doc.match(
      /`for \(let i = 5n; i > 2n; i--\)`[^.]*?`i` bound to `(\d+)`, `(\d+)`, `(\d+)`/,
    );
    expect(m, 'the counting-down example has moved or changed shape').not.toBeNull();

    const asm = unrolledOps('for (let i = 5n; i > 2n; i--)', 'acc = acc * 10n + i;');
    expect(iterationValues(asm), `emitted ${asm}`).toEqual([m![1], m![2], m![3]]);
  }, 30_000);

  it('anti-vacuity: the two loops emit DIFFERENT sequences', () => {
    // A probe that folded both to the same constant would let one regex
    // satisfy both assertions.
    const up = unrolledOps('for (let i = 3n; i < 6n; i++)', 'acc = acc * 10n + i;');
    const down = unrolledOps('for (let i = 5n; i > 2n; i--)', 'acc = acc * 10n + i;');
    expect(up).not.toBe(down);
  }, 30_000);

  it('ir-format.md §4.9 documents every field of the Loop node', () => {
    const anf = read('packages/runar-compiler/src/ir/anf-ir.ts');
    const m = anf.match(/export interface Loop \{([\s\S]*?)\n\}/);
    expect(m, 'the Loop interface has moved').not.toBeNull();
    const fields = [...m![1]!.matchAll(/^\s{2}(\w+)[?]?:/gm)].map((x) => x[1]!);
    expect(fields, 'anti-vacuity: no Loop fields parsed').toContain('iterVar');
    expect(fields.length).toBeGreaterThan(4);

    const section = read('spec/ir-format.md').match(/### 4\.9 `loop`([\s\S]*?)### 4\.10/);
    expect(section, 'ir-format.md §4.9 has moved').not.toBeNull();
    // Only the field TABLE counts. Prose that merely mentions `start` — the
    // paragraph explaining why omitting it is dangerous, say — must not be
    // able to satisfy this: the first version of this check accepted it and
    // stayed green when the table rows were deleted.
    const rows = new Set(
      [...section![1]!.matchAll(/^\| `(\w+)` \|/gm)].map((x) => x[1]!),
    );
    expect(rows.size, 'anti-vacuity: no §4.9 table rows parsed').toBeGreaterThan(3);
    const missing = fields.filter((f) => !rows.has(f));
    expect(
      missing,
      `ir-format.md §4.9 omits loop field(s) ${missing.join(', ')} — and the Go and Rust ` +
        'loaders DEFAULT a missing start/step, so an IR built from the spec loads clean ' +
        'and unrolls wrong',
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// frontend-spec.md — PrimitiveTypeName and the AST node kinds
// ---------------------------------------------------------------------------

describe('R-306: frontend-spec.md lists every primitive type and AST node kind', () => {
  const ast = read('packages/runar-compiler/src/ir/runar-ast.ts');
  const spec = read('spec/frontend-spec.md');

  it('every PrimitiveTypeName is documented', () => {
    const m = ast.match(/export type PrimitiveTypeName =\s*([\s\S]*?);/);
    expect(m, 'the PrimitiveTypeName union has moved').not.toBeNull();
    const names = m![1]!
      .split('|')
      .map((s) => s.trim().replace(/^'|'$/g, ''))
      .filter(Boolean);
    expect(names.length, 'anti-vacuity: no primitive names parsed').toBeGreaterThan(10);

    const missing = names.filter((n) => !spec.includes(`"${n}"`));
    expect(
      missing,
      `frontend-spec.md's PrimitiveTypeName list omits: ${missing.join(', ')}`,
    ).toEqual([]);
  });

  it('every AST node `kind` is documented', () => {
    const kinds = [...ast.matchAll(/^\s{2}kind: '([a-z_]+)';/gm)].map((m) => m[1]!);
    expect(new Set(kinds).size, 'anti-vacuity: no AST kinds parsed').toBeGreaterThan(20);

    const missing = [...new Set(kinds)].filter((k) => !spec.includes(`kind: "${k}"`));
    expect(
      missing,
      `frontend-spec.md documents no node shape for AST kind(s): ${missing.join(', ')}`,
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// spec/README.md — the document index
// ---------------------------------------------------------------------------

describe('R-306: spec/README.md indexes every document in spec/', () => {
  it('no spec file is missing from the index table', () => {
    const files = readdirSync(join(repoRoot, 'spec')).filter(
      (f) => f !== 'README.md' && (f.endsWith('.md') || f.endsWith('.json')),
    );
    expect(files.length, 'anti-vacuity: spec/ is empty').toBeGreaterThan(5);
    const index = read('spec/README.md');
    const missing = files.filter((f) => !index.includes(f));
    expect(
      missing,
      `spec/README.md's Document Index omits: ${missing.join(', ')}`,
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Spec version headers
// ---------------------------------------------------------------------------

describe('R-306: spec documents carry the shipped version', () => {
  it('every **Version:** header matches package.json', () => {
    const version = (JSON.parse(read('package.json')) as { version: string }).version;
    const files = readdirSync(join(repoRoot, 'spec')).filter((f) => f.endsWith('.md'));
    const stale: string[] = [];
    for (const f of files) {
      const m = read(`spec/${f}`).match(/^\*\*Version:\*\* (.+)$/m);
      if (m && m[1]!.trim() !== version) stale.push(`${f} (${m[1]!.trim()})`);
    }
    expect(
      stale,
      `spec docs still headed with an old version while the product ships ${version}: ${stale.join(', ')}`,
    ).toEqual([]);
  });

  it('anti-vacuity: the headers exist at all', () => {
    const files = readdirSync(join(repoRoot, 'spec')).filter((f) => f.endsWith('.md'));
    const withHeader = files.filter((f) => /^\*\*Version:\*\* /m.test(read(`spec/${f}`)));
    expect(withHeader.length).toBeGreaterThan(5);
  });
});

// ---------------------------------------------------------------------------
// docs/getting-started.md — toolchain floors
// ---------------------------------------------------------------------------

describe('R-306: getting-started.md prerequisites are satisfiable by CI', () => {
  const guide = read('docs/getting-started.md');

  it('the Python floor is not above what the package declares or CI runs', () => {
    // A floor higher than CI's own interpreter can never be caught by CI: the
    // guide demanded 3.13 while pyproject declares >=3.10 and every workflow
    // pins 3.11 or 3.12.
    const row = guide.match(/\| \*\*Python\*\* \| ([\d.]+)\+/);
    expect(row, 'the Python prerequisite row has moved').not.toBeNull();
    const declared = read('packages/runar-py/pyproject.toml').match(
      /requires-python\s*=\s*">=([\d.]+)"/,
    );
    expect(declared, 'requires-python not found in runar-py/pyproject.toml').not.toBeNull();

    const asTuple = (s: string) => s.split('.').map(Number);
    const [gMaj, gMin] = asTuple(row![1]!);
    const [dMaj, dMin] = asTuple(declared![1]!);
    expect(
      gMaj! * 100 + gMin!,
      `getting-started requires Python ${row![1]}+ but runar-py declares >=${declared![1]}`,
    ).toBeLessThanOrEqual(dMaj! * 100 + dMin!);
  });

  it('the Zig floor matches the version CI pins', () => {
    const pinned = new Set<string>();
    const wf = join(repoRoot, '.github', 'workflows');
    for (const f of readdirSync(wf).filter((x) => x.endsWith('.yml'))) {
      const text = readFileSync(join(wf, f), 'utf8');
      // `uses: mlugg/setup-zig` blocks carry `version: 0.16.0`.
      if (!/setup-zig/.test(text)) continue;
      for (const m of text.matchAll(/version:\s*'?(\d+\.\d+\.\d+)'?/g)) pinned.add(m[1]!);
    }
    expect(pinned.size, 'anti-vacuity: no Zig version pin found in any workflow').toBeGreaterThan(0);

    const row = guide.match(/\| \*\*Zig\*\* \| ([\d.]+(?:\.x)?)/);
    expect(row, 'the Zig prerequisite row has moved').not.toBeNull();
    const minor = (v: string) => v.split('.').slice(0, 2).join('.');
    const documented = minor(row![1]!);
    const ciMinors = [...pinned].map(minor);
    expect(
      ciMinors,
      `getting-started requires Zig ${row![1]} but CI pins ${[...pinned].join(', ')} — ` +
        'compilers/zig does not build on the documented toolchain',
    ).toContain(documented);
  });
});

// ---------------------------------------------------------------------------
// artifact-format.md — every field the assembler writes
// ---------------------------------------------------------------------------

describe('R-306: artifact-format.md documents every RunarArtifact field', () => {
  it('no field of the assembler’s RunarArtifact is undocumented', () => {
    const src = read('packages/runar-compiler/src/artifact/assembler.ts');
    const m = src.match(/export interface RunarArtifact \{([\s\S]*?)\n\}/);
    expect(m, 'the RunarArtifact interface has moved').not.toBeNull();
    const fields = [...m![1]!.matchAll(/^\s{2}(\w+)\??:/gm)].map((x) => x[1]!);
    expect(fields.length, 'anti-vacuity: no artifact fields parsed').toBeGreaterThan(12);
    expect(fields).toContain('anf');

    const spec = read('spec/artifact-format.md');
    // A field is documented if it has its own `### 3.x \`field\`` heading.
    const documented = new Set(
      [...spec.matchAll(/^### 3\.\d+ `(\w+)`(?: \/ `(\w+)`)?/gm)].flatMap((x) =>
        [x[1]!, x[2]].filter(Boolean) as string[],
      ),
    );
    const missing = fields.filter((f) => !documented.has(f));
    expect(
      missing,
      `artifact-format.md §3 has no section for: ${missing.join(', ')}`,
    ).toEqual([]);
  });

  it('the version example matches ARTIFACT_VERSION', () => {
    const stamped = read('packages/runar-compiler/src/artifact/assembler.ts').match(
      /const ARTIFACT_VERSION = '([^']+)'/,
    );
    expect(stamped, 'ARTIFACT_VERSION has moved').not.toBeNull();
    expect(
      read('spec/artifact-format.md'),
      `artifact-format.md §3.1 does not show the stamped version ${stamped![1]}`,
    ).toContain(`\`"${stamped![1]}"\``);
  });

  it('the unimplemented version check is labelled as unimplemented', () => {
    // No tier reads `version`. The spec states a SHOULD; what it must not do
    // is let a reader assume the check exists.
    const spec = read('spec/artifact-format.md');
    expect(spec).toMatch(/\*\*(Not enforced by any tier|Unimplemented)\.?\*\*/);
    expect(spec).not.toMatch(/The SDK MUST reject artifacts with a/);
  });
});

// ---------------------------------------------------------------------------
// The opcodes Rúnar really emits
// ---------------------------------------------------------------------------

describe('R-306: opcodes.md matches what the emitter emits', () => {
  it('OP_CODESEPARATOR is not listed as unused, and the 0x61ab prologue is documented', () => {
    const spec = read('spec/opcodes.md');
    expect(
      spec,
      'opcodes.md §10 still lists OP_CODESEPARATOR as unused; every stateful contract emits one',
    ).not.toMatch(/\| `0xab` \| `OP_CODESEPARATOR` \| Not used by Rúnar \|/);
    expect(spec).not.toMatch(/Rúnar does not generate NOP opcodes/);
    expect(spec).toContain('`0x61 0xab`');
  });

  it('stateful conformance goldens really do start 61ab', () => {
    const dir = join(repoRoot, 'conformance', 'tests');
    const prefixes = readdirSync(dir)
      .map((d) => join(dir, d, 'expected-script.hex'))
      .filter((p) => existsSync(p))
      .map((p) => readFileSync(p, 'utf8').slice(0, 4));
    const withPrologue = prefixes.filter((p) => p === '61ab').length;
    expect(withPrologue, 'no golden carries the OP_NOP/OP_CODESEPARATOR prologue').toBeGreaterThan(
      10,
    );
  });

  it('the Chronicle-policy opcode counts §13.1 cites are the emitted ones', () => {
    const spec = read('spec/opcodes.md');
    const src =
      `import { SmartContract, assert, ByteString, ecMul } from 'runar-lang';\n` +
      `export class ChronicleProbe extends SmartContract {\n` +
      `  constructor() { super(); }\n` +
      `  public unlock(p: ByteString, k: bigint, expected: ByteString): void {\n` +
      `    assert(ecMul(p, k) === expected);\n` +
      `  }\n` +
      `}\n`;
    const r = compile(src, { fileName: 'ChronicleProbe.runar.ts' });
    expect(r.diagnostics).toEqual([]);
    const count = (op: string) =>
      (r.artifact!.asm.match(new RegExp(`\\b${op}\\b`, 'g')) ?? []).length;

    for (const [op, re] of [
      ['OP_2MUL', /`OP_2MUL` \| `0x8d` \| disabled \| `ecMul` \((\d+) occurrences/],
      ['OP_RSHIFTNUM', /`OP_RSHIFTNUM` \| `0xb7` \| `OP_NOP8` \| `ecMul` \((\d+) occurrences/],
    ] as const) {
      const m = spec.match(re);
      expect(m, `the §13.1 row for ${op} has moved or changed shape`).not.toBeNull();
      expect(
        Number(m![1]),
        `§13.1 says ecMul emits ${m![1]} ${op}; it emits ${count(op)}`,
      ).toBe(count(op));
      expect(count(op), `anti-vacuity: ${op} never appears`).toBeGreaterThan(0);
    }
  }, 60_000);
});

// ---------------------------------------------------------------------------
// type-system.md — the operator rules the checker enforces
// ---------------------------------------------------------------------------

describe('R-306: type-system.md §4 operator rules match the type checker', () => {
  /** Diagnostics from a one-expression contract. */
  function check(expr: string, params = 'a: bigint, b: bigint, s: ByteString, t: ByteString') {
    const src =
      `import { SmartContract, assert, ByteString } from 'runar-lang';\n` +
      `export class OpProbe extends SmartContract {\n` +
      `  constructor() { super(); }\n` +
      `  public unlock(${params}): void {\n` +
      `    assert(${expr});\n` +
      `  }\n` +
      `}\n`;
    return compile(src, { fileName: 'OpProbe.runar.ts' }).diagnostics;
  }

  it('relational operators reject ByteString, as §6.3 says and §4 now says too', () => {
    expect(check('a < b'), 'bigint < bigint must be accepted').toEqual([]);
    const bad = check('s < t');
    expect(bad.length, 'ByteString < ByteString must be a compile-time error').toBeGreaterThan(0);

    // The §4 inference rule must not still admit `T x T`.
    const spec = read('spec/type-system.md');
    expect(spec).not.toMatch(/op ∈ \{==, ===, !=, !==, <, <=, >, >=\}/);
    expect(spec).toMatch(/e1 : bigint\s+e2 : bigint\s+op ∈ \{<, <=, >, >=\}/);
  }, 30_000);

  it('shift and bitwise operators have rules, and they match the checker', () => {
    const spec = read('spec/type-system.md');
    expect(spec, 'no typing rule for << >>').toMatch(/op ∈ \{<<, >>\}/);
    expect(spec, 'no typing rule for & | ^').toMatch(/op ∈ \{&, \|, \^\}/);
    expect(spec, 'no typing rule for ~').toMatch(/~e : ByteString/);

    // Shifts are bigint-only; bitwise admits both bigint and ByteString.
    expect(check('(a << b) === a')).toEqual([]);
    expect(check('(s << t) === s').length, '<< over ByteString must be rejected').toBeGreaterThan(0);
    expect(check('(a & b) === a')).toEqual([]);
    expect(check('(s & t) === s'), '& over ByteString must be accepted').toEqual([]);
  }, 30_000);
});

// ---------------------------------------------------------------------------
// semantics.md §9.3 — there is no script-size diagnostic
// ---------------------------------------------------------------------------

describe('R-306: semantics.md §9.3 does not promise a size warning that does not exist', () => {
  it('a several-hundred-KB script compiles with zero diagnostics', () => {
    const src =
      `import { SmartContract, assert, ByteString, ecMul } from 'runar-lang';\n` +
      `export class BigScript extends SmartContract {\n` +
      `  constructor() { super(); }\n` +
      `  public unlock(p: ByteString, k: bigint, expected: ByteString): void {\n` +
      `    assert(ecMul(p, k) === expected);\n` +
      `  }\n` +
      `}\n`;
    const r = compile(src, { fileName: 'BigScript.runar.ts' });
    const bytes = r.artifact!.script.length / 2;
    expect(bytes, 'anti-vacuity: the probe is not actually a big script').toBeGreaterThan(100_000);
    expect(
      r.diagnostics,
      `a ${bytes}-byte script produced diagnostics, so a size check may now exist — ` +
        'if so, document it in §9.3 rather than deleting this test',
    ).toEqual([]);

    expect(
      read('spec/semantics.md'),
      '§9.3 promises a size warning again; no such check exists',
    ).not.toMatch(/compiler will warn if the generated script exceeds/);
  }, 60_000);

  it('the stack-depth limit §9.3 DOES claim is really enforced', () => {
    // The other half of the same sentence is true, and the guard should say so
    // rather than implying the whole paragraph was fiction.
    const stated = read('spec/semantics.md').match(/\*\*Stack depth\*\*: Maximum (\d+) items/);
    expect(stated, 'the stack-depth claim has moved').not.toBeNull();
    const enforced = read('packages/runar-compiler/src/passes/05-stack-lower.ts').match(
      /const MAX_STACK_DEPTH = (\d+);/,
    );
    expect(enforced, 'MAX_STACK_DEPTH has moved').not.toBeNull();
    expect(Number(stated![1])).toBe(Number(enforced![1]));
  });
});

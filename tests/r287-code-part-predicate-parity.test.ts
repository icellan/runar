/**
 * R-287 (CL-GAP-077) — the seven `methodUsesCodePart` implementations must
 * recognise the same `_codePart` triggers.
 *
 * `_codePart` is an implicit unlocking-script parameter. Whether a method
 * carries it changes the witness layout and therefore the emitted script, so
 * a tier that answers this question differently breaks invariant 2
 * (byte-identical Stack IR + hex) on any ANF program that reaches the
 * disagreement.
 *
 * The drift that motivated this guard: TypeScript and Rust omitted
 * `add_data_output` while the other five listed it. Compiling one ANF program
 * whose sole trigger was `add_data_output` produced three different scripts
 * across the seven tiers. It stayed invisible from source only because
 * `continuationShape` couples `hasDataOutput` to a continuation, so every
 * source-derived `add_data_output` happens to sit beside a
 * `computeStateOutput` call that trips a different clause. The `--ir` front
 * door has no such coupling.
 *
 * This guard reads the seven function bodies, not their prose: comments are
 * stripped before the trigger names are extracted, so an explanatory sentence
 * naming a kind cannot satisfy (or trip) the assertion.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** ANF binding kinds that may trigger `_codePart`, in canonical snake_case. */
const CANDIDATE_KINDS = ['add_output', 'add_raw_output', 'add_data_output'] as const;

/** ANF `call` funcs that may trigger `_codePart`. */
const CANDIDATE_FUNCS = [
  'computeStateOutput',
  'computeStateOutputHash',
  'buildChangeOutput',
  'buildStateOutput',
] as const;

interface TierSpec {
  tier: string;
  file: string;
  /** A substring unique to the function's declaration line. */
  declaration: string;
  /** Comment syntax to strip before extracting names. */
  lineComment: string;
  /**
   * How the tier spells each canonical kind. Java models ANF values as
   * classes, so its bodies say `AddDataOutput`, not `add_data_output`.
   */
  spell?: (kind: string) => string;
}

const TIERS: TierSpec[] = [
  {
    tier: 'typescript',
    file: 'packages/runar-compiler/src/passes/05-stack-lower.ts',
    declaration: 'function methodUsesCodePart(',
    lineComment: '//',
  },
  {
    tier: 'go',
    file: 'compilers/go/codegen/stack.go',
    declaration: 'func methodUsesCodePart(',
    lineComment: '//',
  },
  {
    tier: 'rust',
    file: 'compilers/rust/src/codegen/stack.rs',
    declaration: 'fn method_uses_code_part(',
    lineComment: '//',
    spell: kind => kind.split('_').map(p => p[0]!.toUpperCase() + p.slice(1)).join(''),
  },
  {
    tier: 'python',
    file: 'compilers/python/runar_compiler/codegen/stack.py',
    declaration: 'def _method_uses_code_part(',
    lineComment: '#',
  },
  {
    tier: 'zig',
    file: 'compilers/zig/src/passes/stack_lower.zig',
    declaration: 'fn methodUsesCodePart(',
    lineComment: '//',
  },
  {
    tier: 'ruby',
    file: 'compilers/ruby/lib/runar_compiler/codegen/stack.rb',
    declaration: 'def self.method_uses_code_part?(',
    lineComment: '#',
  },
  {
    tier: 'java',
    file: 'compilers/java/src/main/java/runar/compiler/passes/StackLower.java',
    declaration: 'boolean methodUsesCodePart(',
    lineComment: '//',
    spell: kind => kind.split('_').map(p => p[0]!.toUpperCase() + p.slice(1)).join(''),
  },
];

/**
 * The function body, comments removed.
 *
 * Bodies are delimited by brace/indent structure that differs per language, so
 * rather than parse seven grammars this walks forward from the declaration
 * until the nesting introduced by the declaration line closes — and for the
 * two indentation-delimited tiers (Python, Ruby), until the `def`'s own
 * `return`/`end` terminator. Every tier's function is small and self-contained,
 * which is what makes the crude walk sufficient.
 */
function functionBody(spec: TierSpec): string {
  const source = readFileSync(resolve(repoRoot, spec.file), 'utf8');
  const lines = source.split('\n');
  const start = lines.findIndex(l => l.includes(spec.declaration));
  expect(start, `${spec.tier}: '${spec.declaration}' not found in ${spec.file}`).toBeGreaterThan(-1);

  const stripped: string[] = [];
  const isBraceDelimited = spec.lineComment === '//';
  let depth = 0;
  let opened = false;

  for (let i = start; i < lines.length; i++) {
    const raw = lines[i]!;
    // Strip the comment tail. The trigger names never appear inside a string
    // that also carries a comment marker, so a plain index scan is enough.
    const commentAt = raw.indexOf(spec.lineComment);
    const code = commentAt === -1 ? raw : raw.slice(0, commentAt);
    stripped.push(code);

    if (isBraceDelimited) {
      for (const ch of code) {
        if (ch === '{') { depth++; opened = true; }
        else if (ch === '}') depth--;
      }
      if (opened && depth === 0) break;
    } else if (i > start && /^(end|def |class |\S)/.test(code) && code.trim().length > 0
               && !/^\s/.test(code)) {
      // Left the indented block (Python) — include nothing further.
      break;
    } else if (i > start && /^\s{2}end\s*$/.test(code)) {
      // Ruby's `def self.…` closes at two-space `end`.
      stripped.push('');
      break;
    }
  }

  return stripped.join('\n');
}

function triggersOf(spec: TierSpec): { kinds: string[]; funcs: string[] } {
  const body = functionBody(spec);
  const spell = spec.spell ?? ((k: string) => k);
  return {
    kinds: CANDIDATE_KINDS.filter(k => body.includes(spell(k))),
    funcs: CANDIDATE_FUNCS.filter(f => body.includes(f)),
  };
}

describe('R-287: _codePart trigger set is identical across all seven tiers', () => {
  const observed = TIERS.map(spec => ({ tier: spec.tier, ...triggersOf(spec) }));

  it('each tier recognises at least add_output (anti-vacuity)', () => {
    // Without this, a body-extraction bug that returned an empty string for
    // every tier would make the parity assertion below trivially green.
    for (const row of observed) {
      expect(row.kinds, `${row.tier} extracted no trigger kinds — body extraction is broken`)
        .toContain('add_output');
    }
  });

  it('every tier agrees on the ANF kinds that trigger _codePart', () => {
    const byTier = Object.fromEntries(observed.map(r => [r.tier, r.kinds.join(',')]));
    const distinct = new Set(Object.values(byTier));
    expect(distinct.size, `tiers disagree: ${JSON.stringify(byTier, null, 2)}`).toBe(1);
  });

  it('every tier agrees on the ANF call funcs that trigger _codePart', () => {
    const byTier = Object.fromEntries(observed.map(r => [r.tier, r.funcs.join(',')]));
    const distinct = new Set(Object.values(byTier));
    expect(distinct.size, `tiers disagree: ${JSON.stringify(byTier, null, 2)}`).toBe(1);
  });
});

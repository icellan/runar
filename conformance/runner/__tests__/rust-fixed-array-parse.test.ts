import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { runParseOnly, type CompilerId, type ParseOnlyResult } from '../runner.js';

// ---------------------------------------------------------------------------
// Frontend parity for the `.runar.rs` fixed-array type `[T; N]`
// ---------------------------------------------------------------------------
//
// CLAUDE.md states the project's first invariant as "Frontend parity (no
// exceptions). All seven compilers parse all nine `.runar.{...}` extensions."
// The gate that enforces it — the `--parser-only` matrix in runner.ts — only
// walks `conformance/tests/*`. A surface form that appears in a checked-in
// EXAMPLE but in no fixture is therefore ungated.
//
// `[T; N]` was exactly that: `examples/rust/fixed-array-nested/Grid2x2.v2.runar.rs`
// has been in the tree with `pub grid: [[Bigint; 2]; 2]`, and four of the seven
// tiers (go, python, zig, java) rejected it at the inner `;` — a parse error, not
// a divergence, so nothing downstream ever noticed.
//
// These tests point the SAME nine parse-only drivers at that example plus two
// synthetic sources. The negative control matters as much as the positive ones:
// without it, "make the four parsers accept `[T; N]`" could be satisfied by
// making them accept anything.

const REPO_ROOT = resolve(__dirname, '../../..');

/** ts, go, rust, python, zig, ruby, java — every tier, no allowlist. */
const ALL_TIERS: CompilerId[] = ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'];

/** The checked-in example that proves the gap is pre-existing. */
const NESTED_EXAMPLE = resolve(REPO_ROOT, 'examples/rust/fixed-array-nested/Grid2x2.v2.runar.rs');

/** Minimal single-level `[T; N]` property — the simplest form of the bug. */
const SINGLE_LEVEL_SOURCE = `use runar::prelude::*;

#[runar::contract]
pub struct Row3 {
    pub cells: [Bigint; 3],
    pub tx_preimage: SigHashPreimage,
}

impl Row3 {
    pub fn init(&mut self) {
        self.cells = [0, 0, 0];
    }

    pub fn set0(&mut self, v: Bigint) {
        self.cells[0] = v;
        assert!(true);
    }
}
`;

/**
 * CONTROL (positive): a `.runar.rs` contract with no fixed array anywhere. It
 * parsed in all seven tiers before the fix and must still parse after it —
 * this is the "the fix did not break the ordinary path" half.
 */
const CONTROL_SOURCE = `use runar::prelude::*;

#[runar::contract]
pub struct CounterControl {
    pub count: Bigint,
    pub tx_preimage: SigHashPreimage,
}

impl CounterControl {
    pub fn increment(&mut self) {
        self.count = self.count + 1;
        assert!(true);
    }
}
`;

/**
 * CONTROL (negative): `[Bigint 3]` — a bracketed type with the `;` separator
 * missing. No tier may accept it. This is the half that makes the positive
 * assertions mean something: a parser that swallowed every bracketed token run
 * would pass the two above and fail here.
 */
const MALFORMED_SOURCE = `use runar::prelude::*;

#[runar::contract]
pub struct BrokenArr {
    pub cells: [Bigint 3],
    pub tx_preimage: SigHashPreimage,
}

impl BrokenArr {
    pub fn set0(&mut self, v: Bigint) {
        self.cells[0] = v;
        assert!(true);
    }
}
`;

async function parseAcrossTiers(source: string, sourceFile: string) {
  const results = await Promise.all(
    ALL_TIERS.map((c) => runParseOnly(c, { source, sourceFile })),
  );
  return results.filter((r): r is ParseOnlyResult => r !== undefined);
}

/** Compact `tier: ok|error` table, so a failure names the tier and the reason. */
function table(results: ParseOnlyResult[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of results) {
    out[r.compiler] = r.success
      ? 'ok'
      : (r.error ?? 'unknown').split('\n').filter(Boolean).slice(0, 2).join(' | ').slice(0, 300);
  }
  return out;
}

function expectedOk(): Record<string, string> {
  return Object.fromEntries(ALL_TIERS.map((c) => [c, 'ok']));
}

const TIER_TIMEOUT_MS = 600_000;

describe('.runar.rs fixed-array type `[T; N]` — seven-tier frontend parity', () => {
  it('every available tier parses the checked-in nested example Grid2x2.v2.runar.rs', async () => {
    const source = readFileSync(NESTED_EXAMPLE, 'utf-8');
    // Guard the premise: if the example stops declaring `[[T; N]; M]` this test
    // silently stops testing anything.
    expect(source).toContain('[[Bigint; 2]; 2]');

    const results = await parseAcrossTiers(source, NESTED_EXAMPLE);
    // All seven binaries are expected to be present in this repo's dev/CI setup;
    // a missing one would silently shrink the matrix.
    expect(results.map((r) => r.compiler).sort()).toEqual([...ALL_TIERS].sort());
    expect(table(results)).toEqual(expectedOk());
  }, TIER_TIMEOUT_MS);

  it('every available tier parses a minimal single-level `[T; N]` property', async () => {
    const results = await parseAcrossTiers(SINGLE_LEVEL_SOURCE, resolve(REPO_ROOT, 'Row3.runar.rs'));
    expect(results.map((r) => r.compiler).sort()).toEqual([...ALL_TIERS].sort());
    expect(table(results)).toEqual(expectedOk());
  }, TIER_TIMEOUT_MS);

  it('CONTROL: a `.runar.rs` source with no fixed array still parses in every tier', async () => {
    const results = await parseAcrossTiers(CONTROL_SOURCE, resolve(REPO_ROOT, 'CounterControl.runar.rs'));
    expect(results.map((r) => r.compiler).sort()).toEqual([...ALL_TIERS].sort());
    expect(table(results)).toEqual(expectedOk());
  }, TIER_TIMEOUT_MS);

  it('CONTROL: `[Bigint 3]` (missing `;`) is rejected by every tier', async () => {
    const results = await parseAcrossTiers(MALFORMED_SOURCE, resolve(REPO_ROOT, 'BrokenArr.runar.rs'));
    expect(results.map((r) => r.compiler).sort()).toEqual([...ALL_TIERS].sort());
    const accepted = results.filter((r) => r.success).map((r) => r.compiler);
    expect(accepted).toEqual([]);
  }, TIER_TIMEOUT_MS);
});

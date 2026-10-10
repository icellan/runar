import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, compileHex } from './tier-harness.js';

/**
 * F-206 — `.runar.rb` property-declaration edge cases, seven-tier parity.
 *
 * Probing all seven `.runar.rb` frontends against the TS reference
 * (`01-parse-ruby.ts`) for three shapes found:
 *
 *   - `Bool` as a property type: TS and the native Ruby tier (already fixed
 *     by earlier, unrelated work) alias it to `boolean`, matching
 *     `Boolean`. Go, Rust, Python, Zig and Java did not recognize `Bool` at
 *     all and rejected the property with "unsupported type 'Bool'".
 *   - `prop :x, Bigint, default: -5`: TS, Go, Rust, and Zig already parse a
 *     unary-minus default value (they call the unary-expression parser for
 *     it). Python, the native Ruby tier, and Java called the
 *     PRIMARY-expression parser directly, which has no unary-minus
 *     handling, and rejected the literal with "unexpected token in
 *     expression: '-'".
 *   - `FixedArray[Int, N]` (`N` not numeric): TS, Go, Rust, Zig and the
 *     native Ruby tier already turn the token mismatch into a clean
 *     diagnostic and keep parsing. Python raised an uncaught `ValueError`
 *     from `int(size_tok.value)` and Java raised an uncaught
 *     `NumberFormatException` from `Integer.parseInt(sizeTok.value, 10)` --
 *     both propagated out of the parse function itself (not merely
 *     caught-and-reformatted by the CLI's outer handler), so any caller
 *     that invokes the parser directly (not through the CLI) got an
 *     exception instead of a diagnostic.
 *
 * Fixed in every tier that diverged from the TS reference (frontend parity
 * is a whole-pipeline invariant, so every `.runar.rb` frontend is in scope
 * for this item). Each tier's own unit-test suite additionally proves the
 * exception-vs-diagnostic claim directly at the parser level (Python:
 * tests/test_f206_rb_prop_parser_edges.py; Java: RbParserTest; Go/Rust/Zig:
 * their in-suite parser_ruby tests; Ruby: test_parser_ruby_edges.rb) --
 * this file is the CROSS-TIER gate, driven only through each tier's CLI.
 *
 * What this proves:
 *   - every available tier compiles a `Bool`-typed property to the same
 *     bytes as the equivalent `Boolean`-typed property, and every
 *     available tier agrees on those bytes;
 *   - every available tier compiles `default: -5` without error, and every
 *     available tier agrees on the resulting bytes;
 *   - every available tier's CLI refuses `FixedArray[Int, N]` with a
 *     non-zero exit and a diagnostic that is never a raw traceback, panic,
 *     or uncaught-exception dump.
 * What it does NOT prove: `default:` with other unary operators (`~`, `!`)
 *   beyond what the shared unary parser already covers; FixedArray length
 *   expressions that overflow a 32-bit int (a separate, unexplored edge);
 *   or any surface other than `.runar.rb`.
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n196-rb-prop-shape-'));
});

let seq = 0;
function write(src: string): string {
  const p = join(dir, `${seq++}.runar.rb`);
  writeFileSync(p, src);
  return p;
}

const boolSrc = (typeName: string): string => `require 'runar'

class BoolProp < Runar::SmartContract
  prop :flag, ${typeName}

  runar_public
  def check
    assert @flag
  end
end
`;

const DEFAULT_NEG = `require 'runar'

class DefaultNeg < Runar::SmartContract
  prop :count, Bigint, default: -5

  runar_public x: Bigint
  def check(x)
    assert x + @count == x - 5
  end
end
`;

const FIXED_ARRAY_BAD = `require 'runar'

class FixedArrayBad < Runar::SmartContract
  prop :arr, FixedArray[Int, N]

  runar_public x: Bigint
  def check(x)
    assert x == 0
  end
end
`;

/** Run a tier's CLI and return its exit status plus combined output. */
function run(tier: Tier, file: string): { status: number | null; out: string } {
  const r = spawnSync(tier.cmd!, [...tier.prefix, ...tier.argsFor(file)], {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error) throw new Error(`${tier.id} could not run: ${r.error.message}`);
  return { status: r.status, out: `${r.stdout ?? ''}\n${r.stderr ?? ''}` };
}

describe('F-206 .runar.rb property-declaration shapes — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (process.env.CI === 'true') expect(TIERS.length).toBe(7);
  });

  for (const tier of TIERS) {
    it(`${tier.id} compiles 'Bool' to the same bytes as 'Boolean'`, () => {
      const boolHex = compileHex(tier, write(boolSrc('Bool')));
      const booleanHex = compileHex(tier, write(boolSrc('Boolean')));
      expect(boolHex).toBe(booleanHex);
    });
  }

  it('every available tier agrees on the Bool-typed bytes', () => {
    const results = TIERS.map((t) => `${t.id}=${compileHex(t, write(boolSrc('Bool')))}`);
    const distinct = new Set(results.map((r) => r.split('=')[1]));
    expect(distinct.size, results.join(' ')).toBe(1);
  });

  it('every available tier agrees on the default:-5 bytes', () => {
    const results = TIERS.map((t) => `${t.id}=${compileHex(t, write(DEFAULT_NEG))}`);
    const distinct = new Set(results.map((r) => r.split('=')[1]));
    expect(distinct.size, results.join(' ')).toBe(1);
  });

  for (const tier of TIERS) {
    it(`${tier.id} refuses FixedArray[Int, N] with a clean diagnostic, never a traceback`, () => {
      const r = run(tier, write(FIXED_ARRAY_BAD));
      expect(r.status, r.out.slice(0, 800)).not.toBe(0);
      expect(r.out).not.toMatch(
        /Traceback \(most recent call last\)|Exception in thread|panicked at|goroutine \d+ \[|stack backtrace|\.java:\d+\)\s*$/m,
      );
    });
  }
});

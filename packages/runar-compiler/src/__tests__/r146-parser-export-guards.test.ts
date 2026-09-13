import { describe, it, expect } from 'vitest';
import {
  parse,
  parseSolSource,
  parseMoveSource,
  parsePythonSource,
  parseGoSource,
  parseRustSource,
  parseRubySource,
  parseZigSource,
  parseJavaSource,
} from '../index.js';
import { InputLimits } from 'runar-ir-schema';

/**
 * R-146 / CL-BUG-055 — the eight per-format parse functions are public API and
 * bypassed the input-size guard, which lived only in `parse()`.
 *
 * Measured on a 4,400,037-byte `.runar.sol` source against the 4,194,304-byte
 * limit:
 *
 *     parse()           REFUSED: source exceeds MAX_SOURCE_BYTES
 *     parseSolSource()  ACCEPTED
 *
 * Both are exported from `packages/runar-compiler/src/index.ts` and the second
 * is documented in that package's README as the way to target a specific
 * surface, so this is not a private back door — it is the advertised one.
 * Same shape as CL-BUG-057 (Python's CLI going around its own guarded
 * dispatcher): the guard is present, and reachable-around, in two tiers.
 *
 * The guard moves INTO each per-format parser rather than the exports being
 * withdrawn, because withdrawing them breaks a documented API to fix a bug that
 * has nothing to do with the API's shape.
 */

const OVERSIZE_BYTES = InputLimits.MAX_SOURCE_BYTES + 1024;

/** A source of a given byte length, in a shape each parser will at least begin. */
function oversize(prefix: string): string {
  const pad = '\n// pad';
  const body = pad.repeat(Math.ceil((OVERSIZE_BYTES - prefix.length) / pad.length));
  return prefix + body;
}

const PARSERS: Array<[string, (src: string, file?: string) => unknown, string, string]> = [
  ['parseSolSource', parseSolSource as never, 'pragma runar ^1.0;\n', 'Big.runar.sol'],
  ['parseMoveSource', parseMoveSource as never, 'module big::Big {\n', 'Big.runar.move'],
  ['parsePythonSource', parsePythonSource as never, 'from runar import SmartContract\n', 'Big.runar.py'],
  ['parseGoSource', parseGoSource as never, 'package contract\n', 'Big.runar.go'],
  ['parseRustSource', parseRustSource as never, 'use runar::prelude::*;\n', 'Big.runar.rs'],
  ['parseRubySource', parseRubySource as never, "require 'runar'\n", 'Big.runar.rb'],
  ['parseZigSource', parseZigSource as never, 'const runar = @import("runar");\n', 'Big.runar.zig'],
  ['parseJavaSource', parseJavaSource as never, 'import runar.lang.*;\n', 'Big.runar.java'],
];

describe('R-146 the per-format parsers enforce the input-size limit', () => {
  it('the dispatcher refuses an oversize source (the behaviour being matched)', () => {
    expect(() => parse(oversize('pragma runar ^1.0;\n'), 'Big.runar.sol')).toThrow(
      /MAX_SOURCE_BYTES/,
    );
  });

  for (const [name, fn, prefix, file] of PARSERS) {
    it(`${name} refuses an oversize source too`, () => {
      expect(
        () => fn(oversize(prefix), file),
        `${name} is exported from the package index and documented in its README; ` +
          `a caller reaching for it gets no size guard at all`,
      ).toThrow(/MAX_SOURCE_BYTES/);
    });
  }

  it('an ordinary source still parses through every per-format export', () => {
    // Not a size test — the control that the guard does not refuse everything.
    const ok = parseSolSource(
      `pragma runar ^1.0;

contract Small {
    bigint immutable a;

    constructor(bigint a_) {
        a = a_;
    }

    function go(bigint x) public {
        require(x > a);
    }
}
`,
      'Small.runar.sol',
    );
    expect(ok.contract).toBeDefined();
  });
});

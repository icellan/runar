import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { InputLimits } from 'runar-ir-schema';

/**
 * N-310 — a 4 MiB `.runar.go` source that is one long `result = result = …`
 * chain, or one long `mode ? value : mode ? value : …` chain, is REFUSED with
 * its real syntax diagnostics, never with a bare RangeError.
 *
 * Neither shape is nesting: Go has no chained assignment and no `?:`, so the
 * parser reports one syntax error per link and recovers. At MAX_SOURCE_BYTES that
 * is 10^5 diagnostics, and `compile()` did `diagnostics.push(...parseResult.errors)`
 * — a spread of that many arguments overflows the JS stack, so the whole
 * diagnostic list was replaced by the caught message `Maximum call stack size
 * exceeded`. (It is NOT the F-213 nesting recursion: parseGoSource returns
 * normally, and withNestingLimit has nothing to refuse.)
 *
 * Proves: compile() on both shapes at ~MAX_SOURCE_BYTES fails with the parser's
 * own syntax diagnostics and none of them is a stack-exhaustion message.
 * Does not prove: that the other six tiers cap the flood the way Go does (Go
 * prints 10 + "N more"; Rust/Python print them all) or that these shapes should
 * be reported as nesting — no tier does.
 */

const HEAD =
  'package contract\n\nimport runar "github.com/icellan/runar/packages/runar-go"\n\ntype P struct {\n\trunar.SmartContract\n\tLimit runar.Int `runar:"readonly"`\n}\n\nfunc (c *P) Check(value runar.Int, mode runar.Bool) {\n\tresult := runar.Int(0)\n{BODY}\n\trunar.Assert(result > 0)\n}\n';

// [name, line prefix, repeated link, a diagnostic the parser must still report]
const SHAPES: Array<[string, string, string, string]> = [
  ['a = a = …', '\t', 'result = ', "Unexpected token in expression: '='"],
  ['a ? a : …', '\tresult = ', 'mode ? value : ', "Unexpected token in expression: ':'"],
];

describe('N-310: .runar.go syntax-error floods at the size cap', () => {
  for (const [name, prefix, link, expected] of SHAPES) {
    it(`${name} chain near MAX_SOURCE_BYTES is refused with syntax diagnostics, not a RangeError`, () => {
      const n = Math.floor((InputLimits.MAX_SOURCE_BYTES - HEAD.length - 64) / link.length);
      const src = HEAD.replace('{BODY}', prefix + link.repeat(n) + 'value');
      expect(Buffer.byteLength(src)).toBeLessThanOrEqual(InputLimits.MAX_SOURCE_BYTES);
      const r = compile(src, { fileName: 'P.runar.go' });
      expect(r.success).toBe(false);
      const msgs = r.diagnostics.map((d) => d.message);
      expect(msgs.some((m) => /call stack/i.test(m))).toBe(false);
      expect(msgs).toContain(expected);
    }, 60_000);
  }
});

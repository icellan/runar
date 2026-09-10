/**
 * R-039 — irregular Python builtin aliases must map identically in all 7 tiers.
 *
 * Python contracts are written in snake_case and every tier's `.runar.py`
 * parser rewrites the identifiers to the canonical Rúnar camelCase names.
 * Most names fall out of a mechanical snake→camel rule, but four do not and
 * therefore need an explicit entry in each tier's special-name table:
 *
 *   int_to_str           -> int2str              (digit: "to" collapses to "2")
 *   safe_div             -> safediv              (no interior capital)
 *   safe_mod             -> safemod              (no interior capital)
 *   div_mod              -> divmod               (no interior capital)
 *   require_output_p2pkh -> requireOutputP2PKH   (all-caps PKH token)
 *
 * Before this test the TypeScript tier had none of them: the mechanical rule
 * produced `intToStr` / `safeDiv` / `safeMod` / `divMod` / `requireOutputP2pkh`,
 * all of which the type checker rejects as unknown functions, while the Python
 * and Java tiers compiled the very same source. CLAUDE.md makes frontend
 * parity a no-exceptions invariant, so that is a parity break, not a nicety.
 *
 * The pinned hexes are the SEVEN-TIER agreed fold-OFF output; every tier pins
 * the same strings, which is what makes this a parity gate.
 */
import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

const INT2STR_SNAKE = `
from runar import SmartContract, Bigint, ByteString, public, assert_, int_to_str, len_


class Encoder(SmartContract):
    n: Bigint

    def __init__(self, n: Bigint):
        super().__init__(n)
        self.n = n

    @public
    def unlock(self):
        out: ByteString = int_to_str(self.n, 4)
        assert_(len_(out) == 4)
`;

const MATH_ALIASES = `
from runar import SmartContract, Bigint, public, assert_


class Aliases(SmartContract):
    n: Bigint

    def __init__(self, n: Bigint):
        super().__init__(n)
        self.n = n

    @public
    def unlock(self):
        a: Bigint = safe_div(self.n, 3)
        b: Bigint = safe_mod(self.n, 3)
        c: Bigint = div_mod(self.n, 3)
        assert_(a + b + c > 0)
`;

const INTENT_SNAKE = `
from runar import (
    StatefulSmartContract, ByteString, Bigint, Readonly, public,
)


class Intent(StatefulSmartContract):
    bondPKH: Readonly[ByteString]
    bondAmount: Readonly[Bigint]
    count: Bigint

    def __init__(self, bondPKH: ByteString, bondAmount: Bigint, count: Bigint):
        super().__init__(bondPKH, bondAmount, count)
        self.bondPKH = bondPKH
        self.bondAmount = bondAmount
        self.count = count

    @public
    def payBond(self):
        require_output_p2pkh(0, self.bondPKH, self.bondAmount)
`;

const INTENT_CAMEL = INTENT_SNAKE.replace('require_output_p2pkh', 'requireOutputP2PKH');

const UNKNOWN_BUILTIN = `
from runar import SmartContract, Bigint, public, assert_


class Unknown(SmartContract):
    n: Bigint

    def __init__(self, n: Bigint):
        super().__init__(n)
        self.n = n

    @public
    def unlock(self):
        assert_(not_a_builtin(self.n) > 0)
`;

function hex(source: string, fileName: string): string {
  const result = compile(source, { fileName, disableConstantFolding: true });
  if (!result.success) {
    throw new Error(
      'compilation failed: ' + result.diagnostics.map((d) => d.message).join('; '),
    );
  }
  return result.scriptHex!;
}

describe('R-039 Python builtin alias parity', () => {
  it('int_to_str lowers to the seven-tier int2str script', () => {
    expect(hex(INT2STR_SNAKE, 'Encoder.runar.py')).toBe('0054808277549c');
  });

  it('safe_div / safe_mod / div_mod lower to the seven-tier script', () => {
    expect(hex(MATH_ALIASES, 'Aliases.runar.py')).toBe(
      '00537692699600537692699700536e967b7b97757b7b937c9300a0',
    );
  });

  it('require_output_p2pkh is byte-identical to requireOutputP2PKH', () => {
    expect(hex(INTENT_SNAKE, 'Intent.runar.py')).toBe(hex(INTENT_CAMEL, 'Intent.runar.py'));
  });

  it('still rejects an unknown snake_case function', () => {
    // Guards against the lazy fix: a blanket pass-through that maps any
    // snake_case identifier onto a builtin name would let this compile.
    const result = compile(UNKNOWN_BUILTIN, {
      fileName: 'Unknown.runar.py',
      disableConstantFolding: true,
    });
    expect(result.success).toBe(false);
    expect(result.diagnostics.map((d) => d.message).join('\n')).toMatch(/notABuiltin/);
  });
});

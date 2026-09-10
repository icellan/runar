# frozen_string_literal: true

require_relative "test_helper"

require "tmpdir"
require "runar_compiler/compiler"

# R-039 -- irregular Python builtin aliases must map identically in all 7 tiers.
#
# Python contracts are written in snake_case and every tier's .runar.py parser
# rewrites the identifiers to the canonical Runar camelCase names. Most names
# fall out of a mechanical snake->camel rule, but five do not and therefore
# need an explicit entry in each tier's special-name table:
#
#   int_to_str           -> int2str            (digit: "to" collapses to "2")
#   safe_div             -> safediv            (no interior capital)
#   safe_mod             -> safemod            (no interior capital)
#   div_mod              -> divmod             (no interior capital)
#   require_output_p2pkh -> requireOutputP2PKH (all-caps PKH token)
#
# Before this test the Ruby tier had safe_div/safe_mod/div_mod but neither
# int_to_str nor require_output_p2pkh: the mechanical rule produced intToStr
# and requireOutputP2pkh, which the type checker rejects as unknown functions,
# while the Python tier compiled the very same source. CLAUDE.md makes frontend
# parity a no-exceptions invariant, so that is a parity break.
#
# The pinned hexes are the SEVEN-TIER agreed fold-OFF output.
class TestPyBuiltinAliasParity < Minitest::Test
  INT2STR_SNAKE = <<~PY
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
  PY

  MATH_ALIASES = <<~PY
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
  PY

  INTENT_SNAKE = <<~PY
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
  PY

  UNKNOWN_BUILTIN = <<~PY
    from runar import SmartContract, Bigint, public, assert_


    class Unknown(SmartContract):
        n: Bigint

        def __init__(self, n: Bigint):
            super().__init__(n)
            self.n = n

        @public
        def unlock(self):
            assert_(not_a_builtin(self.n) > 0)
  PY

  def compile_script_hex(source, file_name)
    Dir.mktmpdir do |dir|
      path = File.join(dir, file_name)
      File.write(path, source)
      RunarCompiler.compile_from_source(path, disable_constant_folding: true).script
    end
  end

  def test_int_to_str_lowers_to_the_seven_tier_script
    assert_equal "0054808277549c",
                 compile_script_hex(INT2STR_SNAKE, "Encoder.runar.py"),
                 "int_to_str script diverged from the seven-tier output"
  end

  def test_math_aliases_lower_to_the_seven_tier_script
    assert_equal "00537692699600537692699700536e967b7b97757b7b937c9300a0",
                 compile_script_hex(MATH_ALIASES, "Aliases.runar.py"),
                 "safe_div/safe_mod/div_mod script diverged from the seven-tier output"
  end

  def test_require_output_p2pkh_matches_camel_case
    camel = INTENT_SNAKE.sub("require_output_p2pkh", "requireOutputP2PKH")
    assert_equal compile_script_hex(camel, "Intent.runar.py"),
                 compile_script_hex(INTENT_SNAKE, "Intent.runar.py"),
                 "require_output_p2pkh did not lower byte-identically to requireOutputP2PKH"
  end

  def test_unknown_snake_case_function_is_still_rejected
    # Guards against the lazy fix: a blanket pass-through that maps any
    # snake_case identifier onto a builtin name would let this compile.
    err = assert_raises(StandardError) do
      compile_script_hex(UNKNOWN_BUILTIN, "Unknown.runar.py")
    end
    assert_match(/notABuiltin/, err.message)
  end
end

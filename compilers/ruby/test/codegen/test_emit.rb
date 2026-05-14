# frozen_string_literal: true

require_relative 'codegen_helper'

# Dedicated emit-pass test for the Ruby compiler (GAP-m4).
#
# Mirrors compilers/python/tests/test_emit.py and
# compilers/go/codegen/emit_test.go: pins the Stack-IR -> Bitcoin Script
# hex emission for a canonical fixture so an emit-pass regression fails
# locally instead of surfacing only as a conformance-suite divergence.
#
# The fixture is the in-tree P2PKH example — the same source the
# `basic-p2pkh` conformance fixture compiles. Its locking script is the
# canonical 5-opcode P2PKH template `OP_DUP OP_HASH160 <20-byte slot>
# OP_EQUALVERIFY OP_CHECKSIG`, whose constructor-arg-free skeleton is the
# byte-frozen golden `76a90088ac`.
class TestEmitPass < Minitest::Test
  include CodegenTestHelpers

  P2PKH_SOURCE = File.expand_path(
    '../../../../examples/ruby/p2pkh/P2PKH.runar.rb', __dir__
  )

  # Byte-frozen golden: the constructor-slot skeleton of the P2PKH locking
  # script. Matches conformance/tests/basic-p2pkh/expected-script.hex.
  P2PKH_GOLDEN_HEX = '76a90088ac'

  def test_emit_produces_byte_frozen_p2pkh_locking_script
    source = File.read(P2PKH_SOURCE)
    artifact = compile_ts_source(source, 'P2PKH.runar.rb')

    assert_equal 'P2PKH', artifact.contract_name
    assert_equal P2PKH_GOLDEN_HEX, artifact.script.downcase,
                 'emit pass must produce the byte-frozen P2PKH locking script'
  end

  def test_emit_p2pkh_asm_has_canonical_opcode_shape
    source = File.read(P2PKH_SOURCE)
    artifact = compile_ts_source(source, 'P2PKH.runar.rb')

    asm = artifact.asm
    # Canonical P2PKH spend path: OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG
    assert_includes asm, 'OP_DUP'
    assert_includes asm, 'OP_HASH160'
    assert_includes asm, 'OP_EQUALVERIFY'
    assert_includes asm, 'OP_CHECKSIG'
  end
end

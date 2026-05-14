# frozen_string_literal: true

require_relative 'codegen_helper'

# Codegen op-shape test for the `addDataOutput` intrinsic (GAP-m3).
#
# Previously the Ruby tier only had compile-only coverage
# (`test_stack_lower.rb` asserted `ops.length > 0` / `script.length > 0`).
# This test pins the load-bearing opcodes the data-output serialization
# emits, so a wrong-opcode regression in the Ruby stack lowerer fails
# locally instead of only as a conformance-suite hex divergence.
#
# `add_data_output` lowers to the same wire shape as `add_raw_output`:
#   OP_SIZE + varint(scriptLen) + OP_CAT + 8-byte LE amount (OP_NUM2BIN) + OP_CAT
# (mirrors Go's TestStack_AddDataOutput_WireShapeMatchesAddRawOutput).

class TestAddDataOutputCodegen < Minitest::Test
  include CodegenTestHelpers

  def test_add_data_output_emits_raw_output_wire_shape_opcodes
    source = <<~TS
      import { StatefulSmartContract, bigint, ByteString } from 'runar-lang';

      class DataLogger extends StatefulSmartContract {
        count: bigint;

        constructor(count: bigint) {
          super(count);
          this.count = count;
        }

        public log(note: ByteString): void {
          this.count = this.count + 1n;
          this.addDataOutput(0n, note);
        }
      }
    TS

    artifact = compile_ts_source(source, 'DataLogger.runar.ts')
    assert_equal 'DataLogger', artifact.contract_name
    assert artifact.script.length.positive?, 'script must be non-empty'

    asm = artifact.asm
    # Data-output serialization building blocks — same set Go's wire-shape
    # test pins for add_data_output.
    assert_includes asm, 'OP_SIZE',    'data output must prefix script length'
    assert_includes asm, 'OP_CAT',     'data output assembles via OP_CAT'
    assert_includes asm, 'OP_NUM2BIN', 'data output encodes the 8-byte LE satoshis amount'
  end

  def test_add_data_output_only_method_compiles_with_continuation
    # A stateful method that declares ONLY a data output (no addOutput, no
    # state mutation) still runs the single-output continuation path.
    source = <<~TS
      import { StatefulSmartContract, bigint, ByteString } from 'runar-lang';

      class DataOnly extends StatefulSmartContract {
        owner: bigint;

        constructor(owner: bigint) {
          super(owner);
          this.owner = owner;
        }

        public emitData(payload: ByteString): void {
          this.addDataOutput(0n, payload);
        }
      }
    TS

    artifact = compile_ts_source(source, 'DataOnly.runar.ts')
    asm = artifact.asm
    # Even without state mutation, the data output triggers the
    # continuation-hash machinery, so OP_CAT + OP_NUM2BIN must appear.
    assert_includes asm, 'OP_CAT'
    assert_includes asm, 'OP_NUM2BIN'
  end
end

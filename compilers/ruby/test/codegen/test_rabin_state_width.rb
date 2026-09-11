# frozen_string_literal: true

require_relative "../test_helper"
require_relative "codegen_helper"

# ---------------------------------------------------------------------------
# `RabinSig` / `RabinPubKey` are `bigint` ALIASES. A mutable one is stored in
# the state section as a bare 8-byte OP_NUM2BIN word, on BOTH sides.
#
# This tier's READER already says so in three places — `numeric_state_type?`
# (`codegen/stack.rb`), the deserialize size table (8) and the fixed
# state-section length (8). Its state SERIALIZERS did not: they tested
# `prop.type == "bigint"` literally, so a mutable Rabin field went into the
# accumulator in its MINIMAL script-number encoding with no NUM2BIN at all.
#
# Same class of writer/reader split as the `Sig` defect next door, and the same
# fund loss: for any value whose minimal encoding is not exactly 8 bytes the
# continuation this contract builds cannot be re-read by its own script. Deploy
# succeeds, the first spend succeeds, and the UTXO it creates is dead.
#
# Cause: `31276a06` widened writer AND reader in the TypeScript reference;
# `e06f8c2c` widened only Go's reader, and this tier followed Go.
#
# The lock: a mutable Rabin field must compile BYTE-IDENTICALLY to the same
# contract with a `bigint` field — the path whose writer and reader are known
# to agree. ByteString / Sig (framed) and PubKey (33 raw) stay the negative
# controls, so the equality cannot be satisfied by collapsing every state type
# onto one shape.
# ---------------------------------------------------------------------------

class TestRabinStateWidth < Minitest::Test
  include CodegenTestHelpers

  RABIN_TYPES = %w[RabinSig RabinPubKey].freeze

  # Mutating method, implicit continuation -- the compute-state-bytes writer.
  def write_src(prop_type)
    <<~TS
      class RabinStateWrite extends StatefulSmartContract {
        tag: #{prop_type};
        constructor(tag: #{prop_type}) { super(tag); this.tag = tag; }
        public update(next: #{prop_type}) { this.tag = next; }
      }
    TS
  end

  # Mutating method with an EXPLICIT addOutput -- the `_lower_add_output` writer.
  def add_output_src(prop_type)
    <<~TS
      class RabinStateAddOutput extends StatefulSmartContract {
        tag: #{prop_type};
        constructor(tag: #{prop_type}) { super(tag); this.tag = tag; }
        public update(next: #{prop_type}) { this.tag = next; this.addOutput(1000n, next); }
      }
    TS
  end

  def shapes
    [
      ["implicit continuation", method(:write_src), "RabinStateWrite.runar.ts"],
      ["explicit addOutput", method(:add_output_src), "RabinStateAddOutput.runar.ts"]
    ]
  end

  # The decisive equality: the writer must emit the reader's fixed 8-byte word.
  def test_writes_the_same_fixed_word_as_bigint
    shapes.each do |label, build, file_name|
      control = compile_ts_source(build.call("bigint"), file_name)
      RABIN_TYPES.each do |prop_type|
        got = compile_ts_source(build.call(prop_type), file_name)
        assert_equal control.script, got.script,
                     "#{label}: a mutable #{prop_type} field does not serialize like bigint — " \
                     "the writer disagrees with its own 8-byte reader"
      end
    end
  end

  # The equality must not be reachable by collapsing every state type onto one
  # shape.
  def test_controls_stay_distinct
    shapes.each do |label, build, file_name|
      control = compile_ts_source(build.call("bigint"), file_name)
      %w[ByteString Sig PubKey].each do |prop_type|
        got = compile_ts_source(build.call(prop_type), file_name)
        refute_equal control.script, got.script,
                     "#{label}: a mutable #{prop_type} field compiled identically to bigint — " \
                     "the Rabin equality no longer discriminates"
      end
    end
  end
end

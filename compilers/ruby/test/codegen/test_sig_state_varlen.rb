# frozen_string_literal: true

require_relative "../test_helper"
require_relative "codegen_helper"

# ---------------------------------------------------------------------------
# `Sig` / `SigHashPreimage` state fields are push-data-framed variable-length
# state, exactly like `ByteString`, on BOTH the write and the read side.
#
# `compilers/ruby/lib/runar_compiler/codegen/stack.rb` kept three lists of
# "which state types carry a push-data length prefix":
#
#   * `Codegen.variable_length_state_type?` + the deserialize size table
#     (`:4059`) + the var-length parse loop (`:4170`/`:4181`/`:4196`) — all say
#     ByteString | Sig | SigHashPreimage;
#   * the state SERIALIZERS (`:2872`, `:4012`, `:4239`) — said `== "ByteString"`;
#   * the `var_len_props` set inside the uses-code-part predicate (`:4688`) —
#     same.
#
# Two faces, both fund loss:
#
#   * WRITE — a mutating method wrote the continuation state RAW, with no
#     length prefix, while the reader in the NEXT spend push-data-decodes it
#     and takes the DER `0x30` as a length-48 push. Deploy succeeds, the first
#     spend succeeds, and the UTXO that spend creates is unspendable.
#   * READ — for a TERMINAL method reading a mutable Sig field `uses_code_part`
#     stayed false, the deserializer took its "no _codePart" shortcut and
#     pushed no mutable property at all, so every `load_prop` fell through to
#     the DEPLOY-TIME constructor placeholder.
#
# The deploy-time writer settles which list is right: every SDK's
# `encode_state_value` enumerates the fixed-size types (PubKey, Addr,
# Ripemd160, Sha256, Point, P256Point, P384Point) and push-data-frames the rest.
#
# The lock: a Sig / SigHashPreimage field must compile BYTE-IDENTICALLY to the
# same contract with a ByteString field — the path that was already correct.
# RabinSig (a bigint alias, a bare 8-byte NUM2BIN word) and PubKey (33 raw
# bytes) are the negative controls and must stay DIFFERENT.
# ---------------------------------------------------------------------------

class TestSigStateVarLen < Minitest::Test
  include CodegenTestHelpers

  VAR_LEN_TYPES = %w[Sig SigHashPreimage].freeze

  # Mutating method -- drives the state-continuation WRITE path.
  def write_src(prop_type)
    <<~TS
      class VarLenStateWrite extends StatefulSmartContract {
        tag: #{prop_type};
        constructor(tag: #{prop_type}) { super(tag); this.tag = tag; }
        public update(next: #{prop_type}) { this.tag = next; }
      }
    TS
  end

  # Terminal method reading the field -- drives the uses-code-part predicate.
  def read_src(prop_type)
    <<~TS
      class VarLenStateRead extends StatefulSmartContract {
        tag: #{prop_type};
        constructor(tag: #{prop_type}) { super(tag); this.tag = tag; }
        public check(expected: bigint) { assert(len(this.tag) == expected); }
      }
    TS
  end

  def uses_code_part(artifact, method)
    m = artifact.abi.methods.find { |x| x.name == method }
    refute_nil m, "method '#{method}' not found in the ABI"
    m.uses_code_part == true
  end

  def test_write_path_frames_like_bytestring
    control = compile_ts_source(write_src("ByteString"), "VarLenStateWrite.runar.ts")
    VAR_LEN_TYPES.each do |prop_type|
      got = compile_ts_source(write_src(prop_type), "VarLenStateWrite.runar.ts")
      assert_equal control.script.length, got.script.length,
                   "a mutable #{prop_type} field does not push-data-frame its continuation state"
      assert_equal control.script, got.script,
                   "a mutable #{prop_type} field does not frame its continuation like ByteString"
    end
  end

  def test_terminal_read_matches_bytestring
    control = compile_ts_source(read_src("ByteString"), "VarLenStateRead.runar.ts")
    VAR_LEN_TYPES.each do |prop_type|
      got = compile_ts_source(read_src(prop_type), "VarLenStateRead.runar.ts")
      assert_equal control.script.length, got.script.length,
                   "a terminal read of a mutable #{prop_type} field diverges from the ByteString control"
      assert_equal control.script, got.script,
                   "a terminal read of a mutable #{prop_type} field diverges from the ByteString control"
    end
  end

  def test_terminal_read_uses_code_part
    # The ABI shape, not just the byte count: the SDK reads this flag to decide
    # whether to push _codePart into the unlocking script.
    (VAR_LEN_TYPES + ["ByteString"]).each do |prop_type|
      artifact = compile_ts_source(read_src(prop_type), "VarLenStateRead.runar.ts")
      assert_equal true, uses_code_part(artifact, "check"),
                   "a terminal read of a mutable #{prop_type} field must take the implicit _codePart parameter"
    end
  end

  # Types this change must NOT move into the variable-length set. Without these
  # the assertions above would still pass if every state type collapsed onto the
  # same lowering.
  def test_fixed_width_state_is_not_push_data_framed
    control = compile_ts_source(write_src("ByteString"), "VarLenStateWrite.runar.ts")
    %w[RabinSig RabinPubKey PubKey].each do |prop_type|
      fixed = compile_ts_source(write_src(prop_type), "VarLenStateWrite.runar.ts")
      refute_equal control.script, fixed.script,
                   "#{prop_type} compiled identically to ByteString — it must keep its fixed-width framing"
    end
  end
end

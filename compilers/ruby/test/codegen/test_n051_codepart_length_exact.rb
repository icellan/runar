# frozen_string_literal: true

require_relative "../test_helper"
require_relative "codegen_helper"

# ---------------------------------------------------------------------------
# N-051 (TaffyTail) -- the SIZE(_codePart) pin is ALWAYS an equality.
#
# A stateful contract with a variable-length state section pins the length of
# the spender-supplied `_codePart` with
#
#     76 | 04 LL LL LL LL | 81 | 9c | 69
#     OP_DUP  <len LE32>    OP_BIN2NUM  OP_NUMEQUAL  OP_VERIFY
#
# When a readonly constructor arg of variable width (here the ByteString `tag`)
# is baked into the code, the compiler cannot know the deployed length. It used
# to fall back to OP_GREATERTHANOREQUAL (a2), a lower bound that lets a
# stranger claim a code part truncated at a 0x6a byte inside the baked value.
# Now the comparison stays OP_NUMEQUAL and the length field is recorded as an
# artifact `codePartLenSlots` entry the SDK patches at deploy time.
# ---------------------------------------------------------------------------
class TestN051CodePartLengthExact < Minitest::Test
  include CodegenTestHelpers

  TAFFYTAIL = <<~TS
    import { StatefulSmartContract, assert, extractAmount, checkSig } from 'runar-lang';
    import type { ByteString, PubKey, Sig } from 'runar-lang';

    class TaffyTailVault extends StatefulSmartContract {
      message: ByteString;
      readonly tag: ByteString;
      readonly owner: PubKey;

      constructor(message: ByteString, tag: ByteString, owner: PubKey) {
        super(message, tag, owner);
        this.message = message;
        this.tag = tag;
        this.owner = owner;
      }

      public burn(sig: Sig) {
        assert(checkSig(sig, this.owner));
      }

      public post(next: ByteString, claimedTag: ByteString) {
        assert(claimedTag === this.tag);
        this.addOutput(extractAmount(this.txPreimage), next);
      }
    }
  TS

  # Same variable-length state, but every readonly arg is fixed-width (PubKey),
  # so the deployed code-part length is known at compile time: exact pin, no slot.
  FIXED_WIDTH = <<~TS
    import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
    import type { ByteString, PubKey, Sig } from 'runar-lang';

    class FixedWidthVault extends StatefulSmartContract {
      message: ByteString;
      readonly owner: PubKey;

      constructor(message: ByteString, owner: PubKey) {
        super(message, owner);
        this.message = message;
        this.owner = owner;
      }

      public post(sig: Sig, next: ByteString) {
        assert(checkSig(sig, this.owner));
        this.message = next;
      }
    }
  TS

  # Every 9-byte pin run (76 04 LL LL LL LL 81 cmp 69) as [byte_offset_of_LL, cmp].
  def pins(script_hex)
    out = []
    i = 0
    while i + 18 <= script_hex.length
      seq = script_hex[i, 18]
      if seq.start_with?("7604") && seq[12, 2] == "81" && seq[16, 2] == "69" && %w[9c a2].include?(seq[14, 2])
        out << [i / 2 + 2, seq[14, 2]]
      end
      i += 2
    end
    out
  end

  def test_taffytail_pin_is_numequal_and_recorded_as_a_slot
    artifact = compile_ts_source(TAFFYTAIL, "TaffyTailVault.runar.ts")
    script = artifact.script

    found = pins(script)
    refute_empty found, "TaffyTailVault must carry a verify_code_part_len pin"
    assert(found.all? { |_, cmp| cmp == "9c" }, "every pin must compare with OP_NUMEQUAL, got #{found.inspect}")
    refute_includes script, "81a269", "no lower-bound (OP_GREATERTHANOREQUAL) pin may remain"

    json = JSON.parse(RunarCompiler.artifact_to_json(artifact))
    # Byte-identical with the TS reference compiler (fold OFF).
    assert_equal [{ "byteOffset" => 959 }], json["codePartLenSlots"]
    assert_equal found.map(&:first), json["codePartLenSlots"].map { |s| s["byteOffset"] }

    off = json["codePartLenSlots"][0]["byteOffset"]
    assert_equal "04", script[(off - 1) * 2, 2]
    assert_equal "819c69", script[(off + 4) * 2, 6]

    # Key order: codePartLenSlots sits immediately after codeSepIndexSlots.
    keys = json.keys
    assert_equal keys.index("codeSepIndexSlots") + 1, keys.index("codePartLenSlots")
  end

  def test_fixed_width_contract_keeps_exact_pin_without_slot
    artifact = compile_ts_source(FIXED_WIDTH, "FixedWidthVault.runar.ts")
    found = pins(artifact.script)
    refute_empty found
    assert(found.all? { |_, cmp| cmp == "9c" })

    json = JSON.parse(RunarCompiler.artifact_to_json(artifact))
    refute json.key?("codePartLenSlots"), "an exact compile-time pin must not produce a codePartLenSlots entry"
  end
end

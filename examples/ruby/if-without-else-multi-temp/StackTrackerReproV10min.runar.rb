require 'runar'

# StackTrackerReproV10min — minimal reproducer for issue #36 in Ruby form.
#
# The first ``if (... < out_count)`` branch leaves ``script_len``,
# ``blob_len``, and ``blob`` as branch-private locals on the stack.
# Without the lowerIf branch reconciliation fix, post-ENDIF cleanup
# misindexed against ``p`` and the downstream OP_SPLIT aborted. Mirrors
# the TS fixture in examples/ts/if-without-else-multi-temp/.

class StackTrackerReproV10min < Runar::SmartContract
  def initialize
    super()
  end

  runar_public raw_tx: ByteString, expected_mnee_output_bytes: ByteString, expected_extra_data_output_bytes: ByteString
  def verify_mnee_tx_contains_both_outputs(raw_tx, expected_mnee_output_bytes, expected_extra_data_output_bytes)
    p = 46

    out_count = bin2num(cat(substr(raw_tx, p, 1), num2bin(0, 1)))
    assert out_count < 253
    assert out_count <= 8
    p = p + 1

    found_mnee = false
    found_extra = false

    if 0 < out_count
      script_len = bin2num(cat(substr(raw_tx, p + 8, 1), num2bin(0, 1)))
      assert script_len < 253
      blob_len = 8 + 1 + script_len
      blob = substr(raw_tx, p, blob_len)
      if blob == expected_mnee_output_bytes
        found_mnee = true
      end
      if blob == expected_extra_data_output_bytes
        found_extra = true
      end
      p = p + blob_len
    end
    if 1 < out_count
      script_len = bin2num(cat(substr(raw_tx, p + 8, 1), num2bin(0, 1)))
      assert script_len < 253
      blob_len = 8 + 1 + script_len
      blob = substr(raw_tx, p, blob_len)
      if blob == expected_mnee_output_bytes
        found_mnee = true
      end
      if blob == expected_extra_data_output_bytes
        found_extra = true
      end
      p = p + blob_len
    end

    assert found_mnee
    assert found_extra
  end

  runar_public x: ByteString
  def other(x)
    assert x == x
  end
end

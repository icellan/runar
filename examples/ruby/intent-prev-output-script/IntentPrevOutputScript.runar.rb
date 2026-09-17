require 'runar'

# IntentPrevOutputScript exercises the extractPrevOutputScript intent
# intrinsic.
#
# It does NOT read input 0 (W6 / GhostInput). The intrinsic asserts that a
# caller-supplied byte string hashes to expectedHash and returns it; this
# contract then asserts the string is non-empty. The first argument is a
# compile-time label naming the auto-injected witness parameter
# _prevOutScript_0, which the unlocking script supplies. There is no vin
# lookup, no parent transaction and no input-count check in the emitted
# script. For a construction that binds a specific companion INPUT, see
# examples/ts/companion-verifier/.
class IntentPrevOutputScript < Runar::StatefulSmartContract
  prop :expected_hash, ByteString, readonly: true
  prop :count, Bigint

  def initialize(expected_hash, count)
    super(expected_hash, count)
    @expected_hash = expected_hash
    @count = count
  end

  runar_public
  def bind
    s = extract_prev_output_script(0, @expected_hash)
    assert len(s) > 0
    @count = @count + 1
  end
end

require 'runar'

# ConditionalDataOutput -- Audit regression: a stateful method that
# emits a data output on a conditional branch must keep the canonical
# single-output ``compute_state_output`` state continuation on every path.
#
# See ``conformance/tests/conditional-data-output-stateful/`` for the full
# rationale; the cross-format ports must produce identical Bitcoin Script.

class ConditionalDataOutput < Runar::StatefulSmartContract
  prop :amount, Bigint

  def initialize(amount)
    super(amount)
    @amount = amount
  end

  # The canonical bug: add_data_output is wrapped in a branch.
  # The compiler must register the if's value as a DATA output ref
  # (not a state output ref) so that the parent method's continuation
  # hash keeps compute_state_output.
  runar_public flag: Boolean, payload: ByteString
  def pay(flag, payload)
    @amount = @amount + 1
    if flag
      add_data_output(0, payload)
    end
    assert true
  end
end

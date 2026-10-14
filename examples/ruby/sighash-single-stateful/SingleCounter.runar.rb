# SingleCounter -- Ruby port of
# examples/ts/sighash-single-stateful/SingleCounter.runar.ts.
#
# The class macro runar_sighash 'SINGLE|FORKID' (N-093) declares that bump's
# auto-injected continuation commits only the output at its own index: no
# change segment and no _changePKH / _changeAmount parameter (N-038). SINGLE
# does not pin the continuation's value, so bump re-creates it at the full
# input amount read from the preimage. reset keeps ALL|FORKID.

require 'runar'

class SingleCounter < Runar::StatefulSmartContract
  prop :count, Bigint

  def initialize(count)
    super(count)
    @count = count
  end

  runar_sighash 'SINGLE|FORKID'
  runar_public
  def bump
    add_output(extract_amount(@tx_preimage), @count + 1)
  end

  runar_public
  def reset
    assert @count > 0
    @count = 0
  end
end

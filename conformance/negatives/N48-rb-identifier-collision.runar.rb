# F-017 — a Ruby local whose name converts to a PROPERTY's Rúnar name.
#
# The .runar.rb surface converts snake_case to camelCase and skips empty
# segments, so the local `k_` becomes `k` — the same name as the property
# `@k`. Two distinct source identifiers, one Rúnar name.
#
# Every tier must refuse with:
#   identifier collision: 'k' and 'k_' both convert to 'k'; rename one of them
require 'runar'

class IdentCollisionRb < Runar::SmartContract
  prop :k, Bigint

  def initialize(k)
    super(k)
    @k = k
  end

  runar_public n: Bigint
  def unlock(n)
    k_ = n + 1
    assert k_ == @k
  end
end

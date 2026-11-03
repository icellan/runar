# F-011: an unterminated double-quoted .runar.rb literal. Every tier must
# refuse with:
#   unterminated string literal
require 'runar'

class Guarded < Runar::SmartContract
  runar_public y: Bigint
  def unlock(y)
    tag = "cafe
    assert y < 5
    # "
    assert y >= 0
  end
end

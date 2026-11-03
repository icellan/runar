# F-011: an unterminated single-quoted .runar.rb literal. The line-based
# Ruby tokenizers silently ended it at the line break and compiled the
# program. Every tier must refuse with:
#   unterminated string literal
require 'runar'

class Guarded < Runar::SmartContract
  runar_public y: Bigint
  def unlock(y)
    tag = 'cafe
    assert y < 5
    # '
    assert y >= 0
  end
end

require 'runar'

class IfElse < Runar::SmartContract
  prop :limit, Bigint

  def initialize(limit)
    super(limit)
    @limit = limit
  end

  runar_public value: Bigint, mode: Boolean
  def check(value, mode)
    result = 0
    if mode
      result = value + @limit
    else
      result = value - @limit
    end
    assert result > 0
  end
end

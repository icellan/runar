# Anyone — minimal `asm` raw-script contract (Ruby surface).
require 'runar'

class Anyone < Runar::UnsafeSmartContract
  def initialize
    super()
  end

  runar_public
  def unlock
    asm("51", 0, 1)
  end
end

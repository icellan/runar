# N-002: an index assignment is only a write when its root is a FixedArray
# contract property. Pre-fix TS, Go, Rust and Zig lowered this target as a
# READ, dropping the write, and emitted a deployable script whose state never
# changes (Python refused it since F-013; Ruby and Java failed late on an
# internal __array_access). Every tier must refuse in the validator with:
#   index assignment is only supported on FixedArray contract properties;
#   the target here is not a FixedArray property
# Shape: a ByteString property write on the Ruby surface.
require 'runar'

class Blob < Runar::StatefulSmartContract
  prop :blob, ByteString

  def initialize(blob)
    super(blob)
    @blob = blob
  end

  runar_public
  def poke
    @blob[0] = 7
    assert true
  end
end

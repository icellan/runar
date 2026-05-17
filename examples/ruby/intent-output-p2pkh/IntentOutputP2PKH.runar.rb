require 'runar'

# IntentOutputP2PKH -- exercises the requireOutputP2PKH intent intrinsic.
#
# Note: the property bondPKH and the builtin requireOutputP2PKH are
# spelled in camelCase here (rather than the usual Ruby snake_case)
# because the all-caps PKH token does not round-trip through the
# naive snake_case <-> camelCase transform shared across the
# cross-tier Ruby parsers. Writing them in their canonical camelCase
# form avoids the lossy conversion and keeps the AST byte-identical
# to the Go-source AST after the Go parser lowercases the leading
# char of BondPKH / RequireOutputP2PKH.
class IntentOutputP2PKH < Runar::StatefulSmartContract
  prop :bondPKH, ByteString, readonly: true
  prop :bondAmount, Bigint, readonly: true
  prop :count, Bigint

  def initialize(bondPKH, bondAmount, count)
    super(bondPKH, bondAmount, count)
    @bondPKH = bondPKH
    @bondAmount = bondAmount
    @count = count
  end

  runar_public
  def payBond
    requireOutputP2PKH(0, @bondPKH, @bondAmount)
    @count = @count + 1
  end
end

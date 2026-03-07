# frozen_string_literal: true

# Runar type constants.
#
# Ruby uses Integer for numeric types and String for all byte-string types.
# These constants allow contracts to reference Runar types by name, and
# Ruby's constant resolution provides free typo detection at load time.

module Runar
  module Types
    Bigint       = Integer
    Int          = Integer
    ByteString   = String
    PubKey       = String
    Sig          = String
    Addr         = String
    Sha256       = String
    Ripemd160    = String
    SigHashPreimage = String
    RabinSig     = String
    RabinPubKey  = String
    Point        = String
  end
end

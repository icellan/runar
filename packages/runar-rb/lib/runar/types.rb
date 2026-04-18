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
    # Alias for Sha256. Cross-language parity with the Go SDK, where the
    # type had to be renamed to Sha256Digest to free the identifier
    # `Sha256` for a real hash function.
    Sha256Digest = Sha256
    Ripemd160    = String
    SigHashPreimage = String
    RabinSig     = String
    RabinPubKey  = String
    Point        = String
    OpCodeType   = String
    # Boolean is the Runar boolean type. Ruby uses native true/false values;
    # this constant exists so `prop :active, Boolean` resolves at load time.
    Boolean      = :boolean
  end
end

# frozen_string_literal: true

# Runar — Ruby runtime for Bitcoin Script smart contracts.
#
# Provides types, mock crypto, real hashes, EC operations, and base classes
# for writing and testing Runar smart contracts in Ruby.

require_relative 'runar/types'
require_relative 'runar/dsl'
require_relative 'runar/base'
require_relative 'runar/builtins'
require_relative 'runar/ec'
require_relative 'runar/ec_primitives'
require_relative 'runar/ecdsa'
require_relative 'runar/rabin_sig'
require_relative 'runar/test_keys'
require_relative 'runar/compile_check'

module Runar
  # Re-export Builtins as module functions so they can be called as Runar.method
  extend Builtins
end

# -- Top-level type constants ------------------------------------------------
# Contracts do `require 'runar'` and use types directly: `prop :balance, Bigint`

Bigint       = Runar::Types::Bigint
Int          = Runar::Types::Int
ByteString   = Runar::Types::ByteString
PubKey       = Runar::Types::PubKey
Sig          = Runar::Types::Sig
Addr         = Runar::Types::Addr
Sha256       = Runar::Types::Sha256
Ripemd160    = Runar::Types::Ripemd160
SigHashPreimage = Runar::Types::SigHashPreimage
RabinSig     = Runar::Types::RabinSig
RabinPubKey  = Runar::Types::RabinPubKey
Point        = Runar::Types::Point
Boolean      = Runar::Types::Boolean

# -- Top-level EC constants --------------------------------------------------

EC_P = Runar::EC::EC_P
EC_N = Runar::EC::EC_N
EC_G = Runar::EC::EC_G

# -- Top-level test key constants --------------------------------------------
# These allow test files to reference ALICE, BOB, etc. without a namespace.

ALICE   = Runar::TestKeys::ALICE
BOB     = Runar::TestKeys::BOB
CHARLIE = Runar::TestKeys::CHARLIE
DAVE    = Runar::TestKeys::DAVE
EVE     = Runar::TestKeys::EVE
FRANK   = Runar::TestKeys::FRANK
GRACE   = Runar::TestKeys::GRACE
HEIDI   = Runar::TestKeys::HEIDI
IVAN    = Runar::TestKeys::IVAN
JUDY    = Runar::TestKeys::JUDY

# -- Top-level builtin functions ---------------------------------------------
# These are defined at the top level so contracts can call them without a
# namespace prefix.

# Include Builtins into the Runar base classes so contract instance methods
# can call builtins directly (e.g., `assert check_sig(sig, pub_key)`).
Runar::SmartContract.include(Runar::Builtins)

# Define an EC mixin module that delegates to Runar::EC class methods,
# so contract instance methods can call ec_* directly.
module Runar
  module ECMixin
    %i[ec_add ec_mul ec_mul_gen ec_negate ec_on_curve ec_mod_reduce
       ec_encode_compressed ec_make_point ec_point_x ec_point_y].each do |m|
      define_method(m) { |*args| Runar::EC.send(m, *args) }
    end
  end
end
Runar::SmartContract.include(Runar::ECMixin)

# Define top-level module functions for use outside contract instances
# (e.g., in test setup code).
module Kernel
  # Hash functions
  def hash160(data)
    Runar.hash160(data)
  end

  def hash256(data)
    Runar.hash256(data)
  end

  def sha256(data)
    Runar.sha256(data)
  end

  def ripemd160(data)
    Runar.ripemd160(data)
  end

  # Crypto mocks
  def check_sig(sig, pk)
    Runar.check_sig(sig, pk)
  end

  def check_multi_sig(sigs, pks)
    Runar.check_multi_sig(sigs, pks)
  end

  def check_preimage(preimage)
    Runar.check_preimage(preimage)
  end

  def verify_rabin_sig(msg, sig, padding, pk)
    Runar.verify_rabin_sig(msg, sig, padding, pk)
  end

  def verify_wots(msg, sig, pubkey)
    Runar.verify_wots(msg, sig, pubkey)
  end

  def verify_slh_dsa_sha2_128s(msg, sig, pubkey)
    Runar.verify_slh_dsa_sha2_128s(msg, sig, pubkey)
  end

  def verify_slh_dsa_sha2_128f(msg, sig, pubkey)
    Runar.verify_slh_dsa_sha2_128f(msg, sig, pubkey)
  end

  def verify_slh_dsa_sha2_192s(msg, sig, pubkey)
    Runar.verify_slh_dsa_sha2_192s(msg, sig, pubkey)
  end

  def verify_slh_dsa_sha2_192f(msg, sig, pubkey)
    Runar.verify_slh_dsa_sha2_192f(msg, sig, pubkey)
  end

  def verify_slh_dsa_sha2_256s(msg, sig, pubkey)
    Runar.verify_slh_dsa_sha2_256s(msg, sig, pubkey)
  end

  def verify_slh_dsa_sha2_256f(msg, sig, pubkey)
    Runar.verify_slh_dsa_sha2_256f(msg, sig, pubkey)
  end

  def blake3_compress(chaining_value, block)
    Runar.blake3_compress(chaining_value, block)
  end

  def blake3_hash(message)
    Runar.blake3_hash(message)
  end

  # Binary utilities
  def num2bin(v, length)
    Runar.num2bin(v, length)
  end

  def bin2num(data)
    Runar.bin2num(data)
  end

  def cat(a, b)
    Runar.cat(a, b)
  end

  def substr(data, start, length)
    Runar.substr(data, start, length)
  end

  def left(data, length)
    Runar.left(data, length)
  end

  def right(data, length)
    Runar.right(data, length)
  end

  def reverse_bytes(data)
    Runar.reverse_bytes(data)
  end

  def len_(data)
    Runar.len_(data)
  end

  # Math
  def safediv(a, b)
    Runar.safediv(a, b)
  end

  def safemod(a, b)
    Runar.safemod(a, b)
  end

  def within(x, lo, hi)
    Runar.within(x, lo, hi)
  end

  def sign_(n)
    Runar.sign_(n)
  end

  def pow_(base, exp)
    Runar.pow_(base, exp)
  end

  def mul_div(a, b, c)
    Runar.mul_div(a, b, c)
  end

  def percent_of(amount, bps)
    Runar.percent_of(amount, bps)
  end

  def sqrt_(n)
    Runar.sqrt_(n)
  end

  def gcd_(a, b)
    Runar.gcd_(a, b)
  end

  def divmod_(a, b)
    Runar.divmod_(a, b)
  end

  def log2_(n)
    Runar.log2_(n)
  end

  def bool_cast(n)
    Runar.bool_cast(n)
  end

  # Test helpers
  def mock_sig
    Runar.mock_sig
  end

  def mock_pub_key
    Runar.mock_pub_key
  end

  def mock_preimage
    Runar.mock_preimage
  end

  # Preimage extraction
  def extract_locktime(preimage)
    Runar.extract_locktime(preimage)
  end

  def extract_output_hash(preimage)
    Runar.extract_output_hash(preimage)
  end

  def extract_amount(preimage)
    Runar.extract_amount(preimage)
  end

  def extract_version(preimage)
    Runar.extract_version(preimage)
  end

  def extract_sequence(preimage)
    Runar.extract_sequence(preimage)
  end

  def extract_hash_prevouts(preimage)
    Runar.extract_hash_prevouts(preimage)
  end

  def extract_outpoint(preimage)
    Runar.extract_outpoint(preimage)
  end

  # EC operations
  def ec_add(a, b)
    Runar::EC.ec_add(a, b)
  end

  def ec_mul(p, k)
    Runar::EC.ec_mul(p, k)
  end

  def ec_mul_gen(k)
    Runar::EC.ec_mul_gen(k)
  end

  def ec_negate(p)
    Runar::EC.ec_negate(p)
  end

  def ec_on_curve(p)
    Runar::EC.ec_on_curve(p)
  end

  def ec_mod_reduce(value, m)
    Runar::EC.ec_mod_reduce(value, m)
  end

  def ec_encode_compressed(p)
    Runar::EC.ec_encode_compressed(p)
  end

  def ec_make_point(x, y)
    Runar::EC.ec_make_point(x, y)
  end

  def ec_point_x(p)
    Runar::EC.ec_point_x(p)
  end

  def ec_point_y(p)
    Runar::EC.ec_point_y(p)
  end
end

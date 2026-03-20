# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'OraclePriceFeed.runar'

RSpec.describe OraclePriceFeed do
  # Rabin test keypair (same primes as the Python / TypeScript reference).
  # p = 1361129467683753853853498429727072846227 (130-bit, 3 mod 4)
  # q = 1361129467683753853853498429727082846007 (130-bit, 3 mod 4)
  # n = p * q  (little-endian hex below)
  RABIN_N    = '950b36f00000000000000000000000002863620200000000000000000000000010'
  # Pre-computed Rabin signature for price=60000 (num2bin(60000,8) = 60ea000000000000)
  # Satisfies: (sig^2 + padding) mod n == SHA256(msg) mod n
  RABIN_SIG  = '35f75f63384cae3c1f874e64d0d4692ea1cb595df52fe14930745c43e16f6eb001'
  RABIN_PAD  = '040000000000000000000000000000000000000000000000000000000000000000'

  it 'settles with valid oracle signature and price above threshold' do
    c = OraclePriceFeed.new(RABIN_N, mock_pub_key)
    expect { c.settle(60_000, RABIN_SIG, RABIN_PAD, mock_sig) }.not_to raise_error
  end

  it 'rejects a price below the threshold' do
    c = OraclePriceFeed.new(RABIN_N, mock_pub_key)
    expect { c.settle(50_000, RABIN_SIG, RABIN_PAD, mock_sig) }.to raise_error(RuntimeError)
  end
end

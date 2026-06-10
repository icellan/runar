# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'CovenantVault.runar'

# Adversarial coverage for the CovenantVault contract.
#
# The contract enforces:
#   hash256(num2bin(min_amount, 8) || 1976a914 || recipient || 88ac)
#     == extract_output_hash(tx_preimage)
#
# In the Ruby builtins, every byte string is represented as hex. The mock
# extract_output_hash (packages/runar-rb/lib/runar/builtins.rb:425) returns
# the first 64 hex chars (32 bytes) of the preimage. We drive adversarial
# cases by setting tx_preimage to hash256(adversarial_outputs).
RSpec.describe CovenantVault do
  let(:alice)      { Runar::TestKeys::ALICE }
  let(:bob)        { Runar::TestKeys::BOB }
  let(:min_amount) { 5000 }

  # Build the canonical 34-byte P2PKH output as a hex string:
  #   8-byte LE amount || 1976a914 || pkh || 88ac.
  def p2pkh_output_hex(amount, pkh_hex)
    Runar::Builtins.instance_method(:num2bin).bind_call(self_for_builtins, amount, 8) + \
      '1976a914' + pkh_hex + '88ac'
  end

  # Build a 181-byte preimage hex string whose first 32 bytes are
  # hash256(outputs_hex). Pads with zeros so the preimage is the canonical
  # 181-byte BIP-143 length.
  def preimage_for(outputs_hex)
    sha1 = Digest::SHA256.hexdigest([outputs_hex].pack('H*'))
    sha2 = Digest::SHA256.hexdigest([sha1].pack('H*'))
    sha2 + ('00' * (181 - 32))
  end

  # Helper that gives our helper functions access to the Runar::Builtins
  # instance methods (which are defined on SmartContract instances).
  let(:self_for_builtins) { Class.new { include Runar::Builtins }.new }

  it 'instantiates with valid constructor arguments' do
    c = CovenantVault.new(alice.pub_key, bob.pub_key_hash, min_amount)
    expect(c.owner).not_to be_nil
    expect(c.min_amount).to eq(min_amount)
  end

  it 'accepts the canonical single-output transaction (happy path)' do
    c = CovenantVault.new(alice.pub_key, bob.pub_key_hash, min_amount)
    outputs = p2pkh_output_hex(min_amount, bob.pub_key_hash)
    expect { c.spend(alice.test_sig, preimage_for(outputs)) }.not_to raise_error
  end

  # -- Adversarial: wrong output count ---------------------------------------

  it 'rejects when the spending transaction commits zero outputs (n-1)' do
    c = CovenantVault.new(alice.pub_key, bob.pub_key_hash, min_amount)
    expect { c.spend(alice.test_sig, preimage_for('')) }.to raise_error(RuntimeError)
  end

  it 'rejects when the spending transaction commits an extra output (n+1)' do
    c = CovenantVault.new(alice.pub_key, bob.pub_key_hash, min_amount)
    required = p2pkh_output_hex(min_amount, bob.pub_key_hash)
    extra = p2pkh_output_hex(1000, 'cc' * 20)
    expect { c.spend(alice.test_sig, preimage_for(required + extra)) }
      .to raise_error(RuntimeError)
  end

  # -- Adversarial: swapped output order -------------------------------------

  it 'rejects when the required output is preceded by an unauthorised one' do
    c = CovenantVault.new(alice.pub_key, bob.pub_key_hash, min_amount)
    required = p2pkh_output_hex(min_amount, bob.pub_key_hash)
    other = p2pkh_output_hex(min_amount, 'cc' * 20)
    expect { c.spend(alice.test_sig, preimage_for(other + required)) }
      .to raise_error(RuntimeError)
  end

  # -- Adversarial: value at boundary ----------------------------------------

  it 'rejects when the output amount is one satoshi below min_amount' do
    c = CovenantVault.new(alice.pub_key, bob.pub_key_hash, min_amount)
    candidate = p2pkh_output_hex(min_amount - 1, bob.pub_key_hash)
    expect { c.spend(alice.test_sig, preimage_for(candidate)) }
      .to raise_error(RuntimeError)
  end

  it 'rejects when the output amount is one satoshi above min_amount' do
    c = CovenantVault.new(alice.pub_key, bob.pub_key_hash, min_amount)
    candidate = p2pkh_output_hex(min_amount + 1, bob.pub_key_hash)
    expect { c.spend(alice.test_sig, preimage_for(candidate)) }
      .to raise_error(RuntimeError)
  end
end

# frozen_string_literal: true

require 'spec_helper'

# rubocop:disable Metrics/BlockLength
RSpec.describe Runar::TestKeys do
  describe 'TestKeyPair struct' do
    it 'has the expected fields' do
      expect(Runar::TestKeys::TestKeyPair.members).to eq(%i[name priv_key pub_key pub_key_hash test_sig])
    end
  end

  describe 'TEST_KEYS array' do
    it 'contains all 10 keys' do
      expect(described_class::TEST_KEYS.length).to eq(10)
    end

    it 'contains exactly the expected names' do
      names = described_class::TEST_KEYS.map(&:name)
      expect(names).to eq(%w[alice bob charlie dave eve frank grace heidi ivan judy])
    end
  end

  describe 'field types' do
    described_class::TEST_KEYS.each do |key|
      context "#{key.name}" do
        it 'has a string name' do
          expect(key.name).to be_a(String)
        end

        it 'has a 64-character hex priv_key' do
          expect(key.priv_key).to match(/\A[0-9a-f]{64}\z/)
        end

        it 'has a 66-character hex pub_key (33 bytes compressed)' do
          expect(key.pub_key).to match(/\A(02|03)[0-9a-f]{64}\z/)
        end

        it 'has a 40-character hex pub_key_hash (20 bytes HASH160)' do
          expect(key.pub_key_hash).to match(/\A[0-9a-f]{40}\z/)
        end

        it 'has a non-empty hex test_sig starting with 30 (DER sequence tag)' do
          expect(key.test_sig).to match(/\A30[0-9a-f]+\z/)
        end
      end
    end
  end

  describe 'ALICE' do
    subject(:alice) { described_class::ALICE }

    it 'has the correct private key matching Python reference' do
      expect(alice.priv_key).to eq('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    end

    it 'has the correct pub_key matching Python reference' do
      # Value confirmed against packages/runar-py/runar/test_keys.py
      expect(alice.pub_key).to eq('03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd')
    end

    it 'has the correct pub_key_hash (HASH160 of pub_key)' do
      computed = Runar::Builtins::TEST_MESSAGE_DIGEST # just to confirm require works
      expect(alice.pub_key_hash.length).to eq(40)
      # Verify pub_key_hash is HASH160(pub_key)
      ctx = Object.new.extend(Runar::Builtins)
      expected_hash = ctx.hash160(alice.pub_key)
      expect(alice.pub_key_hash).to eq(expected_hash)
    end

    it 'test_sig verifies against pub_key using ECDSA.verify' do
      digest = Runar::Builtins::TEST_MESSAGE_DIGEST
      expect(Runar::ECDSA.verify(digest, alice.test_sig, alice.pub_key)).to be true
    end

    it 'test_sig matches sign_test_message output' do
      expected = Runar::ECDSA.sign_test_message(alice.priv_key)
      expect(alice.test_sig).to eq(expected)
    end
  end

  describe 'BOB' do
    subject(:bob) { described_class::BOB }

    it 'has the correct private key' do
      expect(bob.priv_key).to eq('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2')
    end

    it 'test_sig verifies against pub_key' do
      digest = Runar::Builtins::TEST_MESSAGE_DIGEST
      expect(Runar::ECDSA.verify(digest, bob.test_sig, bob.pub_key)).to be true
    end

    it 'test_sig does NOT verify against ALICE pub_key' do
      digest = Runar::Builtins::TEST_MESSAGE_DIGEST
      expect(Runar::ECDSA.verify(digest, bob.test_sig, described_class::ALICE.pub_key)).to be false
    end
  end

  describe 'all keys self-verify' do
    described_class::TEST_KEYS.each do |key|
      it "#{key.name}'s test_sig verifies against their own pub_key" do
        digest = Runar::Builtins::TEST_MESSAGE_DIGEST
        expect(Runar::ECDSA.verify(digest, key.test_sig, key.pub_key)).to be true
      end
    end
  end
end
# rubocop:enable Metrics/BlockLength

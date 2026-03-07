# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Runar::DSL do
  describe 'prop' do
    it 'creates accessor methods and stores metadata' do
      klass = Class.new(Runar::StatefulSmartContract) do
        prop :balance, Bigint
      end

      expect(klass.runar_properties).to contain_exactly(
        { name: :balance, type: Integer, readonly: false }
      )
      obj = klass.new
      obj.balance = 42
      expect(obj.balance).to eq(42)
    end

    it 'forces all props to readonly in SmartContract' do
      klass = Class.new(Runar::SmartContract) do
        prop :pub_key_hash, Addr
      end

      expect(klass.runar_properties).to contain_exactly(
        { name: :pub_key_hash, type: String, readonly: true }
      )
      obj = klass.new
      expect(obj).to respond_to(:pub_key_hash)
      expect(obj).not_to respond_to(:pub_key_hash=)
    end

    it 'supports readonly: true on StatefulSmartContract props' do
      klass = Class.new(Runar::StatefulSmartContract) do
        prop :token_id, ByteString, readonly: true
        prop :balance, Bigint
      end

      props = klass.runar_properties
      expect(props[0]).to eq({ name: :token_id, type: String, readonly: true })
      expect(props[1]).to eq({ name: :balance, type: Integer, readonly: false })

      obj = klass.new
      expect(obj).to respond_to(:token_id)
      expect(obj).not_to respond_to(:token_id=)
      expect(obj).to respond_to(:balance=)
    end
  end

  describe 'runar_public' do
    it 'sets visibility on the next defined method' do
      klass = Class.new(Runar::SmartContract) do
        runar_public sig: Sig, pub_key: PubKey
        def unlock(sig, pub_key); end
      end

      methods = klass.runar_methods
      expect(methods[:unlock][:visibility]).to eq(:public)
      expect(methods[:unlock][:param_types]).to eq({ sig: String, pub_key: String })
    end

    it 'works without parameter types' do
      klass = Class.new(Runar::SmartContract) do
        runar_public
        def increment; end
      end

      methods = klass.runar_methods
      expect(methods[:increment][:visibility]).to eq(:public)
      expect(methods[:increment][:param_types]).to eq({})
    end
  end

  describe 'params' do
    it 'stores param types on the next method as private' do
      klass = Class.new(Runar::SmartContract) do
        params amount: Bigint
        def helper(amount); end
      end

      methods = klass.runar_methods
      expect(methods[:helper][:visibility]).to eq(:private)
      expect(methods[:helper][:param_types]).to eq({ amount: Integer })
    end
  end

  describe 'runar_properties and runar_methods' do
    it 'returns empty arrays/hashes when nothing is declared' do
      klass = Class.new(Runar::SmartContract)
      expect(klass.runar_properties).to eq([])
      expect(klass.runar_methods).to eq({})
    end
  end
end

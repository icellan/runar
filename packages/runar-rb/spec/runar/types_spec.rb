# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Runar::Types do
  it 'defines Bigint as Integer' do
    expect(Runar::Types::Bigint).to eq(Integer)
  end

  it 'defines Int as Integer' do
    expect(Runar::Types::Int).to eq(Integer)
  end

  it 'defines ByteString as String' do
    expect(Runar::Types::ByteString).to eq(String)
  end

  it 'defines PubKey as String' do
    expect(Runar::Types::PubKey).to eq(String)
  end

  it 'defines Sig as String' do
    expect(Runar::Types::Sig).to eq(String)
  end

  it 'defines Addr as String' do
    expect(Runar::Types::Addr).to eq(String)
  end

  it 'defines Sha256 as String' do
    expect(Runar::Types::Sha256).to eq(String)
  end

  it 'defines Ripemd160 as String' do
    expect(Runar::Types::Ripemd160).to eq(String)
  end

  it 'defines SigHashPreimage as String' do
    expect(Runar::Types::SigHashPreimage).to eq(String)
  end

  it 'defines RabinSig as String' do
    expect(Runar::Types::RabinSig).to eq(String)
  end

  it 'defines RabinPubKey as String' do
    expect(Runar::Types::RabinPubKey).to eq(String)
  end

  it 'defines Point as String' do
    expect(Runar::Types::Point).to eq(String)
  end

  context 'top-level constants' do
    it 'exposes Bigint at top level' do
      expect(::Bigint).to eq(Integer)
    end

    it 'exposes PubKey at top level' do
      expect(::PubKey).to eq(String)
    end

    it 'exposes Addr at top level' do
      expect(::Addr).to eq(String)
    end

    it 'exposes Point at top level' do
      expect(::Point).to eq(String)
    end
  end
end

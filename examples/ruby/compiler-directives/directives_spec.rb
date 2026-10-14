# frozen_string_literal: true

# Directives (N-093): the native Ruby spellings of the compiler directives.
# Natively, embed_always: true is only property metadata and runar_sighash is
# a no-op, so the contract behaves like any other; compile_check proves the
# Ruby compiler frontend accepts both spellings.

require_relative '../spec_helper'
require_relative 'Directives.runar'

compiler_lib = File.expand_path('../../../compilers/ruby/lib', __dir__)
$LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)

RSpec.describe Directives do
  let(:pk) { mock_pub_key }
  let(:contract) { Directives.new(hash160(pk), '0102') }

  it 'spend_all unlocks with the matching key' do
    expect { contract.spend_all(mock_sig, pk) }.not_to raise_error
  end

  it 'spend_single (runar_sighash) stays an ordinary callable natively' do
    expect { contract.spend_single(mock_sig, pk) }.not_to raise_error
  end

  it 'spend_all fails with a wrong public key' do
    expect { contract.spend_all(mock_sig, '03' + '00' * 32) }.to raise_error(RuntimeError)
  end

  it 'spend_single fails with a wrong public key' do
    expect { contract.spend_single(mock_sig, '03' + '00' * 32) }.to raise_error(RuntimeError)
  end

  it 'keeps deploy_tag on the instance and records embed_always' do
    expect(contract.deploy_tag).to eq('0102')
    tag = Directives.runar_properties.find { |p| p[:name] == :deploy_tag }
    expect(tag[:embed_always]).to be true
  end

  it 'passes the Rúnar compile check' do
    expect(Runar.compile_check(File.expand_path('Directives.runar.rb', __dir__))).to be true
  end
end

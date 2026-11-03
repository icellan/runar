# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'runar/sdk'

# F-024 (R14): the SDK's ANF interpreter derives the post-call state before the
# tx exists; the covenant re-derives it on-chain. For a contract whose state
# depends on +continuationAmount()+ (the injected +_newAmount+) and
# +extractAmount(txPreimage)+ (the spent UTXO's satoshis), the SDK must feed
# the interpreter those real values.
#
# Proves: the Ruby SDK call path derives +last_deposit = continuation - input+
# from the call's real amounts, and the interpreter reads a caller-bound
# +_newAmount+ / Integer +txPreimage+. Ruby ships no ScriptVM, so the on-chain
# verdict is covered by the TS/Go SDK tests, not here.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'F-024 continuationAmount() in the SDK interpreter' do
  # rubocop:enable RSpec/DescribeClass
  let(:caller_address) { '00' * 20 }
  let(:caller_pub_key) { '02' + ('00' * 32) }

  TIP_SRC = <<~RUBY
    require 'runar'

    class Tip < Runar::StatefulSmartContract
      prop :last_deposit, Bigint

      def initialize(last_deposit)
        super(last_deposit)
        @last_deposit = last_deposit
      end

      runar_public
      def deposit
        @last_deposit = continuation_amount() - extract_amount(@tx_preimage)
      end
    end
  RUBY

  def load_artifact(dir)
    compiler_lib = File.expand_path('../../../../compilers/ruby/lib', __dir__)
    $LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)
    require 'runar_compiler'
    path = File.join(dir, 'Tip.runar.rb')
    File.write(path, TIP_SRC)
    Runar::SDK::RunarArtifact.from_json(RunarCompiler.artifact_to_json(RunarCompiler.compile_from_source(path)))
  end

  it 'reads a caller-bound _newAmount and an Integer txPreimage' do
    Dir.mktmpdir do |dir|
      art = load_artifact(dir)
      out = Runar::SDK::ANFInterpreter.compute_new_state(
        art.anf, 'deposit', { 'lastDeposit' => 0 }, { '_newAmount' => 7000, 'txPreimage' => 5000 }
      )
      expect(out['lastDeposit']).to eq(2000)
    end
  end

  it 'derives the post-call state from the real call amounts' do
    Dir.mktmpdir do |dir|
      contract = Runar::SDK::RunarContract.new(load_artifact(dir), [0])
      provider = Runar::SDK::MockProvider.new
      signer   = Runar::SDK::MockSigner.new(pub_key_hex: caller_pub_key, address: caller_address)
      contract.connect(provider, signer)
      provider.add_utxo(caller_address, Runar::SDK::Utxo.new(txid: 'ee' * 32, output_index: 0, satoshis: 1_000_000,
                                                             script: "76a914#{caller_address}88ac"))
      contract.deploy(provider, signer, Runar::SDK::DeployOptions.new(satoshis: 10_000))
      provider.add_utxo(caller_address, Runar::SDK::Utxo.new(txid: 'ff' * 32, output_index: 0, satoshis: 1_000_000,
                                                             script: "76a914#{caller_address}88ac"))
      contract.call('deposit', [], nil, nil, Runar::SDK::CallOptions.new(satoshis: 12_500))
      expect(contract.get_state).to eq('lastDeposit' => 2500)
      expect(contract.get_utxo.satoshis).to eq(12_500)
    end
  end
end

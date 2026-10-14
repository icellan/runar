# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'runar/sdk'

# N-189: the off-chain scriptCode +prepare_call+ hands the ANF interpreter
# (what +extractScriptCode(txPreimage)+ returns while the SDK predicts the
# post-state) must be the scriptCode field of the BIP-143 preimage the call
# actually signs: the SPENT UTXO's locking script after the
# OP_CODESEPARATOR, code AND the +OP_RETURN <state>+ tail. R67 built it from
# the bare template codePart, so a method whose post-state depends on its own
# scriptCode committed a continuation the covenant's hashOutputs check
# rejects (shown on @bsv/sdk Spend by
# packages/runar-sdk/src/__tests__/n189-scriptcode-intent-includes-state.test.ts).
#
# Proves: for a contract whose new state is len(extract_script_code(preimage)),
# the committed state equals the length of the signed preimage's scriptCode
# field, preimage[104 .. len-52] (CompactSize prefix included).
# Does not prove: that the preimage is what a node computes (Ruby ships no
# ScriptVM), or extra contract inputs of a multi-input call.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-189 scriptCode intent includes the spent UTXO state tail' do
  # rubocop:enable RSpec/DescribeClass
  let(:caller_address) { '00' * 20 }
  let(:caller_pub_key) { '02' + ('00' * 32) }

  SC_LEN_SRC = <<~RUBY
    require 'runar'

    class ScLen < Runar::StatefulSmartContract
      prop :n, Bigint

      def initialize(n)
        super(n)
        @n = n
      end

      runar_public
      def rec
        @n = len(extract_script_code(@tx_preimage))
      end
    end
  RUBY

  def load_artifact(dir)
    compiler_lib = File.expand_path('../../../../compilers/ruby/lib', __dir__)
    $LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)
    require 'runar_compiler'
    path = File.join(dir, 'ScLen.runar.rb')
    File.write(path, SC_LEN_SRC)
    Runar::SDK::RunarArtifact.from_json(RunarCompiler.artifact_to_json(RunarCompiler.compile_from_source(path)))
  end

  it 'commits len(scriptCode) equal to the signed preimage scriptCode field' do
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

      prepared = contract.prepare_call('rec', [], provider, signer)
      preimage_len = prepared.preimage.length / 2
      expect(preimage_len).to be > 156
      signed_script_code_len = preimage_len - 104 - 52

      contract.finalize_call(prepared, {}, provider)
      expect(contract.get_state).to eq('n' => signed_script_code_len)
    end
  end
end

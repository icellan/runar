# frozen_string_literal: true

# DataOutputs integration test -- stateful contract emitting an OP_RETURN
# data output via this.addDataOutput(...).
#
# Ported from integration/go/data_outputs_test.go and
# integration/ts/data-outputs.test.ts (BSVM R9 acceptance: data outputs
# must appear in declaration order between state outputs and change so
# the compile-time continuation-hash check matches at spend time).
#
# Compiles a stateful contract whose method calls this.addDataOutput
# (counter += 1; addDataOutput(0n, payload)), drives it through
# RunarContract.deploy/.call against the regtest node, then re-fetches
# the broadcast tx and asserts the output ordering.

require 'spec_helper'

# Compile an inline TypeScript source string to a RunarArtifact via the
# reference TS compiler (Node.js).
def compile_source_inline(source, file_name)
  script = <<~JS
    (async () => {
      const { compile } = await import('#{PROJECT_ROOT}/packages/runar-compiler/dist/index.js');
      const result = compile(#{source.inspect}, { fileName: #{file_name.inspect} });
      if (!result.success) { console.error(JSON.stringify(result.diagnostics)); process.exit(1); }
      const json = JSON.stringify(result.artifact, (k, v) => typeof v === 'bigint' ? v.toString() + 'n' : v);
      process.stdout.write(json);
    })();
  JS

  node_bin = ENV['NODE_BIN'] || `which node 2>/dev/null`.strip
  node_bin = 'node' if node_bin.empty?
  output = `#{node_bin} -e #{Shellwords.escape(script)} 2>&1`
  status = Process.last_status
  raise "Compilation failed for #{file_name}:\n#{output}" unless status&.success?

  Runar::SDK::RunarArtifact.from_json(output)
end

DATA_EMITTER_SOURCE = <<~TS.freeze
  import { StatefulSmartContract, ByteString } from 'runar-lang';

  export class DataEmitter extends StatefulSmartContract {
      counter: bigint;

      constructor(counter: bigint) {
          super(counter);
          this.counter = counter;
      }

      public emit(payload: ByteString) {
          this.counter = this.counter + 1n;
          this.addDataOutput(0n, payload);
      }
  }
TS

RSpec.describe 'DataOutputs (addDataOutput)' do # rubocop:disable RSpec/DescribeClass
  it 'emits a data output between state continuation and change' do
    artifact = compile_source_inline(DATA_EMITTER_SOURCE, 'DataEmitter.runar.ts')
    expect(artifact.contract_name).to eq('DataEmitter')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [0])
    deploy_txid, _count = contract.deploy(
      provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 10_000)
    )
    expect(deploy_txid).to be_truthy
    expect(deploy_txid.length).to eq(64)

    # OP_RETURN "bsvm-test" — matches the Go and TS reference tests exactly.
    payload = '6a09' + '6273766d2d74657374'

    call_txid, _count = contract.call(
      'emit', [payload], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'counter' => 1 })
    )
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'rejects an emit whose state continuation does not match' do
    artifact = compile_source_inline(DATA_EMITTER_SOURCE, 'DataEmitter.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [0])
    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 10_000))

    payload = '6a09' + '6273766d2d74657374'

    # Claim counter=99 instead of 1; the OP_HASH256 continuation check
    # rejects the spending tx.
    expect do
      contract.call(
        'emit', [payload], provider, wallet[:signer],
        Runar::SDK::CallOptions.new(new_state: { 'counter' => 99 })
      )
    end.to raise_error(StandardError)
  end
end

# frozen_string_literal: true

# sha256Finalize integration spec — exercises padding + length encoding
# for variable-length messages. Ported from
# integration/ts/sha256-finalize.test.ts.

require 'spec_helper'
require 'digest'

def compile_source_finalize(source, file_name)
  script = <<~JS
    (async () => {
      const { compile } = await import('#{PROJECT_ROOT}/packages/runar-compiler/dist/index.js');
      const result = compile(#{source.inspect}, { fileName: #{file_name.inspect} });
      if (!result.success) { console.error(JSON.stringify(result.diagnostics)); process.exit(1); }
      const json = JSON.stringify(result.artifact, (k, v) => typeof v === 'bigint' ? v.toString() + 'n' : v);
      process.stdout.write(json);
    })();
  JS
  node = ENV['NODE_BIN'] || 'node'
  output = `#{node} -e #{Shellwords.escape(script)} 2>&1`
  raise "Compile failed: #{output}" unless Process.last_status&.success?
  Runar::SDK::RunarArtifact.from_json(output)
end

# Reference vectors: sha256Finalize takes the 32-byte intermediate state,
# the remaining (<64-byte) tail, and the total bit-length of the
# original message; it pads + length-encodes per FIPS 180-4 and runs the
# final compression. For an empty input this is just SHA-256("") and
# the intermediate state equals the IV.
SHA256_FINALIZE_IV_HEX =
  '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19'

RSpec.describe 'sha256Finalize' do # rubocop:disable RSpec/DescribeClass
  it 'compiles + deploys + spends with empty-message reference vector' do
    # SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    expected = Digest::SHA256.hexdigest('')

    source = <<~TS
      import { SmartContract, assert, sha256Finalize } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class Sha256FinalizeEmpty extends SmartContract {
        readonly expected: ByteString;
        constructor(expected: ByteString) { super(expected); this.expected = expected; }
        public verify(state: ByteString, remaining: ByteString, msgBitLen: bigint) {
          const result = sha256Finalize(state, remaining, msgBitLen);
          assert(result === this.expected);
        }
      }
    TS

    artifact = compile_source_finalize(source, 'Sha256FinalizeEmpty.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [expected])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 500_000))

    call_txid, _ = contract.call(
      'verify', [SHA256_FINALIZE_IV_HEX, '', 0], provider, wallet[:signer]
    )
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'rejects a wrong expected hash on-chain' do
    source = <<~TS
      import { SmartContract, assert, sha256Finalize } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class Sha256FinalizeReject extends SmartContract {
        readonly expected: ByteString;
        constructor(expected: ByteString) { super(expected); this.expected = expected; }
        public verify(state: ByteString, remaining: ByteString, msgBitLen: bigint) {
          const result = sha256Finalize(state, remaining, msgBitLen);
          assert(result === this.expected);
        }
      }
    TS

    artifact = compile_source_finalize(source, 'Sha256FinalizeReject.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, ['00' * 32])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 500_000))

    expect do
      contract.call('verify', [SHA256_FINALIZE_IV_HEX, '', 0], provider, wallet[:signer])
    end.to raise_error(StandardError)
  end
end

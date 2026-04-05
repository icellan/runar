# frozen_string_literal: true

# Baby Bear field arithmetic integration tests -- inline contracts testing
# bbFieldAdd/bbFieldInv on a real regtest node.
#
# Each test compiles a minimal stateless contract that exercises Baby Bear
# built-ins, deploys it on regtest, and spends via contract.call().

require 'spec_helper'
require 'tempfile'

# Baby Bear prime
BB_P = 2_013_265_921

# Compile an inline TypeScript source string to a RunarArtifact.
#
# Writes the source to a temp file in /tmp/, shells out to the TS compiler,
# and cleans up afterwards.
#
# @param source    [String] TypeScript contract source
# @param file_name [String] desired file name suffix (e.g. "MyContract.runar.ts")
# @return [Runar::SDK::RunarArtifact]
def compile_source_bb(source, file_name)
  require 'shellwords'

  script = <<~JS
    (async () => {
      const { compile } = await import('#{PROJECT_ROOT}/packages/runar-compiler/dist/index.js');
      const result = compile(#{source.inspect}, { fileName: #{file_name.inspect} });
      if (!result.success) { console.error(JSON.stringify(result.diagnostics)); process.exit(1); }
      const json = JSON.stringify(result.artifact, (k, v) => typeof v === 'bigint' ? v.toString() + 'n' : v);
      process.stdout.write(json);
    })();
  JS

  output = `node -e #{Shellwords.escape(script)} 2>&1`
  status = Process.last_status
  raise "Compilation failed for #{file_name}:\n#{output}" unless status&.success?

  Runar::SDK::RunarArtifact.from_json(output)
end

RSpec.describe 'Baby Bear field arithmetic' do # rubocop:disable RSpec/DescribeClass
  it 'bbFieldAdd: (3 + 7) mod p = 10' do
    source = <<~TS
      import { SmartContract, assert, bbFieldAdd } from 'runar-lang';

      class BBAddTest extends SmartContract {
        readonly expected: bigint;
        constructor(expected: bigint) { super(expected); this.expected = expected; }
        public verify(a: bigint, b: bigint) {
          assert(bbFieldAdd(a, b) === this.expected);
        }
      }
    TS

    artifact = compile_source_bb(source, 'BBAddTest.runar.ts')
    expect(artifact.contract_name).to eq('BBAddTest')

    contract = Runar::SDK::RunarContract.new(artifact, [10])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy

    call_txid, _count = contract.call('verify', [3, 7], provider, wallet[:signer])
    expect(call_txid).to be_truthy
  end

  it 'bbFieldAdd: wrap-around (p-1) + 1 = 0' do
    source = <<~TS
      import { SmartContract, assert, bbFieldAdd } from 'runar-lang';

      class BBAddWrap extends SmartContract {
        readonly expected: bigint;
        constructor(expected: bigint) { super(expected); this.expected = expected; }
        public verify(a: bigint, b: bigint) {
          assert(bbFieldAdd(a, b) === this.expected);
        }
      }
    TS

    artifact = compile_source_bb(source, 'BBAddWrap.runar.ts')

    contract = Runar::SDK::RunarContract.new(artifact, [0])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy

    call_txid, _count = contract.call('verify', [BB_P - 1, 1], provider, wallet[:signer])
    expect(call_txid).to be_truthy
  end

  it 'bbFieldInv: a * inv(a) = 1 (algebraic identity)' do
    source = <<~TS
      import { SmartContract, assert, bbFieldInv, bbFieldMul } from 'runar-lang';

      class BBInvIdentity extends SmartContract {
        constructor() { super(); }
        public verify(a: bigint) {
          const inv = bbFieldInv(a);
          assert(bbFieldMul(a, inv) === 1n);
        }
      }
    TS

    artifact = compile_source_bb(source, 'BBInvIdentity.runar.ts')
    expect(artifact.contract_name).to eq('BBInvIdentity')

    contract = Runar::SDK::RunarContract.new(artifact, [])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 500_000))
    expect(txid).to be_truthy

    call_txid, _count = contract.call('verify', [42], provider, wallet[:signer])
    expect(call_txid).to be_truthy
  end

  it 'rejects wrong add result on-chain' do
    source = <<~TS
      import { SmartContract, assert, bbFieldAdd } from 'runar-lang';

      class BBAddReject extends SmartContract {
        readonly expected: bigint;
        constructor(expected: bigint) { super(expected); this.expected = expected; }
        public verify(a: bigint, b: bigint) {
          assert(bbFieldAdd(a, b) === this.expected);
        }
      }
    TS

    artifact = compile_source_bb(source, 'BBAddReject.runar.ts')
    # Wrong expected: 3+7=10, not 11
    contract = Runar::SDK::RunarContract.new(artifact, [11])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    expect do
      contract.call('verify', [3, 7], provider, wallet[:signer])
    end.to raise_error(StandardError)
  end
end

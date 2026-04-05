# frozen_string_literal: true

# Merkle proof verification integration tests -- inline contracts testing
# merkleRootSha256 on a real regtest node.
#
# Each test compiles a minimal stateless contract with an unrolled Merkle path
# verification, deploys it on regtest, and spends via contract.call().

require 'spec_helper'
require 'digest'
require 'tempfile'

# ---------------------------------------------------------------------------
# Merkle tree helpers
# ---------------------------------------------------------------------------

def sha256_hex(hex_str)
  Digest::SHA256.hexdigest([hex_str].pack('H*'))
end

def build_sha256_tree(leaves)
  level = leaves.dup
  layers = [level]
  while level.length > 1
    next_level = []
    (0...level.length).step(2) do |i|
      next_level << sha256_hex(level[i] + level[i + 1])
    end
    level = next_level
    layers << level
  end
  { root: level[0], leaves: leaves, layers: layers }
end

def get_proof(tree, index)
  siblings = +''
  idx = index
  (0...tree[:layers].length - 1).each do |d|
    siblings << tree[:layers][d][idx ^ 1]
    idx >>= 1
  end
  [siblings, tree[:leaves][index]]
end

def build_test_tree
  leaves = (0...16).map { |i| sha256_hex(format('%02x', i)) }
  build_sha256_tree(leaves)
end

# Compile an inline TypeScript source string to a RunarArtifact.
def compile_source_merkle(source, file_name)
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

# ---------------------------------------------------------------------------
# Contract source
# ---------------------------------------------------------------------------

MERKLE_SHA256_SOURCE = <<~TS
  import { SmartContract, assert, merkleRootSha256 } from 'runar-lang';
  import type { ByteString } from 'runar-lang';

  class MerkleSha256Test extends SmartContract {
    readonly expectedRoot: ByteString;
    constructor(expectedRoot: ByteString) {
      super(expectedRoot);
      this.expectedRoot = expectedRoot;
    }
    public verify(leaf: ByteString, proof: ByteString, index: bigint) {
      const root = merkleRootSha256(leaf, proof, index, 4n);
      assert(root === this.expectedRoot);
    }
  }
TS

RSpec.describe 'Merkle proof verification' do # rubocop:disable RSpec/DescribeClass
  it 'merkleRootSha256: verifies leaf at index 0 (leftmost)' do
    tree = build_test_tree
    proof, leaf = get_proof(tree, 0)

    artifact = compile_source_merkle(MERKLE_SHA256_SOURCE, 'MerkleSha256Test.runar.ts')
    expect(artifact.contract_name).to eq('MerkleSha256Test')

    contract = Runar::SDK::RunarContract.new(artifact, [tree[:root]])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy

    call_txid, _count = contract.call('verify', [leaf, proof, 0], provider, wallet[:signer])
    expect(call_txid).to be_truthy
  end

  it 'merkleRootSha256: verifies leaf at index 7 (middle)' do
    tree = build_test_tree
    proof, leaf = get_proof(tree, 7)

    artifact = compile_source_merkle(MERKLE_SHA256_SOURCE, 'MerkleSha256Test.runar.ts')

    contract = Runar::SDK::RunarContract.new(artifact, [tree[:root]])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy

    call_txid, _count = contract.call('verify', [leaf, proof, 7], provider, wallet[:signer])
    expect(call_txid).to be_truthy
  end

  it 'rejects wrong leaf on-chain' do
    tree = build_test_tree
    proof, _leaf = get_proof(tree, 0)
    wrong_leaf = sha256_hex('ff')

    artifact = compile_source_merkle(MERKLE_SHA256_SOURCE, 'MerkleSha256Test.runar.ts')

    contract = Runar::SDK::RunarContract.new(artifact, [tree[:root]])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    expect do
      contract.call('verify', [wrong_leaf, proof, 0], provider, wallet[:signer])
    end.to raise_error(StandardError)
  end
end

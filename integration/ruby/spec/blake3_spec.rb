# frozen_string_literal: true

# BLAKE3 integration tests -- inline contracts testing blake3Compress and
# blake3Hash on a real regtest node.
#
# Ported from integration/ts/blake3.test.ts. Each test compiles a minimal
# stateless contract, deploys on regtest, and spends via contract.call().
# The compiled script is ~11 KB (BLAKE3 compression inlined) and is
# validated by a real BSV node, not just the SDK interpreter.

require 'spec_helper'

BLAKE3_IV = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
].freeze
BLAKE3_IV_HEX = BLAKE3_IV.map { |w| w.to_s(16).rjust(8, '0') }.join.freeze
BLAKE3_MSG_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8].freeze

def blake3_rotr32(x, n)
  ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
end

def blake3_add32(a, b)
  (a + b) & 0xFFFFFFFF
end

def blake3_g(state, a, b, c, d, mx, my)
  state[a] = blake3_add32(blake3_add32(state[a], state[b]), mx)
  state[d] = blake3_rotr32(state[d] ^ state[a], 16)
  state[c] = blake3_add32(state[c], state[d])
  state[b] = blake3_rotr32(state[b] ^ state[c], 12)
  state[a] = blake3_add32(blake3_add32(state[a], state[b]), my)
  state[d] = blake3_rotr32(state[d] ^ state[a], 8)
  state[c] = blake3_add32(state[c], state[d])
  state[b] = blake3_rotr32(state[b] ^ state[c], 7)
end

def blake3_round(state, m)
  blake3_g(state, 0, 4,  8, 12, m[0],  m[1])
  blake3_g(state, 1, 5,  9, 13, m[2],  m[3])
  blake3_g(state, 2, 6, 10, 14, m[4],  m[5])
  blake3_g(state, 3, 7, 11, 15, m[6],  m[7])
  blake3_g(state, 0, 5, 10, 15, m[8],  m[9])
  blake3_g(state, 1, 6, 11, 12, m[10], m[11])
  blake3_g(state, 2, 7,  8, 13, m[12], m[13])
  blake3_g(state, 3, 4,  9, 14, m[14], m[15])
end

def reference_blake3_compress(cv_hex, block_hex)
  cv = (0...8).map { |i| cv_hex[(i * 8), 8].to_i(16) }
  m  = (0...16).map { |i| block_hex[(i * 8), 8].to_i(16) }

  state = [
    cv[0], cv[1], cv[2], cv[3],
    cv[4], cv[5], cv[6], cv[7],
    BLAKE3_IV[0], BLAKE3_IV[1], BLAKE3_IV[2], BLAKE3_IV[3],
    0, 0, 64, 11
  ]

  msg = m.dup
  7.times do |r|
    blake3_round(state, msg)
    msg = BLAKE3_MSG_PERM.map { |i| msg[i] } if r < 6
  end

  output = (0...8).map { |i| (state[i] ^ state[i + 8]) & 0xFFFFFFFF }
  output.map { |w| w.to_s(16).rjust(8, '0') }.join
end

def reference_blake3_hash(msg_hex)
  padded = msg_hex.ljust(128, '0')
  reference_blake3_compress(BLAKE3_IV_HEX, padded)
end

def compile_source_blake3(source, file_name)
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

RSpec.describe 'BLAKE3' do # rubocop:disable RSpec/DescribeClass
  describe 'blake3Compress' do
    it 'deploys and spends with empty block + IV chaining value' do
      source = <<~TS
        import { SmartContract, assert, blake3Compress } from 'runar-lang';
        import type { ByteString } from 'runar-lang';

        class Blake3CompressEmpty extends SmartContract {
          readonly expected: ByteString;
          constructor(expected: ByteString) { super(expected); this.expected = expected; }
          public verify(cv: ByteString, block: ByteString) {
            const result = blake3Compress(cv, block);
            assert(result === this.expected);
          }
        }
      TS

      block    = '00' * 64
      expected = reference_blake3_compress(BLAKE3_IV_HEX, block)

      artifact = compile_source_blake3(source, 'Blake3CompressEmpty.runar.ts')
      contract = Runar::SDK::RunarContract.new(artifact, [expected])

      provider = create_provider
      wallet   = create_funded_wallet(provider)

      txid, _ = contract.deploy(
        provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 500_000)
      )
      expect(txid).to be_truthy

      call_txid, _ = contract.call('verify', [BLAKE3_IV_HEX, block], provider, wallet[:signer])
      expect(call_txid).to be_truthy
      expect(call_txid.length).to eq(64)
    end

    it 'rejects a wrong expected hash on-chain' do
      source = <<~TS
        import { SmartContract, assert, blake3Compress } from 'runar-lang';
        import type { ByteString } from 'runar-lang';

        class Blake3CompressReject extends SmartContract {
          readonly expected: ByteString;
          constructor(expected: ByteString) { super(expected); this.expected = expected; }
          public verify(cv: ByteString, block: ByteString) {
            const result = blake3Compress(cv, block);
            assert(result === this.expected);
          }
        }
      TS

      block          = '00' * 64
      wrong_expected = '00' * 32

      artifact = compile_source_blake3(source, 'Blake3CompressReject.runar.ts')
      contract = Runar::SDK::RunarContract.new(artifact, [wrong_expected])

      provider = create_provider
      wallet   = create_funded_wallet(provider)

      contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 500_000))

      expect do
        contract.call('verify', [BLAKE3_IV_HEX, block], provider, wallet[:signer])
      end.to raise_error(StandardError)
    end
  end

  describe 'blake3Hash' do
    it 'deploys and spends with "abc" message' do
      source = <<~TS
        import { SmartContract, assert, blake3Hash } from 'runar-lang';
        import type { ByteString } from 'runar-lang';

        class Blake3HashAbc extends SmartContract {
          readonly expected: ByteString;
          constructor(expected: ByteString) { super(expected); this.expected = expected; }
          public verify(message: ByteString) {
            const result = blake3Hash(message);
            assert(result === this.expected);
          }
        }
      TS

      msg_hex  = '616263'
      expected = reference_blake3_hash(msg_hex)

      artifact = compile_source_blake3(source, 'Blake3HashAbc.runar.ts')
      contract = Runar::SDK::RunarContract.new(artifact, [expected])

      provider = create_provider
      wallet   = create_funded_wallet(provider)

      contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 500_000))

      call_txid, _ = contract.call('verify', [msg_hex], provider, wallet[:signer])
      expect(call_txid).to be_truthy
      expect(call_txid.length).to eq(64)
    end
  end
end

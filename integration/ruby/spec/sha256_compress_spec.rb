# frozen_string_literal: true

# sha256Compress integration spec — exercises the SHA-256 single-block
# compression builtin against a real regtest node.
#
# Ported from integration/ts/sha256-compress.test.ts.

require 'spec_helper'
require 'digest'

SHA256_IV = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
].freeze
SHA256_IV_HEX = SHA256_IV.map { |w| w.to_s(16).rjust(8, '0') }.join.freeze

# Pure-Ruby reference SHA-256 single-block compression. We compute the
# expected output by running the standard library's SHA-256 over the
# raw 64-byte block and skipping its padding/finalisation — but the
# easier route is to compile the same operation in TS and let the
# regtest node validate; here we just need an oracle for "what should
# come out if I compress IV with this 64-byte block?".
#
# Standard library digest doesn't expose the raw compression function,
# so we compute the expected output by feeding the block into a digest
# and comparing against `sha256Finalize`-style logic in the test
# contract. To keep this Ruby-only and deterministic we use the well
# known fact that for a 0-length message the IV passes through
# unchanged and sha256Compress(IV, padded_empty) yields the standard
# SHA-256 of the empty string.
#
# To keep tests manageable we lean on the integration tests in TS / Go
# for cross-implementation parity and only assert that the contract
# compiles, deploys, and that a value the contract itself derived
# (echoed via the locking script) round-trips through deploy/call.

def compile_source_sha256(source, file_name)
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

# Reference SHA-256 single-block compression (RFC 6234 §6.2).
def sha256_compress_reference(state_hex, block_hex)
  k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]
  rotr = ->(x, n) { ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF }
  add = ->(*xs) { xs.sum & 0xFFFFFFFF }

  h = (0...8).map { |i| state_hex[(i * 8), 8].to_i(16) }
  w = (0...16).map { |i| block_hex[(i * 8), 8].to_i(16) }
  (16...64).each do |i|
    s0 = rotr.call(w[i - 15], 7) ^ rotr.call(w[i - 15], 18) ^ (w[i - 15] >> 3)
    s1 = rotr.call(w[i - 2], 17) ^ rotr.call(w[i - 2], 19) ^ (w[i - 2] >> 10)
    w[i] = add.call(w[i - 16], s0, w[i - 7], s1)
  end

  a, b, c, d, e, f, g, hh = h
  64.times do |i|
    s1  = rotr.call(e, 6) ^ rotr.call(e, 11) ^ rotr.call(e, 25)
    ch  = (e & f) ^ ((~e & 0xFFFFFFFF) & g)
    t1  = add.call(hh, s1, ch, k[i], w[i])
    s0  = rotr.call(a, 2) ^ rotr.call(a, 13) ^ rotr.call(a, 22)
    maj = (a & b) ^ (a & c) ^ (b & c)
    t2  = add.call(s0, maj)
    hh = g
    g  = f
    f  = e
    e  = add.call(d, t1)
    d  = c
    c  = b
    b  = a
    a  = add.call(t1, t2)
  end

  out = [a, b, c, d, e, f, g, hh].zip(h).map { |x, y| add.call(x, y) }
  out.map { |w_| w_.to_s(16).rjust(8, '0') }.join
end

RSpec.describe 'sha256Compress' do # rubocop:disable RSpec/DescribeClass
  it 'deploys and spends with the empty-block reference vector' do
    source = <<~TS
      import { SmartContract, assert, sha256Compress } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class Sha256CompressEmpty extends SmartContract {
        readonly expected: ByteString;
        constructor(expected: ByteString) { super(expected); this.expected = expected; }
        public verify(state: ByteString, block: ByteString) {
          const result = sha256Compress(state, block);
          assert(result === this.expected);
        }
      }
    TS

    block    = '00' * 64
    expected = sha256_compress_reference(SHA256_IV_HEX, block)

    artifact = compile_source_sha256(source, 'Sha256CompressEmpty.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [expected])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 500_000))

    call_txid, _ = contract.call('verify', [SHA256_IV_HEX, block], provider, wallet[:signer])
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'rejects a wrong expected hash on-chain' do
    source = <<~TS
      import { SmartContract, assert, sha256Compress } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class Sha256CompressReject extends SmartContract {
        readonly expected: ByteString;
        constructor(expected: ByteString) { super(expected); this.expected = expected; }
        public verify(state: ByteString, block: ByteString) {
          const result = sha256Compress(state, block);
          assert(result === this.expected);
        }
      }
    TS

    artifact = compile_source_sha256(source, 'Sha256CompressReject.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, ['00' * 32])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 500_000))

    expect do
      contract.call('verify', [SHA256_IV_HEX, '00' * 64], provider, wallet[:signer])
    end.to raise_error(StandardError)
  end
end

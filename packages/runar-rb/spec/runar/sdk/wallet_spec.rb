# frozen_string_literal: true

# WalletClient / WalletProvider / WalletSigner mock-backed coverage.
#
# WalletClient is an abstract class — apps subclass it to talk to their
# BRC-100 compatible wallet. The abstract methods intentionally raise
# NotImplementedError so a forgotten override surfaces at call time, not
# silently. This spec exercises that contract plus the concrete
# WalletProvider / WalletSigner adapters against a minimal in-process mock.
#
# Mirrors the Go coverage in packages/runar-go/sdk_wallet_test.go.

require 'spec_helper'
require 'runar/sdk/wallet'

# Minimal BRC-100 wallet stub that records calls and returns deterministic
# data without network I/O.
class MockWalletClient < Runar::SDK::WalletClient
  attr_reader :calls

  def initialize(pub_key_hex: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
    @pub_key_hex = pub_key_hex
    @calls = []
  end

  def get_public_key(protocol_id:, key_id:)
    @calls << [:get_public_key, protocol_id, key_id]
    @pub_key_hex
  end

  def create_signature(hash_to_sign:, protocol_id:, key_id:)
    @calls << [:create_signature, hash_to_sign, protocol_id, key_id]
    '30' + ('ab' * 34)
  end

  def create_action(description:, outputs:)
    @calls << [:create_action, description, outputs]
    { txid: 'deadbeef' * 8, raw_tx: '01000000' }
  end

  def list_outputs(basket:, tags: [], limit: 100)
    @calls << [:list_outputs, basket, tags, limit]
    []
  end
end


RSpec.describe Runar::SDK::WalletClient do
  it 'raises NotImplementedError on every abstract method' do
    base = described_class.new
    expect { base.get_public_key(protocol_id: [2, 'x'], key_id: '1') }.to raise_error(NotImplementedError)
    expect { base.create_signature(hash_to_sign: '00' * 32, protocol_id: [2, 'x'], key_id: '1') }.to raise_error(NotImplementedError)
    expect { base.create_action(description: 'test', outputs: []) }.to raise_error(NotImplementedError)
    expect { base.list_outputs(basket: 'b') }.to raise_error(NotImplementedError)
  end

  it 'allows a concrete subclass to override every method' do
    wallet = MockWalletClient.new
    expect(wallet.get_public_key(protocol_id: [2, 'x'], key_id: '1')).to be_a(String)
    expect(wallet.create_signature(hash_to_sign: '00' * 32, protocol_id: [2, 'x'], key_id: '1')).to be_a(String)
    expect(wallet.create_action(description: 't', outputs: [])).to include(:txid)
    expect(wallet.list_outputs(basket: 'b')).to eq([])
  end
end


RSpec.describe Runar::SDK::WalletProvider do
  let(:wallet) { MockWalletClient.new }
  let(:signer) do
    Runar::SDK::WalletSigner.new(wallet: wallet, protocol_id: [2, 'test'], key_id: '1')
  end

  it 'returns the configured network (default mainnet)' do
    wp = described_class.new(wallet: wallet, signer: signer, basket: 'b')
    expect(wp.get_network).to eq('mainnet')
  end

  it 'returns the configured network override' do
    # R-179: this used to omit arc_url, which built a testnet provider pointing
    # at the MAINNET ARC. A non-mainnet provider now names its own endpoint.
    wp = described_class.new(wallet: wallet, signer: signer, basket: 'b',
                             network: 'testnet', arc_url: 'https://arc.testnet.example')
    expect(wp.get_network).to eq('testnet')
  end

  it 'refuses a non-mainnet provider that names no ARC endpoint (R-179)' do
    expect do
      described_class.new(wallet: wallet, signer: signer, basket: 'b', network: 'testnet')
    end.to raise_error(ArgumentError, /testnet.*arc\.gorillapool\.io|arc\.gorillapool\.io.*testnet/m)
  end

  it 'keeps the mainnet default endpoint exactly as it was (R-179)' do
    [{}, { network: 'mainnet' }].each do |extra|
      wp = described_class.new(wallet: wallet, signer: signer, basket: 'b', **extra)
      expect(wp.get_network).to eq('mainnet')
      expect(wp.instance_variable_get(:@arc_url)).to eq('https://arc.gorillapool.io')
    end
  end

  it 'returns the configured fee rate (default 100)' do
    wp = described_class.new(wallet: wallet, signer: signer, basket: 'b')
    expect(wp.get_fee_rate).to eq(100)
  end

  it 'returns the configured fee rate override' do
    wp = described_class.new(wallet: wallet, signer: signer, basket: 'b', fee_rate: 250)
    expect(wp.get_fee_rate).to eq(250)
  end

  it 'returns nil from get_contract_utxo (wallets do not track contract UTXOs)' do
    wp = described_class.new(wallet: wallet, signer: signer, basket: 'b')
    expect(wp.get_contract_utxo('deadbeef')).to be_nil
  end

  it 'returns a cached tx from get_raw_transaction after cache_tx' do
    wp = described_class.new(wallet: wallet, signer: signer, basket: 'b')
    wp.cache_tx('abc', '01000000deadbeef')
    expect(wp.get_raw_transaction('abc')).to eq('01000000deadbeef')
  end

  it 'caches a raw transaction via cache_tx + get_raw_transaction roundtrip' do
    wp = described_class.new(wallet: wallet, signer: signer, basket: 'b')
    raw = '01000000' + '00' * 20
    wp.cache_tx('abc123', raw)
    expect(wp.get_raw_transaction('abc123')).to eq(raw)
  end
end


RSpec.describe Runar::SDK::WalletSigner do
  let(:wallet) { MockWalletClient.new }
  subject(:signer) do
    described_class.new(wallet: wallet, protocol_id: [2, 'test'], key_id: '1')
  end

  it 'caches the derived public key' do
    first  = signer.get_public_key
    second = signer.get_public_key
    expect(first).to eq(second)
    # One call to the wallet despite two requests
    expect(wallet.calls.count { |c| c.first == :get_public_key }).to eq(1)
  end

  # F-146: Signer#get_address is the Base58Check P2PKH address, the same
  # mainnet address LocalSigner gives for the same key (the mock's key is
  # G = private key 1). It used to be the raw 40-hex hash160, which an
  # address-keyed provider never matches. Proves equality with LocalSigner and
  # the hash160 round-trip; does not prove a live provider lookup.
  it 'returns the same Base58Check P2PKH address as LocalSigner for the same key' do
    require 'runar/sdk/local_signer'
    addr = signer.get_address
    local = Runar::SDK::LocalSigner.new(('00' * 31) + '01')
    expect(addr).to eq(local.get_address)
    expect(addr).to eq('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH')
    expect(Runar::SDK.build_p2pkh_script(addr)).to eq('76a914751e76e8199196d454941c45d1b3a323f1433bd688ac')
  end

  it 'sign_hash delegates to the wallet (no sighash-type byte appended)' do
    sig = signer.sign_hash('ab' * 32)
    expect(sig).to be_a(String)
    # Last call was a signature request
    expect(wallet.calls.last.first).to eq(:create_signature)
  end
end


# F-042: WalletProvider#broadcast used to rescue every error and fall back to a
# locally computed txid, and ignored non-2xx responses, so a transaction ARC
# never accepted was reported as broadcast (and RunarContract then tracked an
# output that does not exist).
#
# PROVES: against a real local HTTP server standing in for ARC, broadcast
# raises on a 5xx, a 4xx with an ARC error body, a 200 whose txStatus is a
# rejection (REJECTED / DOUBLE_SPEND_ATTEMPTED / SEEN_IN_ORPHAN_MEMPOOL), a 200
# carrying an ARC error `status`, a 200 without a txid, a 200 whose txid is not
# this transaction's, a read timeout and a refused connection; only an
# accepting 200 echoing this transaction's txid returns it, and only then is
# the raw tx cached.
# DOES NOT PROVE: behaviour against the live ARC service, or the complete set
# of ARC txStatus values a deployment may emit (the rejection list mirrors
# @bsv/sdk's ARC broadcaster).
RSpec.describe Runar::SDK::WalletProvider, '#broadcast (F-042)' do
  require 'socket'
  require 'net/http'

  # version 1, 0 inputs, 0 outputs, locktime 0 — a well-formed byte string
  # whose double-SHA256 is the txid ARC would report.
  let(:raw_tx) { '01000000000000000000' }
  let(:local_txid) do
    Digest::SHA256.digest(Digest::SHA256.digest([raw_tx].pack('H*'))).reverse.unpack1('H*')
  end
  let(:wallet) { MockWalletClient.new }
  let(:signer) { Runar::SDK::WalletSigner.new(wallet: wallet, protocol_id: [2, 'test'], key_id: '1') }

  def provider_for(url)
    Runar::SDK::WalletProvider.new(wallet: wallet, signer: signer, basket: 'b', arc_url: url)
  end

  # One-shot HTTP server answering the first request with `status_line`/`body`.
  def with_arc(status_line, body)
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    thread = Thread.new do
      client = server.accept
      # Drain request headers + body so the client sees a clean exchange.
      length = 0
      while (line = client.gets) && line != "\r\n"
        length = line.split(':', 2)[1].to_i if line.downcase.start_with?('content-length:')
      end
      client.read(length) if length.positive?
      client.write("HTTP/1.1 #{status_line}\r\nContent-Type: application/json\r\n" \
                   "Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
      client.close
    end
    yield "http://127.0.0.1:#{port}"
  ensure
    thread&.join(5)
    server&.close
  end

  def expect_rejected(provider, pattern)
    expect { provider.broadcast(raw_tx) }.to raise_error(RuntimeError, pattern)
    expect { provider.get_raw_transaction(local_txid) }.to raise_error(RuntimeError, /not found/)
  end

  it 'raises on an HTTP 500' do
    with_arc('500 Internal Server Error', '{"detail":"boom"}') do |url|
      expect_rejected(provider_for(url), /HTTP 500.*boom/m)
    end
  end

  it 'raises on a 4xx carrying an ARC error body' do
    body = JSON.generate(type: 'https://bitcoin-sv.github.io/arc/#/errors?id=_461', title: 'Malformed transaction',
                         status: 461, detail: 'Transaction is malformed', txid: local_txid)
    with_arc('461 Malformed', body) do |url|
      expect_rejected(provider_for(url), /HTTP 461.*Malformed/m)
    end
  end

  %w[REJECTED DOUBLE_SPEND_ATTEMPTED SEEN_IN_ORPHAN_MEMPOOL].each do |status|
    it "raises on a 200 whose txStatus is #{status}" do
      body = JSON.generate(txid: local_txid, txStatus: status, extraInfo: 'nope', status: 200)
      with_arc('200 OK', body) do |url|
        expect_rejected(provider_for(url), /#{status}/)
      end
    end
  end

  it 'raises on a 200 carrying an ARC error status field' do
    body = JSON.generate(txid: local_txid, status: 465, title: 'Fee too low', detail: 'fee too low')
    with_arc('200 OK', body) do |url|
      expect_rejected(provider_for(url), /465.*Fee too low/m)
    end
  end

  it 'raises on a 200 without a txid' do
    with_arc('200 OK', '{"txStatus":"SEEN_ON_NETWORK"}') do |url|
      expect_rejected(provider_for(url), /txid/)
    end
  end

  it 'raises on a 200 whose txid is not the transaction it was sent' do
    body = JSON.generate(txid: 'cc' * 32, txStatus: 'SEEN_ON_NETWORK')
    with_arc('200 OK', body) do |url|
      expect_rejected(provider_for(url), /#{'cc' * 32}.*#{local_txid}/m)
    end
  end

  it 'raises on a read timeout' do
    allow_any_instance_of(Net::HTTP).to receive(:request).and_raise(Net::ReadTimeout)
    expect_rejected(provider_for('http://127.0.0.1:9'), /NOT broadcast.*ReadTimeout/m)
  end

  it 'raises on a refused connection' do
    probe = TCPServer.new('127.0.0.1', 0)
    port = probe.addr[1]
    probe.close
    expect_rejected(provider_for("http://127.0.0.1:#{port}"), /NOT broadcast.*ECONNREFUSED|NOT broadcast.*refused/mi)
  end

  it "returns ARC's txid on an accepting 200 and caches the raw tx" do
    body = JSON.generate(txid: local_txid, txStatus: 'SEEN_ON_NETWORK', status: 200, title: 'OK')
    with_arc('200 OK', body) do |url|
      provider = provider_for(url)
      expect(provider.broadcast(raw_tx)).to eq(local_txid)
      expect(provider.get_raw_transaction(local_txid)).to eq(raw_tx)
    end
  end
end


# F-043: get_utxos passes the signer's 66-char compressed pubkey to
# build_p2pkh_script, which had no pubkey branch and fell through to the Base58
# decoder, where '0' is not in the alphabet — a TypeError on every call.
#
# PROVES: with a WalletSigner whose key is the secp256k1 generator G
# (0279be667e…), get_utxos returns, keeps the spendable outputs whose script is
# 76a914 HASH160(G) 88ac, and drops an output locked to another key's P2PKH
# (the Genesis address) and an unspendable one.
# DOES NOT PROVE: behaviour against a real BRC-100 wallet. (The empty-locking-script
# policy is pinned separately, in the N-043 example below.)
RSpec.describe Runar::SDK::WalletProvider, '#get_utxos (F-043)' do
  g_script       = '76a914751e76e8199196d454941c45d1b3a323f1433bd688ac'
  genesis_script = '76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac'

  let(:outputs) do
    [
      { outpoint: "#{'aa' * 32}.0", satoshis: 1000, locking_script: g_script, spendable: true },
      { outpoint: "#{'bb' * 32}.1", satoshis: 2000, locking_script: genesis_script, spendable: true },
      { outpoint: "#{'cc' * 32}.2", satoshis: 3000, locking_script: g_script, spendable: false },
      { outpoint: "#{'dd' * 32}.3", satoshis: 4000, locking_script: g_script, spendable: true }
    ]
  end
  let(:wallet) do
    w = MockWalletClient.new
    outs = outputs
    w.define_singleton_method(:list_outputs) { |basket:, tags: [], limit: 100| outs }
    w
  end
  let(:signer) { Runar::SDK::WalletSigner.new(wallet: wallet, protocol_id: [2, 'test'], key_id: '1') }

  it 'keeps only spendable outputs locked to the P2PKH of the signer pubkey' do
    wp = described_class.new(wallet: wallet, signer: signer, basket: 'b')
    utxos = wp.get_utxos('ignored')
    expect(utxos.map { |u| [u.txid, u.output_index, u.satoshis, u.script] }).to eq(
      [['aa' * 32, 0, 1000, g_script], ['dd' * 32, 3, 4000, g_script]]
    )
  end
end

# N-043: an output reported with an empty / missing locking script is dropped
# (fail-closed), matching the TypeScript reference. It used to be kept with
# script ''.
# PROVES: only the output carrying the signer's P2PKH script is returned.
# DOES NOT PROVE: behaviour against a real BRC-100 wallet.
RSpec.describe Runar::SDK::WalletProvider, '#get_utxos (N-043)' do
  g_script = '76a914751e76e8199196d454941c45d1b3a323f1433bd688ac'

  it 'drops spendable outputs whose locking script is empty or missing' do
    outs = [
      { outpoint: "#{'aa' * 32}.0", satoshis: 1000, locking_script: g_script, spendable: true },
      { outpoint: "#{'bb' * 32}.1", satoshis: 2000, locking_script: '', spendable: true },
      { outpoint: "#{'cc' * 32}.2", satoshis: 3000, spendable: true }
    ]
    wallet = MockWalletClient.new
    wallet.define_singleton_method(:list_outputs) { |basket:, tags: [], limit: 100| outs }
    signer = Runar::SDK::WalletSigner.new(wallet: wallet, protocol_id: [2, 'test'], key_id: '1')
    wp = described_class.new(wallet: wallet, signer: signer, basket: 'b')
    expect(wp.get_utxos('ignored').map { |u| [u.txid, u.script] }).to eq([['aa' * 32, g_script]])
  end
end

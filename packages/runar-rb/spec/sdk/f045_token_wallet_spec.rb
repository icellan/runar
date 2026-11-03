# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'runar/sdk'

# F-045: TokenWallet#transfer / #merge must sign the transaction that is
# actually broadcast, and #merge must spend BOTH token UTXOs. Pre-fix both
# BIP-143-signed a locally built throwaway tx and passed that concrete Sig into
# +call+ (+resolve_method_args+ only auto-signs nil Sig slots, so the stale
# signature was embedded verbatim); #merge also left the second token UTXO
# unspent.
#
# Oracle: Ruby ships no ScriptVM. Every signature the wallet's signer made for
# a TOKEN input must have been computed over a tx whose BIP-143-relevant fields
# (version, every outpoint + sequence, every output, locktime) equal the
# broadcast tx's; BIP-143 reads nothing else except the subscript and amount,
# taken from the spent UTXO. The on-chain verdict for the same flow is proven
# by the TS/Go F-045 tests.
#
# Proves: each token-input signature covers the broadcast tx; #merge spends both
# token outpoints exactly once into one continuation holding the summed supply.
# Does NOT prove: script execution in this tier, node acceptance, or token
# semantics beyond this fixture (its transfer does not reassign the holder).
# rubocop:disable RSpec/DescribeClass, RSpec/MultipleExpectations, RSpec/ExampleLength
RSpec.describe 'F-045 TokenWallet signs the transaction it broadcasts' do
  # rubocop:enable RSpec/DescribeClass
  f045_src = <<~TS
    import { StatefulSmartContract, assert, checkSig, len } from 'runar-lang';
    import type { PubKey, Sig, Addr } from 'runar-lang';

    class WalletToken extends StatefulSmartContract {
      supply: bigint;
      holder: PubKey;

      constructor(supply: bigint, holder: PubKey) {
        super(supply, holder);
        this.supply = supply;
        this.holder = holder;
      }

      public transfer(sig: Sig, to: Addr) {
        assert(checkSig(sig, this.holder));
        assert(len(to) === 20n);
      }

      public merge(sig: Sig, otherSupply: bigint, otherHolder: PubKey) {
        assert(checkSig(sig, this.holder));
        assert(otherHolder === this.holder);
        assert(otherSupply >= 0n);
        this.supply = this.supply + otherSupply;
      }
    }
  TS

  holder_key = "#{'00' * 31}45"
  other_key = "#{'00' * 31}47"

  # LocalSigner that records every [tx_hex, input_index] it signs.
  recording = Class.new(Runar::SDK::LocalSigner) do
    def log
      @log ||= []
    end

    def sign(tx_hex, input_index, subscript, satoshis, sighash_type = nil)
      log << [tx_hex, input_index]
      super
    end
  end

  let(:artifact) do
    Dir.mktmpdir do |dir|
      compiler_lib = File.expand_path('../../../../compilers/ruby/lib', __dir__)
      $LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)
      require 'runar_compiler'
      path = File.join(dir, 'WalletToken.runar.ts')
      File.write(path, f045_src)
      Runar::SDK::RunarArtifact.from_json(RunarCompiler.artifact_to_json(RunarCompiler.compile_from_source(path)))
    end
  end

  def parse(hex)
    Runar::SDK.send(:parse_raw_tx, [hex].pack('H*'))
  end

  # The tx fields BIP-143 reads (unlocking scripts excluded).
  def sighash_view(hex)
    t = parse(hex)
    [t[:version], t[:inputs].map { |i| [i[:prev_txid], i[:prev_output_index], i[:sequence]] },
     t[:outputs].map { |o| [o[:satoshis], o[:script]] }, t[:locktime]]
  end

  def outpoints(hex)
    parse(hex)[:inputs].map { |i| "#{i[:prev_txid].reverse.unpack1('H*')}:#{i[:prev_output_index]}" }
  end

  def setup_wallet(signer_class, key, supplies, token_sats: 5_000, funding_sats: 200_000)
    signer = signer_class.new(key)
    addr = signer.get_address
    pub = signer.get_public_key
    provider = Runar::SDK::MockProvider.new
    tokens = supplies.each_with_index.map do |s, i|
      lock = Runar::SDK::RunarContract.new(artifact, [s, pub]).get_locking_script
      txid = format('%02x', i + 1) * 32
      provider.add_transaction(Runar::SDK::TransactionData.new(
                                 txid: txid, version: 1, inputs: [], locktime: 0,
                                 outputs: [Runar::SDK::TxOutput.new(script: lock, satoshis: token_sats)]
                               ))
      utxo = Runar::SDK::Utxo.new(txid: txid, output_index: 0, satoshis: token_sats, script: lock)
      provider.add_utxo(addr, utxo)
      utxo
    end
    provider.add_utxo(addr, Runar::SDK::Utxo.new(txid: 'fe' * 32, output_index: 0, satoshis: funding_sats,
                                                 script: Runar::SDK.build_p2pkh_script(addr)))
    [provider, Runar::SDK::TokenWallet.new(artifact, provider, signer), tokens, signer]
  end

  def expect_token_sigs_cover(signer, tokens, broadcast)
    want = sighash_view(broadcast)
    spent = outpoints(broadcast)
    idxs = tokens.map { |u| spent.index("#{u.txid}:0") }.compact
    expect(idxs).not_to be_empty
    idxs.each do |idx|
      # The LAST signature for this input is the one embedded.
      signed = signer.log.select { |_, i| i == idx }.map(&:first)
      expect(signed).not_to be_empty, "signer never signed token input #{idx}"
      expect(sighash_view(signed.last)).to eq(want), "token input #{idx} was signed over a different tx"
    end
  end

  it 'transfer: the token-input signature covers the broadcast tx (hash160 and Base58 recipient)' do
    other_addr = Runar::SDK::LocalSigner.new(other_key).get_address
    # An Addr is a hash160; the Base58 address is the documented form.
    [Runar::SDK.build_p2pkh_script(other_addr)[6, 40], other_addr].each do |recipient|
      provider, wallet, tokens, signer = setup_wallet(recording, holder_key, [100])
      wallet.transfer(recipient, 100)
      broadcast = provider.get_broadcasted_txs.last
      expect(outpoints(broadcast).first).to eq("#{tokens[0].txid}:0")
      expect_token_sigs_cover(signer, tokens, broadcast)
    end
  end

  it 'merge: spends BOTH token outpoints exactly once, signed over the broadcast tx, supply summed' do
    # Second case: token UTXOs larger than the funding coin -- funding
    # selection must not also pick the second token UTXO as a P2PKH input.
    [[5_000, 200_000], [300_000, 50_000]].each do |token_sats, funding_sats|
      provider, wallet, tokens, signer = setup_wallet(recording, holder_key, [100, 250],
                                                      token_sats: token_sats, funding_sats: funding_sats)
      wallet.merge
      broadcast = provider.get_broadcasted_txs.last
      spent = outpoints(broadcast)
      tokens.each { |u| expect(spent.count("#{u.txid}:0")).to eq(1), spent.inspect }
      expect(spent.uniq.length).to eq(spent.length)
      expect_token_sigs_cover(signer, tokens, broadcast)
      out0 = parse(broadcast)[:outputs][0]
      merged = Runar::SDK::RunarContract.from_utxo(
        artifact, Runar::SDK::Utxo.new(txid: '00' * 32, output_index: 0, satoshis: out0[:satoshis],
                                       script: out0[:script].unpack1('H*'))
      )
      expect(merged.get_state['supply']).to eq(350)
    end
  end

  # N-042: the same wallet against the SHIPPED example contract
  # examples/ts/token-wallet-naive-INSECURE/WalletToken.runar.ts, compiled by
  # this tier's compiler. Same oracle as above (signature coverage; Ruby has no
  # ScriptVM -- the TS and Go N-042 tests script-execute it).
  # Proves: the shipped example compiles in the Ruby tier and TokenWallet's
  # transfer / merge drive it, signing the tx they broadcast. Does NOT prove
  # script execution here, or that the example is a sound token (see its header).
  context 'with the shipped WalletToken example (N-042)' do
    let(:artifact) do
      compiler_lib = File.expand_path('../../../../compilers/ruby/lib', __dir__)
      $LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)
      require 'runar_compiler'
      path = File.expand_path('../../../../examples/ts/token-wallet-naive-INSECURE/WalletToken.runar.ts', __dir__)
      raise "shipped TokenWallet example missing: #{path}" unless File.exist?(path)

      Runar::SDK::RunarArtifact.from_json(RunarCompiler.artifact_to_json(RunarCompiler.compile_from_source(path)))
    end

    it 'transfer drives the shipped example' do
      provider, wallet, tokens, signer = setup_wallet(recording, holder_key, [100])
      expect(wallet.get_balance).to eq(100)
      wallet.transfer(Runar::SDK::LocalSigner.new(other_key).get_address, 100)
      broadcast = provider.get_broadcasted_txs.last
      expect(outpoints(broadcast).first).to eq("#{tokens[0].txid}:0")
      expect_token_sigs_cover(signer, tokens, broadcast)
    end

    it 'merge drives the shipped example and sums the supply' do
      provider, wallet, tokens, signer = setup_wallet(recording, holder_key, [100, 250])
      wallet.merge
      broadcast = provider.get_broadcasted_txs.last
      spent = outpoints(broadcast)
      tokens.each { |u| expect(spent.count("#{u.txid}:0")).to eq(1), spent.inspect }
      expect_token_sigs_cover(signer, tokens, broadcast)
      out0 = parse(broadcast)[:outputs][0]
      merged = Runar::SDK::RunarContract.from_utxo(
        artifact, Runar::SDK::Utxo.new(txid: '00' * 32, output_index: 0, satoshis: out0[:satoshis],
                                       script: out0[:script].unpack1('H*'))
      )
      expect(merged.get_state['supply']).to eq(350)
    end
  end
end
# rubocop:enable RSpec/MultipleExpectations, RSpec/ExampleLength

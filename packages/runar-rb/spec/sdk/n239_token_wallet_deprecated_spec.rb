# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# N-239: TokenWallet#merge / #transfer are deprecated and unsafe. The ABI they
# drive cannot be made sound: merge(sig, otherSupply, otherHolder) cannot
# authenticate its companion input (supply inflation) and
# transfer(sig, to: Addr) cannot re-key a PubKey holder. User decision R92:
# deprecate (marker + one-time runtime warning + docs), do not redesign or
# remove.
#
# Proves: each method carries a YARD @deprecated tag; calling it writes a
# warning to $stderr naming its specific unsoundness and pointing to token-ft
# (FungibleTokenExample), once per process, not per call; the method's own
# behaviour (here, its error path) is unchanged.
# Does NOT prove: that anyone reads the warning, or anything on-chain — the
# happy paths stay covered by f045_token_wallet_spec.rb.
RSpec.describe 'N-239: TokenWallet merge/transfer deprecation' do
  let(:wallet) do
    artifact = Runar::SDK::RunarArtifact.new(contract_name: 'WalletToken', script: '76a988ac')
    Runar::SDK::TokenWallet.new(artifact, Runar::SDK::MockProvider.new, Runar::SDK::MockSigner.new)
  end

  # Other specs in this process may already have spent the once.
  before { Runar::SDK::TokenWallet.instance_variable_set(:@deprecation_warned, {}) }

  def stderr_of
    orig = $stderr
    $stderr = StringIO.new
    yield
    $stderr.string
  ensure
    $stderr = orig
  end

  it 'merge warns once about supply inflation and points to token-ft' do
    out = stderr_of do
      2.times { expect { wallet.merge }.to raise_error(/need at least 2 UTXOs/) }
    end
    expect(out.scan('TokenWallet#merge').length).to eq(1), out
    %w[deprecated supply\ inflation token-ft FungibleTokenExample].each do |needle|
      expect(out).to include(needle)
    end
  end

  it 'transfer warns once about holder re-key and points to token-ft' do
    out = stderr_of do
      2.times { expect { wallet.transfer('recipient', 1) }.to raise_error(/no token UTXOs found/) }
    end
    expect(out.scan('TokenWallet#transfer').length).to eq(1), out
    %w[deprecated re-key token-ft FungibleTokenExample].each do |needle|
      expect(out).to include(needle)
    end
  end

  it 'both methods carry a YARD @deprecated tag' do
    src = File.read(File.expand_path('../../lib/runar/sdk/token_wallet.rb', __dir__))
    %w[transfer merge].each do |m|
      expect(src).to match(/# @deprecated[^\n]*\n(?:\s*#[^\n]*\n)*\s*def #{m}\b/), "#{m} lacks @deprecated"
    end
  end
end

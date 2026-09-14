# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# R-062 — the unsound-primitive deploy gate must cover the WALLET funding path.
#
# +deploy+ refuses to fund an artifact the compiler marked unsound unless the
# caller names every listed primitive. +deploy_with_wallet+ is a SECOND funding
# path — a BRC-100 wallet creates and funds the transaction via +create_action+
# — and it ran the DoS script-size bound but never the unsound gate.
#
# Three cases, because over-rejection here breaks every legitimate wallet
# deploy: refusal, an ordinary artifact, and an acknowledged unsound one.
RSpec.describe 'R-062 deploy_with_wallet unsound-primitive gate' do
  # Records every create_action the SDK reaches — proof the gate ran before it.
  class RecordingWallet < Runar::SDK::WalletClient
    attr_reader :actions

    def initialize
      @actions = []
    end

    def create_action(description:, outputs:)
      @actions << { description: description, outputs: outputs }
      { txid: 'ab' * 32 }
    end
  end

  def artifact(*primitives)
    Runar::SDK::RunarArtifact.new(
      version: 'runar-v1.0.0-rc.1',
      contract_name: 'Sp1Rollup',
      script: '51',
      unsound_primitives: primitives
    )
  end

  def connected(*primitives)
    wallet = RecordingWallet.new
    signer = Runar::SDK::MockSigner.new
    provider = Runar::SDK::WalletProvider.new(wallet: wallet, signer: signer, basket: 'test-basket')
    contract = Runar::SDK::RunarContract.new(artifact(*primitives), [])
    contract.connect(provider, signer)
    [contract, wallet]
  end

  it 'refuses an unacknowledged unsound artifact, and never reaches the wallet' do
    contract, wallet = connected('verifySP1FRI')
    expect { contract.deploy_with_wallet(satoshis: 1) }
      .to raise_error(Runar::SDK::UnsoundPrimitiveError, /verifySP1FRI/)
    expect { contract.deploy_with_wallet(satoshis: 1) }
      .to raise_error(Runar::SDK::UnsoundPrimitiveError, /Sp1Rollup\.deploy_with_wallet/)
    expect { contract.deploy_with_wallet(satoshis: 1) }
      .to raise_error(Runar::SDK::UnsoundPrimitiveError, /acknowledge_unsound/)
    expect(wallet.actions).to be_empty
  end

  it 'CONTROL: an ordinary artifact still funds through the wallet path' do
    contract, wallet = connected
    result = contract.deploy_with_wallet(satoshis: 1)
    expect(result[:txid]).to eq('ab' * 32)
    expect(wallet.actions.length).to eq(1)
  end

  it 'CONTROL: an acknowledged unsound artifact still funds through the wallet path' do
    contract, wallet = connected('verifySP1FRI')
    result = contract.deploy_with_wallet(satoshis: 1, acknowledge_unsound: ['verifySP1FRI'])
    expect(result[:txid]).to eq('ab' * 32)
    expect(wallet.actions.length).to eq(1)
  end

  it 'treats a PARTIAL acknowledgement as a refusal' do
    contract, wallet = connected('verifySP1FRI', 'someFutureStub')
    expect { contract.deploy_with_wallet(satoshis: 1, acknowledge_unsound: ['verifySP1FRI']) }
      .to raise_error(Runar::SDK::UnsoundPrimitiveError, /someFutureStub/)
    expect(wallet.actions).to be_empty
  end
end

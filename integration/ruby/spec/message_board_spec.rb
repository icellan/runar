# frozen_string_literal: true

# MessageBoard integration spec — exercises a stateful contract whose
# `post` method is open (anyone can post) and whose `burn` method is
# gated by an owner signature. Ported from
# integration/ts/message-board.test.ts.

require 'spec_helper'

RSpec.describe 'MessageBoard' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the MessageBoard contract' do
    artifact = compile_contract('examples/ts/message-board/MessageBoard.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('MessageBoard')
    expect(artifact.script.length).to be > 0
  end

  it 'deploys with an initial message and owner pubkey' do
    artifact = compile_contract('examples/ts/message-board/MessageBoard.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    initial_message = '68656c6c6f20776f726c64' # "hello world"
    contract = Runar::SDK::RunarContract.new(artifact, [initial_message, wallet[:pub_key_hex]])

    txid, _count = contract.deploy(
      provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000)
    )
    expect(txid).to be_truthy
    expect(txid.length).to eq(64)
  end

  it 'allows anyone to post a new message' do
    artifact = compile_contract('examples/ts/message-board/MessageBoard.runar.ts')

    provider = create_provider
    owner    = create_funded_wallet(provider)
    poster   = create_funded_wallet(provider)

    initial_message = '68656c6c6f' # "hello"
    new_message     = '776f726c64' # "world"

    contract = Runar::SDK::RunarContract.new(artifact, [initial_message, owner[:pub_key_hex]])
    contract.deploy(provider, owner[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # post() requires no signature; a non-owner should be able to call it.
    call_txid, _ = contract.call(
      'post', [new_message], provider, poster[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'message' => new_message })
    )
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'rejects burn from a non-owner signer' do
    artifact = compile_contract('examples/ts/message-board/MessageBoard.runar.ts')

    provider = create_provider
    owner    = create_funded_wallet(provider)
    attacker = create_funded_wallet(provider)

    initial_message = '68656c6c6f'

    contract = Runar::SDK::RunarContract.new(artifact, [initial_message, owner[:pub_key_hex]])
    contract.deploy(provider, owner[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # burn() requires the owner's signature — attacker's signer must fail.
    expect do
      contract.call('burn', [nil], provider, attacker[:signer])
    end.to raise_error(StandardError)
  end
end

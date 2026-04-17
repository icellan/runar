# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'
require 'json'

# Convert a UTF-8 string to hex.
def utf8_to_hex(str)
  str.encode('UTF-8').bytes.map { |b| format('%02x', b) }.join
end

# Convert a hex string to UTF-8.
def hex_to_utf8(hex)
  [hex].pack('H*').force_encoding('UTF-8')
end

RSpec.describe Runar::SDK::Ordinals do
  # -----------------------------------------------------------------------
  # build_inscription_envelope
  # -----------------------------------------------------------------------
  describe '.build_inscription_envelope' do
    it 'builds a text inscription envelope' do
      content_type = 'text/plain'
      data = utf8_to_hex('Hello, ordinals!')
      envelope = described_class.build_inscription_envelope(content_type, data)

      # Starts with OP_FALSE OP_IF PUSH3 "ord" OP_1
      expect(envelope.start_with?('006303' + '6f7264' + '51')).to be true
      # Ends with OP_ENDIF
      expect(envelope.end_with?('68')).to be true
      # Contains content type hex
      expect(envelope).to include(utf8_to_hex(content_type))
      # Contains data
      expect(envelope).to include(data)
    end

    it 'builds an envelope with large data (OP_PUSHDATA2)' do
      content_type = 'image/png'
      # 300 bytes of data, triggers OP_PUSHDATA2 (> 255 bytes)
      data = 'ff' * 300
      envelope = described_class.build_inscription_envelope(content_type, data)

      # Should contain OP_PUSHDATA2 (4d) for the data push
      # The data is 300 bytes = 0x012c LE = 2c01
      expect(envelope).to include('4d' + '2c01' + data)
      # Still valid envelope
      expect(envelope.start_with?('006303' + '6f7264' + '51')).to be true
      expect(envelope.end_with?('68')).to be true
    end

    it 'builds an envelope with medium data (OP_PUSHDATA1)' do
      # 100 bytes, triggers OP_PUSHDATA1 (> 75 bytes, <= 255)
      data = 'ab' * 100
      envelope = described_class.build_inscription_envelope('application/octet-stream', data)

      # Should contain OP_PUSHDATA1 (4c) for the data push: 100 = 0x64
      expect(envelope).to include('4c' + '64' + data)
    end

    it 'handles empty data with OP_0' do
      envelope = described_class.build_inscription_envelope('text/plain', '')
      # Data push is OP_0 (00)
      # The last bytes should be: 00 00 68 (OP_0 delimiter, OP_0 data, OP_ENDIF)
      expect(envelope.end_with?('000068')).to be true
    end
  end

  # -----------------------------------------------------------------------
  # parse_inscription_envelope
  # -----------------------------------------------------------------------
  describe '.parse_inscription_envelope' do
    it 'round-trips a text inscription' do
      original_ct = 'text/plain'
      original_data = utf8_to_hex('Hello!')
      envelope = described_class.build_inscription_envelope(original_ct, original_data)
      parsed = described_class.parse_inscription_envelope(envelope)

      expect(parsed).not_to be_nil
      expect(parsed.content_type).to eq('text/plain')
      expect(parsed.data).to eq(original_data)
    end

    it 'round-trips a BSV-20 JSON inscription' do
      json_str = JSON.generate({ p: 'bsv-20', op: 'deploy', tick: 'TEST', max: '21000000' })
      original_data = utf8_to_hex(json_str)
      envelope = described_class.build_inscription_envelope('application/bsv-20', original_data)
      parsed = described_class.parse_inscription_envelope(envelope)

      expect(parsed).not_to be_nil
      expect(parsed.content_type).to eq('application/bsv-20')
      expect(parsed.data).to eq(original_data)
    end

    it 'round-trips large data (OP_PUSHDATA2)' do
      data = 'ff' * 300
      envelope = described_class.build_inscription_envelope('image/png', data)
      parsed = described_class.parse_inscription_envelope(envelope)

      expect(parsed).not_to be_nil
      expect(parsed.content_type).to eq('image/png')
      expect(parsed.data).to eq(data)
    end

    it 'returns nil for script without envelope' do
      script = 'a914' + ('00' * 20) + '87' # P2SH-like
      expect(described_class.parse_inscription_envelope(script)).to be_nil
    end

    it 'parses envelope embedded in a larger script' do
      prefix = 'a914' + ('00' * 20) + '8788ac' # some contract code
      data = utf8_to_hex('test')
      envelope = described_class.build_inscription_envelope('text/plain', data)
      suffix = '6a' + '08' + ('00' * 8) # OP_RETURN + state

      full_script = prefix + envelope + suffix
      parsed = described_class.parse_inscription_envelope(full_script)

      expect(parsed).not_to be_nil
      expect(parsed.content_type).to eq('text/plain')
      expect(parsed.data).to eq(data)
    end
  end

  # -----------------------------------------------------------------------
  # find_inscription_envelope
  # -----------------------------------------------------------------------
  describe '.find_inscription_envelope' do
    it 'finds envelope bounds in a script' do
      prefix = 'aabb'
      envelope = described_class.build_inscription_envelope('text/plain', utf8_to_hex('hi'))
      suffix = 'ccdd'

      script = prefix + envelope + suffix
      bounds = described_class.find_inscription_envelope(script)

      expect(bounds).not_to be_nil
      expect(bounds.start_hex).to eq(prefix.length)
      expect(bounds.end_hex).to eq(prefix.length + envelope.length)
    end

    it 'returns nil when no envelope present' do
      expect(described_class.find_inscription_envelope('76a914' + ('00' * 20) + '88ac')).to be_nil
    end

    it 'finds envelope between code and OP_RETURN for stateful scripts' do
      code = '76a914' + ('00' * 20) + '88ac'
      envelope = described_class.build_inscription_envelope('text/plain', utf8_to_hex('ord'))
      state = '6a' + '08' + '0000000000000000' # OP_RETURN + 8 bytes

      full_script = code + envelope + state
      bounds = described_class.find_inscription_envelope(full_script)

      expect(bounds).not_to be_nil
      expect(bounds.start_hex).to eq(code.length)
      expect(bounds.end_hex).to eq(code.length + envelope.length)
    end
  end

  # -----------------------------------------------------------------------
  # strip_inscription_envelope
  # -----------------------------------------------------------------------
  describe '.strip_inscription_envelope' do
    it 'removes the envelope and preserves surrounding script' do
      prefix = 'aabb'
      envelope = described_class.build_inscription_envelope('text/plain', utf8_to_hex('hi'))
      suffix = 'ccdd'

      stripped = described_class.strip_inscription_envelope(prefix + envelope + suffix)
      expect(stripped).to eq(prefix + suffix)
    end

    it 'returns the script unchanged if no envelope' do
      script = '76a914' + ('00' * 20) + '88ac'
      expect(described_class.strip_inscription_envelope(script)).to eq(script)
    end
  end

  # -----------------------------------------------------------------------
  # BSV-20 helpers
  # -----------------------------------------------------------------------
  describe 'BSV-20' do
    it 'builds a deploy inscription' do
      inscription = described_class.bsv20_deploy(tick: 'RUNAR', max: '21000000', lim: '1000')
      expect(inscription.content_type).to eq('application/bsv-20')
      json = JSON.parse(hex_to_utf8(inscription.data))
      expect(json).to eq({
        'p' => 'bsv-20', 'op' => 'deploy',
        'tick' => 'RUNAR', 'max' => '21000000', 'lim' => '1000'
      })
    end

    it 'builds a deploy inscription without optional fields' do
      inscription = described_class.bsv20_deploy(tick: 'TEST', max: '1000')
      json = JSON.parse(hex_to_utf8(inscription.data))
      expect(json).to eq({ 'p' => 'bsv-20', 'op' => 'deploy', 'tick' => 'TEST', 'max' => '1000' })
      expect(json).not_to have_key('lim')
      expect(json).not_to have_key('dec')
    end

    it 'builds a deploy inscription with decimals' do
      inscription = described_class.bsv20_deploy(tick: 'USDT', max: '100000000', dec: '8')
      json = JSON.parse(hex_to_utf8(inscription.data))
      expect(json['dec']).to eq('8')
    end

    it 'builds a mint inscription' do
      inscription = described_class.bsv20_mint(tick: 'RUNAR', amt: '1000')
      expect(inscription.content_type).to eq('application/bsv-20')
      json = JSON.parse(hex_to_utf8(inscription.data))
      expect(json).to eq({ 'p' => 'bsv-20', 'op' => 'mint', 'tick' => 'RUNAR', 'amt' => '1000' })
    end

    it 'builds a transfer inscription' do
      inscription = described_class.bsv20_transfer(tick: 'RUNAR', amt: '50')
      expect(inscription.content_type).to eq('application/bsv-20')
      json = JSON.parse(hex_to_utf8(inscription.data))
      expect(json).to eq({ 'p' => 'bsv-20', 'op' => 'transfer', 'tick' => 'RUNAR', 'amt' => '50' })
    end
  end

  # -----------------------------------------------------------------------
  # BSV-21 helpers
  # -----------------------------------------------------------------------
  describe 'BSV-21' do
    it 'builds a deploy+mint inscription' do
      inscription = described_class.bsv21_deploy_mint(amt: '1000000', dec: '18', sym: 'RNR')
      expect(inscription.content_type).to eq('application/bsv-20')
      json = JSON.parse(hex_to_utf8(inscription.data))
      expect(json).to eq({
        'p' => 'bsv-20', 'op' => 'deploy+mint',
        'amt' => '1000000', 'dec' => '18', 'sym' => 'RNR'
      })
    end

    it 'builds a deploy+mint without optional fields' do
      inscription = described_class.bsv21_deploy_mint(amt: '500')
      json = JSON.parse(hex_to_utf8(inscription.data))
      expect(json).to eq({ 'p' => 'bsv-20', 'op' => 'deploy+mint', 'amt' => '500' })
      expect(json).not_to have_key('dec')
      expect(json).not_to have_key('sym')
    end

    it 'builds a transfer inscription' do
      inscription = described_class.bsv21_transfer(
        id: '3b313338fa0555aebeaf91d8db1ffebd74773c67c8ad5181ff3d3f51e21e0000_1',
        amt: '100'
      )
      expect(inscription.content_type).to eq('application/bsv-20')
      json = JSON.parse(hex_to_utf8(inscription.data))
      expect(json).to eq({
        'p' => 'bsv-20', 'op' => 'transfer',
        'id' => '3b313338fa0555aebeaf91d8db1ffebd74773c67c8ad5181ff3d3f51e21e0000_1',
        'amt' => '100'
      })
    end
  end
end

# =========================================================================
# Contract integration tests
# =========================================================================
RSpec.describe 'RunarContract with inscription' do
  # Minimal stateless artifact (P2PKH-style).
  let(:p2pkh_artifact_hash) do
    {
      'version'          => 'runar-v0.1.0',
      'compilerVersion'  => '0.4.4',
      'contractName'     => 'P2PKH',
      'abi'              => {
        'constructor' => { 'params' => [{ 'name' => 'pubKeyHash', 'type' => 'Addr' }] },
        'methods'     => [{
          'name'     => 'unlock',
          'params'   => [{ 'name' => 'sig', 'type' => 'Sig' }, { 'name' => 'pubKey', 'type' => 'PubKey' }],
          'isPublic' => true
        }]
      },
      'script'           => 'a9007c7c9c69007c7cac69',
      'asm'              => '',
      'constructorSlots' => [
        { 'paramIndex' => 0, 'byteOffset' => 1 },
        { 'paramIndex' => 0, 'byteOffset' => 6 }
      ],
      'buildTimestamp'   => '2026-01-01T00:00:00.000Z'
    }
  end

  # Minimal stateful (counter) artifact.
  let(:counter_artifact_hash) do
    {
      'version'              => 'runar-v0.1.0',
      'compilerVersion'      => '0.4.4',
      'contractName'         => 'Counter',
      'abi'                  => {
        'constructor' => { 'params' => [{ 'name' => 'count', 'type' => 'bigint' }] },
        'methods'     => [{
          'name'     => 'increment',
          'params'   => [
            { 'name' => '_changePKH', 'type' => 'Addr' },
            { 'name' => '_changeAmount', 'type' => 'bigint' },
            { 'name' => 'txPreimage', 'type' => 'SigHashPreimage' }
          ],
          'isPublic' => true
        }]
      },
      # Fake minimal script -- just enough to test envelope splicing
      'script'               => 'aabbccdd',
      'asm'                  => '',
      'stateFields'          => [{ 'name' => 'count', 'type' => 'bigint', 'index' => 0 }],
      'constructorSlots'     => [],
      'buildTimestamp'       => '2026-01-01T00:00:00.000Z'
    }
  end

  let(:p2pkh_artifact) { Runar::SDK::RunarArtifact.from_hash(p2pkh_artifact_hash) }
  let(:counter_artifact) { Runar::SDK::RunarArtifact.from_hash(counter_artifact_hash) }

  context 'stateless contract' do
    it 'get_locking_script includes inscription envelope' do
      pub_key_hash = '00' * 20
      contract = Runar::SDK::RunarContract.new(p2pkh_artifact, [pub_key_hash])
      contract.with_inscription(
        Runar::SDK::Inscription.new(
          content_type: 'text/plain',
          data: utf8_to_hex('Hello!')
        )
      )

      locking_script = contract.get_locking_script
      envelope = Runar::SDK::Ordinals.build_inscription_envelope('text/plain', utf8_to_hex('Hello!'))

      # The locking script should end with the inscription envelope
      expect(locking_script.end_with?(envelope)).to be true

      # Should be parseable
      parsed = Runar::SDK::Ordinals.parse_inscription_envelope(locking_script)
      expect(parsed).not_to be_nil
      expect(parsed.content_type).to eq('text/plain')
      expect(parsed.data).to eq(utf8_to_hex('Hello!'))
    end

    it 'get_locking_script without inscription is unchanged' do
      pub_key_hash = '00' * 20
      contract_a = Runar::SDK::RunarContract.new(p2pkh_artifact, [pub_key_hash])
      contract_b = Runar::SDK::RunarContract.new(p2pkh_artifact, [pub_key_hash])

      expect(contract_a.get_locking_script).to eq(contract_b.get_locking_script)
    end

    it 'with_inscription returns self for chaining' do
      contract = Runar::SDK::RunarContract.new(p2pkh_artifact, ['00' * 20])
      result = contract.with_inscription(Runar::SDK::Inscription.new(content_type: 'text/plain', data: ''))
      expect(result).to equal(contract)
    end

    it 'inscription reader returns the stored inscription' do
      contract = Runar::SDK::RunarContract.new(p2pkh_artifact, ['00' * 20])
      expect(contract.inscription).to be_nil
      contract.with_inscription(Runar::SDK::Inscription.new(content_type: 'image/png', data: 'ff00ff'))
      expect(contract.inscription).to eq(Runar::SDK::Inscription.new(content_type: 'image/png', data: 'ff00ff'))
    end
  end

  context 'stateful contract' do
    it 'get_locking_script places envelope between code and OP_RETURN' do
      contract = Runar::SDK::RunarContract.new(counter_artifact, [0])
      json_str = '{"p":"bsv-20","op":"deploy","tick":"TEST","max":"1000"}'
      contract.with_inscription(
        Runar::SDK::Inscription.new(
          content_type: 'application/bsv-20',
          data: utf8_to_hex(json_str)
        )
      )

      locking_script = contract.get_locking_script
      envelope = Runar::SDK::Ordinals.build_inscription_envelope(
        'application/bsv-20', utf8_to_hex(json_str)
      )

      # Script structure: code + envelope + OP_RETURN + state
      code_end = locking_script.index(envelope)
      expect(code_end).to be > 0

      after_envelope = locking_script[(code_end + envelope.length)..]
      expect(after_envelope.start_with?('6a')).to be true # OP_RETURN
    end

    it 'findLastOpReturn correctly skips envelope and finds real OP_RETURN' do
      contract = Runar::SDK::RunarContract.new(counter_artifact, [42])
      contract.with_inscription(
        Runar::SDK::Inscription.new(
          content_type: 'text/plain',
          data: utf8_to_hex('test')
        )
      )

      locking_script = contract.get_locking_script
      op_return_pos = Runar::SDK::State.find_last_op_return(locking_script)

      expect(op_return_pos).to be > 0
      # Everything before OP_RETURN should include both the code and the envelope
      code_part = locking_script[0, op_return_pos]
      expect(code_part).to include('aabbccdd') # original code
      expect(Runar::SDK::Ordinals.find_inscription_envelope(code_part)).not_to be_nil
    end
  end

  context 'from_utxo' do
    it 'detects inscription from stateless UTXO' do
      pub_key_hash = '00' * 20
      original = Runar::SDK::RunarContract.new(p2pkh_artifact, [pub_key_hash])
      original.with_inscription(
        Runar::SDK::Inscription.new(content_type: 'image/png', data: 'deadbeef')
      )

      locking_script = original.get_locking_script
      reconnected = Runar::SDK::RunarContract.from_utxo(
        p2pkh_artifact,
        { txid: '00' * 32, output_index: 0, satoshis: 1, script: locking_script }
      )

      expect(reconnected.inscription).not_to be_nil
      expect(reconnected.inscription.content_type).to eq('image/png')
      expect(reconnected.inscription.data).to eq('deadbeef')
    end

    it 'detects inscription and state from stateful UTXO' do
      original = Runar::SDK::RunarContract.new(counter_artifact, [7])
      original.with_inscription(
        Runar::SDK::Inscription.new(content_type: 'text/plain', data: utf8_to_hex('my counter'))
      )

      locking_script = original.get_locking_script
      reconnected = Runar::SDK::RunarContract.from_utxo(
        counter_artifact,
        { txid: '00' * 32, output_index: 0, satoshis: 1, script: locking_script }
      )

      # Inscription round-trips
      expect(reconnected.inscription).not_to be_nil
      expect(reconnected.inscription.content_type).to eq('text/plain')
      expect(reconnected.inscription.data).to eq(utf8_to_hex('my counter'))

      # State round-trips
      expect(reconnected.get_state['count']).to eq(7)
    end

    it 'produces identical locking script on reconnected stateful contract' do
      original = Runar::SDK::RunarContract.new(counter_artifact, [99])
      original.with_inscription(
        Runar::SDK::Inscription.new(content_type: 'text/plain', data: utf8_to_hex('persisted'))
      )

      locking_script = original.get_locking_script
      reconnected = Runar::SDK::RunarContract.from_utxo(
        counter_artifact,
        { txid: '00' * 32, output_index: 0, satoshis: 1, script: locking_script }
      )

      # Reconnected contract should produce the same locking script
      expect(reconnected.get_locking_script).to eq(locking_script)
    end

    it 'from_utxo with no inscription sets inscription to nil' do
      contract = Runar::SDK::RunarContract.new(p2pkh_artifact, ['00' * 20])
      locking_script = contract.get_locking_script

      reconnected = Runar::SDK::RunarContract.from_utxo(
        p2pkh_artifact,
        { txid: '00' * 32, output_index: 0, satoshis: 1, script: locking_script }
      )

      expect(reconnected.inscription).to be_nil
    end
  end

  context 'BSV-20 integration' do
    it 'deploys a P2PKH contract with BSV-20 deploy inscription' do
      inscription = Runar::SDK::Ordinals.bsv20_deploy(tick: 'RUNAR', max: '21000000')
      contract = Runar::SDK::RunarContract.new(p2pkh_artifact, ['00' * 20])
      contract.with_inscription(inscription)

      locking_script = contract.get_locking_script
      parsed = Runar::SDK::Ordinals.parse_inscription_envelope(locking_script)

      expect(parsed).not_to be_nil
      expect(parsed.content_type).to eq('application/bsv-20')

      # Verify the JSON content
      json = JSON.parse(hex_to_utf8(parsed.data))
      expect(json['p']).to eq('bsv-20')
      expect(json['op']).to eq('deploy')
      expect(json['tick']).to eq('RUNAR')
    end
  end
end

# =========================================================================
# GorillaPoolProvider unit tests
# =========================================================================
RSpec.describe Runar::SDK::GorillaPoolProvider do
  describe '#initialize' do
    it 'defaults to mainnet' do
      provider = described_class.new
      expect(provider.get_network).to eq('mainnet')
    end

    it 'accepts testnet' do
      provider = described_class.new(network: 'testnet')
      expect(provider.get_network).to eq('testnet')
    end
  end

  describe '#get_fee_rate' do
    it 'returns 100 (standard BSV relay fee in sat/KB)' do
      provider = described_class.new
      expect(provider.get_fee_rate).to eq(100)
    end
  end

  describe '#get_network' do
    it 'returns the configured network' do
      expect(described_class.new(network: 'mainnet').get_network).to eq('mainnet')
      expect(described_class.new(network: 'testnet').get_network).to eq('testnet')
    end
  end

  describe 'class hierarchy' do
    it 'is a subclass of Provider' do
      expect(described_class.superclass).to eq(Runar::SDK::Provider)
    end

    it 'responds to all Provider interface methods' do
      provider = described_class.new
      %i[get_transaction broadcast get_utxos get_contract_utxo get_network
         get_raw_transaction get_fee_rate].each do |method|
        expect(provider).to respond_to(method)
      end
    end

    it 'responds to ordinal-specific methods' do
      provider = described_class.new
      %i[get_inscriptions_by_address get_inscription get_bsv20_balance
         get_bsv20_utxos get_bsv21_balance get_bsv21_utxos].each do |method|
        expect(provider).to respond_to(method)
      end
    end
  end

  describe 'base URL construction' do
    it 'uses mainnet URL for mainnet' do
      provider = described_class.new(network: 'mainnet')
      expect(provider.instance_variable_get(:@base_url)).to eq('https://ordinals.gorillapool.io/api')
    end

    it 'uses testnet URL for testnet' do
      provider = described_class.new(network: 'testnet')
      expect(provider.instance_variable_get(:@base_url)).to eq('https://testnet.ordinals.gorillapool.io/api')
    end
  end
end

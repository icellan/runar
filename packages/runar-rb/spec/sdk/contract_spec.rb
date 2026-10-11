# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

RSpec.describe Runar::SDK::RunarContract do
  # ---------------------------------------------------------------------------
  # Fixture helpers
  # ---------------------------------------------------------------------------

  # A minimal stateless artifact (P2PKH-style) with one constructor param and
  # one constructor slot — the pubkey hash placeholder sits at byte offset 3 of
  # the locking script (after OP_DUP OP_HASH160 OP_PUSHDATA1(20)).
  #
  # Script layout (25 bytes):
  #   76          OP_DUP
  #   a9          OP_HASH160
  #   14          push 20 bytes              ← constructor slot placeholder byte
  #   {20 bytes}  pubkey hash               ← replaced by build_code_script
  #   88          OP_EQUALVERIFY
  #   ac          OP_CHECKSIG
  #
  # The artifact's #script contains a single placeholder byte at offset 3
  # (byte_offset: 3).  build_code_script replaces that 1-byte placeholder with
  # the full encoded constructor arg (encode_push_data of the 20-byte hash).
  #
  # NOTE: the real P2PKH script uses a raw push (14 + 20 bytes); here we use
  # OP_PUSHDATA1 style for illustration.  What matters is that the constructor
  # slot mechanics work correctly.
  SAMPLE_PKH       = ('ab' * 20).freeze
  SAMPLE_ADDRESS   = '00' * 20  # used as MockSigner address
  SAMPLE_PUB_KEY   = ('02' + '00' * 32).freeze

  # Minimal stateless artifact JSON.
  STATELESS_ARTIFACT_JSON = JSON.generate(
    version:         '1.0',
    compilerVersion: '0.1.0',
    contractName:    'P2PKH',
    abi:             {
      constructor: { params: [{ name: 'pubKeyHash', type: 'Addr' }] },
      methods:     [{ name: 'unlock', params: [{ name: 'sig', type: 'Sig' },
                                               { name: 'pk',  type: 'PubKey' }], isPublic: true }]
    },
    # Script: 76 a9 14 00 00...00 88 ac
    # Byte offset 3 is the push-data placeholder byte (0x00 = 1 null byte).
    # build_code_script replaces the single byte at offset 3 with encode_push_data(pkh).
    script:          '76a9' + '14' + ('00' * 20) + '88ac',
    asm:             '',
    stateFields:     [],
    constructorSlots: [{ paramIndex: 0, byteOffset: 2 }]
  ).freeze

  # Minimal stateful (counter) artifact.
  STATEFUL_ARTIFACT_JSON = JSON.generate(
    version:         '1.0',
    compilerVersion: '0.1.0',
    contractName:    'Counter',
    abi:             {
      constructor: { params: [{ name: 'count', type: 'bigint' }] },
      methods:     [{ name: 'increment', params: [], isPublic: true }]
    },
    # Placeholder script — content is not interpreted by contract.rb unit tests.
    script:          'aabbcc',
    asm:             '',
    stateFields:     [{ name: 'count', type: 'bigint', index: 0 }],
    constructorSlots: [],
    codeSeparatorIndex: 0
  ).freeze

  # Stateful (counter) artifact with ANF IR — used to test auto-computed state.
  #
  # The ANF IR describes an increment() method that adds 1 to the 'count'
  # property via an update_prop node.  It mirrors the minimal Counter contract:
  #
  #   class Counter extends StatefulSmartContract {
  #     count: bigint;
  #     public increment() { this.count += 1n; }
  #   }
  STATEFUL_ANF_ARTIFACT_JSON = JSON.generate(
    version:            '1.0',
    compilerVersion:    '0.1.0',
    contractName:       'Counter',
    abi:                {
      constructor: { params: [{ name: 'count', type: 'bigint' }] },
      methods:     [{ name: 'increment', params: [], isPublic: true }]
    },
    script:             'aabbcc',
    asm:                '',
    stateFields:        [{ name: 'count', type: 'bigint', index: 0 }],
    constructorSlots:   [],
    codeSeparatorIndex: 0,
    anf:                {
      'properties' => [{ 'name' => 'count', 'type' => 'bigint', 'readonly' => false }],
      'methods'    => [
        {
          'name'     => 'increment',
          'isPublic' => true,
          'params'   => [],
          'body'     => [
            # t0 = count  (load current value)
            { 'name' => 't0', 'value' => { 'kind' => 'load_prop', 'name' => 'count' } },
            # t1 = 1
            { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => 1 } },
            # t2 = t0 + t1
            { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => '+', 'left' => 't0', 'right' => 't1' } },
            # update_prop count = t2
            { 'name' => 't3', 'value' => { 'kind' => 'update_prop', 'name' => 'count', 'value' => 't2' } }
          ]
        }
      ]
    }
  ).freeze

  def stateless_artifact
    Runar::SDK::RunarArtifact.from_json(STATELESS_ARTIFACT_JSON)
  end

  def stateful_artifact
    Runar::SDK::RunarArtifact.from_json(STATEFUL_ARTIFACT_JSON)
  end

  def stateful_anf_artifact
    Runar::SDK::RunarArtifact.from_json(STATEFUL_ANF_ARTIFACT_JSON)
  end

  def make_utxo(txid, satoshis, script: 'aabb', index: 0)
    Runar::SDK::Utxo.new(txid: txid, output_index: index, satoshis: satoshis, script: script)
  end

  def mock_provider
    Runar::SDK::MockProvider.new
  end

  def mock_signer
    Runar::SDK::MockSigner.new(pub_key_hex: SAMPLE_PUB_KEY, address: SAMPLE_ADDRESS)
  end

  # ---------------------------------------------------------------------------
  # Constructor validation
  # ---------------------------------------------------------------------------

  describe '#initialize' do
    it 'raises ArgumentError when arg count is wrong (too few)' do
      expect { described_class.new(stateless_artifact, []) }
        .to raise_error(ArgumentError, /expected 1 constructor args.*got 0/i)
    end

    it 'raises ArgumentError when arg count is wrong (too many)' do
      expect { described_class.new(stateless_artifact, [SAMPLE_PKH, 'extra']) }
        .to raise_error(ArgumentError, /expected 1 constructor args.*got 2/i)
    end

    it 'accepts the correct number of args' do
      expect { described_class.new(stateless_artifact, [SAMPLE_PKH]) }.not_to raise_error
    end

    it 'initialises state from constructor args for stateful contracts' do
      contract = described_class.new(stateful_artifact, [42])
      expect(contract.get_state).to eq('count' => 42)
    end

    it 'stores get_utxo as nil before deployment' do
      contract = described_class.new(stateless_artifact, [SAMPLE_PKH])
      expect(contract.get_utxo).to be_nil
    end
  end

  # ---------------------------------------------------------------------------
  # build_code_script — constructor slot splicing
  # ---------------------------------------------------------------------------

  describe '#build_code_script' do
    subject(:contract) { described_class.new(stateless_artifact, [SAMPLE_PKH]) }

    it 'returns a String' do
      expect(contract.build_code_script).to be_a(String)
    end

    it 'is not empty' do
      expect(contract.build_code_script).not_to be_empty
    end

    it 'splices the constructor arg into the script at the byte offset' do
      code = contract.build_code_script
      # encode_push_data of a 20-byte value produces 14{40 hex chars} (21 hex pairs = 42 hex chars).
      # Byte offset 2 means hex offset 4. The original script starts with '76a9'.
      # After splicing, those 4 leading chars are preserved, followed by the encoded arg.
      expect(code).to start_with('76a9')
      # The encoded push-data for the 20-byte hash should be present in the result.
      expected_push = Runar::SDK::State.encode_push_data(SAMPLE_PKH)
      expect(code).to include(expected_push)
    end

    it 'preserves the tail of the original script after the splice' do
      code = contract.build_code_script
      expect(code).to end_with('88ac')
    end

    it 'produces the same result on repeated calls' do
      expect(contract.build_code_script).to eq(contract.build_code_script)
    end
  end

  # ---------------------------------------------------------------------------
  # get_locking_script
  # ---------------------------------------------------------------------------

  describe '#get_locking_script' do
    it 'returns a non-empty hex string for stateless contracts' do
      contract = described_class.new(stateless_artifact, [SAMPLE_PKH])
      script   = contract.get_locking_script
      expect(script).to be_a(String)
      expect(script).not_to be_empty
      expect(script.length).to be_even
    end

    it 'appends OP_RETURN + state hex for stateful contracts' do
      contract = described_class.new(stateful_artifact, [7])
      script   = contract.get_locking_script
      # OP_RETURN = 6a
      expect(script).to include('6a')
    end

    it 'does not include OP_RETURN for stateless contracts' do
      contract = described_class.new(stateless_artifact, [SAMPLE_PKH])
      # Find the op_return at an opcode boundary — stateless scripts should not have one.
      op_return_pos = Runar::SDK::State.find_last_op_return(contract.get_locking_script)
      expect(op_return_pos).to eq(-1)
    end

    # R84: a ctor arg with no constructorSlots entry is never appended. This
    # used to fall back to appending the raw arg to the end of the script
    # ("backward compat" for pre-slot-splicing artifacts). That shape —
    # constructorSlots empty, abi ctor params non-empty — is byte-identical
    # to what TODAY's compiler emits when every ctor-needed property is
    # eliminated by DCE (no method ever reads it), so the old fallback
    # silently deployed a script that was NOT the compiled template: the
    # appended bytes leave extra items on the stack and the spend fails the
    # consensus clean-stack rule (proved against the real @bsv/sdk Spend
    # oracle in
    # packages/runar-sdk/src/__tests__/n013-dce-eliminated-ctor-args.test.ts).
    # Matches the Java SDK, which never had this fallback.
    it 'R84: a stateless ctor arg with no constructorSlots entry is not appended' do
      no_slot_artifact_json = JSON.generate(
        version:          '1.0',
        compilerVersion:  '0.1.0',
        contractName:     'Unused',
        abi:              {
          constructor: { params: [{ name: 'target', type: 'bigint' }] },
          methods:     [{ name: 'check', params: [], isPublic: true }]
        },
        script:           '009c',
        asm:              '',
        stateFields:      [],
        constructorSlots: []
      )
      no_slot_artifact = Runar::SDK::RunarArtifact.from_json(no_slot_artifact_json)
      contract = described_class.new(no_slot_artifact, [42])

      # New behavior (R84): nothing is appended; the deployed script is
      # exactly the compiled template.
      expect(contract.get_locking_script).to eq('009c')
    end
  end

  # ---------------------------------------------------------------------------
  # build_unlocking_script
  # ---------------------------------------------------------------------------

  describe '#build_unlocking_script' do
    subject(:contract) { described_class.new(stateless_artifact, [SAMPLE_PKH]) }

    let(:sig) { '30' + ('00' * 70) + '41' }

    it 'returns a non-empty hex string' do
      result = contract.build_unlocking_script('unlock', [sig, SAMPLE_PUB_KEY])
      expect(result).to be_a(String)
      expect(result).not_to be_empty
    end

    it 'encodes each arg as push data' do
      result = contract.build_unlocking_script('unlock', [sig, SAMPLE_PUB_KEY])
      expect(result).to include(Runar::SDK::State.encode_push_data(sig))
      expect(result).to include(Runar::SDK::State.encode_push_data(SAMPLE_PUB_KEY))
    end

    it 'does not append a method selector when there is only one public method' do
      # Single public method → no selector suffix needed.
      script_with_args  = contract.build_unlocking_script('unlock', [sig, SAMPLE_PUB_KEY])
      expected_body     = Runar::SDK::State.encode_push_data(sig) + Runar::SDK::State.encode_push_data(SAMPLE_PUB_KEY)
      expect(script_with_args).to eq(expected_body)
    end
  end

  # ---------------------------------------------------------------------------
  # connect / resolve errors
  # ---------------------------------------------------------------------------

  describe '#connect and provider/signer resolution' do
    let(:contract) { described_class.new(stateless_artifact, [SAMPLE_PKH]) }

    it 'raises RuntimeError when deploy is called without provider' do
      expect { contract.deploy }.to raise_error(RuntimeError, /no provider/)
    end

    it 'raises RuntimeError when deploy is called without signer (after connect with only provider)' do
      contract.connect(mock_provider, nil) rescue nil
      # connect stores nil; deploy should raise signer error
      # (We just need a provider-less or signer-less scenario covered.)
      c2 = described_class.new(stateless_artifact, [SAMPLE_PKH])
      c2.instance_variable_set(:@provider, mock_provider)
      expect { c2.deploy }.to raise_error(RuntimeError, /no signer/)
    end

    it 'stores provider and signer via connect' do
      provider = mock_provider
      signer   = mock_signer
      contract.connect(provider, signer)
      expect(contract.instance_variable_get(:@provider)).to be(provider)
      expect(contract.instance_variable_get(:@signer)).to be(signer)
    end
  end

  # ---------------------------------------------------------------------------
  # Deploy lifecycle with MockProvider
  # ---------------------------------------------------------------------------

  describe '#deploy' do
    let(:provider) { mock_provider }
    let(:signer)   { mock_signer }
    let(:contract) { described_class.new(stateless_artifact, [SAMPLE_PKH]) }

    before do
      # Fund the signer address with a sufficient UTXO.
      provider.add_utxo(SAMPLE_ADDRESS, make_utxo('aa' * 32, 1_000_000, script: '76a914' + SAMPLE_ADDRESS + '88ac'))
    end

    it 'returns [txid, transaction]' do
      txid, tx = contract.deploy(provider, signer)
      expect(txid).to be_a(String)
      expect(txid).not_to be_empty
      expect(tx).to be_a(Runar::SDK::Transaction)
    end

    it 'broadcasts exactly one transaction' do
      contract.deploy(provider, signer)
      expect(provider.get_broadcasted_txs.length).to eq(1)
    end

    it 'tracks the contract UTXO after deployment' do
      contract.deploy(provider, signer)
      utxo = contract.get_utxo
      expect(utxo).not_to be_nil
      expect(utxo.satoshis).to eq(10_000)
    end

    it 'raises RuntimeError when no UTXOs are available' do
      empty_provider = mock_provider
      expect { contract.deploy(empty_provider, signer) }
        .to raise_error(RuntimeError, /no UTXOs/)
    end

    it 'uses the satoshis value from DeployOptions' do
      opts = Runar::SDK::DeployOptions.new(satoshis: 5_000)
      contract.deploy(provider, signer, opts)
      expect(contract.get_utxo.satoshis).to eq(5_000)
    end
  end

  # ---------------------------------------------------------------------------
  # Deploy -> Call chain with MockProvider + MockSigner (stateful counter).
  #
  # Mirrors the TypeScript contract-lifecycle.test.ts pattern: deploy a stateful
  # contract, retrieve the deploy UTXO, build + broadcast a call tx against it,
  # and assert new state reflects the expected increment.
  # ---------------------------------------------------------------------------

  describe '#call after deploy' do
    let(:provider) { mock_provider }
    let(:signer)   { mock_signer }
    let(:contract) { described_class.new(stateful_anf_artifact, [5]) }

    before do
      # Fund the signer address with a large P2PKH UTXO for deploy + call fees.
      provider.add_utxo(
        SAMPLE_ADDRESS,
        make_utxo('ee' * 32, 1_000_000, script: '76a914' + SAMPLE_ADDRESS + '88ac')
      )
      contract.connect(provider, signer)
    end

    it 'broadcasts a call transaction after deploy and updates state' do
      # Deploy: broadcasts 1 tx, tracks deploy UTXO.
      deploy_txid, deploy_tx = contract.deploy
      expect(deploy_txid).to be_a(String)
      expect(deploy_tx).to be_a(Runar::SDK::Transaction)
      expect(provider.get_broadcasted_txs.length).to eq(1)

      # Retrieve the deploy UTXO: #get_utxo should track the contract UTXO.
      deploy_utxo = contract.get_utxo
      expect(deploy_utxo).not_to be_nil
      expect(deploy_utxo.txid).to eq(deploy_txid)
      expect(deploy_utxo.output_index).to eq(0)
      expect(deploy_utxo.satoshis).to eq(10_000)

      # Fund the call so the call builder has change-source UTXOs as well.
      provider.add_utxo(
        SAMPLE_ADDRESS,
        make_utxo('ff' * 32, 1_000_000, script: '76a914' + SAMPLE_ADDRESS + '88ac')
      )

      # Call increment(): builds + broadcasts a call tx spending the deploy UTXO.
      call_txid, call_tx = contract.call('increment', [])
      expect(call_txid).to be_a(String)
      expect(call_txid).not_to be_empty
      expect(call_txid).not_to eq(deploy_txid)
      expect(call_tx).to be_a(Runar::SDK::Transaction)

      # Provider broadcast count: deploy + call = 2.
      expect(provider.get_broadcasted_txs.length).to eq(2)

      # State: ANF interpreter increments 'count' from 5 -> 6.
      expect(contract.get_state).to eq('count' => 6)

      # UTXO tracking: #get_utxo now points at the new (post-call) contract UTXO.
      new_utxo = contract.get_utxo
      expect(new_utxo).not_to be_nil
      expect(new_utxo.txid).to eq(call_txid)
      expect(new_utxo.txid).not_to eq(deploy_txid)
    end

    # #131: a stateful call with a future locktime must produce non-final
    # input sequences (0xfffffffe) so consensus actually enforces nLockTime.
    it 'threads a future locktime into non-final input sequences (#131)' do
      contract.deploy
      provider.add_utxo(
        SAMPLE_ADDRESS,
        make_utxo('ff' * 32, 1_000_000, script: '76a914' + SAMPLE_ADDRESS + '88ac')
      )

      contract.call('increment', [], nil, nil,
                    Runar::SDK::CallOptions.new(locktime: 800_000))
      call_tx_hex = provider.get_broadcasted_txs.last

      # locktime written LE at the tail.
      expect(call_tx_hex).to end_with('00350c00')

      # Every input sequence must be 0xfffffffe (LE hex "feffffff").
      pos = 8
      count, ic = Runar::SDK.read_varint_hex(call_tx_hex, pos)
      pos += ic
      count.times do
        pos += 72 # prev txid (64) + output index (8)
        script_len, sl = Runar::SDK.read_varint_hex(call_tx_hex, pos)
        pos += sl + script_len * 2
        expect(call_tx_hex[pos, 8]).to eq('feffffff')
        pos += 8
      end
    end
  end

  # ---------------------------------------------------------------------------
  # funding_signer — sign funding inputs with a distinct key (issue #134)
  # ---------------------------------------------------------------------------

  describe 'funding_signer (#134)' do
    METHOD_PUB  = "02#{'aa' * 32}"
    FUNDING_PUB = "02#{'bb' * 32}"
    METHOD_ADDR = ('aa' * 20)

    let(:method_signer)  { Runar::SDK::MockSigner.new(pub_key_hex: METHOD_PUB, address: METHOD_ADDR) }
    let(:funding_signer) { Runar::SDK::MockSigner.new(pub_key_hex: FUNDING_PUB, address: 'bb' * 20) }
    let(:provider)       { mock_provider }

    before do
      provider.add_utxo(METHOD_ADDR,
                        make_utxo('ee' * 32, 1_000_000, script: "76a914#{METHOD_ADDR}88ac"))
    end

    it 'deploy signs funding inputs with funding_signer, pushing its pubkey' do
      contract = described_class.new(stateful_anf_artifact, [5])
      contract.deploy(provider, method_signer,
                      Runar::SDK::DeployOptions.new(satoshis: 1_000, funding_signer: funding_signer))
      deploy_tx = provider.get_broadcasted_txs.last
      expect(deploy_tx).to include(FUNDING_PUB)
      expect(deploy_tx).not_to include(METHOD_PUB)
    end

    it 'deploy defaults to the connected signer when funding_signer is unset' do
      contract = described_class.new(stateful_anf_artifact, [5])
      contract.deploy(provider, method_signer, Runar::SDK::DeployOptions.new(satoshis: 1_000))
      deploy_tx = provider.get_broadcasted_txs.last
      expect(deploy_tx).to include(METHOD_PUB)
    end

    it 'call signs funding inputs with funding_signer, pushing its pubkey' do
      contract = described_class.new(stateful_anf_artifact, [5])
      contract.connect(provider, method_signer)
      contract.instance_variable_set(
        :@current_utxo,
        Runar::SDK::Utxo.new(txid: 'cc' * 32, output_index: 0,
                             satoshis: 10_000, script: contract.get_locking_script)
      )
      contract.call('increment', [], nil, nil,
                    Runar::SDK::CallOptions.new(funding_signer: funding_signer))
      call_tx = provider.get_broadcasted_txs.last
      expect(call_tx).to include(FUNDING_PUB)
    end
  end

  # ---------------------------------------------------------------------------
  # #call funding selection (issue #133)
  # ---------------------------------------------------------------------------

  describe '#call funding selection (#133)' do
    let(:provider) { mock_provider }
    let(:signer)   { mock_signer }
    let(:contract) { described_class.new(stateful_anf_artifact, [5]) }

    def input_count(tx_hex)
      count, = Runar::SDK.read_varint_hex(tx_hex, 8)
      count
    end

    # Give the contract a deployed UTXO directly (no deploy noise) so the
    # provider's funding set contains only the coins each test adds.
    def deploy_manually(satoshis = 10_000)
      contract.connect(provider, signer)
      contract.instance_variable_set(
        :@current_utxo,
        Runar::SDK::Utxo.new(txid: 'cc' * 32, output_index: 0,
                             satoshis: satoshis, script: contract.get_locking_script)
      )
    end

    def fund(address_utxos)
      address_utxos.each { |txid, sats| provider.add_utxo(SAMPLE_ADDRESS, make_utxo(txid, sats, script: '76a914' + SAMPLE_ADDRESS + '88ac')) }
    end

    it 'selects the smallest-sufficient funding, not all wallet UTXOs' do
      deploy_manually
      fund([['a0' * 32, 100_000], ['a1' * 32, 100_000], ['a2' * 32, 100_000]])
      contract.call('increment', [])
      call_tx = provider.get_broadcasted_txs.last
      # 1 contract input + 1 funding input = 2 (NOT 4).
      expect(input_count(call_tx)).to eq(2)
    end

    it 'raises clearly when max_funding_inputs cannot cover outputs + fee' do
      deploy_manually
      # Continuation value 16k against a 10k contract input needs ~6k of
      # funding; with 3k coins that is 2 inputs. Cap at 1 => must raise.
      fund([['b0' * 32, 3_000], ['b1' * 32, 3_000], ['b2' * 32, 3_000]])
      expect do
        contract.call('increment', [], nil, nil,
                      Runar::SDK::CallOptions.new(satoshis: 16_000, max_funding_inputs: 1))
      end.to raise_error(/max_funding_inputs/)
    end

    it 'honors a max_funding_inputs cap that is sufficient' do
      deploy_manually
      fund([['c0' * 32, 3_000], ['c1' * 32, 3_000], ['c2' * 32, 3_000]])
      expect do
        contract.call('increment', [], nil, nil,
                      Runar::SDK::CallOptions.new(satoshis: 16_000, max_funding_inputs: 3))
      end.not_to raise_error
    end
  end

  # ---------------------------------------------------------------------------
  # get_state / set_state
  # ---------------------------------------------------------------------------

  describe '#get_state and #set_state' do
    subject(:contract) { described_class.new(stateful_artifact, [99]) }

    it 'returns a Hash' do
      expect(contract.get_state).to be_a(Hash)
    end

    it 'returns a copy so mutation does not affect internal state' do
      state = contract.get_state
      state['count'] = 0
      expect(contract.get_state['count']).to eq(99)
    end

    it 'updates state with set_state' do
      contract.set_state('count' => 100)
      expect(contract.get_state['count']).to eq(100)
    end

    it 'merges — does not replace the entire state hash' do
      contract.set_state('count' => 50)
      expect(contract.get_state.key?('count')).to be true
    end
  end

  # ---------------------------------------------------------------------------
  # from_txid
  # ---------------------------------------------------------------------------

  describe '.from_txid' do
    let(:artifact)  { stateless_artifact }
    let(:provider)  { mock_provider }
    let(:script)    { described_class.new(artifact, [SAMPLE_PKH]).get_locking_script }
    let(:tx) do
      Runar::SDK::Transaction.new(
        txid: 'beef' * 16,
        outputs: [Runar::SDK::TxOutput.new(script: script, satoshis: 10_000)]
      )
    end

    before { provider.add_transaction(tx) }

    it 'returns a RunarContract instance' do
      contract = described_class.from_txid(artifact, tx.txid, 0, provider)
      expect(contract).to be_a(described_class)
    end

    it 'tracks the UTXO correctly' do
      contract = described_class.from_txid(artifact, tx.txid, 0, provider)
      expect(contract.get_utxo.txid).to eq(tx.txid)
      expect(contract.get_utxo.satoshis).to eq(10_000)
    end

    it 'raises ArgumentError for an out-of-range output index' do
      expect { described_class.from_txid(artifact, tx.txid, 5, provider) }
        .to raise_error(ArgumentError, /out of range/)
    end

    # F-273: Ruby Array supports negative indexing (arr[-1] == arr.last), so
    # without an explicit `< 0` guard a negative output_index silently binds
    # to the LAST output of the tx (typically change) instead of raising.
    #
    # Proves: output_index=-1 raises ArgumentError instead of resolving via
    # Ruby's negative-array-index semantics. Does not prove: behaviour for
    # output indices below -1, or for a tx with more than one output (this
    # fixture's tx has exactly one output, so -1 and 0 denote the same
    # element here — the guard change still fires regardless of tx shape).
    it 'raises ArgumentError for a negative output index instead of silently binding to the last output' do
      expect { described_class.from_txid(artifact, tx.txid, -1, provider) }
        .to raise_error(ArgumentError, /out of range/)
    end

    # #119: from_txid must recover the REAL constructor args baked into the
    # deployed script, not 0 placeholders.
    it 'restores the real constructor args from the deployed script (#119)' do
      contract = described_class.from_txid(artifact, tx.txid, 0, provider)
      restored = contract.instance_variable_get(:@constructor_args)
      expect(restored).to eq([SAMPLE_PKH])
      expect(restored).not_to eq([0])
    end
  end

  # ---------------------------------------------------------------------------
  # from_utxo — restore real constructor args (issue #119)
  # ---------------------------------------------------------------------------

  describe '.from_utxo restores constructor args (#119)' do
    let(:artifact) { stateless_artifact }
    let(:script)   { described_class.new(artifact, [SAMPLE_PKH]).get_locking_script }

    it 'recovers the baked-in pubKeyHash instead of a 0 placeholder' do
      utxo = Runar::SDK::Utxo.new(
        txid: 'ab' * 32, output_index: 0, satoshis: 10_000, script: script
      )
      contract = described_class.from_utxo(artifact, utxo)
      restored = contract.instance_variable_get(:@constructor_args)
      expect(restored).to eq([SAMPLE_PKH])
    end
  end

  # ---------------------------------------------------------------------------
  # Stateful contract: get_state from locking script
  # ---------------------------------------------------------------------------

  describe 'stateful contract state round-trip' do
    let(:contract) { described_class.new(stateful_artifact, [42]) }

    it 'encodes and decodes state correctly' do
      locking_script = contract.get_locking_script
      decoded = Runar::SDK::State.extract_state_from_script(stateful_artifact, locking_script)
      expect(decoded).to eq('count' => 42)
    end

    it 'reflects set_state changes in the locking script' do
      contract.set_state('count' => 7)
      locking_script = contract.get_locking_script
      decoded = Runar::SDK::State.extract_state_from_script(stateful_artifact, locking_script)
      expect(decoded).to eq('count' => 7)
    end
  end

  # ---------------------------------------------------------------------------
  # ANF interpreter auto-computation of new state
  # ---------------------------------------------------------------------------

  describe 'ANF auto-state in prepare_call' do
    let(:provider) { mock_provider }
    let(:signer)   { mock_signer }
    let(:contract) { described_class.new(stateful_anf_artifact, [5]) }

    before do
      # Deploy the contract so prepare_call has a current UTXO to spend.
      provider.add_utxo(
        SAMPLE_ADDRESS,
        make_utxo('cc' * 32, 1_000_000, script: '76a914' + SAMPLE_ADDRESS + '88ac')
      )
      contract.connect(provider, signer)
      contract.deploy
    end

    it 'auto-computes new state from ANF IR when new_state is nil' do
      # count starts at 5; increment() should produce count = 6
      _prepared = contract.prepare_call('increment', [])
      expect(contract.get_state['count']).to eq(6)
    end

    it 'explicit new_state overrides ANF auto-computation' do
      opts = Runar::SDK::CallOptions.new(new_state: { 'count' => 99 })
      _prepared = contract.prepare_call('increment', [], nil, nil, opts)
      expect(contract.get_state['count']).to eq(99)
    end

    it 'prepare_call works normally when artifact has no ANF' do
      # Use the stateful artifact without ANF data — no auto-computation,
      # state should remain unchanged (build_continuation with nil new_state
      # does not modify state).
      no_anf_contract = described_class.new(stateful_artifact, [10])
      provider.add_utxo(
        SAMPLE_ADDRESS,
        make_utxo('dd' * 32, 1_000_000, script: '76a914' + SAMPLE_ADDRESS + '88ac')
      )
      no_anf_contract.connect(provider, signer)
      no_anf_contract.deploy
      _prepared = no_anf_contract.prepare_call('increment', [])
      # Without ANF, state is not mutated by the interpreter.
      expect(no_anf_contract.get_state['count']).to eq(10)
    end
  end

  # ---------------------------------------------------------------------------
  # ANF data outputs (this.addDataOutput) — extraction must run regardless of
  # whether the caller supplied an explicit new_state. Data outputs are part
  # of method-body behaviour (not state) and the on-chain continuation hash
  # check fails at spend time if they're missing from the spending tx.
  #
  # Regression: integration/ruby/spec/data_outputs_spec.rb
  # Reference:  packages/runar-go/sdk_contract.go (always runs ANF interp).
  # ---------------------------------------------------------------------------

  describe 'ANF data output extraction' do
    # Stateful contract whose emit() bumps `counter` and emits a single
    # this.addDataOutput(0n, payload). The payload binding is t_script
    # (load_const hex string) and the satoshis binding is t_sats
    # (load_const 0). The payload value is the bytes that will appear as
    # the data output's full script.
    let(:emit_payload_hex) { '6a04deadbeef' } # OP_RETURN <4-byte push>
    let(:data_emitter_artifact_json) do
      JSON.generate(
        version:            '1.0',
        compilerVersion:    '0.1.0',
        contractName:       'DataEmitter',
        abi:                {
          constructor: { params: [{ name: 'counter', type: 'bigint' }] },
          methods:     [{ name: 'emit', params: [], isPublic: true }]
        },
        script:             'aabbcc',
        asm:                '',
        stateFields:        [{ name: 'counter', type: 'bigint', index: 0 }],
        constructorSlots:   [],
        codeSeparatorIndex: 0,
        anf:                {
          'properties' => [{ 'name' => 'counter', 'type' => 'bigint', 'readonly' => false }],
          'methods'    => [
            {
              'name'     => 'emit',
              'isPublic' => true,
              'params'   => [],
              'body'     => [
                { 'name' => 't_sats',   'value' => { 'kind' => 'load_const', 'value' => 0 } },
                { 'name' => 't_script', 'value' => { 'kind' => 'load_const', 'value' => emit_payload_hex } },
                { 'name' => 't_emit',   'value' => { 'kind' => 'add_data_output', 'satoshis' => 't_sats', 'scriptBytes' => 't_script' } },
                { 'name' => 't_prop',   'value' => { 'kind' => 'load_prop', 'name' => 'counter' } },
                { 'name' => 't_one',    'value' => { 'kind' => 'load_const', 'value' => 1 } },
                { 'name' => 't_sum',    'value' => { 'kind' => 'bin_op', 'op' => '+', 'left' => 't_prop', 'right' => 't_one' } },
                { 'name' => 't_upd',    'value' => { 'kind' => 'update_prop', 'name' => 'counter', 'value' => 't_sum' } }
              ]
            }
          ]
        }
      )
    end

    let(:data_emitter_artifact) { Runar::SDK::RunarArtifact.from_json(data_emitter_artifact_json) }
    let(:provider) { mock_provider }
    let(:signer)   { mock_signer }
    let(:contract) { described_class.new(data_emitter_artifact, [0]) }

    before do
      provider.add_utxo(
        SAMPLE_ADDRESS,
        make_utxo('11' * 32, 1_000_000, script: '76a914' + SAMPLE_ADDRESS + '88ac')
      )
      contract.connect(provider, signer)
      contract.deploy
    end

    it 'extracts data outputs from ANF when new_state is nil' do
      prepared = contract.prepare_call('emit', [])
      expect(prepared.tx_hex).to include(emit_payload_hex)
    end

    # Bug regression: when the caller pre-computes new_state, the SDK used to
    # short-circuit the ANF interpreter pass entirely, so addDataOutput
    # payloads were never extracted and the spending tx omitted the data
    # output — which made the on-chain continuation hash check fail.
    it 'extracts data outputs from ANF even when new_state is supplied' do
      opts = Runar::SDK::CallOptions.new(new_state: { 'counter' => 1 })
      prepared = contract.prepare_call('emit', [], nil, nil, opts)
      expect(prepared.tx_hex).to include(emit_payload_hex)
    end
  end
end

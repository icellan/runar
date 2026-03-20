# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK::Codegen' do
  # rubocop:enable RSpec/DescribeClass

  # ---------------------------------------------------------------------------
  # Helper: build artifacts
  # ---------------------------------------------------------------------------

  def make_p2pkh_artifact
    Runar::SDK::RunarArtifact.new(
      contract_name: 'P2PKH',
      abi: Runar::SDK::ABI.new(
        constructor_params: [
          Runar::SDK::ABIParam.new(name: 'pubKeyHash', type: 'Ripemd160')
        ],
        methods: [
          Runar::SDK::ABIMethod.new(
            name: 'unlock',
            params: [
              Runar::SDK::ABIParam.new(name: 'sig', type: 'Sig'),
              Runar::SDK::ABIParam.new(name: 'pubKey', type: 'PubKey')
            ],
            is_public: true
          )
        ]
      ),
      script: 'deadbeef',
      state_fields: []
    )
  end

  def make_counter_artifact
    Runar::SDK::RunarArtifact.new(
      contract_name: 'Counter',
      abi: Runar::SDK::ABI.new(
        constructor_params: [
          Runar::SDK::ABIParam.new(name: 'count', type: 'bigint')
        ],
        methods: [
          Runar::SDK::ABIMethod.new(
            name: 'increment',
            params: [
              Runar::SDK::ABIParam.new(name: 'sig', type: 'Sig'),
              Runar::SDK::ABIParam.new(name: 'txPreimage', type: 'SigHashPreimage'),
              Runar::SDK::ABIParam.new(name: '_changePKH', type: 'Ripemd160'),
              Runar::SDK::ABIParam.new(name: '_changeAmount', type: 'bigint'),
              Runar::SDK::ABIParam.new(name: '_newAmount', type: 'bigint')
            ],
            is_public: true,
            is_terminal: false
          ),
          Runar::SDK::ABIMethod.new(
            name: 'reset',
            params: [
              Runar::SDK::ABIParam.new(name: 'sig', type: 'Sig')
            ],
            is_public: true,
            is_terminal: true
          )
        ]
      ),
      script: 'cafebabe',
      state_fields: [
        Runar::SDK::StateField.new(name: 'count', type: 'bigint', index: 0)
      ]
    )
  end

  def make_no_params_artifact
    Runar::SDK::RunarArtifact.new(
      contract_name: 'Simple',
      abi: Runar::SDK::ABI.new(
        constructor_params: [],
        methods: [
          Runar::SDK::ABIMethod.new(
            name: 'execute',
            params: [],
            is_public: true
          )
        ]
      ),
      script: 'aabb',
      state_fields: []
    )
  end

  # ---------------------------------------------------------------------------
  # Mustache renderer
  # ---------------------------------------------------------------------------

  describe 'render_mustache' do
    it 'interpolates variables' do
      result = Runar::SDK::Codegen.render_mustache('Hello {{name}}!', { 'name' => 'World' })
      expect(result).to eq('Hello World!')
    end

    it 'renders sections for truthy values' do
      template = '{{#show}}visible{{/show}}'
      expect(Runar::SDK::Codegen.render_mustache(template, { 'show' => true })).to eq('visible')
      expect(Runar::SDK::Codegen.render_mustache(template, { 'show' => false })).to eq('')
    end

    it 'iterates over arrays' do
      template = '{{#items}}[{{.}}]{{/items}}'
      result = Runar::SDK::Codegen.render_mustache(template, { 'items' => %w[a b c] })
      expect(result).to eq('[a][b][c]')
    end

    it 'iterates over array of hashes' do
      template = '{{#items}}{{name}},{{/items}}'
      result = Runar::SDK::Codegen.render_mustache(template, {
        'items' => [{ 'name' => 'x' }, { 'name' => 'y' }],
      })
      expect(result).to eq('x,y,')
    end

    it 'renders inverted sections for falsy values' do
      template = '{{^show}}hidden{{/show}}'
      expect(Runar::SDK::Codegen.render_mustache(template, { 'show' => false })).to eq('hidden')
      expect(Runar::SDK::Codegen.render_mustache(template, { 'show' => true })).to eq('')
    end

    it 'renders inverted sections for empty arrays' do
      template = '{{^items}}none{{/items}}'
      expect(Runar::SDK::Codegen.render_mustache(template, { 'items' => [] })).to eq('none')
    end

    it 'replaces missing variables with empty string' do
      result = Runar::SDK::Codegen.render_mustache('a{{missing}}b', {})
      expect(result).to eq('ab')
    end
  end

  # ---------------------------------------------------------------------------
  # Name conversion
  # ---------------------------------------------------------------------------

  describe 'to_snake_case' do
    it 'converts camelCase to snake_case' do
      expect(Runar::SDK::Codegen.to_snake_case('pubKeyHash')).to eq('pub_key_hash')
      expect(Runar::SDK::Codegen.to_snake_case('releaseBySeller')).to eq('release_by_seller')
      expect(Runar::SDK::Codegen.to_snake_case('increment')).to eq('increment')
    end

    it 'handles consecutive capitals' do
      expect(Runar::SDK::Codegen.to_snake_case('parseHTMLDoc')).to eq('parse_html_doc')
    end
  end

  describe 'to_pascal_case' do
    it 'capitalizes the first letter' do
      expect(Runar::SDK::Codegen.to_pascal_case('increment')).to eq('Increment')
      expect(Runar::SDK::Codegen.to_pascal_case('releaseBySeller')).to eq('ReleaseBySeller')
    end
  end

  describe 'safe_method_name' do
    it 'prefixes reserved names with call_' do
      expect(Runar::SDK::Codegen.safe_method_name('connect')).to eq('call_connect')
      expect(Runar::SDK::Codegen.safe_method_name('deploy')).to eq('call_deploy')
    end

    it 'does not prefix non-reserved names' do
      expect(Runar::SDK::Codegen.safe_method_name('increment')).to eq('increment')
      expect(Runar::SDK::Codegen.safe_method_name('transfer')).to eq('transfer')
    end
  end

  # ---------------------------------------------------------------------------
  # Type mapping
  # ---------------------------------------------------------------------------

  describe 'map_type' do
    it 'maps known ABI types to Ruby types' do
      expect(Runar::SDK::Codegen.map_type('bigint')).to eq('Integer')
      expect(Runar::SDK::Codegen.map_type('boolean')).to eq('Boolean')
      expect(Runar::SDK::Codegen.map_type('Sig')).to eq('String')
      expect(Runar::SDK::Codegen.map_type('PubKey')).to eq('String')
      expect(Runar::SDK::Codegen.map_type('ByteString')).to eq('String')
    end

    it 'returns Object for unknown types' do
      expect(Runar::SDK::Codegen.map_type('Unknown')).to eq('Object')
    end
  end

  # ---------------------------------------------------------------------------
  # Param classification
  # ---------------------------------------------------------------------------

  describe 'classify_params' do
    it 'marks Sig params as hidden' do
      method = Runar::SDK::ABIMethod.new(
        name: 'unlock',
        params: [
          Runar::SDK::ABIParam.new(name: 'sig', type: 'Sig'),
          Runar::SDK::ABIParam.new(name: 'pubKey', type: 'PubKey')
        ]
      )
      classified = Runar::SDK::Codegen.classify_params(method, false)
      expect(classified[0]['hidden']).to be true
      expect(classified[1]['hidden']).to be false
    end

    it 'marks SigHashPreimage and internal params as hidden for stateful contracts' do
      method = Runar::SDK::ABIMethod.new(
        name: 'increment',
        params: [
          Runar::SDK::ABIParam.new(name: 'sig', type: 'Sig'),
          Runar::SDK::ABIParam.new(name: 'txPreimage', type: 'SigHashPreimage'),
          Runar::SDK::ABIParam.new(name: '_changePKH', type: 'Ripemd160'),
          Runar::SDK::ABIParam.new(name: '_changeAmount', type: 'bigint'),
          Runar::SDK::ABIParam.new(name: '_newAmount', type: 'bigint')
        ]
      )
      classified = Runar::SDK::Codegen.classify_params(method, true)
      expect(classified.map { |p| p['hidden'] }).to eq([true, true, true, true, true])
    end
  end

  describe 'terminal_method?' do
    it 'returns true for stateless contracts' do
      method = Runar::SDK::ABIMethod.new(name: 'unlock', params: [])
      expect(Runar::SDK::Codegen.terminal_method?(method, false)).to be true
    end

    it 'uses explicit is_terminal attribute' do
      method = Runar::SDK::ABIMethod.new(name: 'increment', params: [], is_terminal: false)
      expect(Runar::SDK::Codegen.terminal_method?(method, true)).to be false
    end

    it 'falls back to checking for _changePKH param' do
      method_with = Runar::SDK::ABIMethod.new(
        name: 'increment',
        params: [Runar::SDK::ABIParam.new(name: '_changePKH', type: 'Ripemd160')]
      )
      method_without = Runar::SDK::ABIMethod.new(
        name: 'burn',
        params: [Runar::SDK::ABIParam.new(name: 'sig', type: 'Sig')]
      )
      expect(Runar::SDK::Codegen.terminal_method?(method_with, true)).to be false
      expect(Runar::SDK::Codegen.terminal_method?(method_without, true)).to be true
    end
  end

  # ---------------------------------------------------------------------------
  # P2PKH codegen (stateless, single Sig + PubKey)
  # ---------------------------------------------------------------------------

  describe 'generate_ruby for P2PKH (stateless)' do
    subject(:code) { Runar::SDK::Codegen.generate_ruby(make_p2pkh_artifact) }

    it 'generates valid Ruby code' do
      expect(code).to be_a(String)
      expect(code).not_to be_empty
    end

    it 'includes the contract class name' do
      expect(code).to include('class P2PKHContract')
    end

    it 'includes constructor with keyword args' do
      expect(code).to include('pub_key_hash:')
    end

    it 'includes the unlock method' do
      expect(code).to include('def unlock(')
    end

    it 'includes pub_key as a user param (Sig is hidden)' do
      expect(code).to include('pub_key:')
    end

    it 'includes prepare and finalize methods for Sig params' do
      expect(code).to include('def prepare_unlock(')
      expect(code).to include('def finalize_unlock(')
    end

    it 'passes nil for hidden Sig params in SDK args' do
      expect(code).to include('nil, pub_key')
    end

    it 'includes the contract accessor' do
      expect(code).to include('attr_reader :contract')
    end

    it 'includes from_txid class method' do
      expect(code).to include('def self.from_txid(')
    end

    it 'includes TerminalOutput for terminal methods' do
      expect(code).to include('TerminalOutput')
    end

    it 'does not include stateful call options' do
      expect(code).not_to include('StatefulCallOptions')
    end

    it 'wraps in Runar::Contracts module' do
      expect(code).to include('module Runar')
      expect(code).to include('module Contracts')
    end

    it 'includes frozen_string_literal pragma' do
      expect(code).to include('# frozen_string_literal: true')
    end
  end

  # ---------------------------------------------------------------------------
  # Counter codegen (stateful, with terminal and non-terminal methods)
  # ---------------------------------------------------------------------------

  describe 'generate_ruby for Counter (stateful)' do
    subject(:code) { Runar::SDK::Codegen.generate_ruby(make_counter_artifact) }

    it 'includes the contract class name' do
      expect(code).to include('class CounterContract')
    end

    it 'includes constructor with keyword args' do
      expect(code).to include('count:')
    end

    it 'includes the increment method (stateful)' do
      expect(code).to include('def increment(')
    end

    it 'includes the reset method (terminal)' do
      expect(code).to include('def reset(')
    end

    it 'includes stateful call options struct' do
      expect(code).to include('CounterStatefulCallOptions')
    end

    it 'includes TerminalOutput for terminal methods' do
      expect(code).to include('TerminalOutput')
    end

    it 'includes prepare/finalize for increment (has Sig)' do
      expect(code).to include('def prepare_increment(')
      expect(code).to include('def finalize_increment(')
    end

    it 'includes prepare/finalize for reset (has Sig)' do
      expect(code).to include('def prepare_reset(')
      expect(code).to include('def finalize_reset(')
    end

    it 'hides internal stateful params from user-facing methods' do
      # increment should have no user-visible params (all hidden)
      expect(code).to match(/def increment\(\s*options:/)
    end
  end

  # ---------------------------------------------------------------------------
  # No-params contract
  # ---------------------------------------------------------------------------

  describe 'generate_ruby for Simple (no constructor params)' do
    subject(:code) { Runar::SDK::Codegen.generate_ruby(make_no_params_artifact) }

    it 'uses parameterless constructor' do
      expect(code).to include('def initialize(artifact)')
      expect(code).not_to include('def initialize(artifact,')
    end

    it 'includes the execute method' do
      expect(code).to include('def execute(')
    end
  end

  # ---------------------------------------------------------------------------
  # Context builder
  # ---------------------------------------------------------------------------

  describe 'build_codegen_context' do
    it 'builds context for P2PKH' do
      ctx = Runar::SDK::Codegen.build_codegen_context(make_p2pkh_artifact)
      expect(ctx['contractName']).to eq('P2PKH')
      expect(ctx['isStateful']).to be false
      expect(ctx['hasConstructorParams']).to be true
      expect(ctx['constructorParams'].length).to eq(1)
      expect(ctx['methods'].length).to eq(1)
    end

    it 'builds context for Counter' do
      ctx = Runar::SDK::Codegen.build_codegen_context(make_counter_artifact)
      expect(ctx['contractName']).to eq('Counter')
      expect(ctx['isStateful']).to be true
      expect(ctx['hasStatefulMethods']).to be true
      expect(ctx['hasTerminalMethods']).to be true
      expect(ctx['methods'].length).to eq(2)
    end
  end
end

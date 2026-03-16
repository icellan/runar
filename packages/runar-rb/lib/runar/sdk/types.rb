# frozen_string_literal: true

# Runar SDK types for deploying and interacting with compiled contracts on BSV.
#
# These structs model the data exchanged between the SDK, the blockchain
# provider, and the signing layer. They mirror the types defined in the Python
# and Go SDKs so all four language implementations are structurally consistent.

module Runar
  module SDK
    # An unspent transaction output.
    Utxo = Struct.new(:txid, :output_index, :satoshis, :script, keyword_init: true)

    # A transaction input.
    TxInput = Struct.new(:txid, :output_index, :script, :sequence, keyword_init: true) do
      def initialize(txid:, output_index:, script:, sequence: 0xFFFFFFFF)
        super
      end
    end

    # A transaction output.
    TxOutput = Struct.new(:script, :satoshis, keyword_init: true)

    # A parsed Bitcoin transaction (data shape for get_transaction return value).
    #
    # Named TransactionData to distinguish from any lower-level transaction class
    # that may be used in the signing layer.
    TransactionData = Struct.new(:txid, :version, :inputs, :outputs, :locktime, :raw, keyword_init: true) do
      def initialize(txid:, version: 1, inputs: [], outputs: [], locktime: 0, raw: '')
        super
      end
    end

    # Backward-compatibility alias — existing code using Transaction continues to work.
    Transaction = TransactionData

    # A single ABI parameter.
    ABIParam = Struct.new(:name, :type, keyword_init: true)

    # A contract method descriptor.
    ABIMethod = Struct.new(:name, :params, :is_public, :is_terminal, keyword_init: true) do
      def initialize(name:, params: [], is_public: true, is_terminal: nil)
        super
      end
    end

    # Contract ABI: constructor params and method descriptors.
    ABI = Struct.new(:constructor_params, :methods, keyword_init: true) do
      def initialize(constructor_params: [], methods: [])
        super
      end
    end

    # A state field in a stateful contract.
    StateField = Struct.new(:name, :type, :index, :initial_value, keyword_init: true) do
      def initialize(name:, type:, index:, initial_value: nil)
        super
      end
    end

    # Where a constructor placeholder resides in the compiled script.
    ConstructorSlot = Struct.new(:param_index, :byte_offset, keyword_init: true)

    # Compiled output of a Runar compiler.
    #
    # Use RunarArtifact.from_hash to load from a JSON-parsed Hash, or
    # RunarArtifact.from_json to parse a raw JSON string.
    class RunarArtifact
      attr_reader :version, :compiler_version, :contract_name, :abi,
                  :script, :asm, :state_fields, :constructor_slots,
                  :build_timestamp, :code_separator_index, :code_separator_indices

      def initialize(
        version: '',
        compiler_version: '',
        contract_name: '',
        abi: ABI.new,
        script: '',
        asm: '',
        state_fields: [],
        constructor_slots: [],
        build_timestamp: '',
        code_separator_index: nil,
        code_separator_indices: nil
      )
        @version               = version
        @compiler_version      = compiler_version
        @contract_name         = contract_name
        @abi                   = abi
        @script                = script
        @asm                   = asm
        @state_fields          = state_fields
        @constructor_slots     = constructor_slots
        @build_timestamp       = build_timestamp
        @code_separator_index  = code_separator_index
        @code_separator_indices = code_separator_indices
      end

      # Load an artifact from a JSON-parsed Hash (keys may be camelCase strings).
      def self.from_hash(hash)
        abi_raw = hash.fetch('abi', {})

        ctor_params = Array(abi_raw.dig('constructor', 'params')).map do |p|
          ABIParam.new(name: p['name'], type: p['type'])
        end

        methods = Array(abi_raw['methods']).map do |m|
          params = Array(m['params']).map { |p| ABIParam.new(name: p['name'], type: p['type']) }
          ABIMethod.new(
            name: m['name'],
            params: params,
            is_public: m.fetch('isPublic', true),
            is_terminal: m['isTerminal']
          )
        end

        state_fields = Array(hash['stateFields']).map do |sf|
          StateField.new(
            name: sf['name'],
            type: sf['type'],
            index: sf['index'],
            initial_value: sf['initialValue']
          )
        end

        constructor_slots = Array(hash['constructorSlots']).map do |cs|
          ConstructorSlot.new(param_index: cs['paramIndex'], byte_offset: cs['byteOffset'])
        end

        new(
          version:               hash.fetch('version', ''),
          compiler_version:      hash.fetch('compilerVersion', ''),
          contract_name:         hash.fetch('contractName', ''),
          abi:                   ABI.new(constructor_params: ctor_params, methods: methods),
          script:                hash.fetch('script', ''),
          asm:                   hash.fetch('asm', ''),
          state_fields:          state_fields,
          constructor_slots:     constructor_slots,
          build_timestamp:       hash.fetch('buildTimestamp', ''),
          code_separator_index:  hash['codeSeparatorIndex'],
          code_separator_indices: hash['codeSeparatorIndices']
        )
      end

      # Load an artifact from a raw JSON string.
      def self.from_json(json_string)
        require 'json'
        from_hash(JSON.parse(json_string))
      end
    end

    # Options for deploying a contract.
    DeployOptions = Struct.new(:satoshis, :change_address, keyword_init: true) do
      def initialize(satoshis: 10_000, change_address: '')
        super
      end
    end

    # Specification for a single contract continuation output (multi-output methods).
    OutputSpec = Struct.new(:satoshis, :state, keyword_init: true)

    # Specification for an exact output in a terminal method call.
    #
    # Terminal methods verify output structure on-chain via extractOutputHash().
    # The transaction is built with only the contract UTXO as input and no
    # change output — the fee comes from the contract balance.
    TerminalOutput = Struct.new(:script_hex, :satoshis, keyword_init: true)

    # Options for calling a contract method.
    #
    # The +outputs+ field supports multi-output patterns (e.g., token splits).
    # The +terminal_outputs+ field is used when a method verifies an exact
    # output set on-chain — the transaction is built with no change output
    # and no funding inputs beyond the contract UTXO.
    CallOptions = Struct.new(
      :satoshis,
      :change_address,
      :change_pub_key,
      :new_state,
      :outputs,
      :additional_contract_inputs,
      :additional_contract_input_args,
      :terminal_outputs,
      keyword_init: true
    ) do
      def initialize(
        satoshis: 0,
        change_address: '',
        change_pub_key: '',
        new_state: nil,
        outputs: nil,
        additional_contract_inputs: nil,
        additional_contract_input_args: nil,
        terminal_outputs: nil
      )
        super
      end
    end

    # Result of +prepare_call+ — contains everything needed for external signing
    # and subsequent +finalize_call+.
    #
    # Public fields (+sighash+, +preimage+, +op_push_tx_sig+, +tx_hex+,
    # +sig_indices+) are for external signer coordination.  All other fields
    # are internal state consumed by +finalize_call+.
    PreparedCall = Struct.new(
      # Public — callers use these to coordinate external signing.
      :sighash,             # 64-char hex — BIP-143 hash external signers sign
      :preimage,            # hex — full BIP-143 preimage
      :op_push_tx_sig,      # hex — OP_PUSH_TX DER sig (empty if not needed)
      :tx_hex,              # hex — built TX (P2PKH funding signed, primary input uses placeholder sigs)
      :sig_indices,         # Array<Integer> — user-visible arg positions needing external Sig values

      # Internal — consumed by finalize_call.
      :method_name,
      :resolved_args,
      :method_selector_hex,
      :is_stateful,
      :is_terminal,
      :needs_op_push_tx,
      :method_needs_change,
      :change_pkh_hex,
      :change_amount,
      :method_needs_new_amount,
      :new_amount,
      :preimage_index,
      :contract_utxo,
      :new_locking_script,
      :new_satoshis,
      :has_multi_output,
      :contract_outputs,
      :code_sep_idx,
      keyword_init: true
    ) do
      # rubocop:disable Metrics/ParameterLists
      def initialize(
        sighash: '',
        preimage: '',
        op_push_tx_sig: '',
        tx_hex: '',
        sig_indices: [],
        method_name: '',
        resolved_args: [],
        method_selector_hex: '',
        is_stateful: false,
        is_terminal: false,
        needs_op_push_tx: false,
        method_needs_change: false,
        change_pkh_hex: '',
        change_amount: 0,
        method_needs_new_amount: false,
        new_amount: 0,
        preimage_index: -1,
        contract_utxo: nil,
        new_locking_script: '',
        new_satoshis: 0,
        has_multi_output: false,
        contract_outputs: [],
        code_sep_idx: -1
      )
        super
      end
      # rubocop:enable Metrics/ParameterLists
    end
  end
end

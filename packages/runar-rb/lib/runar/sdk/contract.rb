# frozen_string_literal: true

require 'digest'
require_relative 'types'
require_relative 'provider'
require_relative 'signer'
require_relative 'state'
require_relative 'deployment'
require_relative 'calling'
require_relative 'oppushtx'
require_relative 'anf_interpreter'
require_relative 'wallet'
require_relative 'ordinals'

# RunarContract — runtime wrapper for a compiled Runar contract.
#
# Handles deployment, method invocation, state tracking, and script
# construction. Mirrors the Python SDK RunarContract class in structure and
# behavior.
#
# Public method names (get_state, set_state, get_locking_script, etc.) mirror
# the Python and Go SDKs for cross-language consistency. The Naming/AccessorMethodName
# and Naming/PredicatePrefix cops are suppressed on these methods because matching
# the SDK interface across four languages takes priority over Ruby naming conventions.
#
# Usage (stateless):
#
#   artifact = Runar::SDK::RunarArtifact.from_json(File.read('Contract.json'))
#   contract = Runar::SDK::RunarContract.new(artifact, [pub_key_hash])
#   contract.connect(provider, signer)
#   txid, _tx = contract.deploy
#   txid, _tx = contract.call('unlock', [sig, pub_key])
#
# Usage (stateful):
#
#   contract = Runar::SDK::RunarContract.new(artifact, [0])   # count = 0
#   txid, _tx = contract.deploy(provider, signer)
#   txid, _tx = contract.call('increment', [], provider, signer)
#   contract.get_state  # => { 'count' => 1 }
#
# Method visibility notes:
#   - State helpers (encode_push_data, encode_script_int, serialize_state, etc.)
#     are called via State.method_name — they are public module-function methods
#     on Runar::SDK::State.
#   - Deployment/calling/oppushtx helpers (select_utxos, build_deploy_transaction,
#     etc.) are called via SDK.method_name — they are public module-function
#     methods on Runar::SDK.

module Runar
  module SDK
    # rubocop:disable Naming/AccessorMethodName, Naming/PredicatePrefix
    class RunarContract
      attr_reader :artifact, :inscription

      # @param artifact         [RunarArtifact] compiled contract artifact
      # @param constructor_args [Array]         constructor argument values
      # @raise [ArgumentError] when arg count does not match the ABI
      def initialize(artifact, constructor_args)
        expected = artifact.abi.constructor_params.length
        actual   = constructor_args.length
        if actual != expected
          raise ArgumentError,
                "RunarContract: expected #{expected} constructor args for " \
                "#{artifact.contract_name}, got #{actual}"
        end

        @artifact         = artifact
        @constructor_args = constructor_args.dup
        @state            = {}
        @code_script      = ''
        @current_utxo     = nil
        @provider         = nil
        @signer           = nil
        @inscription      = nil

        init_state_from_constructor_args
      end

      # Attach a 1sat ordinals inscription to this contract.
      #
      # The inscription envelope is injected into the locking script between the
      # compiled code and the state section (if any). Once deployed, the inscription
      # is immutable -- it persists identically across all state transitions.
      #
      # @param insc [Inscription] inscription data (content_type + hex data)
      # @return [self] for chaining
      def with_inscription(insc)
        @inscription = insc
        self
      end

      # Return the UTXO currently tracked by this contract, or nil if not deployed.
      #
      # @return [Utxo, nil]
      def get_utxo
        @current_utxo
      end

      # Store provider and signer for use by subsequent deploy/call invocations.
      #
      # @param provider [Provider]
      # @param signer   [Signer]
      def connect(provider, signer)
        @provider = provider
        @signer   = signer
      end

      # Deploy the contract to the blockchain.
      #
      # Builds the locking script (code + optional state), selects UTXOs,
      # constructs and signs the transaction, broadcasts it, and begins
      # tracking the contract UTXO.
      #
      # @param provider [Provider, nil]      overrides connected provider
      # @param signer   [Signer, nil]        overrides connected signer
      # @param options  [DeployOptions, nil] deployment parameters
      # @return [Array(String, TransactionData)] [txid, transaction]
      def deploy(provider = nil, signer = nil, options = nil)
        provider = resolve_provider(provider, 'deploy')
        signer   = resolve_signer(signer, 'deploy')
        opts     = options || DeployOptions.new

        address        = signer.get_address
        change_address = opts.change_address.to_s.empty? ? address : opts.change_address
        locking_script = get_locking_script

        fee_rate  = provider.get_fee_rate
        all_utxos = provider.get_utxos(address)

        raise "RunarContract.deploy: no UTXOs found for #{address}" if all_utxos.empty?

        utxos         = SDK.select_utxos(all_utxos, opts.satoshis, locking_script.length / 2, fee_rate: fee_rate)
        change_script = SDK.build_p2pkh_script(change_address)

        tx_hex, input_count = SDK.build_deploy_transaction(
          locking_script, utxos, opts.satoshis, change_address, change_script, fee_rate: fee_rate
        )

        # Sign all P2PKH funding inputs.
        signed_tx = tx_hex
        pub_key   = signer.get_public_key
        input_count.times do |i|
          utxo      = utxos[i]
          sig       = signer.sign(signed_tx, i, utxo.script, utxo.satoshis)
          unlock    = State.encode_push_data(sig) + State.encode_push_data(pub_key)
          signed_tx = SDK.insert_unlocking_script(signed_tx, i, unlock)
        end

        txid = provider.broadcast(signed_tx)

        @current_utxo = Utxo.new(
          txid: txid, output_index: 0,
          satoshis: opts.satoshis, script: locking_script
        )

        tx = begin
          provider.get_transaction(txid)
        rescue StandardError
          TransactionData.new(
            txid: txid, version: 1,
            outputs: [TxOutput.new(satoshis: opts.satoshis, script: locking_script)],
            raw: signed_tx
          )
        end

        [txid, tx]
      end

      # Deploy the contract using a BRC-100 wallet.
      #
      # The wallet owns the coins and creates the transaction itself via
      # +create_action+. Requires the contract to be connected to a
      # WalletProvider (via +connect+).
      #
      # @param satoshis    [Integer]     satoshis to lock in the contract output (default: 1)
      # @param description [String, nil] human-readable description for the wallet action
      # @return [Hash] { txid: String, output_index: Integer }
      def deploy_with_wallet(satoshis: 1, description: nil)
        unless @provider.is_a?(WalletProvider)
          raise 'deploy_with_wallet requires a connected WalletProvider. ' \
                'Call connect(wallet_provider, signer) first.'
        end

        wallet = @provider.wallet
        basket = @provider.basket
        locking_script = get_locking_script
        desc = description || 'Runar contract deployment'

        result = wallet.create_action(
          description: desc,
          outputs: [{
            locking_script: locking_script,
            satoshis: satoshis,
            output_description: "Deploy #{@artifact.contract_name}",
            basket: basket
          }]
        )

        txid = result[:txid] || result['txid'] || ''
        raw_tx = result[:raw_tx] || result['raw_tx']
        output_index = 0

        # Cache the raw tx if available.
        @provider.cache_tx(txid, raw_tx) if raw_tx && !raw_tx.empty?

        @current_utxo = Utxo.new(
          txid: txid,
          output_index: output_index,
          satoshis: satoshis,
          script: locking_script
        )

        { txid: txid, output_index: output_index }
      end

      # Invoke a public method (spend the contract UTXO).
      #
      # For stateful contracts, the preimage and k=1 OP_PUSH_TX signature are
      # computed automatically. For methods with +Sig+ params, a 72-byte
      # placeholder is substituted during transaction construction then replaced
      # with a real signature.
      #
      # @param method_name [String]          ABI method name
      # @param args        [Array]           user-supplied arguments
      # @param provider    [Provider, nil]   overrides connected provider
      # @param signer      [Signer, nil]     overrides connected signer
      # @param options     [CallOptions, nil]
      # @return [Array(String, TransactionData)] [txid, transaction]
      def call(method_name, args = [], provider = nil, signer = nil, options = nil)
        provider = resolve_provider(provider, 'call')
        signer   = resolve_signer(signer, 'call')

        prepared   = prepare_call(method_name, args, provider, signer, options)
        signatures = {}
        prepared.sig_indices.each do |idx|
          subscript = prepared.contract_utxo.script
          if prepared.is_stateful && prepared.code_sep_idx >= 0
            trim_pos  = (prepared.code_sep_idx + 1) * 2
            subscript = subscript[trim_pos..] if trim_pos <= subscript.length
          end
          signatures[idx] = signer.sign(
            prepared.tx_hex, 0,
            subscript,
            prepared.contract_utxo.satoshis
          )
        end

        finalize_call(prepared, signatures, provider)
      end

      # Prepare a method call without signing the primary contract input's Sig
      # params. Returns a +PreparedCall+ struct for use with +finalize_call+.
      #
      # P2PKH funding inputs ARE signed. Only the primary contract input's Sig
      # params are left as 72-byte placeholders.
      #
      # @param method_name [String]
      # @param args        [Array, nil]
      # @param provider    [Provider, nil]
      # @param signer      [Signer, nil]
      # @param options     [CallOptions, nil]
      # @return [PreparedCall]
      # rubocop:disable Metrics/AbcSize, Metrics/MethodLength, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
      def prepare_call(method_name, args = [], provider = nil, signer = nil, options = nil)
        provider = resolve_provider(provider, 'prepare_call')
        signer   = resolve_signer(signer, 'prepare_call')
        args     = Array(args)

        method = find_method(method_name)
        unless method
          raise ArgumentError,
                "RunarContract.prepare_call: method '#{method_name}' not found in #{@artifact.contract_name}"
        end

        is_stateful = !@artifact.state_fields.empty?

        method_needs_change     = method.params.any? { |p| p.name == '_changePKH' }
        method_needs_new_amount = method.params.any? { |p| p.name == '_newAmount' }

        user_params = if is_stateful
                        method.params.reject do |p|
                          p.type == 'SigHashPreimage' ||
                            p.name == '_changePKH' ||
                            p.name == '_changeAmount' ||
                            p.name == '_newAmount'
                        end
                      else
                        method.params
                      end

        if user_params.length != args.length
          raise ArgumentError,
                "RunarContract.prepare_call: method '#{method_name}' expects " \
                "#{user_params.length} args, got #{args.length}"
        end

        unless @current_utxo
          raise 'RunarContract.prepare_call: contract is not deployed. Call deploy() or from_txid() first.'
        end

        contract_utxo = Utxo.new(
          txid: @current_utxo.txid, output_index: @current_utxo.output_index,
          satoshis: @current_utxo.satoshis, script: @current_utxo.script
        )
        address        = signer.get_address
        opts           = options || CallOptions.new
        change_address = opts.change_address.to_s.empty? ? address : opts.change_address

        extra_input_count = Array(opts.additional_contract_inputs).length
        estimated_inputs  = 1 + extra_input_count + 1
        resolved_args, sig_indices, preimage_index, prevouts_indices =
          resolve_method_args(args, user_params, signer, estimated_inputs: estimated_inputs)

        needs_op_push_tx    = preimage_index >= 0 || is_stateful
        method_selector_hex = compute_method_selector(method_name, is_stateful)
        code_sep_idx        = get_code_sep_index(find_method_index(method_name))

        change_pkh_hex = compute_change_pkh(signer, is_stateful, method_needs_change)

        # Auto-compute new state via ANF interpreter when artifact has ANF IR and
        # no explicit new_state was provided. This mirrors the Python SDK behavior:
        # compute_new_state is called here (where method_name and args are available),
        # not in build_continuation (which has neither).
        if is_stateful && @artifact.anf && opts.new_state.nil?
          named_args = build_named_args(user_params, resolved_args)
          opts = opts.dup
          opts.new_state = ANFInterpreter.compute_new_state(
            @artifact.anf, method_name, @state, named_args,
            constructor_args: @constructor_args
          )
        end

        # Terminal call path: build a transaction with exact outputs, no funding inputs.
        if opts.terminal_outputs && !opts.terminal_outputs.empty?
          return prepare_terminal(
            method_name, resolved_args, signer, opts,
            is_stateful, needs_op_push_tx, method_needs_change,
            sig_indices, preimage_index,
            method_selector_hex, change_pkh_hex, contract_utxo, code_sep_idx
          )
        end

        # Multi-output path: build contract_outputs from opts.outputs when present.
        # Single-output path: fall through to build_continuation.
        has_multi_output = is_stateful && opts.outputs && !Array(opts.outputs).empty?
        contract_outputs = nil
        new_locking_script = ''
        new_satoshis = 0

        if has_multi_output
          code_script = @code_script.empty? ? build_code_script : @code_script
          contract_outputs = Array(opts.outputs).map do |out_spec|
            state_dict = out_spec.is_a?(OutputSpec) ? out_spec.state : (out_spec['state'] || out_spec[:state])
            sats = out_spec.is_a?(OutputSpec) ? out_spec.satoshis : (out_spec['satoshis'] || out_spec[:satoshis] || 1)
            state_hex = State.serialize_state(@artifact.state_fields, state_dict)
            { script: "#{code_script}6a#{state_hex}", satoshis: sats }
          end
        else
          new_locking_script, new_satoshis = build_continuation(is_stateful, opts)
        end

        # Normalise additional contract inputs to Utxo objects.
        extra_contract_utxos = Array(opts.additional_contract_inputs).map do |item|
          case item
          when Utxo then item
          when Hash
            Utxo.new(
              txid: item[:txid] || item['txid'],
              output_index: item[:output_index] || item['output_index'],
              satoshis: item[:satoshis] || item['satoshis'],
              script: item[:script] || item['script']
            )
          else item
          end
        end

        # Resolve per-input args for additional contract inputs.
        raw_per_input_args = Array(opts.additional_contract_input_args)
        resolved_per_input_args = extra_contract_utxos.each_with_index.map do |_, i|
          input_args = (raw_per_input_args[i] || resolved_args).dup
          user_params.each_with_index do |param, j|
            case param.type
            when 'Sig'    then input_args[j] = '00' * 72 if input_args[j].nil?
            when 'PubKey' then input_args[j] = signer.get_public_key if input_args[j].nil?
            end
          end
          input_args
        end

        fee_rate          = provider.get_fee_rate
        change_script     = SDK.build_p2pkh_script(change_address)
        all_funding_utxos = provider.get_utxos(address)
        additional_utxos  = all_funding_utxos.reject do |u|
          u.txid == @current_utxo.txid && u.output_index == @current_utxo.output_index
        end

        unlocking_script = if needs_op_push_tx
                             build_stateful_prefix('00' * 72, method_needs_change) +
                               build_unlocking_script(method_name, resolved_args)
                           else
                             build_unlocking_script(method_name, resolved_args)
                           end

        # Build placeholder unlocking scripts for extra contract inputs.
        extra_unlock_placeholders = extra_contract_utxos.each_with_index.map do |_, i|
          args_for_placeholder = resolved_per_input_args[i] || resolved_args
          build_stateful_prefix('00' * 72, method_needs_change) +
            build_unlocking_script(method_name, args_for_placeholder)
        end

        call_options = {}
        call_options[:contract_outputs] = contract_outputs if contract_outputs
        if extra_contract_utxos.any?
          call_options[:additional_contract_inputs] = extra_contract_utxos.each_with_index.map do |utxo, i|
            { utxo: utxo, unlocking_script: extra_unlock_placeholders[i] }
          end
        end

        tx_hex, _input_count, change_amount = SDK.build_call_transaction(
          contract_utxo, unlocking_script, new_locking_script,
          new_satoshis, change_address, change_script,
          additional_utxos.empty? ? nil : additional_utxos,
          fee_rate: fee_rate,
          options: call_options.empty? ? nil : call_options
        )

        p2pkh_start_idx = 1 + extra_contract_utxos.length
        signed_tx = sign_funding_inputs(tx_hex, additional_utxos, signer, p2pkh_start_idx)

        signed_tx, change_amount, final_op_push_tx_sig, final_preimage =
          compute_preimage_passes(
            signed_tx, contract_utxo, resolved_args, sig_indices,
            method_name, method_needs_change, method_needs_new_amount,
            change_pkh_hex, method_selector_hex, code_sep_idx,
            change_amount, new_satoshis, new_locking_script,
            change_address, change_script, additional_utxos, fee_rate, signer,
            is_stateful, needs_op_push_tx, preimage_index,
            contract_outputs: contract_outputs,
            extra_contract_utxos: extra_contract_utxos,
            resolved_per_input_args: resolved_per_input_args,
            prevouts_indices: prevouts_indices
          )

        sighash = final_preimage.empty? ? '' : Digest::SHA256.hexdigest([final_preimage].pack('H*'))

        build_prepared_call(
          sighash, final_preimage, final_op_push_tx_sig, signed_tx,
          sig_indices, method_name, resolved_args, method_selector_hex,
          is_stateful, needs_op_push_tx, method_needs_change, change_pkh_hex,
          change_amount, method_needs_new_amount, new_satoshis, preimage_index,
          contract_utxo, new_locking_script, code_sep_idx,
          has_multi_output: has_multi_output,
          contract_outputs: contract_outputs || []
        )
      end
      # rubocop:enable Metrics/AbcSize, Metrics/MethodLength, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

      # Complete a prepared call by injecting external signatures and broadcasting.
      #
      # @param prepared   [PreparedCall]            result of +prepare_call+
      # @param signatures [Hash<Integer, String>]   map from arg index to hex signature
      # @param provider   [Provider, nil]           overrides connected provider
      # @return [Array(String, TransactionData)] [txid, transaction]
      # rubocop:disable Metrics/MethodLength
      def finalize_call(prepared, signatures, provider = nil)
        provider = resolve_provider(provider, 'finalize_call')

        resolved_args = prepared.resolved_args.dup
        prepared.sig_indices.each { |idx| resolved_args[idx] = signatures[idx] if signatures.key?(idx) }

        primary_unlock = assemble_primary_unlock(prepared, resolved_args)
        final_tx       = SDK.insert_unlocking_script(prepared.tx_hex, 0, primary_unlock)
        txid           = provider.broadcast(final_tx)

        update_tracked_utxo(txid, prepared)

        tx = begin
          provider.get_transaction(txid)
        rescue StandardError
          TransactionData.new(txid: txid, version: 1, raw: final_tx)
        end

        [txid, tx]
      end
      # rubocop:enable Metrics/MethodLength

      # Reconnect to an existing deployed contract by looking up the transaction
      # on-chain.
      #
      # @param artifact      [RunarArtifact]
      # @param txid          [String]   txid of the deploy transaction
      # @param output_index  [Integer]  index of the contract output
      # @param provider      [Provider]
      # @return [RunarContract]
      # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
      def self.from_txid(artifact, txid, output_index, provider)
        tx = provider.get_transaction(txid)
        if output_index >= tx.outputs.length
          raise ArgumentError,
                "RunarContract.from_txid: output index #{output_index} out of range " \
                "(tx has #{tx.outputs.length} outputs)"
        end

        output     = tx.outputs[output_index]
        dummy_args = Array.new(artifact.abi.constructor_params.length, 0)
        contract   = new(artifact, dummy_args)

        stateful = !artifact.state_fields.empty?
        code_script = if stateful
                        last_or = State.find_last_op_return(output.script)
                        last_or != -1 ? output.script[0, last_or] : output.script
                      else
                        output.script
                      end

        contract.instance_variable_set(:@code_script, code_script)

        # Detect inscription envelope in the code portion.
        if code_script && !code_script.empty?
          insc = Ordinals.parse_inscription_envelope(code_script)
          contract.instance_variable_set(:@inscription, insc) if insc
        end

        contract.instance_variable_set(
          :@current_utxo,
          Utxo.new(txid: txid, output_index: output_index, satoshis: output.satoshis, script: output.script)
        )

        if stateful
          state = State.extract_state_from_script(artifact, output.script)
          contract.instance_variable_set(:@state, state) if state
        end

        contract
      end
      # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

      # Reconnect to an existing deployed contract from a UTXO.
      #
      # This is the synchronous equivalent of +from_txid+ -- use it when the
      # UTXO data is already available (e.g. from an overlay service or cache)
      # without needing a Provider to fetch the transaction.
      #
      # @param artifact [RunarArtifact]
      # @param utxo     [Utxo, Hash] the UTXO containing the contract output.
      #   Accepts a Utxo struct or a Hash with :txid, :output_index, :satoshis, :script keys.
      # @return [RunarContract]
      def self.from_utxo(artifact, utxo)
        utxo = normalize_utxo(utxo)
        dummy_args = Array.new(artifact.abi.constructor_params.length, 0)
        contract   = new(artifact, dummy_args)

        stateful = !artifact.state_fields.empty?
        code_script = if stateful
                        last_or = State.find_last_op_return(utxo.script)
                        last_or != -1 ? utxo.script[0, last_or] : utxo.script
                      else
                        utxo.script
                      end

        contract.instance_variable_set(:@code_script, code_script)

        # Detect inscription envelope in the code portion. Keep it in @code_script
        # (do NOT strip) so that stateful continuation outputs preserve it.
        if code_script && !code_script.empty?
          insc = Ordinals.parse_inscription_envelope(code_script)
          contract.instance_variable_set(:@inscription, insc) if insc
        end

        contract.instance_variable_set(
          :@current_utxo,
          Utxo.new(txid: utxo.txid, output_index: utxo.output_index,
                   satoshis: utxo.satoshis, script: utxo.script)
        )

        if stateful
          state = State.extract_state_from_script(artifact, utxo.script)
          contract.instance_variable_set(:@state, state) if state
        end

        contract
      end

      # Normalize a UTXO argument to a Utxo struct.
      # @api private
      def self.normalize_utxo(utxo)
        case utxo
        when Utxo then utxo
        when Hash
          Utxo.new(
            txid: utxo[:txid] || utxo['txid'],
            output_index: utxo[:output_index] || utxo['output_index'] || utxo[:outputIndex] || utxo['outputIndex'],
            satoshis: utxo[:satoshis] || utxo['satoshis'],
            script: utxo[:script] || utxo['script'] || ''
          )
        else
          utxo
        end
      end
      private_class_method :normalize_utxo

      # Return the full locking script hex (code script + optional envelope + optional OP_RETURN + state).
      #
      # When loaded from chain, @code_script already contains the inscription
      # envelope (if any). When built from the template, we splice it in.
      #
      # @return [String]
      def get_locking_script
        built_from_template = @code_script.empty?
        script = built_from_template ? build_code_script : @code_script

        # Inject inscription envelope between code and state (template-built only;
        # chain-loaded @code_script already includes it).
        if built_from_template && @inscription
          script += Ordinals.build_inscription_envelope(@inscription.content_type, @inscription.data)
        end

        unless @artifact.state_fields.empty?
          state_hex = State.serialize_state(@artifact.state_fields, @state)
          script    = "#{script}6a#{state_hex}" unless state_hex.empty? # OP_RETURN
        end

        script
      end

      # Build the unlocking script for a method call without broadcasting.
      #
      # @param method_name [String]
      # @param args        [Array]
      # @return [String] hex-encoded unlocking script
      def build_unlocking_script(method_name, args)
        script              = args.map { |a| encode_arg(a) }.join
        public_methods_list = get_public_methods

        if public_methods_list.length > 1
          method_index = public_methods_list.index { |m| m.name == method_name }
          raise ArgumentError, "build_unlocking_script: public method '#{method_name}' not found" unless method_index

          script += State.encode_script_int(method_index)
        end

        script
      end

      # Build the code script (artifact script with constructor args spliced in).
      #
      # For each constructor slot, the 1-byte placeholder at +byte_offset+ in
      # the artifact script is replaced with the encoded arg value. Slots are
      # processed in descending byte_offset order so earlier substitutions do
      # not shift the offsets of later ones.
      #
      # @return [String] hex-encoded code script
      # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
      def build_code_script
        script = @artifact.script.dup

        # Collect all substitutions: constructor slots + codeSepIndex slots.
        # Process in descending byte offset so splicing doesn't shift later offsets.
        substitutions = []

        if @artifact.constructor_slots.any?
          @artifact.constructor_slots.each do |slot|
            encoded = encode_arg(@constructor_args[slot.param_index])
            substitutions << { byte_offset: slot.byte_offset, encoded: encoded }
          end
        end

        if @artifact.code_sep_index_slots.any?
          resolved = resolved_code_sep_slot_values
          @artifact.code_sep_index_slots.each_with_index do |slot, i|
            encoded = encode_arg(resolved[i])
            substitutions << { byte_offset: slot.byte_offset, encoded: encoded }
          end
        end

        if substitutions.any?
          substitutions.sort_by! { |s| -s[:byte_offset] }
          substitutions.each do |sub|
            hex_offset = sub[:byte_offset] * 2
            script = "#{script[0, hex_offset]}#{sub[:encoded]}#{script[hex_offset + 2..]}"
          end
        elsif @artifact.state_fields.empty?
          # Backward compatibility: stateless artifacts without constructorSlots.
          @constructor_args.each { |arg| script += encode_arg(arg) }
        end

        script
      end
      # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

      # Return a copy of the current state.
      #
      # @return [Hash]
      def get_state
        @state.dup
      end

      # Update state values directly (useful for testing).
      #
      # @param new_state [Hash]
      def set_state(new_state)
        @state.merge!(new_state)
      end

      private

      # ---------------------------------------------------------------------------
      # Initialisation helpers
      # ---------------------------------------------------------------------------

      # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
      def init_state_from_constructor_args
        return if @artifact.state_fields.empty?

        @artifact.state_fields.each do |field|
          if !field.initial_value.nil?
            @state[field.name] = revive_state_value(field.initial_value, field)
          else
            param_idx = @artifact.abi.constructor_params.index { |p| p.name == field.name }
            param_idx = field.index if param_idx.nil? && field.index < @constructor_args.length
            @state[field.name] = @constructor_args[param_idx] if param_idx && param_idx < @constructor_args.length
          end
        end
      end
      # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

      # Revive a deserialized initial_value — possibly nested — into Ruby
      # types, peeling every FixedArray wrapper off the field type.
      def revive_state_value(value, field)
        if field.respond_to?(:fixed_array) && field.fixed_array
          leaf_type = SDK::State.unwrap_fixed_array_leaf(field.type)
          return revive_nested_value(value, leaf_type)
        end

        revive_json_value(value, field.type)
      end

      def revive_nested_value(value, leaf_type)
        return value.map { |v| revive_nested_value(v, leaf_type) } if value.is_a?(Array)

        revive_json_value(value, leaf_type)
      end

      def revive_json_value(value, field_type)
        return value unless value.is_a?(String)
        return value unless %w[bigint int].include?(field_type)

        value.end_with?('n') ? value.chomp('n').to_i : value.to_i
      end

      # ---------------------------------------------------------------------------
      # prepare_call decomposition helpers
      # ---------------------------------------------------------------------------

      # rubocop:disable Metrics/AbcSize, Metrics/MethodLength, Metrics/CyclomaticComplexity, Metrics/ParameterLists
      def prepare_terminal(
        method_name, resolved_args, _signer, opts,
        is_stateful, needs_op_push_tx, method_needs_change,
        sig_indices, preimage_index,
        method_selector_hex, change_pkh_hex, contract_utxo, code_sep_idx
      )
        # Normalize terminal outputs — accept TerminalOutput structs or hashes.
        term_outputs = Array(opts.terminal_outputs).map do |item|
          case item
          when TerminalOutput
            item
          when Hash
            script = item['scriptHex'] || item[:script_hex] || item['script_hex'] || ''
            sats = item['satoshis'] || item[:satoshis] || 0
            TerminalOutput.new(script_hex: script, satoshis: sats)
          else
            item
          end
        end

        # Build placeholder unlocking script (terminal has no change output).
        term_unlock_script = if needs_op_push_tx
                               build_stateful_prefix('00' * 72, false) +
                                 build_unlocking_script(method_name, resolved_args)
                             else
                               build_unlocking_script(method_name, resolved_args)
                             end

        # Build raw terminal transaction: single input, exact outputs, no change.
        build_terminal_tx = lambda do |unlock|
          tx = +''
          tx << SDK.to_le32(1)
          tx << SDK.encode_varint(1)
          tx << SDK.reverse_hex(contract_utxo.txid)
          tx << SDK.to_le32(contract_utxo.output_index)
          tx << SDK.encode_varint(unlock.length / 2)
          tx << unlock
          tx << 'ffffffff'
          tx << SDK.encode_varint(term_outputs.length)
          term_outputs.each do |out|
            tx << SDK.to_le64(out.satoshis)
            tx << SDK.encode_varint(out.script_hex.length / 2)
            tx << out.script_hex
          end
          tx << SDK.to_le32(0)
          tx
        end

        term_tx              = build_terminal_tx.call(term_unlock_script)
        final_op_push_tx_sig = ''
        final_preimage       = ''

        if is_stateful
          # Two-pass stateful terminal: compute preimage with placeholder, then stabilize.
          build_stateful_terminal_unlock = lambda do |tx|
            op_sig, preimage = SDK.compute_op_push_tx(
              tx, 0, contract_utxo.script, contract_utxo.satoshis, code_sep_idx
            )
            args_hex   = resolved_args.map { |a| encode_arg(a) }.join
            change_hex = ''
            if method_needs_change && !change_pkh_hex.empty?
              change_hex = State.encode_push_data(change_pkh_hex) + State.encode_script_int(0)
            end
            unlock = build_stateful_prefix(op_sig, false) +
                     args_hex +
                     change_hex +
                     State.encode_push_data(preimage) +
                     method_selector_hex
            [unlock, op_sig, preimage]
          end

          # First pass — size the unlocking script.
          first_unlock, = build_stateful_terminal_unlock.call(term_tx)
          term_tx = build_terminal_tx.call(first_unlock)

          # Second pass — stable preimage with final TX layout.
          final_unlock, op_sig, preimage = build_stateful_terminal_unlock.call(term_tx)
          term_tx              = SDK.insert_unlocking_script(term_tx, 0, final_unlock)
          final_op_push_tx_sig = op_sig
          final_preimage       = preimage

        elsif needs_op_push_tx || !sig_indices.empty?
          if needs_op_push_tx
            sig_hex, preimage_hex = SDK.compute_op_push_tx(
              term_tx, 0, contract_utxo.script, contract_utxo.satoshis, code_sep_idx
            )
            final_op_push_tx_sig          = sig_hex
            resolved_args[preimage_index] = preimage_hex
          end

          real_unlock = build_unlocking_script(method_name, resolved_args)
          if needs_op_push_tx && !final_op_push_tx_sig.empty?
            real_unlock = build_stateful_prefix(final_op_push_tx_sig, false) + real_unlock
            tmp_tx      = SDK.insert_unlocking_script(term_tx, 0, real_unlock)
            final_sig, final_pre = SDK.compute_op_push_tx(
              tmp_tx, 0, contract_utxo.script, contract_utxo.satoshis, code_sep_idx
            )
            resolved_args[preimage_index] = final_pre
            final_op_push_tx_sig          = final_sig
            final_preimage                = final_pre
            real_unlock = build_stateful_prefix(final_sig, false) +
                          build_unlocking_script(method_name, resolved_args)
          end
          term_tx = SDK.insert_unlocking_script(term_tx, 0, real_unlock)
          final_preimage = resolved_args[preimage_index] if final_preimage.empty? && needs_op_push_tx
        end

        sighash = final_preimage.empty? ? '' : Digest::SHA256.hexdigest([final_preimage].pack('H*'))

        PreparedCall.new(
          sighash: sighash,
          preimage: final_preimage,
          op_push_tx_sig: final_op_push_tx_sig,
          tx_hex: term_tx,
          sig_indices: sig_indices,
          method_name: method_name,
          resolved_args: resolved_args,
          method_selector_hex: method_selector_hex,
          is_stateful: is_stateful,
          is_terminal: true,
          needs_op_push_tx: needs_op_push_tx,
          method_needs_change: method_needs_change,
          change_pkh_hex: change_pkh_hex,
          change_amount: 0,
          method_needs_new_amount: false,
          new_amount: 0,
          preimage_index: preimage_index,
          contract_utxo: contract_utxo,
          new_locking_script: '',
          new_satoshis: 0,
          has_multi_output: false,
          contract_outputs: [],
          code_sep_idx: code_sep_idx
        )
      end
      # rubocop:enable Metrics/AbcSize, Metrics/MethodLength, Metrics/CyclomaticComplexity, Metrics/ParameterLists

      # Map positional resolved_args to a Hash keyed by parameter name.
      #
      # Mirrors the Python SDK's _build_named_args helper. Used to build the
      # named-args dict passed to ANFInterpreter.compute_new_state.
      #
      # @param user_params  [Array<ABIParam>]
      # @param resolved_args [Array]
      # @return [Hash]
      def build_named_args(user_params, resolved_args)
        result = {}
        user_params.each_with_index do |param, i|
          result[param.name] = resolved_args[i] if i < resolved_args.length
        end
        result
      end

      # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength
      def resolve_method_args(args, user_params, signer, estimated_inputs: 2)
        resolved_args    = args.dup
        sig_indices      = []
        preimage_index   = -1
        prevouts_indices = []

        user_params.each_with_index do |param, i|
          case param.type
          when 'Sig'
            if args[i].nil?
              sig_indices << i
              resolved_args[i] = '00' * 72
            end
          when 'PubKey'
            resolved_args[i] = signer.get_public_key if args[i].nil?
          when 'SigHashPreimage'
            if args[i].nil?
              preimage_index   = i
              resolved_args[i] = '00' * 181
            end
          when 'ByteString'
            if args[i].nil?
              prevouts_indices << i
              # 36 bytes per input (txid 32 + vout 4) as placeholder
              resolved_args[i] = '00' * (36 * estimated_inputs)
            end
          end
        end

        [resolved_args, sig_indices, preimage_index, prevouts_indices]
      end
      # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength

      def compute_change_pkh(signer, is_stateful, method_needs_change)
        return '' unless is_stateful && method_needs_change

        pub_key_bytes = [signer.get_public_key].pack('H*')
        Digest::RMD160.digest(Digest::SHA256.digest(pub_key_bytes)).unpack1('H*')
      end

      def build_continuation(is_stateful, opts)
        return ['', 0] unless is_stateful

        new_satoshis = opts.satoshis.positive? ? opts.satoshis : @current_utxo.satoshis
        opts.new_state&.each { |k, v| @state[k] = v }
        [get_locking_script, new_satoshis]
      end

      def sign_funding_inputs(tx_hex, additional_utxos, signer, start_idx = 1)
        signed_tx = tx_hex
        pub_key   = signer.get_public_key
        additional_utxos.each_with_index do |utxo, i|
          idx       = start_idx + i
          sig       = signer.sign(signed_tx, idx, utxo.script, utxo.satoshis)
          unlock    = State.encode_push_data(sig) + State.encode_push_data(pub_key)
          signed_tx = SDK.insert_unlocking_script(signed_tx, idx, unlock)
        end
        signed_tx
      end

      # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/ParameterLists, Metrics/PerceivedComplexity
      def compute_preimage_passes(
        signed_tx, contract_utxo, resolved_args, sig_indices,
        method_name, method_needs_change, method_needs_new_amount,
        change_pkh_hex, method_selector_hex, code_sep_idx,
        change_amount, new_satoshis, new_locking_script,
        change_address, change_script, additional_utxos, fee_rate, signer,
        is_stateful, needs_op_push_tx, preimage_index,
        contract_outputs: nil,
        extra_contract_utxos: [],
        resolved_per_input_args: [],
        prevouts_indices: []
      )
        final_op_push_tx_sig = ''
        final_preimage       = ''

        if is_stateful
          signed_tx, change_amount, final_op_push_tx_sig, final_preimage =
            stateful_preimage_passes(
              signed_tx, contract_utxo, resolved_args,
              method_name, method_needs_change, method_needs_new_amount,
              change_pkh_hex, method_selector_hex, code_sep_idx,
              change_amount, new_satoshis, new_locking_script,
              change_address, change_script, additional_utxos, fee_rate, signer,
              contract_outputs: contract_outputs,
              extra_contract_utxos: extra_contract_utxos,
              resolved_per_input_args: resolved_per_input_args,
              prevouts_indices: prevouts_indices
            )

          # Update resolved_args with final prevouts so finalize_call can rebuild
          # the primary unlock with the correct allPrevouts values.
          if prevouts_indices.any?
            all_prevouts = extract_all_prevouts(signed_tx)
            prevouts_indices.each { |idx| resolved_args[idx] = all_prevouts }
          end

        elsif needs_op_push_tx || !sig_indices.empty?
          signed_tx, final_op_push_tx_sig, final_preimage =
            stateless_preimage_pass(
              signed_tx, contract_utxo, resolved_args, method_name,
              code_sep_idx, needs_op_push_tx, preimage_index
            )
          final_preimage = resolved_args[preimage_index] if final_preimage.empty? && needs_op_push_tx
        end

        [signed_tx, change_amount, final_op_push_tx_sig, final_preimage]
      end
      # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/ParameterLists, Metrics/PerceivedComplexity

      # rubocop:disable Metrics/AbcSize, Metrics/MethodLength, Metrics/ParameterLists, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
      def stateful_preimage_passes(
        signed_tx, contract_utxo, resolved_args,
        method_name, method_needs_change, method_needs_new_amount,
        change_pkh_hex, method_selector_hex, code_sep_idx,
        change_amount, new_satoshis, new_locking_script,
        change_address, change_script, additional_utxos, fee_rate, signer,
        contract_outputs: nil,
        extra_contract_utxos: [],
        resolved_per_input_args: [],
        prevouts_indices: []
      )
        pub_key     = signer.get_public_key
        p2pkh_start = 1 + extra_contract_utxos.length

        call_opts = {}
        call_opts[:contract_outputs] = contract_outputs if contract_outputs

        # First pass — build unlock with placeholder Sig/prevouts params.
        input0_unlock, = build_stateful_unlock(
          signed_tx, 0, contract_utxo, resolved_args,
          method_name, method_needs_change, method_needs_new_amount,
          change_pkh_hex, method_selector_hex, code_sep_idx,
          change_amount, new_satoshis,
          prevouts_indices: prevouts_indices
        )

        # First-pass unlocks for extra contract inputs.
        extra_unlocks_pass1 = extra_contract_utxos.each_with_index.map do |extra_utxo, i|
          args_for = resolved_per_input_args[i] || resolved_args
          unlock, = build_stateful_unlock(
            signed_tx, i + 1, extra_utxo, args_for,
            method_name, method_needs_change, method_needs_new_amount,
            change_pkh_hex, method_selector_hex, code_sep_idx,
            change_amount, new_satoshis,
            prevouts_indices: prevouts_indices
          )
          unlock
        end

        # Rebuild TX with real-sized unlocks for all contract inputs.
        rebuild_opts = call_opts.dup
        if extra_contract_utxos.any?
          rebuild_opts[:additional_contract_inputs] = extra_contract_utxos.each_with_index.map do |utxo, i|
            { utxo: utxo, unlocking_script: extra_unlocks_pass1[i] }
          end
        end

        tx_hex, _ic, change_amount = SDK.build_call_transaction(
          contract_utxo, input0_unlock, new_locking_script,
          new_satoshis, change_address, change_script,
          additional_utxos.empty? ? nil : additional_utxos,
          fee_rate: fee_rate,
          options: rebuild_opts.empty? ? nil : rebuild_opts
        )
        signed_tx = sign_funding_inputs(tx_hex, additional_utxos, signer, p2pkh_start)

        # Second pass — stable preimage with finalised TX layout.
        final_unlock, op_sig, preimage = build_stateful_unlock(
          signed_tx, 0, contract_utxo, resolved_args,
          method_name, method_needs_change, method_needs_new_amount,
          change_pkh_hex, method_selector_hex, code_sep_idx,
          change_amount, new_satoshis,
          prevouts_indices: prevouts_indices
        )
        signed_tx = SDK.insert_unlocking_script(signed_tx, 0, final_unlock)

        # Second-pass unlocks for extra contract inputs.
        # Sig params for extra inputs are signed with the signer (not kept as placeholders).
        extra_contract_utxos.each_with_index do |extra_utxo, i|
          args_for = (resolved_per_input_args[i] || resolved_args).dup

          # Sign Sig params for extra contract inputs using the signer.
          # Use subscript trimmed at OP_CODESEPARATOR, as the script verifies
          # user checkSig after the separator.
          sig_subscript = extra_utxo.script
          if code_sep_idx >= 0
            trim_pos = (code_sep_idx + 1) * 2
            sig_subscript = extra_utxo.script[trim_pos..] if trim_pos <= extra_utxo.script.length
          end
          args_for.each_with_index do |arg, j|
            args_for[j] = signer.sign(signed_tx, i + 1, sig_subscript, extra_utxo.satoshis) if arg == '00' * 72
          end

          extra_unlock, = build_stateful_unlock(
            signed_tx, i + 1, extra_utxo, args_for,
            method_name, method_needs_change, method_needs_new_amount,
            change_pkh_hex, method_selector_hex, code_sep_idx,
            change_amount, new_satoshis,
            prevouts_indices: prevouts_indices
          )
          signed_tx = SDK.insert_unlocking_script(signed_tx, i + 1, extra_unlock)
        end

        # Re-sign P2PKH inputs after second-pass rebuild.
        additional_utxos.each_with_index do |utxo, i|
          sig    = signer.sign(signed_tx, p2pkh_start + i, utxo.script, utxo.satoshis)
          unlock = State.encode_push_data(sig) + State.encode_push_data(pub_key)
          signed_tx = SDK.insert_unlocking_script(signed_tx, p2pkh_start + i, unlock)
        end

        [signed_tx, change_amount, op_sig, preimage]
      end
      # rubocop:enable Metrics/AbcSize, Metrics/MethodLength, Metrics/ParameterLists, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

      def stateless_preimage_pass(signed_tx, contract_utxo, resolved_args, method_name,
                                  code_sep_idx, needs_op_push_tx, preimage_index)
        final_op_push_tx_sig = ''
        final_preimage       = ''

        if needs_op_push_tx
          sig_hex, preimage_hex = SDK.compute_op_push_tx(
            signed_tx, 0, contract_utxo.script, contract_utxo.satoshis, code_sep_idx
          )
          final_op_push_tx_sig          = sig_hex
          resolved_args[preimage_index] = preimage_hex
        end

        real_unlock = build_unlocking_script(method_name, resolved_args)
        if needs_op_push_tx && !final_op_push_tx_sig.empty?
          real_unlock = build_stateful_prefix(final_op_push_tx_sig, false) + real_unlock
          tmp_tx      = SDK.insert_unlocking_script(signed_tx, 0, real_unlock)
          final_sig, final_pre = SDK.compute_op_push_tx(
            tmp_tx, 0, contract_utxo.script, contract_utxo.satoshis, code_sep_idx
          )
          resolved_args[preimage_index] = final_pre
          final_op_push_tx_sig          = final_sig
          final_preimage                = final_pre
          real_unlock = build_stateful_prefix(final_sig, false) +
                        build_unlocking_script(method_name, resolved_args)
        end
        signed_tx = SDK.insert_unlocking_script(signed_tx, 0, real_unlock)

        [signed_tx, final_op_push_tx_sig, final_preimage]
      end

      # rubocop:disable Metrics/ParameterLists
      def build_prepared_call(
        sighash, final_preimage, final_op_push_tx_sig, signed_tx,
        sig_indices, method_name, resolved_args, method_selector_hex,
        is_stateful, needs_op_push_tx, method_needs_change, change_pkh_hex,
        change_amount, method_needs_new_amount, new_satoshis, preimage_index,
        contract_utxo, new_locking_script, code_sep_idx,
        has_multi_output: false,
        contract_outputs: []
      )
        PreparedCall.new(
          sighash: sighash,
          preimage: final_preimage,
          op_push_tx_sig: final_op_push_tx_sig,
          tx_hex: signed_tx,
          sig_indices: sig_indices,
          method_name: method_name,
          resolved_args: resolved_args,
          method_selector_hex: method_selector_hex,
          is_stateful: is_stateful,
          is_terminal: false,
          needs_op_push_tx: needs_op_push_tx,
          method_needs_change: method_needs_change,
          change_pkh_hex: change_pkh_hex,
          change_amount: change_amount,
          method_needs_new_amount: method_needs_new_amount,
          new_amount: new_satoshis,
          preimage_index: preimage_index,
          contract_utxo: contract_utxo,
          new_locking_script: new_locking_script,
          new_satoshis: new_satoshis,
          has_multi_output: has_multi_output,
          contract_outputs: contract_outputs,
          code_sep_idx: code_sep_idx
        )
      end
      # rubocop:enable Metrics/ParameterLists

      # ---------------------------------------------------------------------------
      # finalize_call helpers
      # ---------------------------------------------------------------------------

      # rubocop:disable Metrics/AbcSize
      def assemble_primary_unlock(prepared, resolved_args)
        if prepared.is_stateful
          args_hex = resolved_args.map { |a| encode_arg(a) }.join

          change_hex = ''
          if prepared.method_needs_change && !prepared.change_pkh_hex.empty?
            change_hex = State.encode_push_data(prepared.change_pkh_hex) +
                         State.encode_script_int(prepared.change_amount)
          end

          new_amount_hex = prepared.method_needs_new_amount ? State.encode_script_int(prepared.new_amount) : ''

          build_stateful_prefix(prepared.op_push_tx_sig, prepared.method_needs_change) +
            args_hex + change_hex + new_amount_hex +
            State.encode_push_data(prepared.preimage) +
            prepared.method_selector_hex

        elsif prepared.needs_op_push_tx
          pi = prepared.preimage_index
          resolved_args[pi] = prepared.preimage if pi >= 0
          build_stateful_prefix(prepared.op_push_tx_sig, false) +
            build_unlocking_script(prepared.method_name, resolved_args)

        else
          build_unlocking_script(prepared.method_name, resolved_args)
        end
      end
      # rubocop:enable Metrics/AbcSize

      # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
      def update_tracked_utxo(txid, prepared)
        if prepared.is_terminal
          # Terminal call consumes the contract UTXO — no continuation to track.
          @current_utxo = nil
        elsif prepared.is_stateful && prepared.has_multi_output && !prepared.contract_outputs.empty?
          # Multi-output: track output 0 (first continuation), matching TS SDK behavior.
          first = prepared.contract_outputs[0]
          @current_utxo = Utxo.new(
            txid: txid, output_index: 0,
            satoshis: first[:satoshis],
            script: first[:script]
          )
        elsif prepared.is_stateful && !prepared.new_locking_script.empty?
          @current_utxo = Utxo.new(
            txid: txid, output_index: 0,
            satoshis: prepared.new_satoshis.positive? ? prepared.new_satoshis : prepared.contract_utxo.satoshis,
            script: prepared.new_locking_script
          )
        else
          @current_utxo = nil
        end
      end
      # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity

      # ---------------------------------------------------------------------------
      # Code separator helpers
      # ---------------------------------------------------------------------------

      # Get the code script hex (locking script without state) for use as _codePart.
      #
      # Returns the code portion that the on-chain contract uses for output
      # reconstruction. Includes the inscription envelope if one is attached --
      # this is required for stateful contracts where the on-chain hashOutputs
      # verification includes the envelope as part of the codePart.
      def get_code_part_hex
        return @code_script unless @code_script.empty?

        code = build_code_script
        if @inscription
          code += Ordinals.build_inscription_envelope(@inscription.content_type, @inscription.data)
        end
        code
      end

      def adjust_code_sep_offset(base_offset)
        shift = 0

        @artifact.constructor_slots.each do |slot|
          next unless slot.byte_offset < base_offset

          encoded = encode_arg(@constructor_args[slot.param_index])
          shift  += encoded.length / 2 - 1
        end

        # Also account for codeSepIndex slot expansions before this offset
        if @artifact.code_sep_index_slots.any?
          resolved = resolved_code_sep_slot_values
          @artifact.code_sep_index_slots.each_with_index do |slot, i|
            next unless slot.byte_offset < base_offset

            encoded = encode_arg(resolved[i])
            shift  += encoded.length / 2 - 1
          end
        end

        base_offset + shift
      end

      # Resolve adjusted codeSepIndex values for each codeSepIndexSlot.
      # Each slot stores the template-relative codeSepIndex; we adjust it
      # accounting for constructor slot expansions that precede it.
      def resolved_code_sep_slot_values
        @artifact.code_sep_index_slots.map do |slot|
          base = slot.code_sep_index
          shift = 0
          @artifact.constructor_slots.each do |cs|
            next unless cs.byte_offset < base

            encoded = encode_arg(@constructor_args[cs.param_index])
            shift  += encoded.length / 2 - 1
          end
          base + shift
        end
      end

      def get_code_sep_index(method_index)
        indices = @artifact.code_separator_indices
        if indices && method_index >= 0 && method_index < indices.length
          return adjust_code_sep_offset(indices[method_index])
        end

        base = @artifact.code_separator_index
        return -1 if base.nil?

        adjust_code_sep_offset(base)
      end

      def has_code_separator?
        !@artifact.code_separator_index.nil? || !@artifact.code_separator_indices.to_a.empty?
      end

      def build_stateful_prefix(op_sig_hex, needs_code_part)
        prefix = +''
        prefix << State.encode_push_data(get_code_part_hex) if needs_code_part && has_code_separator?
        prefix << State.encode_push_data(op_sig_hex)
        prefix
      end

      # ---------------------------------------------------------------------------
      # Method lookup helpers
      # ---------------------------------------------------------------------------

      def find_method(name)
        @artifact.abi.methods.find { |m| m.name == name && m.is_public }
      end

      def get_public_methods
        @artifact.abi.methods.select(&:is_public)
      end

      def find_method_index(name)
        get_public_methods.index { |m| m.name == name } || 0
      end

      def compute_method_selector(method_name, is_stateful)
        return '' unless is_stateful

        public_methods_list = get_public_methods
        return '' if public_methods_list.length <= 1

        idx = public_methods_list.index { |m| m.name == method_name }
        idx ? State.encode_script_int(idx) : ''
      end

      # ---------------------------------------------------------------------------
      # Resolver helpers
      # ---------------------------------------------------------------------------

      def resolve_provider(override, context)
        p = override || @provider
        raise "RunarContract.#{context}: no provider. Call connect() or pass one." unless p

        p
      end

      def resolve_signer(override, context)
        s = override || @signer
        raise "RunarContract.#{context}: no signer. Call connect() or pass one." unless s

        s
      end

      # ---------------------------------------------------------------------------
      # Argument encoding
      # ---------------------------------------------------------------------------

      # Encode a single method argument as Script push data.
      #
      # @param value [Integer, String, TrueClass, FalseClass]
      # @return [String] hex-encoded push instruction
      def encode_arg(value)
        case value
        when true    then '51'  # OP_1
        when false   then '00'  # OP_0
        when Integer then State.encode_script_int(value)
        when String  then State.encode_push_data(value)
        else              State.encode_push_data(value.to_s)
        end
      end

      # ---------------------------------------------------------------------------
      # Transaction parsing helpers
      # ---------------------------------------------------------------------------

      # Extract all input outpoints (txid + vout, 36 bytes each) from a raw tx hex.
      #
      # Returns the concatenated outpoints as a hex string, matching the
      # BIP-143 allPrevouts format used by contracts that call extractHashPrevouts.
      #
      # @param tx_hex [String] hex-encoded raw transaction
      # @return [String] hex-encoded concatenation of all (txid LE + vout LE) pairs
      # rubocop:disable Metrics/MethodLength
      def extract_all_prevouts(tx_hex)
        # Positions are in hex chars (2 chars = 1 byte).
        pos = 8 # skip version (4 bytes = 8 hex chars)

        input_count, ic_hex_len = SDK.read_varint_hex(tx_hex, pos)
        pos += ic_hex_len

        prevouts = +''
        input_count.times do
          prevouts << tx_hex[pos, 72] # txid (32 bytes) + vout (4 bytes) = 36 bytes = 72 hex chars
          pos += 72

          script_len, sl_hex_len = SDK.read_varint_hex(tx_hex, pos)
          pos += sl_hex_len + script_len * 2 + 8 # scriptSig + sequence (4 bytes = 8 hex chars)
        end
        prevouts
      end
      # rubocop:enable Metrics/MethodLength

      # ---------------------------------------------------------------------------
      # Stateful unlock builder
      # ---------------------------------------------------------------------------

      # Build the full stateful unlocking script for an input.
      #
      # Called twice per call() invocation (two-pass preimage computation) to
      # ensure the preimage is stable after unlocking script sizes are finalised.
      # Placeholder Sig params are kept as-is so the caller can inject real
      # signatures in finalize_call.
      #
      # Returns [unlock_hex, op_sig_hex, preimage_hex].
      #
      # rubocop:disable Metrics/AbcSize, Metrics/MethodLength, Metrics/ParameterLists
      def build_stateful_unlock(tx_hex, input_idx, contract_utxo, resolved_args,
                                _method_name, method_needs_change, method_needs_new_amount,
                                change_pkh_hex, method_selector_hex, code_sep_idx,
                                change_amount, new_satoshis,
                                prevouts_indices: [])
        op_sig, preimage = SDK.compute_op_push_tx(
          tx_hex, input_idx, contract_utxo.script, contract_utxo.satoshis, code_sep_idx
        )

        # Inject real allPrevouts into any ByteString placeholders.
        effective_args = if prevouts_indices.any?
                           all_prevouts = extract_all_prevouts(tx_hex)
                           args = resolved_args.dup
                           prevouts_indices.each { |idx| args[idx] = all_prevouts }
                           args
                         else
                           resolved_args
                         end

        args_hex = effective_args.map { |a| encode_arg(a) }.join

        change_hex = ''
        if method_needs_change && !change_pkh_hex.empty?
          change_hex = State.encode_push_data(change_pkh_hex) + State.encode_script_int(change_amount)
        end

        new_amount_hex = method_needs_new_amount ? State.encode_script_int(new_satoshis) : ''

        unlock = build_stateful_prefix(op_sig, method_needs_change) +
                 args_hex + change_hex + new_amount_hex +
                 State.encode_push_data(preimage) +
                 method_selector_hex

        [unlock, op_sig, preimage]
      end
      # rubocop:enable Metrics/AbcSize, Metrics/MethodLength, Metrics/ParameterLists
    end
    # rubocop:enable Naming/AccessorMethodName, Naming/PredicatePrefix
  end
end

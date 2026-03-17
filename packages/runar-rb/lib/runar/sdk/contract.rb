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
      attr_reader :artifact

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

        init_state_from_constructor_args
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

        resolved_args, sig_indices, preimage_index = resolve_method_args(args, user_params, signer)

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
            @artifact.anf, method_name, @state, named_args
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

        new_locking_script, new_satoshis = build_continuation(is_stateful, opts)

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

        tx_hex, _input_count, change_amount = SDK.build_call_transaction(
          contract_utxo, unlocking_script, new_locking_script,
          new_satoshis, change_address, change_script,
          additional_utxos.empty? ? nil : additional_utxos,
          fee_rate: fee_rate
        )

        signed_tx = sign_funding_inputs(tx_hex, additional_utxos, signer)

        signed_tx, change_amount, final_op_push_tx_sig, final_preimage =
          compute_preimage_passes(
            signed_tx, contract_utxo, resolved_args, sig_indices,
            method_name, method_needs_change, method_needs_new_amount,
            change_pkh_hex, method_selector_hex, code_sep_idx,
            change_amount, new_satoshis, new_locking_script,
            change_address, change_script, additional_utxos, fee_rate, signer,
            is_stateful, needs_op_push_tx, preimage_index
          )

        sighash = final_preimage.empty? ? '' : Digest::SHA256.hexdigest([final_preimage].pack('H*'))

        build_prepared_call(
          sighash, final_preimage, final_op_push_tx_sig, signed_tx,
          sig_indices, method_name, resolved_args, method_selector_hex,
          is_stateful, needs_op_push_tx, method_needs_change, change_pkh_hex,
          change_amount, method_needs_new_amount, new_satoshis, preimage_index,
          contract_utxo, new_locking_script, code_sep_idx
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

      # Return the full locking script hex (code script + optional OP_RETURN + state).
      #
      # @return [String]
      def get_locking_script
        script = @code_script.empty? ? build_code_script : @code_script

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

        if @artifact.constructor_slots.any?
          sorted_slots = @artifact.constructor_slots.sort_by { |s| -s.byte_offset }
          sorted_slots.each do |slot|
            encoded    = encode_arg(@constructor_args[slot.param_index])
            hex_offset = slot.byte_offset * 2
            script     = "#{script[0, hex_offset]}#{encoded}#{script[hex_offset + 2..]}"
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
            @state[field.name] = revive_json_value(field.initial_value, field.type)
          else
            param_idx = @artifact.abi.constructor_params.index { |p| p.name == field.name }
            param_idx = field.index if param_idx.nil? && field.index < @constructor_args.length
            @state[field.name] = @constructor_args[param_idx] if param_idx && param_idx < @constructor_args.length
          end
        end
      end
      # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

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

      def resolve_method_args(args, user_params, signer)
        resolved_args  = args.dup
        sig_indices    = []
        preimage_index = -1

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
          end
        end

        [resolved_args, sig_indices, preimage_index]
      end

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

      def sign_funding_inputs(tx_hex, additional_utxos, signer)
        signed_tx = tx_hex
        pub_key   = signer.get_public_key
        additional_utxos.each_with_index do |utxo, i|
          sig       = signer.sign(signed_tx, 1 + i, utxo.script, utxo.satoshis)
          unlock    = State.encode_push_data(sig) + State.encode_push_data(pub_key)
          signed_tx = SDK.insert_unlocking_script(signed_tx, 1 + i, unlock)
        end
        signed_tx
      end

      # rubocop:disable Metrics/MethodLength, Metrics/ParameterLists
      def compute_preimage_passes(
        signed_tx, contract_utxo, resolved_args, sig_indices,
        method_name, method_needs_change, method_needs_new_amount,
        change_pkh_hex, method_selector_hex, code_sep_idx,
        change_amount, new_satoshis, new_locking_script,
        change_address, change_script, additional_utxos, fee_rate, signer,
        is_stateful, needs_op_push_tx, preimage_index
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
              change_address, change_script, additional_utxos, fee_rate, signer
            )

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
      # rubocop:enable Metrics/MethodLength, Metrics/ParameterLists

      # rubocop:disable Metrics/AbcSize, Metrics/MethodLength, Metrics/ParameterLists
      def stateful_preimage_passes(
        signed_tx, contract_utxo, resolved_args,
        method_name, method_needs_change, method_needs_new_amount,
        change_pkh_hex, method_selector_hex, code_sep_idx,
        change_amount, new_satoshis, new_locking_script,
        change_address, change_script, additional_utxos, fee_rate, signer
      )
        pub_key = signer.get_public_key

        # First pass — build unlock with placeholder Sig params.
        input0_unlock, = build_stateful_unlock(
          signed_tx, 0, contract_utxo, resolved_args,
          method_name, method_needs_change, method_needs_new_amount,
          change_pkh_hex, method_selector_hex, code_sep_idx,
          change_amount, new_satoshis
        )

        # Rebuild TX with real unlock (size may differ from placeholder).
        tx_hex, _ic, change_amount = SDK.build_call_transaction(
          contract_utxo, input0_unlock, new_locking_script,
          new_satoshis, change_address, change_script,
          additional_utxos.empty? ? nil : additional_utxos,
          fee_rate: fee_rate
        )
        signed_tx = sign_funding_inputs(tx_hex, additional_utxos, signer)

        # Second pass — stable preimage with finalised TX layout.
        final_unlock, op_sig, preimage = build_stateful_unlock(
          signed_tx, 0, contract_utxo, resolved_args,
          method_name, method_needs_change, method_needs_new_amount,
          change_pkh_hex, method_selector_hex, code_sep_idx,
          change_amount, new_satoshis
        )
        signed_tx = SDK.insert_unlocking_script(signed_tx, 0, final_unlock)

        # Re-sign P2PKH inputs after second-pass rebuild.
        additional_utxos.each_with_index do |utxo, i|
          sig    = signer.sign(signed_tx, 1 + i, utxo.script, utxo.satoshis)
          unlock = State.encode_push_data(sig) + State.encode_push_data(pub_key)
          signed_tx = SDK.insert_unlocking_script(signed_tx, 1 + i, unlock)
        end

        [signed_tx, change_amount, op_sig, preimage]
      end
      # rubocop:enable Metrics/AbcSize, Metrics/MethodLength, Metrics/ParameterLists

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
        contract_utxo, new_locking_script, code_sep_idx
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

      def update_tracked_utxo(txid, prepared)
        if prepared.is_terminal
          # Terminal call consumes the contract UTXO — no continuation to track.
          @current_utxo = nil
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

      # ---------------------------------------------------------------------------
      # Code separator helpers
      # ---------------------------------------------------------------------------

      def get_code_part_hex
        @code_script.empty? ? build_code_script : @code_script
      end

      def adjust_code_sep_offset(base_offset)
        return base_offset if @artifact.constructor_slots.empty?

        shift = 0
        @artifact.constructor_slots.each do |slot|
          next unless slot.byte_offset < base_offset

          encoded = encode_arg(@constructor_args[slot.param_index])
          shift  += encoded.length / 2 - 1
        end
        base_offset + shift
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
      # rubocop:disable Metrics/ParameterLists
      def build_stateful_unlock(tx_hex, input_idx, contract_utxo, resolved_args,
                                _method_name, method_needs_change, method_needs_new_amount,
                                change_pkh_hex, method_selector_hex, code_sep_idx,
                                change_amount, new_satoshis)
        op_sig, preimage = SDK.compute_op_push_tx(
          tx_hex, input_idx, contract_utxo.script, contract_utxo.satoshis, code_sep_idx
        )

        args_hex = resolved_args.map { |a| encode_arg(a) }.join

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
      # rubocop:enable Metrics/ParameterLists
    end
    # rubocop:enable Naming/AccessorMethodName, Naming/PredicatePrefix
  end
end

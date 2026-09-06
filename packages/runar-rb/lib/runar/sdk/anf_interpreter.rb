# frozen_string_literal: true

require 'digest'
require_relative '../ecdsa'

# Lightweight ANF interpreter for auto-computing state transitions.
#
# Given a compiled artifact's ANF IR, the current contract state, and
# method arguments, this interpreter walks the ANF bindings and computes
# the new state. It handles +update_prop+ nodes to track state mutations,
# while skipping on-chain-only operations like +check_preimage+,
# +deserialize_state+, and +get_state_script+. +add_data_output+ entries
# are surfaced through the +data_outputs+ array, and +add_raw_output+
# entries through the +raw_outputs+ array — the simulator does not
# introspect raw scripts (they're caller-supplied) but forwards them so
# off-chain transaction builders can splice them in at the correct index.
#
# This enables the SDK to auto-compute +new_state+ for stateful contract
# calls, so callers don't need to duplicate contract logic.
#
# Usage:
#
#   new_state = Runar::SDK::ANFInterpreter.compute_new_state(
#     artifact.anf, 'increment', { 'count' => 0 }, {}
#   )

module Runar
  module SDK
    # Raised by {ANFInterpreter.execute_strict} when an +assert(predicate)+
    # in the ANF body evaluates to a falsy value during strict-mode
    # interpretation. Carries the contract method name plus the ANF binding
    # name (e.g. +t17+, +t8+) so a developer can pinpoint the exact failing
    # guard. The +to_s+ / +message+ rendering matches the TS / Go / Java /
    # Zig SDKs byte-for-byte so cross-tier diffing on the wire is stable.
    class AssertionFailureError < StandardError
      attr_reader :method_name, :binding_name

      def initialize(method_name, binding_name)
        @method_name = method_name
        @binding_name = binding_name
        super("assert failed in #{method_name}: binding '#{binding_name}' evaluated to false")
      end
    end

    # Required cryptographic context for
    # {ANFInterpreter.execute_on_chain_authoritative}.
    #
    # +sighash+ is the 32-byte BIP-143 sighash digest the on-chain VM would
    # verify signatures against (and that the caller would have signed with
    # +LocalSigner#sign+ before broadcasting). The interpreter:
    #
    # - verifies +checkSig(sig, pk)+ by parsing +pk+ as a SEC1 secp256k1 point
    #   (compressed or uncompressed), parsing +sig+ as DER (with optional
    #   trailing sighash type byte stripped), and ECDSA-verifying against the
    #   sighash. Any mismatch returns +false+, which then trips the enclosing
    #   +assert(...)+ and raises {AssertionFailureError}.
    # - verifies +checkMultiSig(sigs, pks)+ by iterating signatures
    #   left-to-right and consuming pubkeys greedily, mirroring Bitcoin's
    #   +OP_CHECKMULTISIG+.
    # - verifies +checkPreimage(preimage)+ by computing
    #   +SHA256(SHA256(preimage))+ and comparing it to +sighash+ byte-for-byte
    #   — the on-chain +OP_PUSH_TX+ semantic.
    class OnChainCryptoContext
      # @return [String] 32-byte binary sighash
      attr_reader :sighash

      # @param sighash [String] hex string (64 chars) or 32-byte binary string
      def initialize(sighash)
        bytes = if sighash.is_a?(String) && sighash.length == 64 && sighash.match?(/\A[0-9a-fA-F]+\z/)
                  [sighash].pack('H*')
                elsif sighash.is_a?(String) && sighash.bytesize == 32
                  sighash.dup.force_encoding(Encoding::ASCII_8BIT)
                else
                  raise ArgumentError,
                        "OnChainCryptoContext: sighash must be 32 bytes (binary) or 64 hex chars"
                end
        if bytes.bytesize != 32
          raise ArgumentError,
                "OnChainCryptoContext: sighash must be exactly 32 bytes, got #{bytes.bytesize}"
        end
        @sighash = bytes
      end

      # 32-byte sighash as a hex string.
      # @return [String]
      def sighash_hex
        @sighash.unpack1('H*')
      end
    end

    module ANFInterpreter
      module_function

      # Implicit params injected by the compiler — never required from the caller.
      IMPLICIT_PARAMS = %w[_changePKH _changeAmount _newAmount txPreimage].freeze

      # The on-disk ANF spelling of a bigint literal: decimal digits with a
      # trailing +n+. Unambiguous against a hex ByteString literal, which never
      # contains +n+.
      BIGINT_LITERAL_RE = /\A-?\d+n\z/

      # Maximum number of iterations allowed for a single loop node.
      #
      # Bitcoin Script loops (unrolled at compile time) are bounded by script size
      # limits. A count above this threshold in the ANF IR almost certainly
      # indicates a malformed or adversarially crafted artifact rather than a
      # legitimate contract. Capping here prevents the interpreter from hanging or
      # consuming unbounded memory when simulating state transitions.
      MAX_LOOP_ITERATIONS = 65_536

      # Compute the new state after executing a contract method.
      #
      # @param anf          [Hash]   the ANF IR from the compiled artifact (plain Hash from JSON)
      # @param method_name  [String] the method to execute (must be a public method)
      # @param current_state [Hash]  current contract state (property name → value)
      # @param args         [Hash]   method arguments (param name → value)
      # @param constructor_args [Array] constructor arg values (declaration order) for readonly fields
      # @param max_loop_iterations [Integer] optional override for the loop iteration limit
      # @return [Hash] the updated state (merged with current_state)
      # @raise [ArgumentError] when method_name is not found as a public method in the ANF IR
      def compute_new_state(anf, method_name, current_state, args, constructor_args: [], max_loop_iterations: MAX_LOOP_ITERATIONS)
        state, _data_outputs, _raw_outputs = compute_new_state_and_data_outputs(
          anf, method_name, current_state, args,
          constructor_args: constructor_args,
          max_loop_iterations: max_loop_iterations,
        )
        state
      end

      # Like #compute_new_state but also returns data outputs resolved
      # from +this.addDataOutput(...)+ and raw outputs resolved from
      # +this.addRawOutput(...)+ in declaration order. Each data-output
      # entry is +{satoshis: Integer, script: String}+ where +script+ is
      # the +OP_RETURN+ payload bytes; each raw-output entry shares the
      # same shape but +script+ is the caller-supplied raw locking
      # script. The SDK uses these to populate the tx between state
      # outputs and the change output so the on-chain continuation-hash
      # check matches.
      #
      # @return [Array(Hash, Array<Hash>, Array<Hash>)]
      #   +[new_state, data_outputs, raw_outputs]+
      def compute_new_state_and_data_outputs(anf, method_name, current_state, args, constructor_args: [], max_loop_iterations: MAX_LOOP_ITERATIONS)
        run_method(anf, method_name, current_state, args, constructor_args, nil, max_loop_iterations)
      end

      # Strict-mode counterpart of #compute_new_state_and_data_outputs.
      #
      # Walks the same ANF body but raises {Runar::SDK::AssertionFailureError}
      # on the first +assert(predicate)+ binding (or +call(func: 'assert')+
      # lowering) whose predicate is falsy. Crypto built-ins (+checkSig+,
      # +checkMultiSig+, +checkPreimage+) still mock-return +true+; only
      # explicit +assert(...)+ predicates are enforced.
      #
      # @return [Array(Hash, Array<Hash>, Array<Hash>)]
      #   +[new_state, data_outputs, raw_outputs]+
      # @raise  [Runar::SDK::AssertionFailureError] on the first falsy assert
      def execute_strict(anf, method_name, current_state, args, constructor_args = [], max_loop_iterations: MAX_LOOP_ITERATIONS)
        run_method(anf, method_name, current_state, args, constructor_args, method_name, max_loop_iterations, nil)
      end

      # Strict-mode execution with intent-intrinsic witness routing.
      #
      # Mirrors the TS reference interpreter's
      # {RunarInterpreter#setPrevOutScript} / {RunarInterpreter#setSerialisedOutputs}
      # channel for the ANF-tier. The desugared intrinsics
      # (+extractPrevOutputScript+, +requireOutputP2PKH+,
      # +currentBlockHeight+) lower to +load_param+ of synthetic ABI slots
      # (+_prevOutScript_<i>+ / +_serialisedOutputs+) plus a +hash256+ /
      # +substr+ / +cat+ / +num2bin+ chain that the existing evaluator already
      # supports. This entry point:
      #
      # - injects +witness_bytes+ into the +load_param+ lookup so the
      #   desugared chain sees real bytes instead of +nil+;
      # - overrides +extractLocktime+ / +extractOutputHash+ /
      #   +extractAmount+ etc. to return the supplied +mock_preimage+ /
      #   +mock_preimage_bytes+ values rather than the default zero
      #   placeholder;
      # - raises {AssertionFailureError} with a contextual message that
      #   mirrors the TS source-level error string (matched by the
      #   conformance tests' +.error+ regexes) when the assertion source
      #   pattern is recognised; falls back to the generic
      #   "assert failed in <method>" message otherwise.
      #
      # Witness / preimage values may be supplied as hex strings or raw
      # 8-bit binary strings; the latter are converted via +unpack1('H*')+.
      #
      # @param anf                  [Hash]
      # @param method_name          [String]
      # @param current_state        [Hash]
      # @param args                 [Hash]
      # @param constructor_args     [Array]
      # @param witness_bytes        [Hash{String => String}] synthetic
      #   param name (+_prevOutScript_<i>+ / +_serialisedOutputs+) → bytes
      # @param mock_preimage        [Hash{String,Symbol => Integer}]
      #   locktime / amount / version / sequence overrides
      # @param mock_preimage_bytes  [Hash{String,Symbol => String}]
      #   outputHash / hashPrevouts / hashSequence / outpoint overrides
      # @param max_loop_iterations  [Integer]
      # @return [Array(Hash, Array<Hash>, Array<Hash>)]
      # @raise  [AssertionFailureError, RuntimeError]
      def execute_strict_with_witness(
        anf, method_name, current_state, args,
        constructor_args: [], witness_bytes: {}, mock_preimage: {},
        mock_preimage_bytes: {}, max_loop_iterations: MAX_LOOP_ITERATIONS
      )
        Thread.current[:runar_witness_bytes] = normalize_byte_map(witness_bytes)
        Thread.current[:runar_mock_preimage] = stringify_keys(mock_preimage)
        Thread.current[:runar_mock_preimage_bytes] = normalize_byte_map(mock_preimage_bytes)
        Thread.current[:runar_method_body_index] = nil
        Thread.current[:runar_anf_for_context] = anf
        state_outputs = []
        Thread.current[:runar_state_outputs] = state_outputs
        new_state, data_outputs, raw_outputs = run_method(
          anf, method_name, current_state, args, constructor_args,
          method_name, max_loop_iterations, nil,
        )
        [new_state, data_outputs, raw_outputs, state_outputs]
      ensure
        Thread.current[:runar_witness_bytes] = nil
        Thread.current[:runar_mock_preimage] = nil
        Thread.current[:runar_mock_preimage_bytes] = nil
        Thread.current[:runar_method_body_index] = nil
        Thread.current[:runar_anf_for_context] = nil
        Thread.current[:runar_state_outputs] = nil
      end

      # Normalise a {name => bytes} map so values are hex strings.
      # Accepts hex strings (pass through) or 8-bit binary strings
      # (encoded). Other types are rejected.
      def normalize_byte_map(map)
        out = {}
        return out if map.nil?

        map.each do |k, v|
          key = k.to_s
          out[key] = case v
                     when nil then nil
                     when String
                       if v.length.even? && v.match?(/\A[0-9a-fA-F]*\z/)
                         v.downcase
                       else
                         v.dup.force_encoding(Encoding::ASCII_8BIT).unpack1('H*')
                       end
                     when Array
                       v.pack('C*').unpack1('H*')
                     else
                       raise ArgumentError,
                             "witness/preimage bytes must be hex string or binary string, got #{v.class}"
                     end
        end
        out
      end

      # Stringify hash keys (allow symbol or string keys at the call site).
      def stringify_keys(h)
        return {} if h.nil?

        h.each_with_object({}) { |(k, v), acc| acc[k.to_s] = v }
      end

      # On-chain authoritative counterpart of #execute_strict.
      #
      # Walks the same ANF body but additionally performs *real* cryptographic
      # verification of +checkSig+, +checkMultiSig+, and +checkPreimage+
      # against the supplied 32-byte sighash. Any failed predicate trips the
      # enclosing +assert(...)+ and raises {AssertionFailureError}. Lenient
      # and strict modes still mock-return +true+ for these built-ins; only
      # this entry point performs real verification.
      #
      # @param anf              [Hash]   the ANF IR (plain Hash from JSON)
      # @param method_name      [String] the public method to execute
      # @param current_state    [Hash]   current contract state
      # @param args             [Hash]   method arguments
      # @param constructor_args [Array]  positional constructor args
      # @param ctx              [OnChainCryptoContext] mandatory sighash ctx
      # @param max_loop_iterations [Integer] optional override for loop cap
      # @return [Array(Hash, Array<Hash>, Array<Hash>)]
      # @raise  [AssertionFailureError] on the first falsy assert (incl. the
      #         implicit one wrapping a failed crypto built-in)
      def execute_on_chain_authoritative(
        anf, method_name, current_state, args, constructor_args, ctx,
        max_loop_iterations: MAX_LOOP_ITERATIONS
      )
        unless ctx.is_a?(OnChainCryptoContext)
          raise ArgumentError,
                "execute_on_chain_authoritative: ctx must be an OnChainCryptoContext"
        end
        run_method(
          anf, method_name, current_state, args, constructor_args,
          method_name, max_loop_iterations, ctx,
        )
      end

      # Shared entry-point for lenient, strict, and on-chain modes.
      #
      # +strict_method_name+ == nil → lenient (asserts skipped).
      # +strict_method_name+ != nil → strict (asserts enforced; first falsy
      # predicate raises {Runar::SDK::AssertionFailureError}).
      # +real_crypto_ctx+ != nil    → on-chain mode (real ECDSA + hash256
      # checks for +checkSig+/+checkMultiSig+/+checkPreimage+; implies
      # strict-mode assertions).
      def run_method(anf, method_name, current_state, args, constructor_args, strict_method_name, max_loop_iterations, real_crypto_ctx = nil)
        method = find_public_method(anf, method_name)

        unless method
          raise ArgumentError,
                "computeNewState: method '#{method_name}' not found in ANF IR"
        end

        # Store the configurable loop limit for use in eval_value.
        Thread.current[:runar_max_loop_iterations] = max_loop_iterations
        # Thread strict-mode state through the evaluator without changing
        # the existing eval_bindings / eval_value signatures (mirrors the
        # loop-limit pattern above). nil = lenient.
        Thread.current[:runar_strict_method] = strict_method_name
        # Thread real-crypto context through the evaluator. nil in lenient
        # and strict modes; an OnChainCryptoContext in on-chain mode.
        Thread.current[:runar_real_crypto] = real_crypto_ctx
        # Per-binding raw stack bytes for byte-array-op results (& | ^ << >> ~),
        # keyed by binding name. Lets a chained op read the real (possibly
        # non-minimal) length of a prior op's result instead of re-minimising its
        # numeric value. One fresh map per top-level method invocation; env stays
        # pure (decoded values) so state serialization is unaffected. Mirrors the
        # TS anf-interpreter's threaded +scriptBytes+ side-map.
        Thread.current[:runar_script_bytes] = {}

        # Build constructor param index: position among non-initialized properties.
        # Properties with initialValue are excluded from the constructor, so
        # constructor_args[i] corresponds to the i-th property without initialValue.
        ctor_idx = {}
        ci = 0
        Array(anf['properties']).each do |prop|
          if prop['initialValue'].nil?
            ctor_idx[prop['name']] = ci
            ci += 1
          end
        end

        # Initialize environment with property values.
        env = {}
        Array(anf['properties']).each do |prop|
          name = prop['name']
          if current_state.key?(name)
            env[name] = current_state[name]
          elsif !prop['initialValue'].nil?
            env[name] = prop['initialValue']
          elsif ctor_idx.key?(name) && ctor_idx[name] < constructor_args.length
            env[name] = constructor_args[ctor_idx[name]]
          end
        end

        # Load method params, skipping implicit compiler-injected ones.
        Array(method['params']).each do |param|
          pname = param['name']
          next if IMPLICIT_PARAMS.include?(pname)
          next unless args.key?(pname) || args.key?(pname.to_sym)

          env[pname] = args.key?(pname) ? args[pname] : args[pname.to_sym]
        end

        state_delta = {}
        data_outputs = []
        # +raw_outputs+ collects entries from +add_raw_output+ ANF kinds.
        # The simulator does NOT introspect their script bytes (the script
        # is caller-supplied); it surfaces them so an off-chain transaction
        # builder can emit the output at the correct index.
        raw_outputs = []
        # +ordered_outputs+ records the state-class outputs (+add_output+
        # continuation + +add_raw_output+) in SOURCE order (finding G1). The
        # compiler folds both into the covenant continuation +hashOutputs+ in
        # exactly this order (see 04-anf-lower's shared +addOutputRefs+ list),
        # so an off-chain transaction builder MUST emit them in this order or
        # the on-chain state-check OP_VERIFY rejects. Each entry is
        # +{kind: :state | :raw, satoshis: Integer, script: String?}+ (+script+
        # for +:raw+ only; +:state+ entries take the freshly computed
        # continuation script from the caller). +add_data_output+ is NOT
        # recorded here — data outputs are always emitted after every
        # state-class output, in their own +data_outputs+ list.
        ordered_outputs = []
        eval_bindings(Array(method['body']), env, state_delta, data_outputs, raw_outputs, ordered_outputs, anf)

        [current_state.merge(state_delta), data_outputs, raw_outputs, ordered_outputs]
      ensure
        Thread.current[:runar_max_loop_iterations] = nil
        Thread.current[:runar_strict_method] = nil
        Thread.current[:runar_real_crypto] = nil
        Thread.current[:runar_script_bytes] = nil
      end

      # Walk a list of ANF bindings, updating env with each result.
      #
      # @param bindings    [Array<Hash>] list of { name:, value: } binding nodes
      # @param env         [Hash]        current name → value environment (mutated in place)
      # @param state_delta [Hash]        accumulated state mutations (mutated in place)
      # @param data_outputs [Array<Hash>] accumulated +add_data_output+ entries
      # @param raw_outputs  [Array<Hash>] accumulated +add_raw_output+ entries
      # @param ordered_outputs [Array<Hash>] state-class outputs (state + raw)
      #   in source order (finding G1)
      # @param anf         [Hash, nil]   full ANF IR (for method lookup)
      def eval_bindings(bindings, env, state_delta, data_outputs, raw_outputs, ordered_outputs, anf = nil)
        # Maintain a name → value-hash index so the assert error-message
        # synthesis can walk the desugar chain (only populated under
        # {execute_strict_with_witness}; lenient + plain strict modes leave
        # the slot nil).
        if Thread.current[:runar_witness_bytes]
          index = Thread.current[:runar_method_body_index] ||= {}
          bindings.each { |b| index[b['name']] = b['value'] }
        end
        bindings.each do |binding|
          val = eval_value(binding['value'], env, state_delta, data_outputs, raw_outputs, ordered_outputs, anf, binding['name'])
          env[binding['name']] = val
        end
      end

      # Evaluate a single ANF value node, dispatching on its kind.
      #
      # @param value        [Hash]
      # @param env          [Hash]
      # @param state_delta  [Hash]
      # @param data_outputs [Array<Hash>]
      # @param raw_outputs  [Array<Hash>]
      # @param ordered_outputs [Array<Hash>] state-class outputs (state + raw)
      #   in source order (finding G1)
      # @param anf          [Hash, nil]
      # @return [Object]
      # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
      def eval_value(value, env, state_delta, data_outputs, raw_outputs, ordered_outputs, anf = nil, binding_name = nil)
        kind = value['kind'].to_s

        case kind
        when 'load_param'
          name = value['name']
          if env.key?(name)
            env[name]
          else
            witness = Thread.current[:runar_witness_bytes]
            if witness && (name == '_serialisedOutputs' || name.start_with?('_prevOutScript_'))
              if witness[name].nil?
                if name.start_with?('_prevOutScript_')
                  idx = name.sub('_prevOutScript_', '')
                  raise "extractPrevOutputScript(#{idx}) requires witness bytes. " \
                        "Call set_prev_out_script(#{idx}, bytes) before invoking the method."
                else
                  raise 'requireOutputP2PKH requires serialised-outputs witness bytes. ' \
                        'Call set_serialised_outputs(bytes) before invoking the method.'
                end
              end
              witness[name]
            else
              env[name]
            end
          end

        when 'load_prop'
          env[value['name']]

        when 'load_const'
          v = value['value']
          # Handle @ref: aliases — resolve to the named env variable. The alias
          # also carries (or clears) the target's raw stack bytes so a chained
          # length-sensitive op sees this slot's real width (NEW-006); every
          # local rebind lowers to exactly this shape.
          if v.is_a?(String) && v.start_with?('@ref:')
            target = v[5..]
            alias_script_bytes(target, binding_name) if binding_name
            env[target]
          elsif v.is_a?(String) && v.match?(BIGINT_LITERAL_RE)
            # On-disk ANF spells every bigint as a +"<decimal>n"+ STRING (see
            # +jsonWithBigInt+ in runar-cli's compile command) -- that is the
            # artifact every SDK loads with a bare +JSON.parse+. Decode it here
            # so a const operand is an Integer, not a String: the byte-op paths
            # below gate on +!_.is_a?(String)+, so leaving it a string silently
            # routes +<< >> & | ^ ~+ down the ByteString branch and the SDK
            # builds a continuation the deployed script disagrees with
            # (NEW-008). Go / Rust / Zig already decode this shape; this makes
            # all seven agree with the script.
            #
            # Unambiguous: ANF ByteString literals are hex and +n+ is not a hex
            # digit, so +\A-?\d+n\z+ cannot be a bytestring.
            v.chomp('n').to_i
          else
            v
          end

        when 'bin_op'
          op        = value['op']
          left_val  = env[value['left']]
          right_val = env[value['right']]
          # Numeric byte-array ops (& | ^ << >>) thread the operands' real stack
          # bytes through the per-binding side-map so chained expressions match
          # the deployed script: a shift/bitwise result can be non-minimal, and
          # the next length-sensitive op must see that real length. ByteString
          # ops (result_type 'bytes' / string operands) fall through to
          # #eval_bin_op, which keeps the minimal-operand path for everything else.
          if numeric_byte_op?(op, value['result_type'], left_val, right_val)
            sbytes = (Thread.current[:runar_script_bytes] ||= {})
            # Operand bytes = the raw bytes registered by a prior byte-op (keyed
            # by ref name) if present, else the value's minimal encoding.
            ab = sbytes[value['left']] || encode_scriptnum_bytes(to_int(left_val))
            rb = if op == '<<' || op == '>>'
                   # Shift count is read as a NUMBER on-chain — it decodes with
                   # fRequireMinimal and aborts on a non-minimal operand. Only
                   # ab's length matters otherwise.
                   assert_minimal_numeric_operand(op == '<<' ? 'OP_LSHIFT' : 'OP_RSHIFT', value['right'], sbytes)
                   scriptnum_shift_bytes(op, ab, to_int(right_val))
                 else
                   bb = sbytes[value['right']] || encode_scriptnum_bytes(to_int(right_val))
                   scriptnum_bitwise_bytes(op, ab, bb)
                 end
            sbytes[binding_name] = rb if binding_name
            decode_scriptnum_bytes(rb)
          else
            # Every NUMERIC consumer decodes its operands with fRequireMinimal
            # on-chain and aborts on a non-minimal encoding. A shift result is
            # length-preserving and can be non-minimal (+1 >> 1+ leaves
            # [0x00]), so the threaded bytes — not the re-minimised value —
            # decide whether the deployed script spends here.
            opcode = NUMERIC_CONSUMER_OPCODES[op]
            # Read the side-map without creating it: outside a
            # #compute_new_state call there are no threaded bytes to check.
            sbytes = Thread.current[:runar_script_bytes]
            if opcode && sbytes
              assert_minimal_numeric_operand(opcode, value['left'], sbytes)
              assert_minimal_numeric_operand(opcode, value['right'], sbytes)
            end
            eval_bin_op(op, left_val, right_val, value['result_type'])
          end

        when 'unary_op'
          op          = value['op']
          operand_val = env[value['operand']]
          # OP_INVERT threads the operand's real stack bytes too, so chained
          # ~(shift/bitwise result) preserves the deployed byte length.
          if op == '~' && value['result_type'] != 'bytes' && !operand_val.is_a?(String)
            sbytes = (Thread.current[:runar_script_bytes] ||= {})
            ab = sbytes[value['operand']] || encode_scriptnum_bytes(to_int(operand_val))
            rb = scriptnum_invert_bytes(ab)
            sbytes[binding_name] = rb if binding_name
            decode_scriptnum_bytes(rb)
          else
            # Every other unary op reads its operand as a script NUMBER
            # (+-+ -> OP_NEGATE) or coerces it to a boolean (+!+ -> OP_NOT),
            # both fRequireMinimal decodes. +~+ never reaches here on the
            # numeric path — it is a byte op and must keep accepting
            # non-minimal bytes.
            sbytes = Thread.current[:runar_script_bytes]
            if sbytes
              assert_minimal_numeric_operand(
                op == '!' ? 'boolean coercion' : 'numeric operand', value['operand'], sbytes
              )
            end
            eval_unary_op(op, operand_val, value['result_type'])
          end

        when 'call'
          # The single funnel every numeric builtin (+abs+, +min+, +max+,
          # +within+, +safediv+, +clamp+, +sign+, +bool+, ...) reads its
          # operands through. Only a NUMERIC byte-op result ever carries
          # threaded bytes, and a bigint argument is exactly what those
          # builtins decode with fRequireMinimal on-chain — a ByteString
          # argument can never carry an entry here, so gating every argument
          # costs nothing and cannot miss a builtin.
          sbytes = Thread.current[:runar_script_bytes]
          if sbytes
            Array(value['args']).each do |a|
              assert_minimal_numeric_operand('numeric operand', a, sbytes)
            end
          end
          call_args = Array(value['args']).map { |a| env[a] }
          # Strict mode: a +call(func: 'assert', args: [pred])+ lowering path
          # enforces the predicate the same way the dedicated +assert+ ANF
          # node does.
          strict_method = Thread.current[:runar_strict_method]
          if strict_method && value['func'] == 'assert'
            unless is_truthy(call_args.first)
              raise AssertionFailureError.new(strict_method, binding_name)
            end

            nil
          else
            eval_call(value['func'], call_args)
          end

        when 'method_call'
          call_args = Array(value['args']).map { |a| env[a] }
          eval_method_call(env[value['object']], value['method'], call_args, env, state_delta, data_outputs, raw_outputs, ordered_outputs, anf)

        when 'if'
          cond   = env[value['cond']]
          branch = is_truthy(cond) ? value['then'] : value['else']
          child_env = env.dup
          eval_bindings(Array(branch), child_env, state_delta, data_outputs, raw_outputs, ordered_outputs, anf)
          env.merge!(child_env)
          # The node's value IS the taken arm's last binding — an alias, so the
          # raw stack bytes follow it out of the branch (NEW-006).
          if branch && !branch.empty?
            last_name = branch.last['name']
            alias_script_bytes(last_name, binding_name) if binding_name
            child_env[last_name]
          end

        when 'loop'
          count    = (value['count'] || 0).to_i
          limit = Thread.current[:runar_max_loop_iterations] || MAX_LOOP_ITERATIONS
          if count > limit
            raise "ANF interpreter: loop count #{count} exceeds maximum of #{limit}"
          end

          body     = Array(value['body'])
          iter_var = value['iterVar'].to_s
          # Iteration i binds iterVar = start + i*step (#121). Older ANF
          # payloads without start/step describe zero-start counting-up loops.
          start = to_int(value['start'] || 0)
          step  = value.key?('step') ? to_int(value['step']) : 1
          last_val = nil
          count.times do |i|
            env[iter_var] = start + i * step
            loop_env = env.dup
            eval_bindings(body, loop_env, state_delta, data_outputs, raw_outputs, ordered_outputs, anf)
            env.merge!(loop_env)
            # Same alias rule as the +if+ node: the loop's value IS its body's
            # last binding, so the raw stack bytes follow it out (NEW-006).
            last_val = nil
            unless body.empty?
              last_name = body.last['name']
              alias_script_bytes(last_name, binding_name) if binding_name
              last_val = loop_env[last_name]
            end
          end
          last_val

        when 'assert'
          # Lenient mode: skip; the on-chain script enforces.
          # Strict mode: enforce — falsy predicate raises AssertionFailureError.
          # If the witness-routing channel is active, also walk the assert's
          # source structure to emit a contextual error string that mirrors
          # the TS source-level interpreter (so the conformance tests' .error
          # regexes match).
          strict_method = Thread.current[:runar_strict_method]
          if strict_method
            # Marker-based skip: the compiler auto-emits the final
            # continuation-hash check on every stateful-contract method
            # (hash256(stateOutput ‖ changeOutput) ==
            # extractOutputHash(preimage)). The lowering pass in
            # +compilers/ruby/lib/runar_compiler/frontend/anf_lower.rb+
            # tags ONLY that assert with +isAutoInjectedStateCheck:
            # true+. Under +execute_strict_with_witness+,
            # +computeStateOutput+ / +get_state_script+ /
            # +buildChangeOutput+ are not modelled off-chain so the assert
            # is unenforceable — skip it. Developer-written covenant
            # asserts with the identical IR shape carry no marker and ARE
            # enforced (the previous structural recognizer misfired on
            # them; see BUG-002).
            if value['isAutoInjectedStateCheck'] == true
              return nil
            end
            if Thread.current[:runar_witness_bytes] &&
               check_preimage_assert?(value['value'])
              return nil
            end

            pred = env[value['value']]
            unless is_truthy(pred)
              ctx_msg = intent_assert_context(value['value'])
              if ctx_msg
                raise ctx_msg
              end

              raise AssertionFailureError.new(strict_method, binding_name)
            end
          end
          nil

        when 'update_prop'
          new_val = env[value['value']]
          env[value['name']]         = new_val
          state_delta[value['name']] = new_val
          nil

        when 'add_output'
          # Map stateValues to mutable properties in declaration order.
          state_values = Array(value['stateValues'])
          if state_values.any? && anf
            mutable_props = Array(anf['properties'])
              .reject { |p| p['readonly'] }
              .map { |p| p['name'] }
            state_values.each_with_index do |sv, i|
              next if i >= mutable_props.length

              resolved  = env[sv]
              prop_name = mutable_props[i]
              env[prop_name]         = resolved
              state_delta[prop_name] = resolved
            end
          end
          # Surface state-output emissions to the caller under the
          # witness-routing channel so the test harness can assert
          # outputs.length / outputs[i].satoshis. Lenient + plain strict
          # paths don't care (they only consume state).
          state_outs = Thread.current[:runar_state_outputs]
          if state_outs
            sat_ref = value['satoshis']
            sats = env[sat_ref]
            sats = sats.to_i if sats
            state_outs << { satoshis: sats || 0 }
          end
          # Record the state continuation output in SOURCE order (finding G1): a
          # method may interleave raw outputs around it, and the on-chain
          # covenant folds them into hashOutputs in exactly this order.
          state_sats = env[value['satoshis']]
          ordered_outputs << { kind: :state, satoshis: (state_sats ? state_sats.to_i : 0) }
          nil

        when 'add_data_output'
          # Resolve the two arg refs and record the data output.
          sat_ref = value['satoshis']
          script_ref = value['scriptBytes']
          sats = env[sat_ref]
          sats = sats.to_i if sats
          script_val = env[script_ref]
          script_hex = script_val.is_a?(String) ? script_val : ''
          data_outputs << { satoshis: sats || 0, script: script_hex }
          nil

        when 'add_raw_output'
          # +addRawOutput(satoshis, scriptBytes)+. The simulator does not
          # introspect the script bytes (they are caller-supplied raw
          # locking script); it forwards them in the result envelope so an
          # off-chain transaction builder can emit the output at the
          # correct index. Crypto built-ins remain mocked even in strict
          # mode. Mirrors the +add_data_output+ arm above.
          sat_ref = value['satoshis']
          script_ref = value['scriptBytes']
          sats = env[sat_ref]
          sats = sats.to_i if sats
          script_val = env[script_ref]
          script_hex = script_val.is_a?(String) ? script_val : ''
          raw_outputs << { satoshis: sats || 0, script: script_hex }
          # Also record in the ordered state-class output list so a transaction
          # builder can emit it at the correct SOURCE-order index (finding G1).
          ordered_outputs << { kind: :raw, satoshis: sats || 0, script: script_hex }
          nil

        when 'check_preimage', 'deserialize_state', 'get_state_script'
          # On-chain-only operations — skip in simulation.
          nil

        else
          nil
        end
      end
      # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity

      # ---------------------------------------------------------------------------
      # Binary operations
      # ---------------------------------------------------------------------------

      # Evaluate a binary operation on two values.
      #
      # When result_type is 'bytes', or both operands are strings, byte semantics
      # are used. Otherwise numeric (bigint) semantics apply.
      #
      # @param op          [String]
      # @param left        [Object]
      # @param right       [Object]
      # @param result_type [String, nil]
      # @return [Object]
      # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength
      def eval_bin_op(op, left, right, result_type = nil)
        if result_type == 'bytes' || (left.is_a?(String) && right.is_a?(String))
          return eval_bytes_bin_op(op, (left || '').to_s, (right || '').to_s)
        end

        l = to_int(left)
        r = to_int(right)

        case op
        when '+'  then l + r
        when '-'  then l - r
        when '*'  then l * r
        when '/'  then r == 0 ? 0 : truncate_div(l, r)
        when '%'  then r == 0 ? 0 : truncate_mod(l, r)
        when '==', '===' then l == r
        when '!=', '!==' then l != r
        when '<'  then l < r
        when '<=' then l <= r
        when '>'  then l > r
        when '>=' then l >= r
        when '&&', 'and' then is_truthy(left) && is_truthy(right)
        when '||', 'or'  then is_truthy(left) || is_truthy(right)
        # OP_AND/OP_OR/OP_XOR/OP_LSHIFT/OP_RSHIFT operate on the operands'
        # minimal script-number BYTES, not their numeric value. Native integer
        # ops disagree with the deployed script (e.g. 255 << 1 is 254 on-chain,
        # not 510; 255 & 1 aborts). Delegate to the byte-array helpers so the
        # simulator matches the on-chain semantics byte-for-byte.
        when '&', '|', '^' then scriptnum_bitwise(op, l, r)
        when '<<', '>>'    then scriptnum_shift(op, l, r)
        else 0
        end
      end
      # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength

      # Integer division truncating toward zero (matching JS/Bitcoin semantics).
      #
      # Ruby's built-in `/` floors toward negative infinity; this matches
      # truncation toward zero used by Bitcoin Script and JavaScript.
      #
      # @param a [Integer]
      # @param b [Integer]
      # @return [Integer]
      def truncate_div(a, b)
        if (a < 0) != (b < 0) && (a % b != 0)
          (a.to_f / b).truncate
        else
          a / b
        end
      end

      # Modulo matching truncation toward zero.
      #
      # @param a [Integer]
      # @param b [Integer]
      # @return [Integer]
      def truncate_mod(a, b)
        a - truncate_div(a, b) * b
      end

      # Binary op for byte strings (hex-encoded).
      #
      # @param op    [String]
      # @param left  [String]
      # @param right [String]
      # @return [Object]
      def eval_bytes_bin_op(op, left, right)
        case op
        when '+'          then left + right   # concatenation
        when '==', '===' then left == right
        when '!=', '!==' then left != right
        else ''
        end
      end

      # ---------------------------------------------------------------------------
      # Unary operations
      # ---------------------------------------------------------------------------

      # Evaluate a unary operation on a value.
      #
      # @param op          [String]
      # @param operand     [Object]
      # @param result_type [String, nil]
      # @return [Object]
      def eval_unary_op(op, operand, result_type = nil)
        if result_type == 'bytes'
          return eval_bytes_unary_op(op, operand)
        end

        val = to_int(operand)
        case op
        when '-'      then -val
        when '!', 'not' then !is_truthy(operand)
        # OP_INVERT flips every bit of the operand's minimal script-number
        # bytes, not native Ruby ~val (e.g. ~5 is -122 on-chain, not -6; ~0 is
        # 0 because 0 encodes to the empty byte string).
        when '~'      then scriptnum_invert(val)
        else val
        end
      end

      # Unary op for byte strings.
      #
      # @param op      [String]
      # @param operand [Object]
      # @return [Object]
      def eval_bytes_unary_op(op, operand)
        return operand unless op == '~'

        hex_str = (operand || '').to_s
        [hex_str].pack('H*').bytes.map { |b| (~b) & 0xff }.pack('C*').unpack1('H*')
      end

      # ---------------------------------------------------------------------------
      # Built-in function calls
      # ---------------------------------------------------------------------------

      # Evaluate a call to a built-in function.
      #
      # @param func [String]
      # @param args [Array]
      # @return [Object]
      # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
      def eval_call(func, args)
        real_crypto = Thread.current[:runar_real_crypto]

        case func
        # Crypto built-ins:
        #   - lenient + strict modes: mock-return true
        #   - on-chain mode: real ECDSA / hash256 verification against the
        #     32-byte sighash supplied via OnChainCryptoContext. Failed
        #     verification returns false, which trips the enclosing
        #     assert(...) and raises AssertionFailureError.
        when 'checkSig'
          real_crypto ? verify_ecdsa_real(args[0], args[1], real_crypto.sighash) : true

        when 'checkMultiSig'
          real_crypto ? verify_multi_sig_real(args[0], args[1], real_crypto.sighash) : true

        when 'checkPreimage'
          real_crypto ? verify_preimage_real(args[0], real_crypto.sighash) : true

        # Real hash functions.
        when 'sha256'   then hash_fn('sha256',   args[0])
        when 'hash256'  then hash_fn('hash256',  args[0])
        when 'hash160'  then hash_fn('hash160',  args[0])
        when 'ripemd160' then hash_fn('ripemd160', args[0])

        # Assert — no-op in simulation.
        when 'assert'
          nil

        # Byte operations.
        when 'num2bin'
          n      = to_int(args[0])
          length = to_int(args[1]).to_i
          num2bin_hex(n, length)

        when 'bin2num'
          bin2num_int((args[0] || '').to_s)

        when 'cat'
          (args[0] || '').to_s + (args[1] || '').to_s

        when 'substr'
          hex_str = (args[0] || '').to_s
          start   = to_int(args[1]).to_i
          length  = to_int(args[2]).to_i
          hex_str[start * 2, length * 2] || ''

        when 'reverseBytes'
          hex_str = (args[0] || '').to_s
          hex_str.scan(/../).reverse.join

        when 'len'
          hex_str = (args[0] || '').to_s
          hex_str.length / 2

        # Math built-ins.
        when 'abs'
          to_int(args[0]).abs

        when 'min'
          [to_int(args[0]), to_int(args[1])].min

        when 'max'
          [to_int(args[0]), to_int(args[1])].max

        when 'within'
          x = to_int(args[0])
          x >= to_int(args[1]) && x < to_int(args[2])

        when 'safediv'
          d = to_int(args[1])
          d == 0 ? 0 : truncate_div(to_int(args[0]), d)

        when 'safemod'
          d = to_int(args[1])
          d == 0 ? 0 : truncate_mod(to_int(args[0]), d)

        when 'clamp'
          v  = to_int(args[0])
          lo = to_int(args[1])
          hi = to_int(args[2])
          v < lo ? lo : v > hi ? hi : v

        when 'sign'
          v = to_int(args[0])
          v > 0 ? 1 : v < 0 ? -1 : 0

        when 'pow'
          base = to_int(args[0])
          exp  = to_int(args[1])
          exp < 0 ? 0 : base**exp

        when 'sqrt'
          v = to_int(args[0])
          integer_sqrt(v)

        when 'gcd'
          a = to_int(args[0]).abs
          b = to_int(args[1]).abs
          a, b = b, a % b while b != 0
          a

        when 'divmod'
          a = to_int(args[0])
          b = to_int(args[1])
          b == 0 ? 0 : truncate_div(a, b)

        when 'log2'
          v = to_int(args[0])
          integer_log2(v)

        when 'bool'
          is_truthy(args[0]) ? 1 : 0

        when 'mulDiv'
          truncate_div(to_int(args[0]) * to_int(args[1]), to_int(args[2]))

        when 'percentOf'
          truncate_div(to_int(args[0]) * to_int(args[1]), 10_000)

        # Preimage intrinsics — default to dummy values, but allow
        # explicit overrides via the mock-preimage channel threaded
        # through {execute_strict_with_witness}.
        when 'extractOutputHash', 'extractOutputs'
          mock_bytes = Thread.current[:runar_mock_preimage_bytes]
          (mock_bytes && mock_bytes['outputHash']) || ('00' * 32)

        when 'extractHashPrevouts'
          mock_bytes = Thread.current[:runar_mock_preimage_bytes]
          (mock_bytes && mock_bytes['hashPrevouts']) || ('00' * 32)

        when 'extractHashSequence'
          mock_bytes = Thread.current[:runar_mock_preimage_bytes]
          (mock_bytes && mock_bytes['hashSequence']) || ('00' * 32)

        when 'extractOutpoint'
          mock_bytes = Thread.current[:runar_mock_preimage_bytes]
          (mock_bytes && mock_bytes['outpoint']) || ('00' * 36)

        when 'extractLocktime'
          mock_pre = Thread.current[:runar_mock_preimage]
          to_int((mock_pre && (mock_pre['locktime'] || mock_pre[:locktime])) || 0)

        when 'extractAmount'
          mock_pre = Thread.current[:runar_mock_preimage]
          if mock_pre && (mock_pre.key?('amount') || mock_pre.key?(:amount))
            to_int(mock_pre['amount'] || mock_pre[:amount])
          else
            '00' * 32
          end

        when 'extractVersion'
          mock_pre = Thread.current[:runar_mock_preimage]
          to_int((mock_pre && (mock_pre['version'] || mock_pre[:version])) || 1)

        when 'extractSequence'
          mock_pre = Thread.current[:runar_mock_preimage]
          to_int((mock_pre && (mock_pre['sequence'] || mock_pre[:sequence])) || 0xfffffffe)

        when 'extractSigHashType'
          # GAP-302: the auto-injected stateful covenant pins the sighash type
          # to SIGHASH_ALL | FORKID (0x41). The interpreter mocks a valid
          # preimage (checkPreimage passes), so report the canonical pinned
          # type here too -- otherwise the pin assert spuriously fails.
          mock_pre = Thread.current[:runar_mock_preimage]
          to_int((mock_pre && (mock_pre['sigHashType'] || mock_pre[:sigHashType])) || 0x41)

        else
          nil
        end
      end
      # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity

      # ---------------------------------------------------------------------------
      # Private method calls
      # ---------------------------------------------------------------------------

      # Evaluate a call to a private method defined in the ANF IR.
      #
      # Creates a new child environment with property values from the caller,
      # maps positional args to the method's params, evaluates the body,
      # propagates any state mutations back to the caller, and returns the
      # value of the last binding.
      #
      # @param _obj         [Object]      receiver (unused — all calls are this-calls)
      # @param method_name  [String, nil]
      # @param args         [Array]
      # @param caller_env   [Hash, nil]
      # @param state_delta  [Hash, nil]
      # @param data_outputs [Array<Hash>]
      # @param raw_outputs  [Array<Hash>]
      # @param ordered_outputs [Array<Hash>] state-class outputs (state + raw)
      #   in source order (finding G1)
      # @param anf          [Hash, nil]
      # @return [Object]
      def eval_method_call(_obj, method_name, args, caller_env = nil, state_delta = nil, data_outputs = [], raw_outputs = [], ordered_outputs = [], anf = nil)
        return nil unless anf && method_name

        private_method = Array(anf['methods']).find do |m|
          m['name'] == method_name && !m['isPublic']
        end

        return nil unless private_method

        # Build a new env seeded with property values from the caller.
        new_env = {}
        if caller_env
          Array(anf['properties']).each do |prop|
            name = prop['name']
            new_env[name] = caller_env[name] if caller_env.key?(name)
          end
        end

        # Map positional args to the method's declared params.
        params = Array(private_method['params'])
        params.each_with_index do |param, i|
          new_env[param['name']] = args[i] if i < args.length
        end

        body = Array(private_method['body'])
        child_delta = {}
        # Save & shadow the caller's body-index so this private method's
        # binding names (which can collide with the caller's, e.g. +t0+)
        # don't pollute intent-intrinsic assert-context lookups in the
        # caller's frame after we return.
        saved_index = Thread.current[:runar_method_body_index]
        Thread.current[:runar_method_body_index] = {} if saved_index
        # Private methods have their own binding namespace, so they get a fresh
        # byte-op side-map (binding names like +t0+ can collide with the
        # caller's). Mirrors the TS +evalMethodCall+, which calls +evalBindings+
        # without threading the parent +scriptBytes+.
        saved_script_bytes = Thread.current[:runar_script_bytes]
        Thread.current[:runar_script_bytes] = {}
        begin
          eval_bindings(body, new_env, child_delta, data_outputs, raw_outputs, ordered_outputs, anf)
        ensure
          Thread.current[:runar_method_body_index] = saved_index
          Thread.current[:runar_script_bytes] = saved_script_bytes
        end

        # Propagate state mutations back to the caller environment.
        state_delta&.merge!(child_delta)
        if caller_env
          child_delta.each { |k, v| caller_env[k] = v }
        end

        body.empty? ? nil : new_env[body.last['name']]
      end

      # ---------------------------------------------------------------------------
      # Hash helpers
      # ---------------------------------------------------------------------------

      # Compute a named hash function over hex-encoded input.
      #
      # @param name      [String] 'sha256', 'hash256', 'ripemd160', or 'hash160'
      # @param input_val [Object] hex-encoded byte string
      # @return [String] hex-encoded digest
      def hash_fn(name, input_val)
        hex_str = (input_val || '').to_s
        data    = [hex_str].pack('H*')

        case name
        when 'sha256'   then Digest::SHA256.hexdigest(data)
        when 'hash256'  then Digest::SHA256.hexdigest(Digest::SHA256.digest(data))
        when 'ripemd160' then Digest::RMD160.hexdigest(data)
        when 'hash160'  then Digest::RMD160.hexdigest(Digest::SHA256.digest(data))
        else ''
        end
      end

      # ---------------------------------------------------------------------------
      # Real ECDSA / preimage verification (used by execute_on_chain_authoritative)
      # ---------------------------------------------------------------------------

      # Coerce a checkSig / checkPreimage arg into a hex string. Accepts
      # hex strings (returned as-is) and 8-bit binary strings (encoded to
      # hex). Returns nil if the value is not coercible to bytes.
      def to_hex_arg(v)
        return nil if v.nil?

        case v
        when String
          # Even-length hex string: pass through.
          if v.length.even? && v.match?(/\A[0-9a-fA-F]*\z/)
            v
          else
            nil
          end
        else
          nil
        end
      end

      # Verify an ECDSA signature against a 32-byte sighash. Pubkey must be
      # SEC1 (33-byte compressed or 65-byte uncompressed); signature must be
      # DER with an optional trailing sighash type byte (stripped by
      # +Runar::ECDSA.parse_der_signature_bytes+). Returns +false+ on any
      # decode error so the enclosing +assert(...)+ fires.
      #
      # The 32-byte sighash is the ECDSA digest itself (no extra hash) — this
      # mirrors the on-chain +OP_CHECKSIG+ semantic, where the script
      # interpreter feeds the BIP-143 sighash directly into ECDSA-verify. The
      # test fixtures' signatures are produced by +ECDSA-sign(sighash, priv)+
      # against the same 32-byte sighash with no additional hashing.
      def verify_ecdsa_real(sig_val, pk_val, sighash_bytes)
        return false unless sighash_bytes.is_a?(String) && sighash_bytes.bytesize == 32

        sig_hex = to_hex_arg(sig_val)
        pk_hex  = to_hex_arg(pk_val)
        return false if sig_hex.nil? || pk_hex.nil?

        begin
          Runar::ECDSA.verify(sighash_bytes.unpack1('H*'), sig_hex, pk_hex)
        rescue StandardError
          false
        end
      end

      # Verify a list of signatures against a list of pubkeys. Mirrors
      # Bitcoin's +OP_CHECKMULTISIG+: iterate sigs left-to-right, consume
      # pubkeys greedily.
      def verify_multi_sig_real(sigs_val, pks_val, sighash_bytes)
        return false unless sigs_val.is_a?(Array) && pks_val.is_a?(Array)
        return false if sigs_val.length > pks_val.length

        pk_idx = 0
        sigs_val.each do |sig|
          matched = false
          while pk_idx < pks_val.length
            ok = verify_ecdsa_real(sig, pks_val[pk_idx], sighash_bytes)
            pk_idx += 1
            if ok
              matched = true
              break
            end
          end
          return false unless matched
        end
        true
      end

      # Verify that +SHA256(SHA256(preimage)) == sighash+ — the on-chain
      # +OP_PUSH_TX+ semantic for +checkPreimage+.
      def verify_preimage_real(preimage_val, sighash_bytes)
        return false unless sighash_bytes.is_a?(String) && sighash_bytes.bytesize == 32

        pre_hex = to_hex_arg(preimage_val)
        return false if pre_hex.nil?

        pre_bytes = [pre_hex].pack('H*')
        computed = Digest::SHA256.digest(Digest::SHA256.digest(pre_bytes))
        computed == sighash_bytes
      end

      # ---------------------------------------------------------------------------
      # Numeric helpers
      # ---------------------------------------------------------------------------

      # Convert any value to an Integer.
      #
      # Handles Ruby Integer, Float, Boolean, and String (including "42n" BigInt
      # notation from JSON serialization).
      #
      # @param v [Object]
      # @return [Integer]
      def to_int(v)
        case v
        when Integer then v
        when TrueClass  then 1
        when FalseClass then 0
        when Float   then v.to_i
        when String
          # "42n" format from JSON serialized bigints.
          if v.match?(/\A-?\d+n\z/)
            v.chomp('n').to_i
          elsif v.match?(/\A-?\d+\z/)
            v.to_i
          else
            0
          end
        else
          0
        end
      end

      # Determine truthiness of a value using Runar/Bitcoin Script semantics.
      #
      # @param v [Object]
      # @return [Boolean]
      #
      # Matches on-chain Bitcoin Script OP_IF semantics for truthiness.
      # A value is falsy if it is empty, all-zero bytes, or negative zero (0x80).
      def is_truthy(v) # rubocop:disable Naming/PredicateName
        case v
        when TrueClass  then true
        when FalseClass then false
        when Integer    then v != 0
        when Float      then v != 0.0
        when String
          return false if v.empty?
          return false if v == '0' || v == 'false'
          # Hex-encoded byte string: apply Bitcoin Script semantics
          if v.length.even? && v.match?(/\A[0-9a-fA-F]*\z/)
            bytes = [v].pack('H*').bytes
            return false if bytes.empty?
            # All-zero bytes: falsy (e.g. "00", "0000")
            return false if bytes.all?(&:zero?)
            # Negative zero: all zeros except last byte is 0x80 (e.g. "80", "0080")
            return false if bytes[0...-1].all?(&:zero?) && bytes[-1] == 0x80
          end
          true
        else false
        end
      end

      # ---------------------------------------------------------------------------
      # Byte encoding helpers
      # ---------------------------------------------------------------------------

      # Convert an integer to a little-endian sign-magnitude hex string --
      # exactly what OP_NUM2BIN computes (NEW-013).
      #
      # The order of the two steps below is load-bearing. This used to set the
      # sign bit on the last MAGNITUDE byte and pad zeros AFTER it, so
      # +num2bin(-1, 2)+ produced +8100+ while the script produces +0180+. The
      # result is the bytes the SDK puts in the call transaction, so the wrong
      # order built continuations the deployed script rejects -- and six of the
      # seven SDKs shared the mistake, which is why tier-vs-tier parity never
      # caught it.
      #
      # The engine pads FIRST and then puts the sign bit on the new
      # most-significant byte.
      #
      # @param n        [Integer]
      # @param byte_len [Integer]
      # @return [String] hex-encoded bytes (2 * byte_len characters)
      def num2bin_hex(n, byte_len)
        # 1. Minimal BSV script-number encoding: little-endian magnitude with
        #    the sign in bit 7 of the top byte, growing one byte when magnitude
        #    data already occupies that bit.
        negative = n < 0

        result_bytes = []
        tmp = n.abs
        while tmp > 0
          result_bytes << (tmp & 0xff)
          tmp >>= 8
        end
        unless result_bytes.empty?
          if (result_bytes.last & 0x80) != 0
            result_bytes << (negative ? 0x80 : 0x00)
          elsif negative
            result_bytes[-1] |= 0x80
          end
        end

        # 2a. Field too narrow for the value: OP_NUM2BIN rejects this outright
        #     ("impossible encoding"). The interpreter keeps its historical
        #     truncation rather than growing a new failure mode here; an
        #     equal-length encoding is already final and needs no sign-bit move.
        if result_bytes.length >= byte_len
          return result_bytes[0, byte_len].map { |b| format('%02x', b) }.join
        end

        # 2b. Padded: lift the sign bit off the magnitude, zero-extend, and
        #     re-apply it to the byte that is now most significant.
        sign_bit = 0
        unless result_bytes.empty?
          sign_bit = result_bytes.last & 0x80
          result_bytes[-1] &= 0x7f
        end
        result_bytes << 0x00 while result_bytes.length < byte_len
        result_bytes[byte_len - 1] |= 0x80 if sign_bit != 0

        result_bytes.map { |b| format('%02x', b) }.join
      end

      # Convert a little-endian sign-magnitude hex string to an integer.
      #
      # @param hex_str [String]
      # @return [Integer]
      def bin2num_int(hex_str)
        return 0 if hex_str.nil? || hex_str.empty?

        result_bytes = hex_str.scan(/../).map { |h| h.to_i(16) }
        return 0 if result_bytes.empty?

        negative = (result_bytes.last & 0x80) != 0
        result_bytes[-1] &= 0x7f

        result = 0
        result_bytes.each_with_index { |b, i| result |= b << (8 * i) }

        negative ? -result : result
      end

      # ---------------------------------------------------------------------------
      # Script-number bitwise / shift semantics (byte-array ops, NOT numeric)
      #
      # OP_AND/OP_OR/OP_XOR/OP_INVERT/OP_LSHIFT/OP_RSHIFT operate on the RAW BYTES
      # of the operands' minimal script-number encoding, not on their numeric
      # value. AND/OR/XOR require equal-length operands and abort otherwise;
      # shifts treat the byte array as a big-endian bit string, preserve its
      # length, and abort on a negative count. These helpers reproduce exactly
      # what the on-chain opcodes do so the interpreter (which models values as
      # integers) agrees with the deployed script byte-for-byte. Mirrors
      # packages/runar-testing/src/vm/utils.ts scriptNumber{Bitwise,Invert,Shift}.
      # ---------------------------------------------------------------------------

      # Encode an integer as minimal little-endian sign-magnitude bytes (Bitcoin
      # script-number format). 0 → []. Matches encode_script_number in the
      # compiler codegen and the TS vm/utils encodeScriptNumber.
      #
      # @param n [Integer]
      # @return [Array<Integer>] minimal byte values
      def encode_scriptnum_bytes(n)
        return [] if n == 0

        negative = n < 0
        abs_n    = n.abs
        bytes    = []
        while abs_n > 0
          bytes << (abs_n & 0xff)
          abs_n >>= 8
        end
        if (bytes.last & 0x80) != 0
          bytes << (negative ? 0x80 : 0x00)
        elsif negative
          bytes[-1] |= 0x80
        end
        bytes
      end

      # Decode minimal little-endian sign-magnitude bytes back to an integer.
      # [] → 0. Reuses the existing #bin2num_int decoder.
      #
      # @param bytes [Array<Integer>]
      # @return [Integer]
      def decode_scriptnum_bytes(bytes)
        return 0 if bytes.empty?

        bin2num_int(bytes.map { |b| format('%02x', b) }.join)
      end

      # Whether a +bin_op+ is a NUMERIC byte-array op (& | ^ << >>) — i.e. one
      # whose operands are script numbers rather than ByteStrings. Mirrors the TS
      # +isNumericByteOp+ guard: the op is one of the byte-array ops, the result
      # is not a ByteString, and neither operand is a (hex) string. Only these
      # thread the raw-stack-byte side-map; ByteString ops keep their own path.
      #
      # @param op          [String]
      # @param result_type [String, nil]
      # @param left        [Object]
      # @param right       [Object]
      # @return [Boolean]
      def numeric_byte_op?(op, result_type, left, right)
        %w[& | ^ << >>].include?(op) &&
          result_type != 'bytes' &&
          !left.is_a?(String) &&
          !right.is_a?(String)
      end

      # Source operators that consume their operands as SCRIPT NUMBERS, mapped
      # to the opcode they lower to. Those opcodes decode with
      # +fRequireMinimal = true+ and abort on a non-minimally-encoded operand.
      #
      # Deliberately EXCLUDES the byte-array ops +& | ^ ~+ (which take
      # non-minimal bytes and only require equal length) and the boolean ops
      # +&& ||+ (OP_BOOLAND/OP_BOOLOR read truthiness, not a decoded number).
      # +<< >>+ are handled separately: only their COUNT operand is a number.
      NUMERIC_CONSUMER_OPCODES = {
        '+' => 'OP_ADD',
        '-' => 'OP_SUB',
        '*' => 'OP_MUL',
        '/' => 'OP_DIV',
        '%' => 'OP_MOD',
        '==' => 'OP_NUMEQUAL',
        '===' => 'OP_NUMEQUAL',
        '!=' => 'OP_NUMNOTEQUAL',
        '!==' => 'OP_NUMNOTEQUAL',
        '<' => 'OP_LESSTHAN',
        '<=' => 'OP_LESSTHANOREQUAL',
        '>' => 'OP_GREATERTHAN',
        '>=' => 'OP_GREATERTHANOREQUAL',
      }.freeze

      # Abort when the operand bound to +ref+ carries threaded stack bytes that
      # are NOT the minimal encoding of its decoded value — exactly the
      # condition on which a numeric opcode's +fRequireMinimal+ decode fails
      # on-chain. A shift preserves its operand's byte length, so +1 >> 1+
      # leaves the 1-byte [0x00]; re-minimising it to 0 off-chain reports a
      # spend the deployed script rejects, locking the UTXO.
      #
      # Only bindings produced by a byte-array op appear in +sbytes+; every
      # other value is minimal on-chain, so an absent entry is always fine. The
      # check is confined to the numeric consumers (see
      # {NUMERIC_CONSUMER_OPCODES}): OP_AND/OP_OR/OP_XOR/OP_INVERT and a
      # shift's VALUE operand legitimately take non-minimal bytes, so rejecting
      # them here would break spends the chain accepts (see
      # conformance/fuzz-regressions/entries/2026-07-14-chained-shift-or-nonminimal).
      #
      # @param opcode [String] opcode name for the abort message
      # @param ref    [String, nil] binding name of the operand
      # @param sbytes [Hash{String=>Array<Integer>}] raw-stack-byte side-map
      # @return [void]
      # @raise [RuntimeError] when the operand's bytes are non-minimal
      def assert_minimal_numeric_operand(opcode, ref, sbytes)
        raw = sbytes[ref]
        return if raw.nil?

        decoded = decode_scriptnum_bytes(raw)
        minimal = encode_scriptnum_bytes(decoded)
        return if raw == minimal

        raise "#{opcode}: non-minimally encoded script number " \
              "(operand bytes #{hexify_scriptnum_bytes(raw)} decode to #{decoded}, " \
              "minimal encoding is #{hexify_scriptnum_bytes(minimal)})"
      end

      # Render raw stack bytes as a hex string for abort messages.
      #
      # @param bytes [Array<Integer>]
      # @return [String]
      def hexify_scriptnum_bytes(bytes)
        bytes.map { |b| format('%02x', b) }.join
      end

      # ---------------------------------------------------------------------------
      # Raw-stack-byte helpers (thread non-minimal chained intermediates)
      #
      # The +*_bytes+ helpers operate on RAW stack bytes — the exact byte array a
      # value would occupy on the deployed script's stack — NOT a value's minimal
      # encoding. This matters for CHAINED expressions: a shift/bitwise RESULT can
      # be a non-minimal byte array (e.g. +2 << 8+ leaves a 1-byte +0x00+, not the
      # empty encoding of 0), and feeding it to a length-sensitive +& | ^+/shift
      # must see that real length to agree with the deployed script. #eval_value
      # threads these bytes via a per-binding side-map (Thread.current
      # +:runar_script_bytes+); values from other sources (literals, arithmetic)
      # are minimal on-chain, so their bytes are re-derived via
      # #encode_scriptnum_bytes. Mirrors the TS anf-interpreter scriptNumber*Bytes.
      # ---------------------------------------------------------------------------

      # Carry a binding's raw stack bytes across an ALIAS — a binding whose value
      # IS another binding's slot: the +load_const "@ref:<name>"+ every local
      # rebind lowers to, an +if+ adopting its taken arm's last value, a +loop+
      # adopting its body's. Without this a chained length-sensitive op
      # re-minimises the aliased value and disagrees with the deployed script
      # (NEW-006: +2 << 8+ leaves a 1-byte +0x00+ on the stack but +[]+ when
      # re-minimised from the integer 0). Mirrors the stack-lowering pass, which
      # carries its +raw_slots+ marker across the same constructs.
      #
      # CLEARS when the source has no entry: the alias target is then a freshly
      # pushed, minimal value, so a stale entry left by an EARLIER binding of the
      # SAME name (+let m0 = 2 << 8; m0 = 300;+) would otherwise be read as this
      # slot's width.
      #
      # @param from [String] name of the aliased (source) binding
      # @param to   [String] name of the aliasing (target) binding
      # @return [void]
      def alias_script_bytes(from, to)
        sbytes = (Thread.current[:runar_script_bytes] ||= {})
        if sbytes.key?(from)
          sbytes[to] = sbytes[from]
        else
          sbytes.delete(to)
        end
      end

      # OP_AND/OP_OR/OP_XOR on two raw byte arrays. Aborts on a length mismatch,
      # exactly like the on-chain opcodes.
      #
      # @param op [String] '&', '|', or '^'
      # @param av [Array<Integer>] raw stack bytes of the left operand
      # @param bv [Array<Integer>] raw stack bytes of the right operand
      # @return [Array<Integer>] result bytes (same length as the operands)
      def scriptnum_bitwise_bytes(op, av, bv)
        if av.length != bv.length
          name = op == '&' ? 'OP_AND' : op == '|' ? 'OP_OR' : 'OP_XOR'
          raise "#{name}: operands must be same length"
        end
        av.each_index.map do |i|
          case op
          when '&' then av[i] & bv[i]
          when '|' then av[i] | bv[i]
          else av[i] ^ bv[i]
          end
        end
      end

      # OP_INVERT: flip every bit of the operand's raw stack bytes
      # (length-preserving).
      #
      # @param av [Array<Integer>] raw stack bytes
      # @return [Array<Integer>] inverted bytes
      def scriptnum_invert_bytes(av)
        av.map { |x| (~x) & 0xff }
      end

      # OP_LSHIFT/OP_RSHIFT on raw stack bytes as a big-endian bit string,
      # preserving byte length (LSHIFT masks off overflow MSBs). +shift+ is the
      # numeric shift count (read as a number on-chain, so only +val+'s bytes are
      # length-significant). Aborts on a negative shift count.
      #
      # @param op    [String] '<<' or '>>'
      # @param val   [Array<Integer>] raw stack bytes to shift
      # @param shift [Integer]
      # @return [Array<Integer>] shifted bytes (same length as +val+)
      def scriptnum_shift_bytes(op, val, shift)
        if shift < 0
          raise(op == '<<' ? 'OP_LSHIFT: negative shift' : 'OP_RSHIFT: negative shift')
        end

        n = shift.to_i
        return val.dup if val.empty? || n == 0

        num = 0
        val.each { |byte| num = (num << 8) | byte }
        if op == '<<'
          bit_len = val.length * 8
          num = (num << n) & ((1 << bit_len) - 1)
        else
          num >>= n
        end
        result = Array.new(val.length, 0)
        (val.length - 1).downto(0) do |i|
          result[i] = num & 0xff
          num >>= 8
        end
        result
      end

      # OP_AND/OP_OR/OP_XOR on two script-number-valued integers (minimal
      # operands). Aborts on a length mismatch, exactly like the on-chain
      # opcodes. Used for the single-op path (values fresh from minimal
      # encoding); the chained path calls #scriptnum_bitwise_bytes directly.
      #
      # @param op [String] '&', '|', or '^'
      # @return [Integer]
      def scriptnum_bitwise(op, a, b)
        decode_scriptnum_bytes(
          scriptnum_bitwise_bytes(op, encode_scriptnum_bytes(a), encode_scriptnum_bytes(b)),
        )
      end

      # OP_INVERT on a script-number-valued integer (minimal operand).
      #
      # @param a [Integer]
      # @return [Integer]
      def scriptnum_invert(a)
        decode_scriptnum_bytes(scriptnum_invert_bytes(encode_scriptnum_bytes(a)))
      end

      # OP_LSHIFT/OP_RSHIFT on a script-number-valued integer (minimal operand).
      # Aborts on a negative shift count.
      #
      # @param op    [String] '<<' or '>>'
      # @param a     [Integer]
      # @param shift [Integer]
      # @return [Integer]
      def scriptnum_shift(op, a, shift)
        decode_scriptnum_bytes(scriptnum_shift_bytes(op, encode_scriptnum_bytes(a), shift))
      end

      # ---------------------------------------------------------------------------
      # Math helpers
      # ---------------------------------------------------------------------------

      # Integer square root using Newton's method (matching the Python reference).
      #
      # @param v [Integer]
      # @return [Integer]
      def integer_sqrt(v)
        return 0 if v <= 0

        x = v
        y = (x + 1) / 2
        while y < x
          x = y
          y = (x + v / x) / 2
        end
        x
      end

      # Integer base-2 logarithm (floor).
      #
      # @param v [Integer]
      # @return [Integer]
      def integer_log2(v)
        return 0 if v <= 0

        bits = 0
        x    = v
        while x > 1
          x >>= 1
          bits += 1
        end
        bits
      end

      # ---------------------------------------------------------------------------
      # Private helpers
      # ---------------------------------------------------------------------------

      # Detect whether an assert predicate ref is +check_preimage(...)+.
      # The check is unenforceable without a real sighash, so under
      # +execute_strict_with_witness+ we skip it (mirroring the TS
      # AST interpreter, which does not run check_preimage in the test
      # harness either).
      def check_preimage_assert?(pred_ref)
        idx_map = Thread.current[:runar_method_body_index]
        return false unless idx_map

        pred = idx_map[pred_ref]
        pred.is_a?(Hash) && pred['kind'] == 'check_preimage'
      end

      # Detect whether an assert predicate ref is the auto-emitted
      # continuation-hash check the compiler appends to every
      # stateful-contract public method. Pattern:
      #
      #   bin_op === bytes (hash256_ref, extractOutputHash_ref)
      #     where hash256_ref = call hash256(cat_ref)
      #       and cat_ref     = call cat(state_ref, change_ref)
      #       and state_ref   = call computeStateOutput(...)
      #             OR  state_ref upstream depends on get_state_script
      #       and change_ref  = call buildChangeOutput(...)
      #
      # Only matches when the structural shape is unambiguously the
      # compiler-emitted continuation check; otherwise returns false.
      def continuation_hash_assert?(pred_ref)
        idx_map = Thread.current[:runar_method_body_index]
        return false unless idx_map

        pred = idx_map[pred_ref]
        return false unless pred.is_a?(Hash) && pred['kind'] == 'bin_op'
        return false unless ['===', '==', '!==', '!='].include?(pred['op'])

        left  = idx_map[pred['left']]
        right = idx_map[pred['right']]
        return false unless left.is_a?(Hash) && left['kind'] == 'call' && left['func'] == 'hash256'
        return false unless right.is_a?(Hash) && right['kind'] == 'call' && right['func'] == 'extractOutputHash'

        cat_ref = Array(left['args']).first
        cat_node = cat_ref ? idx_map[cat_ref] : nil
        return false unless cat_node.is_a?(Hash) && cat_node['kind'] == 'call' && cat_node['func'] == 'cat'

        cat_args = Array(cat_node['args'])
        state_node = cat_args[0] ? idx_map[cat_args[0]] : nil
        change_node = cat_args[1] ? idx_map[cat_args[1]] : nil

        # The "state half" of the cat is one of three shapes the compiler
        # emits depending on the contract surface:
        #   - +call computeStateOutput(...)+ — standard stateful contract
        #     desugar path
        #   - +get_state_script+ ANF kind — earlier IR shape some methods
        #     bake out directly
        #   - +add_output(...)+ — when the user's body calls
        #     +this.addOutput(satoshis, ...stateValues)+, the compiler reuses
        #     that node as the state-output reference and concats it with the
        #     change output for the continuation hash.
        state_ok = state_node.is_a?(Hash) && (
          (state_node['kind'] == 'call' && state_node['func'] == 'computeStateOutput') ||
          state_node['kind'] == 'get_state_script' ||
          state_node['kind'] == 'add_output'
        )
        change_ok = change_node.is_a?(Hash) && change_node['kind'] == 'call' && change_node['func'] == 'buildChangeOutput'

        state_ok && change_ok
      end

      # If the binding referenced by an +assert+ predicate originated in
      # one of the three intent-intrinsic desugar shapes, return a
      # contextual error string matching the TS source-level interpreter.
      # Otherwise return +nil+ so the caller falls back to the generic
      # {AssertionFailureError} message.
      #
      # Recognised shapes (LEFT = bin_op +===+ bytes operand):
      # - +hash256(<load_param '_prevOutScript_<idx>'>)+ → emit
      #   "extractPrevOutputScript(<idx>): hash256(witness) !== expectedHash"
      # - +hash256(<load_param '_serialisedOutputs'>)+ → emit
      #   "requireOutputP2PKH: hash256(serialisedOutputs) !== preimage.hashOutputs"
      # - +substr(<load_param '_serialisedOutputs'>, 0, *)+ → emit
      #   "requireOutputP2PKH(<idx>): output bytes mismatch" (with
      #   +<idx> = offset / 34+)
      #
      # @param pred_ref [String] the +value['value']+ ref on the assert node
      # @return [String, nil]
      def intent_assert_context(pred_ref)
        return nil unless Thread.current[:runar_witness_bytes]

        idx_map = Thread.current[:runar_method_body_index]
        return nil unless idx_map

        pred = idx_map[pred_ref]
        return nil unless pred.is_a?(Hash) && pred['kind'] == 'bin_op'
        return nil unless ['===', '==', '!==', '!='].include?(pred['op'])

        left = idx_map[pred['left']]
        return nil unless left.is_a?(Hash) && left['kind'] == 'call'

        call_args = Array(left['args'])
        first_arg = call_args.first ? idx_map[call_args.first] : nil

        if left['func'] == 'hash256' && first_arg.is_a?(Hash) && first_arg['kind'] == 'load_param'
          name = first_arg['name'].to_s
          if name.start_with?('_prevOutScript_')
            idx = name.sub('_prevOutScript_', '')
            return "extractPrevOutputScript(#{idx}): hash256(witness) !== expectedHash"
          elsif name == '_serialisedOutputs'
            return 'requireOutputP2PKH: hash256(serialisedOutputs) !== preimage.hashOutputs'
          end
        end

        if left['func'] == 'substr' && first_arg.is_a?(Hash) && first_arg['kind'] == 'load_param' &&
           first_arg['name'].to_s == '_serialisedOutputs'
          offset_node = call_args[1] ? idx_map[call_args[1]] : nil
          length_node = call_args[2] ? idx_map[call_args[2]] : nil
          length_val = length_node.is_a?(Hash) ? length_node['value'] : nil
          # Only emit the requireOutputP2PKH-substr error for the 34-byte
          # canonical-P2PKH window; other substr( _serialisedOutputs, ...)
          # callsites would be unrelated.
          if length_val.to_i == 34
            offset_val = offset_node.is_a?(Hash) ? offset_node['value'].to_i : 0
            idx = offset_val / 34
            return "requireOutputP2PKH(#{idx}): output bytes mismatch"
          end
        end

        nil
      end

      # Find a public method by name in the ANF IR.
      #
      # @param anf         [Hash]
      # @param method_name [String]
      # @return [Hash, nil]
      def find_public_method(anf, method_name)
        Array(anf['methods']).find do |m|
          m['name'] == method_name && m['isPublic']
        end
      end
    end
  end
end

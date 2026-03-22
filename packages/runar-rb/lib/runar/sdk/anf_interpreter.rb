# frozen_string_literal: true

require 'digest'

# Lightweight ANF interpreter for auto-computing state transitions.
#
# Given a compiled artifact's ANF IR, the current contract state, and
# method arguments, this interpreter walks the ANF bindings and computes
# the new state. It handles +update_prop+ nodes to track state mutations,
# while skipping on-chain-only operations like +check_preimage+,
# +deserialize_state+, +get_state_script+, +add_output+, and +add_raw_output+.
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
    module ANFInterpreter
      module_function

      # Implicit params injected by the compiler — never required from the caller.
      IMPLICIT_PARAMS = %w[_changePKH _changeAmount _newAmount txPreimage].freeze

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
      # @return [Hash] the updated state (merged with current_state)
      # @raise [ArgumentError] when method_name is not found as a public method in the ANF IR
      def compute_new_state(anf, method_name, current_state, args)
        method = find_public_method(anf, method_name)

        unless method
          raise ArgumentError,
                "computeNewState: method '#{method_name}' not found in ANF IR"
        end

        # Initialize environment with property values.
        env = {}
        Array(anf['properties']).each do |prop|
          name = prop['name']
          env[name] = current_state.fetch(name, prop['initialValue'])
        end

        # Load method params, skipping implicit compiler-injected ones.
        Array(method['params']).each do |param|
          pname = param['name']
          next if IMPLICIT_PARAMS.include?(pname)
          next unless args.key?(pname) || args.key?(pname.to_sym)

          env[pname] = args.key?(pname) ? args[pname] : args[pname.to_sym]
        end

        state_delta = {}
        eval_bindings(Array(method['body']), env, state_delta, anf)

        current_state.merge(state_delta)
      end

      # Walk a list of ANF bindings, updating env with each result.
      #
      # @param bindings    [Array<Hash>] list of { name:, value: } binding nodes
      # @param env         [Hash]        current name → value environment (mutated in place)
      # @param state_delta [Hash]        accumulated state mutations (mutated in place)
      # @param anf         [Hash, nil]   full ANF IR (for method lookup)
      def eval_bindings(bindings, env, state_delta, anf = nil)
        bindings.each do |binding|
          val = eval_value(binding['value'], env, state_delta, anf)
          env[binding['name']] = val
        end
      end

      # Evaluate a single ANF value node, dispatching on its kind.
      #
      # @param value       [Hash]
      # @param env         [Hash]
      # @param state_delta [Hash]
      # @param anf         [Hash, nil]
      # @return [Object]
      # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
      def eval_value(value, env, state_delta, anf = nil)
        kind = value['kind'].to_s

        case kind
        when 'load_param', 'load_prop'
          env[value['name']]

        when 'load_const'
          v = value['value']
          # Handle @ref: aliases — resolve to the named env variable.
          v.is_a?(String) && v.start_with?('@ref:') ? env[v[5..]] : v

        when 'bin_op'
          eval_bin_op(
            value['op'],
            env[value['left']],
            env[value['right']],
            value['result_type']
          )

        when 'unary_op'
          eval_unary_op(
            value['op'],
            env[value['operand']],
            value['result_type']
          )

        when 'call'
          call_args = Array(value['args']).map { |a| env[a] }
          eval_call(value['func'], call_args)

        when 'method_call'
          call_args = Array(value['args']).map { |a| env[a] }
          eval_method_call(env[value['object']], value['method'], call_args, env, state_delta, anf)

        when 'if'
          cond   = env[value['cond']]
          branch = is_truthy(cond) ? value['then'] : value['else']
          child_env = env.dup
          eval_bindings(Array(branch), child_env, state_delta, anf)
          env.merge!(child_env)
          branch && !branch.empty? ? child_env[branch.last['name']] : nil

        when 'loop'
          count    = (value['count'] || 0).to_i
          if count > MAX_LOOP_ITERATIONS
            raise "ANF interpreter: loop count #{count} exceeds maximum of #{MAX_LOOP_ITERATIONS}"
          end

          body     = Array(value['body'])
          iter_var = value['iterVar'].to_s
          last_val = nil
          count.times do |i|
            env[iter_var] = i
            loop_env = env.dup
            eval_bindings(body, loop_env, state_delta, anf)
            env.merge!(loop_env)
            last_val = body.empty? ? nil : loop_env[body.last['name']]
          end
          last_val

        when 'assert'
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
          nil

        when 'check_preimage', 'deserialize_state', 'get_state_script', 'add_raw_output'
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
        when '&'  then l & r
        when '|'  then l | r
        when '^'  then l ^ r
        when '<<' then l << r
        when '>>' then l >> r
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
        when '~'      then ~val
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
        case func
        # Mock crypto — always return true in simulation.
        when 'checkSig', 'checkMultiSig', 'checkPreimage'
          true

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

        # Preimage intrinsics — return dummy values in simulation.
        when 'extractOutputHash', 'extractAmount'
          '00' * 32

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
      # @param _obj        [Object]      receiver (unused — all calls are this-calls)
      # @param method_name [String, nil]
      # @param args        [Array]
      # @param caller_env  [Hash, nil]
      # @param state_delta [Hash, nil]
      # @param anf         [Hash, nil]
      # @return [Object]
      def eval_method_call(_obj, method_name, args, caller_env = nil, state_delta = nil, anf = nil)
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
        eval_bindings(body, new_env, child_delta, anf)

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
      # --- Divergence from on-chain Bitcoin Script semantics ---
      #
      # Bitcoin Script treats a ByteString as falsy if it is empty OR if it
      # consists entirely of zero bytes (e.g. "00", "0000", "80" — the negative
      # zero encoding). In this interpreter, ByteStrings are represented as
      # hex-encoded Ruby Strings. The string "00" is non-empty and does not
      # match the special-cased values ('', '0', 'false'), so it evaluates as
      # TRUTHY here even though the single zero byte 0x00 is FALSY on-chain.
      #
      # Consequence: simulation may diverge from on-chain behavior for contracts
      # whose control flow depends on zero-valued ByteString conditions (e.g. a
      # branch on the result of num2bin(0, 1) == "00"). Numeric zero (Integer 0)
      # is handled correctly. This divergence affects only hex-encoded zero-byte
      # strings passed through the 'if' or boolean operator paths.
      def is_truthy(v) # rubocop:disable Naming/PredicateName
        case v
        when TrueClass  then true
        when FalseClass then false
        when Integer    then v != 0
        when Float      then v != 0.0
        when String     then v != '' && v != '0' && v != 'false'
        else false
        end
      end

      # ---------------------------------------------------------------------------
      # Byte encoding helpers
      # ---------------------------------------------------------------------------

      # Convert an integer to a little-endian sign-magnitude hex string.
      #
      # This matches Bitcoin Script's num2bin semantics: the sign bit occupies
      # the MSB of the last byte, and the value is padded (or truncated) to the
      # requested byte length.
      #
      # @param n        [Integer]
      # @param byte_len [Integer]
      # @return [String] hex-encoded bytes (2 * byte_len characters)
      def num2bin_hex(n, byte_len)
        return '00' * byte_len if n == 0

        negative = n < 0
        abs_n    = n.abs

        result_bytes = []
        tmp = abs_n
        while tmp > 0
          result_bytes << (tmp & 0xff)
          tmp >>= 8
        end

        # Encode sign bit into the last byte, adding an extra byte if needed.
        if negative
          if (result_bytes.last & 0x80) == 0
            result_bytes[-1] |= 0x80
          else
            result_bytes << 0x80
          end
        else
          result_bytes << 0x00 if (result_bytes.last & 0x80) != 0
        end

        # Pad to requested length, then truncate.
        result_bytes << 0x00 while result_bytes.length < byte_len
        result_bytes = result_bytes[0, byte_len]

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

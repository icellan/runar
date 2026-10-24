# frozen_string_literal: true

# N-069 -- presence and JSON type of the ANF IR's required fields.
#
# Checked on the raw JSON.parse document BEFORE anf_program_from_hash reads it.
# That reader defaulted a missing list to empty, so a public method with no
# `body` loaded with zero bindings and `--ir --hex` exited 0 printing an EMPTY
# locking script -- anyone-can-spend. `params: {}` was accepted too, and
# `body: "x"` died as "undefined method 'map' for an instance of String".
#
# The required set is anf-ir.schema.json's `required` keys, minus the ones
# every loader defaults for older payloads (loop start/step, add_output
# preimage). The diagnostics are shared verbatim with the other six tiers
# (Java's F-084 loader is the origin), pinned by
# conformance/negatives/ir-required-fields.test.ts:
#
#   IR validation: required field <path> is missing
#   IR validation: <path> must be <a type>, got <json type>

module RunarCompiler
  module IR
    module RequiredFields
      module_function

      def json_type(v)
        case v
        when nil then "null"
        when String then "string"
        when true, false then "boolean"
        when Array then "array"
        when Hash then "object"
        else "number"
        end
      end

      def field_path(path, key)
        path.empty? ? key : "#{path}.#{key}"
      end

      def malformed(path, expected, got)
        ArgumentError.new("IR validation: #{path} must be #{expected}, got #{json_type(got)}")
      end

      # Absence and a JSON null are both "missing".
      def req(obj, key, path)
        v = obj[key]
        raise ArgumentError, "IR validation: required field #{field_path(path, key)} is missing" if v.nil?

        v
      end

      def req_str(obj, path, *keys)
        keys.each do |key|
          v = req(obj, key, path)
          raise malformed(field_path(path, key), "a string", v) unless v.is_a?(String)
        end
      end

      def req_bool(obj, key, path)
        v = req(obj, key, path)
        raise malformed(field_path(path, key), "a boolean", v) unless [true, false].include?(v)
      end

      def req_list(obj, key, path)
        v = req(obj, key, path)
        raise malformed(field_path(path, key), "an array", v) unless v.is_a?(Array)

        v
      end

      def as_obj(v, path)
        raise malformed(path, "an object", v) unless v.is_a?(Hash)

        v
      end

      def req_str_list(obj, key, path)
        lp = field_path(path, key)
        req_list(obj, key, path).each_with_index do |e, i|
          raise malformed("#{lp}[#{i}]", "a string", e) unless e.is_a?(String)
        end
      end

      def check_bindings(obj, key, path)
        lp = field_path(path, key)
        req_list(obj, key, path).each_with_index do |b, i|
          bp = "#{lp}[#{i}]"
          binding = as_obj(b, bp)
          req_str(binding, bp, "name")
          check_value(as_obj(binding["value"], "#{bp}.value"), "#{bp}.value")
        end
      end

      # N-208: an OPTIONAL string field. Absent or JSON null is legal; a
      # present value of any other type is refused rather than silently
      # read as the field's "not set" behaviour (see the three callers
      # below).
      def opt_str(obj, key, path)
        v = obj[key]
        return if v.nil?
        raise malformed(field_path(path, key), "a string", v) unless v.is_a?(String)
      end

      # N-208: an OPTIONAL boolean field, same absent/null rule as +opt_str+.
      def opt_bool(obj, key, path)
        v = obj[key]
        return if v.nil?
        raise malformed(field_path(path, key), "a boolean", v) unless [true, false].include?(v)
      end

      def check_value(v, path)
        req_str(v, path, "kind")
        case v["kind"]
        when "load_param", "load_prop" then req_str(v, path, "name")
        when "bin_op"
          req_str(v, path, "op", "left", "right")
          # N-208: a non-string `result_type` (e.g. a number) used to fall
          # through the same `d["result_type"]` as a genuinely absent
          # field, silently discarding the "bytes" hint and lowering the
          # comparison as numeric instead of byte-equality -- a different
          # script with no diagnostic.
          opt_str(v, "result_type", path)
        when "unary_op" then req_str(v, path, "op", "operand")
        when "call"
          req_str(v, path, "func")
          req_str_list(v, "args", path)
        when "method_call"
          req_str(v, path, "object", "method")
          req_str_list(v, "args", path)
        when "if"
          req_str(v, path, "cond")
          check_bindings(v, "then", path)
          check_bindings(v, "else", path)
          req_str_list(v, "results", path) if v.key?("results")
        when "loop"
          check_bindings(v, "body", path)
          req_str(v, path, "iterVar")
        when "assert"
          req_str(v, path, "value")
          # N-208: a non-bool `isAutoInjectedStateCheck` (e.g. the string
          # "true") used to compare unequal to `true` and silently become
          # `false` -- the off-chain SDK interpreters that skip THIS assert
          # based on the marker would then stop skipping it, with no
          # diagnostic.
          opt_bool(v, "isAutoInjectedStateCheck", path)
        when "update_prop" then req_str(v, path, "name", "value")
        when "check_preimage", "deserialize_state" then req_str(v, path, "preimage")
        when "add_output"
          req_str(v, path, "satoshis")
          req_str_list(v, "stateValues", path)
          # N-208: `preimage` is deliberately NOT required here (see the
          # module comment above -- it is one of the fields every loader
          # defaults for older payloads), but a PRESENT value of the wrong
          # type used to be accepted unchecked and fed into ref-collection,
          # where a non-string ref can never match a real binding name.
          opt_str(v, "preimage", path)
        when "add_raw_output", "add_data_output" then req_str(v, path, "satoshis", "scriptBytes")
        when "array_literal" then req_str_list(v, "elements", path)
        end
        # load_const, get_state_script, raw_script: value-level rules check
        # their fields. Unknown kinds are refused by validate_ir.
      end

      # F-038 / F-065: optional keys the artifact copies into the fields the SDK
      # signs by. Absent or null is legal (IR written before they existed); a
      # present value must be one the source path can produce. Shared verbatim
      # with the other six tiers.
      PARENT_CLASSES = %w[SmartContract StatefulSmartContract UnsafeSmartContract].freeze
      SIGHASH_TYPES = [0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3].freeze

      def opt_parent_class(obj)
        v = obj["parentClass"]
        return if v.nil?
        raise malformed("parentClass", "a string", v) unless v.is_a?(String)
        return if PARENT_CLASSES.include?(v)

        raise ArgumentError, "IR validation: parentClass must be one of #{PARENT_CLASSES.join(', ')}, got #{v}"
      end

      def opt_sighash_type(obj, path)
        v = obj["sigHashType"]
        return if v.nil?
        lp = field_path(path, "sigHashType")
        raise malformed(lp, "an integer", v) unless v.is_a?(Numeric)
        return if SIGHASH_TYPES.include?(v)

        raise ArgumentError, "IR validation: #{lp} must be one of #{SIGHASH_TYPES.join(', ')}, got #{v}"
      end

      # N-059 / F-102 (F-068 in Go): a check_preimage binding's optional
      # sighashFlag, at every nesting depth. Codegen appends `sighashFlag & 0xff`
      # to the OP_PUSH_TX binding, so an out-of-set value was truncated to a byte
      # no BSV spend can satisfy (999999 -> 0x3F, FORKID clear) and an explicit 0
      # emitted a 0x00 byte. Absent (or null) means the default ALL|FORKID. In a
      # public method the flag must also equal the method's sigHashType (default
      # 0x41): the artifact tells the SDK to sign under sigHashType, the script
      # derives its sighash under the flag, and a divergence is unspendable. Both
      # diagnostics are shared verbatim with the other six tiers.
      SIGHASH_DEFAULT = 0x41

      def check_sighash_flags(obj, key, path, method, is_public, declared)
        lp = field_path(path, key)
        obj[key].each_with_index do |binding, i|
          vp = "#{lp}[#{i}].value"
          v = binding["value"]
          case v["kind"]
          when "if"
            check_sighash_flags(v, "then", vp, method, is_public, declared)
            check_sighash_flags(v, "else", vp, method, is_public, declared)
          when "loop"
            check_sighash_flags(v, "body", vp, method, is_public, declared)
          when "check_preimage"
            flag = v["sighashFlag"]
            if flag.nil?
              flag = SIGHASH_DEFAULT
            elsif !flag.is_a?(Numeric)
              raise malformed(field_path(vp, "sighashFlag"), "an integer", flag)
            elsif !SIGHASH_TYPES.include?(flag)
              raise ArgumentError,
                    "IR validation: method #{method} binding #{binding['name']} check_preimage has " \
                    "sighashFlag #{flag}; sighashFlag must be one of {0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3} " \
                    "(ALL/NONE/SINGLE with FORKID, optionally ANYONECANPAY). Any other value is " \
                    "truncated to a sighash byte no BSV spend can satisfy."
            end
            if is_public && flag != declared
              raise ArgumentError,
                    "IR validation: method #{method} binding #{binding['name']} check_preimage has " \
                    "sighashFlag #{flag.to_i} but the method declares sigHashType #{declared}; a public " \
                    "method's check_preimage must bind the sighash type its ABI declares, or the SDK " \
                    "signs a preimage the script rejects."
            end
          end
        end
      end

      # Raise ArgumentError on the first required field that is missing or mistyped.
      def assert!(root)
        program = as_obj(root, "the IR document")
        req_str(program, "", "contractName")
        opt_parent_class(program)
        req_list(program, "properties", "").each_with_index do |p, i|
          pp = "properties[#{i}]"
          prop = as_obj(p, pp)
          req_str(prop, pp, "name", "type")
          req_bool(prop, "readonly", pp)
        end
        req_list(program, "methods", "").each_with_index do |m, i|
          mp = "methods[#{i}]"
          method = as_obj(m, mp)
          req_str(method, mp, "name")
          req_bool(method, "isPublic", mp)
          opt_sighash_type(method, mp)
          req_list(method, "params", mp).each_with_index do |p, j|
            pp = "#{mp}.params[#{j}]"
            req_str(as_obj(p, pp), pp, "name", "type")
          end
          check_bindings(method, "body", mp)
          declared = method["sigHashType"].nil? ? SIGHASH_DEFAULT : method["sigHashType"].to_i
          check_sighash_flags(method, "body", mp, method["name"], method["isPublic"], declared)
        end
        assert_identifiers!(program)
      end

      # N-207: the declared identifiers are non-empty, and a method's parameter
      # names are distinct. Runs after the type walk above, so every field read
      # here is a string. "" is a string, so N-069 alone let an empty name
      # through; and duplicate param names alias ONE stack slot (every
      # load_param resolves to the last declared one, so assert(p0 === p1) over
      # two params of the same name compiled to an always-true script). Shared
      # verbatim with the other six tiers, pinned by
      # conformance/negatives/ir-identifiers.test.ts:
      #
      #   IR validation: <path> must be a non-empty string
      #   IR validation: <path>.name '<name>' duplicates <earlier path>.name
      def non_empty(obj, path, *keys)
        keys.each do |key|
          raise ArgumentError, "IR validation: #{field_path(path, key)} must be a non-empty string" if obj[key] == ""
        end
      end

      def assert_identifiers!(program)
        non_empty(program, "", "contractName")
        program["properties"].each_with_index do |prop, i|
          non_empty(prop, "properties[#{i}]", "name", "type")
        end
        program["methods"].each_with_index do |method, i|
          mp = "methods[#{i}]"
          non_empty(method, mp, "name")
          seen = {}
          method["params"].each_with_index do |param, j|
            pp = "#{mp}.params[#{j}]"
            non_empty(param, pp, "name", "type")
            name = param["name"]
            if seen.key?(name)
              raise ArgumentError, "IR validation: #{pp}.name '#{name}' duplicates #{mp}.params[#{seen[name]}].name"
            end
            seen[name] = j
          end
        end
      end
    end
  end
end

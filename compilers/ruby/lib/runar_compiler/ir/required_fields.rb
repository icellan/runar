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

      def check_value(v, path)
        req_str(v, path, "kind")
        case v["kind"]
        when "load_param", "load_prop" then req_str(v, path, "name")
        when "bin_op" then req_str(v, path, "op", "left", "right")
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
        when "assert" then req_str(v, path, "value")
        when "update_prop" then req_str(v, path, "name", "value")
        when "check_preimage", "deserialize_state" then req_str(v, path, "preimage")
        when "add_output"
          req_str(v, path, "satoshis")
          req_str_list(v, "stateValues", path)
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
        end
      end
    end
  end
end

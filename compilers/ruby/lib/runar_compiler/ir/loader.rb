# frozen_string_literal: true

# ANF IR loader and validator for the Runar compiler.
#
# Direct port of compilers/python/runar_compiler/ir/loader.py. Provides
# functions to load ANF IR from JSON (file path or string), validate the
# structure, and decode typed constant values.

require "json"
require "set"
require_relative "types"

module RunarCompiler
  module IR
    # Maximum number of loop iterations allowed in a single loop binding.
    # Prevents resource exhaustion from malicious or accidental extremely large
    # loop counts during loop unrolling.
    MAX_LOOP_COUNT = 10_000

    # Set of all valid ANF value kinds.
    KNOWN_KINDS = Set.new(%w[
      load_param
      load_prop
      load_const
      bin_op
      unary_op
      call
      method_call
      if
      loop
      assert
      update_prop
      get_state_script
      check_preimage
      deserialize_state
      add_output
      add_raw_output
      add_data_output
      array_literal
    ]).freeze

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    # Load an ANF IR program from a JSON string.
    #
    # Parses the JSON, decodes typed constant values, and validates the
    # structure. Raises +ArgumentError+ on any error.
    def self.load_ir(source)
      begin
        d = JSON.parse(source)
      rescue JSON::ParserError => e
        raise ArgumentError, "invalid IR JSON: #{e.message}"
      end

      program = anf_program_from_hash(d)

      # Decode typed constant values from raw JSON
      begin
        decode_constants(program)
      rescue ArgumentError => e
        raise ArgumentError, "decoding constants: #{e.message}"
      end

      errors = validate_ir(program)
      unless errors.empty?
        raise ArgumentError, "IR validation: #{errors[0]}"
      end

      program
    end

    # Load an ANF IR program from a JSON file on disk.
    #
    # Convenience wrapper around +load_ir+ that reads the file first.
    def self.load_ir_from_file(path)
      begin
        data = File.read(path, encoding: "utf-8")
      rescue SystemCallError => e
        raise ArgumentError, "reading IR file: #{e.message}"
      end

      load_ir(data)
    end

    # -------------------------------------------------------------------
    # Validation
    # -------------------------------------------------------------------

    # Validate the structure of a parsed ANF program.
    #
    # Returns an array of error strings (empty if valid).
    def self.validate_ir(program)
      errors = []

      if program.contract_name.nil? || program.contract_name.empty?
        errors << "contractName is required"
      end

      program.methods.each_with_index do |m, i|
        if m.name.nil? || m.name.empty?
          errors << "method[#{i}] has empty name"
        end

        m.params.each_with_index do |param, j|
          if param.name.nil? || param.name.empty?
            errors << "method #{m.name} param[#{j}] has empty name"
          end
          if param.type.nil? || param.type.empty?
            errors << "method #{m.name} param #{param.name} has empty type"
          end
        end

        errors.concat(_validate_bindings(m.body, m.name))
      end

      program.properties.each_with_index do |prop, i|
        if prop.name.nil? || prop.name.empty?
          errors << "property[#{i}] has empty name"
        end
        if prop.type.nil? || prop.type.empty?
          errors << "property #{prop.name} has empty type"
        end
      end

      errors
    end

    # Validate a list of ANF bindings, including nested ones.
    def self._validate_bindings(bindings, method_name)
      errors = []

      bindings.each_with_index do |binding, i|
        if binding.name.nil? || binding.name.empty?
          errors << "method #{method_name} binding[#{i}] has empty name"
        end

        kind = binding.value.kind
        if kind.nil? || kind.empty?
          errors << "method #{method_name} binding #{binding.name} has empty kind"
          next
        end

        unless KNOWN_KINDS.include?(kind)
          errors << "method #{method_name} binding #{binding.name} " \
                    "has unknown kind #{kind.inspect}"
        end

        # Validate nested bindings
        if kind == "if"
          if binding.value.then
            errors.concat(_validate_bindings(binding.value.then, method_name))
          end
          if binding.value.else_
            errors.concat(_validate_bindings(binding.value.else_, method_name))
          end
        end

        if kind == "loop"
          count = binding.value.count || 0
          if count < 0
            errors << "method #{method_name} binding #{binding.name} " \
                      "has negative loop count #{count}"
          end
          if count > MAX_LOOP_COUNT
            errors << "method #{method_name} binding #{binding.name} " \
                      "has loop count #{count} exceeding maximum #{MAX_LOOP_COUNT}"
          end
          if binding.value.body
            errors.concat(_validate_bindings(binding.value.body, method_name))
          end
        end
      end

      errors
    end
    private_class_method :_validate_bindings
  end
end

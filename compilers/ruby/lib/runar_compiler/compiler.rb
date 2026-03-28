# frozen_string_literal: true

# Main compiler pipeline orchestrator.
#
# Reads source files or ANF IR JSON, runs the compilation pipeline, and produces
# a Runar artifact. Direct port of compilers/python/runar_compiler/compiler.py.

require "json"
require "time"

require_relative "ir/types"

module RunarCompiler
  # -------------------------------------------------------------------------
  # Artifact types -- mirrors the TypeScript RunarArtifact schema
  # -------------------------------------------------------------------------

  ABIParam = Struct.new(:name, :type, keyword_init: true) do
    def initialize(name: "", type: "")
      super
    end
  end

  ABIConstructor = Struct.new(:params, keyword_init: true) do
    def initialize(params: [])
      super
    end
  end

  ABIMethod = Struct.new(:name, :params, :is_public, :is_terminal, keyword_init: true) do
    def initialize(name: "", params: [], is_public: false, is_terminal: nil)
      super
    end
  end

  ABI = Struct.new(:constructor, :methods, keyword_init: true) do
    def initialize(constructor: ABIConstructor.new, methods: [])
      super
    end
  end

  StateField = Struct.new(:name, :type, :index, :initial_value, keyword_init: true) do
    def initialize(name: "", type: "", index: 0, initial_value: nil)
      super
    end
  end

  ConstructorSlot = Struct.new(:param_index, :byte_offset, keyword_init: true) do
    def initialize(param_index: 0, byte_offset: 0)
      super
    end
  end

  Artifact = Struct.new(
    :version,
    :compiler_version,
    :contract_name,
    :abi,
    :script,
    :asm,
    :source_map,
    :ir,
    :state_fields,
    :constructor_slots,
    :code_separator_index,
    :code_separator_indices,
    :build_timestamp,
    :anf,
    keyword_init: true
  ) do
    def initialize(
      version: "",
      compiler_version: "",
      contract_name: "",
      abi: ABI.new,
      script: "",
      asm: "",
      source_map: nil,
      ir: nil,
      state_fields: [],
      constructor_slots: [],
      code_separator_index: nil,
      code_separator_indices: nil,
      build_timestamp: "",
      anf: nil
    )
      super
    end
  end

  SCHEMA_VERSION = "runar-v0.4.4"
  COMPILER_VERSION = "0.4.4-ruby"

  # -------------------------------------------------------------------------
  # CompilationError
  # -------------------------------------------------------------------------

  class CompilationError < StandardError; end

  # -------------------------------------------------------------------------
  # Frontend stub imports (filled in as parsers are ported)
  # -------------------------------------------------------------------------

  # Dispatch to the correct parser based on file extension.
  #
  # Returns a ParseResult-like object (from the frontend package).
  def self._parse_source(source, file_name)
    lower = file_name.downcase
    if lower.end_with?(".runar.py")
      require_relative "frontend/parser_python"
      Frontend.parse_python(source, file_name)
    elsif lower.end_with?(".runar.ts")
      require_relative "frontend/parser_ts"
      Frontend.parse_ts(source, file_name)
    elsif lower.end_with?(".runar.sol")
      require_relative "frontend/parser_sol"
      Frontend.parse_sol(source, file_name)
    elsif lower.end_with?(".runar.move")
      require_relative "frontend/parser_move"
      Frontend.parse_move(source, file_name)
    elsif lower.end_with?(".runar.go")
      require_relative "frontend/parser_go"
      Frontend.parse_go(source, file_name)
    elsif lower.end_with?(".runar.rs")
      require_relative "frontend/parser_rust"
      Frontend.parse_rust(source, file_name)
    elsif lower.end_with?(".runar.rb")
      require_relative "frontend/parser_ruby"
      Frontend.parse_ruby(source, file_name)
    else
      raise ArgumentError,
            "Unsupported source format: #{file_name}. " \
            "Expected .runar.ts, .runar.sol, .runar.move, .runar.go, .runar.rs, .runar.py, or .runar.rb"
    end
  end
  private_class_method :_parse_source

  # Run validation on a parsed ContractNode.
  def self._validate(contract)
    require_relative "frontend/validator"
    Frontend.validate(contract)
  end
  private_class_method :_validate

  # Run type checking on a parsed ContractNode.
  def self._type_check(contract)
    require_relative "frontend/typecheck"
    Frontend.type_check(contract)
  end
  private_class_method :_type_check

  # Lower a ContractNode to ANF IR.
  def self._lower_to_anf(contract)
    require_relative "frontend/anf_lower"
    Frontend.lower_to_anf(contract)
  end
  private_class_method :_lower_to_anf

  # -------------------------------------------------------------------------
  # Backend stub imports
  # -------------------------------------------------------------------------

  # Constant folding: evaluate compile-time-known expressions (Pass 4.25).
  def self._fold_constants(program)
    require_relative "frontend/constant_fold"
    Frontend::ConstantFold.fold_constants(program)
  end
  private_class_method :_fold_constants

  # Optimize EC operations in ANF IR (Pass 4.5).
  def self._optimize_ec(program)
    require_relative "frontend/anf_optimize"
    Frontend::ANFOptimize.optimize_ec(program)
  end
  private_class_method :_optimize_ec

  # Stack lowering: ANF -> Stack IR.
  def self._lower_to_stack(program)
    require_relative "codegen/stack"
    Codegen.lower_to_stack(program)
  end
  private_class_method :_lower_to_stack

  # Peephole optimize a list of StackOps.
  def self._optimize_stack_ops(ops)
    require_relative "codegen/optimizer"
    Codegen.optimize_stack_ops(ops)
  end
  private_class_method :_optimize_stack_ops

  # Emit Bitcoin Script from Stack IR.
  def self._emit(stack_methods)
    require_relative "codegen/emit"
    Codegen.emit(stack_methods)
  end
  private_class_method :_emit

  # Load ANF IR from a JSON file.
  def self._load_ir(path)
    IR.load_ir_from_file(path)
  end
  private_class_method :_load_ir

  # Load ANF IR from raw JSON string/bytes.
  def self._load_ir_from_bytes(data)
    str = data.is_a?(String) ? data : data.encode("utf-8")
    IR.load_ir(str)
  end
  private_class_method :_load_ir_from_bytes

  # -------------------------------------------------------------------------
  # Compilation pipeline
  # -------------------------------------------------------------------------

  # Bake constructor arg values into ANF property initial_values.
  def self._apply_constructor_args(program, args)
    return if args.nil? || args.empty?

    program.properties.each do |prop|
      if args.key?(prop.name)
        prop.initial_value = args[prop.name]
      end
    end
  end
  private_class_method :_apply_constructor_args

  # Read an ANF IR JSON file and compile it to a Runar artifact.
  #
  # @param ir_path [String] path to ANF IR JSON file
  # @param disable_constant_folding [Boolean] skip constant folding pass
  # @return [Artifact]
  def self.compile_from_ir(ir_path, disable_constant_folding: false)
    program = _load_ir(ir_path)
    compile_from_program(program, disable_constant_folding: disable_constant_folding)
  end

  # Compile from raw ANF IR JSON bytes.
  #
  # @param data [String] raw ANF IR JSON
  # @param disable_constant_folding [Boolean] skip constant folding pass
  # @return [Artifact]
  def self.compile_from_ir_bytes(data, disable_constant_folding: false)
    program = _load_ir_from_bytes(data)
    compile_from_program(program, disable_constant_folding: disable_constant_folding)
  end

  # Compile a parsed ANF program to a Runar artifact.
  #
  # @param program [IR::ANFProgram] the ANF program
  # @param disable_constant_folding [Boolean] skip constant folding pass
  # @return [Artifact]
  def self.compile_from_program(program, disable_constant_folding: false)
    # Pass 4.25: Constant folding (on by default)
    program = _fold_constants(program) unless disable_constant_folding

    # Pass 4.5: EC optimization
    program = _optimize_ec(program)

    # Pass 5: Stack lowering
    stack_methods = _lower_to_stack(program)

    # Peephole optimization -- runs on Stack IR before emission.
    stack_methods.each do |sm|
      sm[:ops] = _optimize_stack_ops(sm[:ops])
    end

    # Pass 6: Emit
    emit_result = _emit(stack_methods)

    _assemble_artifact(
      program,
      emit_result.script_hex,
      emit_result.script_asm,
      emit_result.constructor_slots,
      emit_result.code_separator_index,
      emit_result.code_separator_indices,
      source_map: emit_result.source_map,
      stack_methods: stack_methods
    )
  end

  # Compile a source file through all passes to a Runar artifact.
  #
  # Supports .runar.ts, .runar.sol, .runar.move, .runar.go, .runar.rs,
  # .runar.py, and .runar.rb extensions (dispatched by file extension).
  #
  # @param source_path [String] path to the source file
  # @param disable_constant_folding [Boolean] skip constant folding pass
  # @param constructor_args [Hash, nil] constructor argument overrides
  # @return [Artifact]
  def self.compile_from_source(source_path, disable_constant_folding: false, constructor_args: nil)
    source = _read_file(source_path)

    # Pass 1: Parse
    parse_result = _parse_source(source, source_path)
    if parse_result.errors.any?
      raise CompilationError, "parse errors:\n  #{parse_result.error_strings.join("\n  ")}"
    end
    if parse_result.contract.nil?
      raise CompilationError, "no contract found in #{source_path}"
    end

    # Pass 2: Validate
    valid_result = _validate(parse_result.contract)
    if valid_result.errors.any?
      raise CompilationError, "validation errors:\n  #{valid_result.error_strings.join("\n  ")}"
    end

    # Pass 3: Type check
    tc_result = _type_check(parse_result.contract)
    if tc_result.errors.any?
      raise CompilationError, "type check errors:\n  #{tc_result.error_strings.join("\n  ")}"
    end

    # Pass 4: ANF lowering
    program = _lower_to_anf(parse_result.contract)

    # Bake constructor args into ANF properties.
    _apply_constructor_args(program, constructor_args)

    # Feed into existing compilation pipeline (passes 4.25-6)
    compile_from_program(program, disable_constant_folding: disable_constant_folding)
  end

  # Run passes 1-4 on a source file and return the ANF program.
  #
  # @param source_path [String] path to the source file
  # @param disable_constant_folding [Boolean] skip constant folding pass
  # @param constructor_args [Hash, nil] constructor argument overrides
  # @return [IR::ANFProgram]
  def self.compile_source_to_ir(source_path, disable_constant_folding: false, constructor_args: nil)
    source = _read_file(source_path)

    parse_result = _parse_source(source, source_path)
    if parse_result.errors.any?
      raise CompilationError, "parse errors:\n  #{parse_result.error_strings.join("\n  ")}"
    end
    if parse_result.contract.nil?
      raise CompilationError, "no contract found in #{source_path}"
    end

    valid_result = _validate(parse_result.contract)
    if valid_result.errors.any?
      raise CompilationError, "validation errors:\n  #{valid_result.error_strings.join("\n  ")}"
    end

    tc_result = _type_check(parse_result.contract)
    if tc_result.errors.any?
      raise CompilationError, "type check errors:\n  #{tc_result.error_strings.join("\n  ")}"
    end

    program = _lower_to_anf(parse_result.contract)

    # Bake constructor args into ANF properties.
    _apply_constructor_args(program, constructor_args)

    # Pass 4.25: Constant folding (on by default)
    program = _fold_constants(program) unless disable_constant_folding

    # Pass 4.5: EC optimization
    program = _optimize_ec(program)

    program
  end

  # -------------------------------------------------------------------------
  # Artifact assembly
  # -------------------------------------------------------------------------

  # Build the final output artifact from the compilation products.
  def self._assemble_artifact(
    program,
    script_hex,
    script_asm,
    constructor_slots,
    code_separator_index = -1,
    code_separator_indices = nil,
    source_map: nil,
    stack_methods: nil,
    include_ir: false,
    include_source_map: true
  )
    # Build ABI
    # Initialized properties are excluded from constructor params -- they
    # get their values from the initializer, not from the caller.
    constructor_params = program.properties
      .select { |prop| prop.initial_value.nil? }
      .map { |prop| ABIParam.new(name: prop.name, type: prop.type) }

    # Build state fields for stateful contracts
    # index = position in constructor args (not sequential among state fields)
    state_fields = []
    program.properties.each_with_index do |prop, i|
      next if prop.readonly

      sf = StateField.new(name: prop.name, type: prop.type, index: i)
      sf.initial_value = prop.initial_value unless prop.initial_value.nil?
      state_fields << sf
    end

    is_stateful = !state_fields.empty?

    # Build method ABIs (exclude constructor -- it's in abi.constructor, not methods)
    methods = []
    program.methods.each do |method|
      next if method.name == "constructor"

      params = method.params.map { |p| ABIParam.new(name: p.name, type: p.type) }

      # For stateful contracts, mark public methods without _changePKH as terminal
      is_terminal = nil
      if is_stateful && method.is_public
        has_change = method.params.any? { |p| p.name == "_changePKH" }
        is_terminal = true unless has_change
      end

      methods << ABIMethod.new(
        name: method.name,
        params: params,
        is_public: method.is_public,
        is_terminal: is_terminal
      )
    end

    cs_index = code_separator_index >= 0 ? code_separator_index : nil
    cs_indices = code_separator_indices && !code_separator_indices.empty? ? code_separator_indices : nil

    # Source map (include if non-empty and requested)
    sm = nil
    sm = source_map if include_source_map && source_map && !source_map.empty?

    # IR snapshots (include only when explicitly requested)
    ir_snapshot = nil
    if include_ir && !stack_methods.nil?
      ir_snapshot = {
        "anf" => program,
        "stack" => stack_methods,
      }
    end

    art = Artifact.new(
      version: SCHEMA_VERSION,
      compiler_version: COMPILER_VERSION,
      contract_name: program.contract_name,
      abi: ABI.new(
        constructor: ABIConstructor.new(params: constructor_params),
        methods: methods
      ),
      script: script_hex,
      asm: script_asm,
      source_map: sm,
      ir: ir_snapshot,
      state_fields: state_fields,
      constructor_slots: constructor_slots,
      code_separator_index: cs_index,
      code_separator_indices: cs_indices,
      build_timestamp: Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    # Always include ANF IR for stateful contracts -- the SDK uses it
    # to auto-compute state transitions without requiring manual newState.
    art.anf = program if is_stateful

    art
  end
  private_class_method :_assemble_artifact

  # -------------------------------------------------------------------------
  # JSON serialization
  # -------------------------------------------------------------------------

  # Serialize an artifact to pretty-printed JSON.
  #
  # @param artifact [Artifact]
  # @return [String] JSON string with camelCase keys
  def self.artifact_to_json(artifact)
    d = {
      "version" => artifact.version,
      "compilerVersion" => artifact.compiler_version,
      "contractName" => artifact.contract_name,
      "abi" => {
        "constructor" => {
          "params" => artifact.abi.constructor.params.map do |p|
            { "name" => p.name, "type" => p.type }
          end,
        },
        "methods" => artifact.abi.methods.map do |m|
          md = {
            "name" => m.name,
            "params" => m.params.map { |p| { "name" => p.name, "type" => p.type } },
            "isPublic" => m.is_public,
          }
          md["isTerminal"] = m.is_terminal unless m.is_terminal.nil?
          md
        end,
      },
      "script" => artifact.script,
      "asm" => artifact.asm,
    }

    if artifact.source_map && !artifact.source_map.empty?
      require_relative "codegen/emit"
      d["sourceMap"] = {
        "mappings" => artifact.source_map.map do |sm|
          if sm.is_a?(Codegen::SourceMapping)
            {
              "opcodeIndex" => sm.opcode_index,
              "sourceFile" => sm.source_file,
              "line" => sm.line,
              "column" => sm.column,
            }
          else
            sm
          end
        end,
      }
    end

    if !artifact.ir.nil?
      ir_dict = {}
      if artifact.ir.key?("anf") && !artifact.ir["anf"].nil?
        ir_dict["anf"] = _serialize_anf_program(artifact.ir["anf"])
      end
      if artifact.ir.key?("stack") && !artifact.ir["stack"].nil?
        ir_dict["stack"] = _serialize_stack_methods(artifact.ir["stack"])
      end
      d["ir"] = ir_dict unless ir_dict.empty?
    end

    if artifact.state_fields && !artifact.state_fields.empty?
      d["stateFields"] = artifact.state_fields.map do |sf|
        sfd = { "name" => sf.name, "type" => sf.type, "index" => sf.index }
        sfd["initialValue"] = sf.initial_value unless sf.initial_value.nil?
        sfd
      end
    end

    if artifact.constructor_slots && !artifact.constructor_slots.empty?
      d["constructorSlots"] = artifact.constructor_slots.map do |cs|
        { "paramIndex" => cs.param_index, "byteOffset" => cs.byte_offset }
      end
    end

    d["codeSeparatorIndex"] = artifact.code_separator_index unless artifact.code_separator_index.nil?
    d["codeSeparatorIndices"] = artifact.code_separator_indices unless artifact.code_separator_indices.nil?

    d["buildTimestamp"] = artifact.build_timestamp

    d["anf"] = _serialize_anf_program(artifact.anf) unless artifact.anf.nil?

    JSON.pretty_generate(d)
  end

  # -------------------------------------------------------------------------
  # Helpers
  # -------------------------------------------------------------------------

  # Serialize an ANFProgram to a JSON-compatible dict (camelCase keys).
  def self._serialize_anf_program(program)
    # Forward-declare ser_binding so ser_value can reference it for nested if/loop bodies
    ser_binding = nil

    ser_value = lambda do |v|
      d = { "kind" => v.kind }
      d["name"] = v.name unless v.name.nil?
      unless v.raw_value.nil?
        # raw_value is already JSON-ready (string, number, bool)
        d["value"] = if v.raw_value.is_a?(String)
                       begin
                         JSON.parse(v.raw_value)
                       rescue JSON::ParserError
                         v.raw_value
                       end
                     else
                       v.raw_value
                     end
      end
      d["op"] = v.op unless v.op.nil?
      d["left"] = v.left unless v.left.nil?
      d["right"] = v.right unless v.right.nil?
      d["result_type"] = v.result_type unless v.result_type.nil?
      d["operand"] = v.operand unless v.operand.nil?
      d["func"] = v.func unless v.func.nil?
      d["args"] = v.args unless v.args.nil?
      d["object"] = v.object unless v.object.nil?
      d["method"] = v.method unless v.method.nil?
      d["cond"] = v.cond unless v.cond.nil?
      d["then"] = v.then.map { |b| ser_binding.call(b) } unless v.then.nil?
      d["else"] = v.else_.map { |b| ser_binding.call(b) } unless v.else_.nil?
      d["count"] = v.count unless v.count.nil?
      d["iterVar"] = v.iter_var unless v.iter_var.nil?
      d["body"] = v.body.map { |b| ser_binding.call(b) } unless v.body.nil?
      d["value"] = v.value_ref unless v.value_ref.nil?
      d["preimage"] = v.preimage unless v.preimage.nil?
      d["satoshis"] = v.satoshis unless v.satoshis.nil?
      d["stateValues"] = v.state_values unless v.state_values.nil?
      d["scriptBytes"] = v.script_bytes unless v.script_bytes.nil?
      d
    end

    ser_binding = lambda do |b|
      { "name" => b.name, "value" => ser_value.call(b.value) }
    end

    {
      "contractName" => program.contract_name,
      "properties" => program.properties.map do |p|
        pd = { "name" => p.name, "type" => p.type, "readonly" => p.readonly }
        pd["initialValue"] = p.initial_value unless p.initial_value.nil?
        pd
      end,
      "methods" => program.methods.map do |m|
        {
          "name" => m.name,
          "params" => m.params.map { |p| { "name" => p.name, "type" => p.type } },
          "body" => m.body.map { |b| ser_binding.call(b) },
          "isPublic" => m.is_public,
        }
      end,
    }
  end
  private_class_method :_serialize_anf_program

  # Serialize a list of StackMethod objects to a JSON-compatible dict.
  def self._serialize_stack_methods(methods)
    ser_push_value = lambda do |v|
      return nil if v.nil?

      if v[:kind] == "bigint"
        { "kind" => "bigint", "value" => v[:big_int] }
      elsif v[:kind] == "bool"
        { "kind" => "bool", "value" => v[:bool_val] }
      elsif v[:kind] == "bytes"
        bytes_val = v[:bytes_val] || "".b
        hex = bytes_val.is_a?(String) ? bytes_val.unpack1("H*") : ""
        { "kind" => "bytes", "value" => hex }
      else
        { "kind" => v[:kind] }
      end
    end

    ser_op = nil
    ser_op = lambda do |op|
      d = { "op" => op[:op] }

      if op[:op] == "push" && !op[:value].nil?
        d["value"] = ser_push_value.call(op[:value])
      end
      if %w[roll pick].include?(op[:op]) && (op[:depth] || 0) != 0
        d["depth"] = op[:depth]
      end
      if op[:op] == "opcode"
        d["code"] = op[:code]
      end
      if op[:op] == "if"
        d["then"] = (op[:then] || []).map { |o| ser_op.call(o) }
        if op[:else_ops] && !op[:else_ops].empty?
          d["else"] = op[:else_ops].map { |o| ser_op.call(o) }
        end
      end
      if op[:op] == "placeholder"
        d["paramIndex"] = op[:param_index]
        d["paramName"] = op[:param_name]
      end
      if !op[:source_loc].nil?
        d["sourceLoc"] = {
          "file" => op[:source_loc][:file],
          "line" => op[:source_loc][:line],
          "column" => op[:source_loc][:column],
        }
      end
      d
    end

    {
      "methods" => methods.map do |m|
        {
          "name" => m[:name],
          "ops" => (m[:ops] || []).map { |op| ser_op.call(op) },
          "maxStackDepth" => m[:max_stack_depth],
        }
      end,
    }
  end
  private_class_method :_serialize_stack_methods

  # Read a file as text.
  def self._read_file(path)
    File.read(path, encoding: "utf-8")
  rescue SystemCallError => e
    raise CompilationError, "reading source file: #{e.message}"
  end
  private_class_method :_read_file
end

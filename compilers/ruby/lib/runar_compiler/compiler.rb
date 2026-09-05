# frozen_string_literal: true

# Main compiler pipeline orchestrator.
#
# Reads source files or ANF IR JSON, runs the compilation pipeline, and produces
# a Runar artifact. Direct port of compilers/python/runar_compiler/compiler.py.

require "json"
require "time"
require "set"

require_relative "ir/types"
require_relative "frontend/sighash_directive"

module RunarCompiler
  # -------------------------------------------------------------------------
  # Artifact types -- mirrors the TypeScript RunarArtifact schema
  # -------------------------------------------------------------------------

  # An ABI parameter.  +fixed_array+, when non-nil, carries the metadata for a
  # parameter that was re-grouped from expanded FixedArray siblings: element
  # type string, length, and the flat list of synthetic scalar names the SDK
  # uses to flatten/unflatten values across the underlying scalar slots.
  ABIParam = Struct.new(:name, :type, :fixed_array, keyword_init: true) do
    def initialize(name: "", type: "", fixed_array: nil)
      super
    end
  end

  ABIConstructor = Struct.new(:params, keyword_init: true) do
    def initialize(params: [])
      super
    end
  end

  ABIMethod = Struct.new(:name, :params, :is_public, :is_terminal, :uses_code_part, :sig_hash_type, keyword_init: true) do
    def initialize(name: "", params: [], is_public: false, is_terminal: nil, uses_code_part: nil, sig_hash_type: nil)
      super
    end
  end

  ABI = Struct.new(:constructor, :methods, keyword_init: true) do
    def initialize(constructor: ABIConstructor.new, methods: [])
      super
    end
  end

  # A stateful contract state field.  +fixed_array+, when non-nil, carries
  # metadata produced by the iterative re-grouper for a state field whose
  # underlying scalars were created by the FixedArray expansion pass.
  #   fixed_array[:element_type]     — element type string (may itself be "FixedArray<...>")
  #   fixed_array[:length]           — N (outer dimension)
  #   fixed_array[:synthetic_names]  — flat leaf names in declaration order
  StateField = Struct.new(:name, :type, :index, :initial_value, :fixed_array, keyword_init: true) do
    def initialize(name: "", type: "", index: 0, initial_value: nil, fixed_array: nil)
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
    :parent_class,
    :abi,
    :script,
    :asm,
    :source_map,
    :ir,
    :state_fields,
    :constructor_slots,
    :code_sep_index_slots,
    :code_separator_index,
    :code_separator_indices,
    :raw_script_spans,
    :build_timestamp,
    :anf,
    keyword_init: true
  ) do
    def initialize(
      version: "",
      compiler_version: "",
      contract_name: "",
      parent_class: "",
      abi: ABI.new,
      script: "",
      asm: "",
      source_map: nil,
      ir: nil,
      state_fields: [],
      constructor_slots: [],
      code_sep_index_slots: [],
      code_separator_index: nil,
      code_separator_indices: nil,
      raw_script_spans: nil,
      build_timestamp: "",
      anf: nil
    )
      super
    end
  end

  SCHEMA_VERSION = "runar-v1.0.0-rc.1"
  COMPILER_VERSION = "1.0.0-rc.1-ruby"

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
    # DoS-bound size guard. Reject oversized source BEFORE any
    # format-specific parser touches the input. Raises
    # InputLimits::SourceSizeExceededError on rejection. BUG-008 follow-up.
    require_relative "frontend/input_limits"
    Frontend::InputLimits.assert_source_bytes_under_limit(source)

    # Fail-closed guard for the author-facing comment directives +@sighash+
    # (#123, per-method sighash type) and +@embedAlways+ (#109, readonly-field
    # DCE opt-out). Both are honored ONLY on the +.runar.ts+ surface (matching
    # the TypeScript reference); on the other 8 formats Ruby's parsers ignore
    # comments and would silently drop the directive, changing signing / DCE
    # semantics, so the guard fails closed there.
    directive_error = _unsupported_directive_error(source, file_name)
    unless directive_error.nil?
      require_relative "frontend/parse_result"
      require_relative "frontend/diagnostic"
      return Frontend::ParseResult.new(errors: [
        Frontend::Diagnostic.new(message: directive_error, severity: Frontend::Severity::ERROR),
      ])
    end

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
    elsif lower.end_with?(".runar.zig")
      require_relative "frontend/parser_zig"
      Frontend.parse_zig(source, file_name)
    elsif lower.end_with?(".runar.java")
      require_relative "frontend/parser_java"
      Frontend.parse_java(source, file_name)
    else
      raise ArgumentError,
            "Unsupported source format: #{file_name}. " \
            "Expected .runar.ts, .runar.sol, .runar.move, .runar.go, .runar.rs, .runar.py, .runar.rb, .runar.zig, or .runar.java"
    end
  end
  private_class_method :_parse_source

  # Detect the first unsupported author-facing comment directive in +source+,
  # or nil when the source is clean. Word-boundary matched (\b) to mirror the
  # TypeScript compiler's +/@sighash\b/+ / +/@embedAlways\b/+ scans so an
  # identifier like +sighashType+ does not trip the guard.
  #
  # The directives are honored ONLY on the +.runar.ts+ surface (matching the
  # TypeScript reference). For +.runar.ts+ the implemented directives are
  # allowed through to the parser; the other 8 formats always fail closed.
  def self._unsupported_directive_error(source, file_name)
    is_ts = file_name.downcase.end_with?(".runar.ts")

    # @sighash (#123) is implemented for the .runar.ts surface; only the other
    # 8 formats fail closed.
    if source =~ /@sighash\b/ && !is_ts
      return "@sighash directive is not supported by the Ruby compiler for " \
             "this format (issue #123); it is honored only on the .runar.ts surface"
    end

    # @embedAlways (#109) is implemented for the .runar.ts surface; only the
    # other 8 formats fail closed.
    if source =~ /@embedAlways\b/ && !is_ts
      return "@embedAlways directive is not supported by the Ruby compiler for " \
             "this format (issue #109); it is honored only on the .runar.ts surface"
    end

    nil
  end
  private_class_method :_unsupported_directive_error

  # Run validation on a parsed ContractNode.
  def self._validate(contract)
    require_relative "frontend/validator"
    Frontend.validate(contract)
  end
  private_class_method :_validate

  # Public parse-only entry point used by the conformance runner's
  # +--parser-only+ universal-frontend coverage check. Reads the source
  # file, dispatches to the format parser, and runs +Validate+. Raises
  # +CompilationError+ on parse / validate failures; returns +nil+ on
  # success (the caller treats nil as "parser ok").
  def self.parse_and_validate_only(source_path)
    source = File.read(source_path)
    parse_result = _parse_source(source, source_path)
    if parse_result.errors && !parse_result.errors.empty?
      raise CompilationError, "parse errors:\n  " + parse_result.error_strings.join("\n  ")
    end
    if parse_result.contract.nil?
      raise CompilationError, "no contract found in #{source_path}"
    end
    valid = _validate(parse_result.contract)
    if valid.errors && !valid.errors.empty?
      raise CompilationError, "validation errors:\n  " + valid.error_strings.join("\n  ")
    end
    nil
  end

  # Run type checking on a parsed ContractNode.
  def self._type_check(contract)
    require_relative "frontend/typecheck"
    Frontend.type_check(contract)
  end
  private_class_method :_type_check

  # Pass 3b: Expand FixedArray properties into scalar siblings before ANF
  # lowering.  Runs between typecheck and ANF-lower; see
  # +expand_fixed_arrays.rb+ for semantics.
  def self._expand_fixed_arrays(contract)
    require_relative "frontend/expand_fixed_arrays"
    Frontend.expand_fixed_arrays(contract)
  end
  private_class_method :_expand_fixed_arrays

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

  # Dead Code Elimination -- discrete named pass (Pass 4.75).
  # See frontend/dce.rb. Idempotent w.r.t. the EC optimizer's internal DCE;
  # runs as a safety net for any post-EC residual dead bindings and to
  # mirror the standalone DCE pass shape used by the Zig reference compiler.
  def self._eliminate_dead_code(program)
    require_relative "frontend/dce"
    Frontend::DCE.eliminate_dead_code(program)
  end
  private_class_method :_eliminate_dead_code

  # Stack lowering: ANF -> Stack IR.
  def self._lower_to_stack(program, ec_codegen = nil)
    require_relative "codegen/stack"
    Codegen.lower_to_stack(program, ec_codegen)
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
  #
  # When args are provided they are validated before AND after baking so a
  # mistyped or mis-shaped +args+ fails loudly instead of silently baking
  # nothing and emitting OP_0 placeholder scripts that fail opaquely at
  # runtime. Rejects:
  #  (a) a positional array instead of a name-keyed record (Ruby is
  #      dynamically typed, so the natural `[value]` guess must be caught),
  #  (b) keys that match no contract property (typos),
  #  (c) a readonly property referenced by a method body left unbaked after
  #      applying the args (checked on a DCE'd probe so unreferenced
  #      readonlys stay allowed; the constructor's super() call is excluded).
  # The no-args placeholder path (nil / empty record) stays unchecked and
  # byte-identical.
  def self._apply_constructor_args(program, args)
    return if args.nil?
    # An empty *record* is the unchecked no-op placeholder path; an array
    # (even empty) is a shape error handled by check (a) below.
    return if !args.is_a?(Array) && args.empty?

    # (a) Shape / positional-array reject.
    if args.is_a?(Array)
      prop_names = program.properties.map(&:name).join(", ")
      example = program.properties.empty? ? "propName" : program.properties.first.name
      raise CompilationError,
            "constructorArgs must be a record keyed by property name, not a positional array. " \
            "Contract '#{program.contract_name}' properties: [#{prop_names}]. " \
            "Example: { #{example}: <value> }"
    end

    # (b) Unknown-key reject.
    prop_names_list = program.properties.map(&:name)
    args.each_key do |key|
      next if prop_names_list.include?(key)

      raise CompilationError,
            "constructorArgs key '#{key}' does not match any property of contract " \
            "'#{program.contract_name}' (properties: [#{prop_names_list.join(', ')}]). " \
            "Nothing would be baked for this key."
    end

    # Bake values into ANF property initial_values.
    program.properties.each do |prop|
      prop.initial_value = args[prop.name] if args.key?(prop.name)
    end

    # (c) Unbaked-referenced-readonly reject.
    unbaked = _find_unbaked_referenced_readonly(program)
    raise CompilationError, unbaked.join("; ") unless unbaked.empty?
  end
  private_class_method :_apply_constructor_args

  # After baking constructor args, find readonly properties that are
  # REFERENCED by at least one method body but still have no baked
  # initial_value. Such properties would be emitted as OP_0 placeholders,
  # making the compiled script fail opaquely at runtime.
  #
  # @return [Array<String>] error messages (empty when valid)
  def self._find_unbaked_referenced_readonly(program)
    referenced = _collect_referenced_props(program)
    errors = []
    program.properties.each do |prop|
      next unless prop.readonly && prop.initial_value.nil? && referenced.include?(prop.name)

      errors << "readonly property '#{prop.name}' is referenced by a method but has no value " \
                "after baking constructorArgs -- the emitted script would carry an OP_0 " \
                "placeholder that fails at runtime. Provide '#{prop.name}' in constructorArgs " \
                "(or give the property an initializer)."
    end
    errors
  end
  private_class_method :_find_unbaked_referenced_readonly

  # Collect the property names actually referenced by method bodies.
  #
  # The raw ANF may load properties that later prove dead; only after
  # dead-binding elimination do the surviving +load_prop+ nodes reflect real
  # references. DCE mutates +method.body+ in place, so it runs on a throwaway
  # probe whose methods carry duplicated body arrays (the binding objects are
  # only read by DCE, never mutated), leaving the main pipeline untouched.
  #
  # @return [Set<String>]
  def self._collect_referenced_props(program)
    require_relative "frontend/dce"
    probe = IR::ANFProgram.new(
      contract_name: program.contract_name,
      properties: program.properties,
      methods: program.methods.map do |m|
        IR::ANFMethod.new(name: m.name, params: m.params, body: m.body.dup, is_public: m.is_public)
      end,
      parent_class: program.parent_class
    )
    Frontend::DCE.eliminate_dead_code(probe)

    referenced = Set.new
    probe.methods.each do |method|
      # The constructor's super(...) call references every property but is
      # never emitted as script code -- only real method bodies count.
      next if method.name == "constructor"

      _collect_load_prop_refs(method.body, referenced)
    end
    referenced
  end
  private_class_method :_collect_referenced_props

  # Recursively collect +load_prop+ property names from ANF bindings,
  # recursing only through if(then/else) + loop(body).
  def self._collect_load_prop_refs(bindings, out)
    bindings.each do |binding|
      v = binding.value
      case v.kind
      when "load_prop"
        out.add(v.name)
      when "if"
        _collect_load_prop_refs(v.then || [], out)
        _collect_load_prop_refs(v.else_ || [], out)
      when "loop"
        _collect_load_prop_refs(v.body || [], out)
      end
    end
  end
  private_class_method :_collect_load_prop_refs

  # Read an ANF IR JSON file and compile it to a Runar artifact.
  #
  # @param ir_path [String] path to ANF IR JSON file
  # @param disable_constant_folding [Boolean] skip constant folding pass
  # @return [Artifact]
  # Constant folding is a source-pipeline optimization; never re-run it on
  # already-lowered ANF IR. Re-folding pre-lowered IR rewrites bin_ops to
  # constants but leaves the now-dead operand bindings (the fold does no
  # dead-binding elimination), which stack-lowering emits as wasteful push+drop
  # sequences — diverging from the fold-OFF goldens and from the Zig tier, whose
  # compileFromIR never folds IR input. Force folding off here; peephole still folds.
  #
  # `disable_constant_folding` is accepted for signature parity with
  # compile_from_source but is not honoured — the ANF fold is forced OFF for
  # pre-lowered IR input (see the comment above). The EC size flags ARE
  # honoured: they act in stack lowering, downstream of the IR, so the `--ir`
  # path reaches them exactly like `--source`.
  def self.compile_from_ir(ir_path, disable_constant_folding: false,
                           ec_constant_pool: false, ec_reduction_sinking: false,
                           ec_fixed_base_comb: false)
    program = _load_ir(ir_path)
    compile_from_program(program, disable_constant_folding: true,
                         ec_constant_pool: ec_constant_pool,
                         ec_reduction_sinking: ec_reduction_sinking,
                         ec_fixed_base_comb: ec_fixed_base_comb)
  end

  # Compile from raw ANF IR JSON bytes.
  #
  # @param data [String] raw ANF IR JSON
  # @param disable_constant_folding [Boolean] skip constant folding pass
  # @return [Artifact]
  def self.compile_from_ir_bytes(data, disable_constant_folding: false,
                                 ec_constant_pool: false, ec_reduction_sinking: false,
                                 ec_fixed_base_comb: false)
    program = _load_ir_from_bytes(data)
    compile_from_program(program, disable_constant_folding: true,
                         ec_constant_pool: ec_constant_pool,
                         ec_reduction_sinking: ec_reduction_sinking,
                         ec_fixed_base_comb: ec_fixed_base_comb)
  end

  # Compile a parsed ANF program to a Runar artifact.
  #
  # @param program [IR::ANFProgram] the ANF program
  # @param disable_constant_folding [Boolean] skip constant folding pass
  # @return [Artifact]
  # Options handed to the EC / NIST codegen modules.
  #
  # Returns nil -- not an all-false instance -- when nothing is enabled, so
  # those emitters take their untouched default path and the emitted bytes are
  # provably identical to the shipping ones.
  #
  # Cross-tier byte parity for the flags THEMSELVES is gated by
  # conformance/ec-flag-parity/expected.json.
  def self._ec_codegen_options(pool, sinking, comb)
    return nil unless pool || sinking || comb

    require "runar_compiler/codegen/ec"
    Codegen::EC::EcCodegenOptions.new(
      constant_pool: pool, reduction_sinking: sinking, fixed_base_comb: comb
    )
  end
  private_class_method :_ec_codegen_options

  def self.compile_from_program(program, disable_constant_folding: false,
                                ec_constant_pool: false, ec_reduction_sinking: false,
                                ec_fixed_base_comb: false)
    # Pass 4.25: Constant folding (on by default)
    program = _fold_constants(program) unless disable_constant_folding

    # Pass 4.5: EC optimization (delegates internally to frontend/dce.rb
    # for dead-binding cleanup — see Frontend::ANFOptimize.eliminate_dead_bindings).
    program = _optimize_ec(program)

    # Pass 5: Stack lowering
    stack_methods = _lower_to_stack(
      program,
      _ec_codegen_options(ec_constant_pool, ec_reduction_sinking, ec_fixed_base_comb)
    )

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
      code_sep_index_slots: emit_result.code_sep_index_slots,
      source_map: emit_result.source_map,
      raw_script_spans: emit_result.raw_script_spans,
      stack_methods: stack_methods
    )
  end

  # Compile a source file through all passes to a Runar artifact.
  #
  # Supports .runar.ts, .runar.sol, .runar.move, .runar.go, .runar.rs,
  # .runar.py, .runar.rb, and .runar.zig extensions (dispatched by file extension).
  #
  # @param source_path [String] path to the source file
  # @param disable_constant_folding [Boolean] skip constant folding pass
  # @param constructor_args [Hash, nil] constructor argument overrides
  # @return [Artifact]
  def self.compile_from_source(source_path, disable_constant_folding: false, constructor_args: nil,
                               ec_constant_pool: false, ec_reduction_sinking: false,
                               ec_fixed_base_comb: false)
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

    # Pass 3b: Expand FixedArray properties into scalar siblings.
    expand_result = _expand_fixed_arrays(parse_result.contract)
    if expand_result.errors.any?
      raise CompilationError, "fixed-array expansion errors:\n  #{expand_result.error_strings.join("\n  ")}"
    end
    expanded_contract = expand_result.contract

    # Pass 4: ANF lowering
    program = _lower_to_anf(expanded_contract)

    # Bake constructor args into ANF properties.
    _apply_constructor_args(program, constructor_args)

    # Feed into existing compilation pipeline (passes 4.25-6)
    compile_from_program(
      program,
      disable_constant_folding: disable_constant_folding,
      ec_constant_pool: ec_constant_pool,
      ec_reduction_sinking: ec_reduction_sinking,
      ec_fixed_base_comb: ec_fixed_base_comb
    )
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

    # Pass 3b: Expand FixedArray properties before ANF lowering.
    expand_result = _expand_fixed_arrays(parse_result.contract)
    if expand_result.errors.any?
      raise CompilationError, "fixed-array expansion errors:\n  #{expand_result.error_strings.join("\n  ")}"
    end
    expanded_contract = expand_result.contract

    program = _lower_to_anf(expanded_contract)

    # Bake constructor args into ANF properties.
    _apply_constructor_args(program, constructor_args)

    # Pass 4.25: Constant folding (on by default)
    program = _fold_constants(program) unless disable_constant_folding

    # Pass 4.5: EC optimization (delegates internally to frontend/dce.rb
    # for dead-binding cleanup).
    program = _optimize_ec(program)

    program
  end

  # -------------------------------------------------------------------------
  # FixedArray re-grouping
  # -------------------------------------------------------------------------
  #
  # Pass 3b (+expand_fixed_arrays+) expands a property like
  # +board: FixedArray<bigint, 9>+ into 9 scalar siblings +board__0..board__8+.
  # For nested arrays +grid: FixedArray<FixedArray<bigint, 2>, 2>+ it expands
  # into 4 scalar leaves +grid__0__0..grid__1__1+.  The downstream ANF, stack,
  # and emit passes operate purely on those scalars.
  #
  # For the user-facing ABI and state-field list we re-group those synthetic
  # siblings back into a single logical entry tagged +fixed_array+ so the SDK
  # can present the array-shaped API — including nested arrays, which it
  # exposes as nested arrays.
  #
  # Grouping is marker-driven, NOT pattern-driven: every participating entry
  # must carry a +synthetic_array_chain+ attached at expansion time.  A user
  # contract with hand-named +user__0+, +user__1+, +user__2+ properties of the
  # same type will NOT be re-grouped because the marker is missing.
  #
  # The regrouper runs iteratively: each pass collapses one level of the
  # innermost FixedArray (peeling one entry off the end of every chain) and
  # wraps the resulting group's type in one more +FixedArray<...,N>+ layer.
  # Repeat until no entry has any remaining chain.

  # Internal representation of a field going through the regrouping loop.
  # All hash values; no external visibility.
  #   :name           — current user-facing field name
  #   :type           — current type string (already FixedArray<...> once grouped)
  #   :chain          — remaining chain entries, outermost first, innermost at -1
  #   :initial_value  — optional current value (possibly nested array)
  #   :fixed_array    — current grouping metadata hash or nil
  #   :index          — source declaration index (state fields only)
  def self._regroup_one_pass(entries)
    out = []
    changed = false
    i = 0
    while i < entries.length
      entry = entries[i]
      chain = entry[:chain] || []
      if chain.empty?
        out << entry
        i += 1
        next
      end

      marker = chain[-1]
      if marker[:index] != 0
        out << entry
        i += 1
        next
      end

      # Greedily extend the run: every follower must share innermost
      # {base, length}, carry the expected index = k, and match the current
      # type so runs of mixed-type children cannot spuriously collapse.
      run = [entry]
      k = 1
      j = i + 1
      while j < entries.length && k < marker[:length]
        nxt = entries[j]
        nchain = nxt[:chain] || []
        break if nchain.empty?

        m2 = nchain[-1]
        break unless m2[:base] == marker[:base] &&
                     m2[:length] == marker[:length] &&
                     m2[:index] == k &&
                     nxt[:type] == entry[:type]

        run << nxt
        k += 1
        j += 1
      end

      if run.length != marker[:length]
        out << entry
        i += 1
        next
      end

      inner_type = entry[:type]
      grouped_type = "FixedArray<#{inner_type}, #{marker[:length]}>"

      # Flatten synthetic names so the grouped entry's list is the flat
      # leaf list (already-grouped children carry their own flat list).
      synthetic_names = []
      run.each do |e|
        if e[:fixed_array]
          synthetic_names.concat(e[:fixed_array][:synthetic_names])
        else
          synthetic_names << e[:name]
        end
      end

      collapsed_init = nil
      all_have_init = run.all? { |e| !e[:initial_value].nil? }
      collapsed_init = run.map { |e| e[:initial_value] } if all_have_init

      grouped = {
        name: marker[:base],
        type: grouped_type,
        chain: chain[0..-2],
        fixed_array: {
          element_type: inner_type,
          length: marker[:length],
          synthetic_names: synthetic_names
        },
        index: run[0][:index]
      }
      grouped[:initial_value] = collapsed_init unless collapsed_init.nil?

      out << grouped
      i = j
      changed = true
    end
    [out, changed]
  end
  private_class_method :_regroup_one_pass

  # Iteratively regroup synthetic FixedArray runs until no entry has any
  # remaining chain.  Returns the final entries array.
  def self._regroup_synthetic_runs(entries)
    current = entries
    1024.times do
      new_entries, changed = _regroup_one_pass(current)
      current = new_entries
      return current unless changed
    end
    raise "regroup_synthetic_runs: exceeded iteration cap (pathological chain nesting?)"
  end
  private_class_method :_regroup_synthetic_runs

  # Normalise a chain entry which may be keyed with symbols (when coming from
  # the Ruby AST/ANF) or strings (when coming from a JSON-loaded ANF IR).
  def self._normalise_chain(chain)
    return [] if chain.nil? || chain.empty?

    chain.map do |e|
      if e.is_a?(Hash)
        {
          base: e[:base] || e["base"],
          index: e[:index] || e["index"] || 0,
          length: e[:length] || e["length"]
        }
      else
        e
      end
    end
  end
  private_class_method :_normalise_chain

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
    code_sep_index_slots: [],
    source_map: nil,
    raw_script_spans: nil,
    stack_methods: nil,
    include_ir: false,
    include_source_map: true
  )
    # Build ABI
    # Initialized properties are excluded from constructor params -- they
    # get their values from the initializer, not from the caller.
    ctor_entries = []
    program.properties.each do |prop|
      next unless prop.initial_value.nil?

      ctor_entries << {
        name: prop.name,
        type: prop.type,
        chain: _normalise_chain(prop.synthetic_array_chain)
      }
    end
    regrouped_ctor = _regroup_synthetic_runs(ctor_entries)
    constructor_params = regrouped_ctor.map do |e|
      p = ABIParam.new(name: e[:name], type: e[:type])
      if e[:fixed_array]
        p.fixed_array = {
          element_type: e[:fixed_array][:element_type],
          length: e[:fixed_array][:length],
          synthetic_names: e[:fixed_array][:synthetic_names]
        }
      end
      p
    end

    # Build state fields for stateful contracts
    # index = position in constructor args (not sequential among state fields)
    state_entries = []
    program.properties.each_with_index do |prop, i|
      next if prop.readonly

      entry = {
        name: prop.name,
        type: prop.type,
        chain: _normalise_chain(prop.synthetic_array_chain),
        index: i
      }
      entry[:initial_value] = prop.initial_value unless prop.initial_value.nil?
      state_entries << entry
    end
    regrouped_state = _regroup_synthetic_runs(state_entries)
    state_fields = regrouped_state.map do |e|
      sf = StateField.new(name: e[:name], type: e[:type], index: e[:index] || 0)
      sf.initial_value = e[:initial_value] unless e[:initial_value].nil?
      if e[:fixed_array]
        sf.fixed_array = {
          element_type: e[:fixed_array][:element_type],
          length: e[:fixed_array][:length],
          synthetic_names: e[:fixed_array][:synthetic_names]
        }
      end
      sf
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

      # Propagate the authoritative _codePart decision from stack-lowering into
      # the ABI so the SDK supplies _codePart for terminal var-length reads (#100).
      uses_code_part = nil
      sm_match = stack_methods&.find { |sm| sm[:name] == method.name }
      uses_code_part = true if sm_match && sm_match[:uses_code_part]

      # Issue #123: carry a non-default @sighash mode into the ABI so the SDK
      # builds the BIP-143 preimage under the same flags the covenant expects.
      # Omitted for the default (0x41) → existing artifacts are byte-identical.
      sig_hash_type = nil
      if method.is_public && method.respond_to?(:sighash_type) &&
         !method.sighash_type.nil? && method.sighash_type != Frontend::SighashDirective::SIGHASH_DEFAULT
        sig_hash_type = method.sighash_type
      end

      methods << ABIMethod.new(
        name: method.name,
        params: params,
        is_public: method.is_public,
        is_terminal: is_terminal,
        uses_code_part: uses_code_part,
        sig_hash_type: sig_hash_type
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
      # Base class the source contract extends. Authoritative stateful signal
      # for the issue-#42/#44 terminal sighash subscript trim (a
      # StatefulSmartContract with zero mutable fields still needs the trim).
      parent_class: program.parent_class,
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
      code_sep_index_slots: code_sep_index_slots,
      code_separator_index: cs_index,
      code_separator_indices: cs_indices,
      raw_script_spans: (raw_script_spans && !raw_script_spans.empty? ? raw_script_spans : nil),
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
    abi_param_to_hash = lambda do |p|
      h = { "name" => p.name, "type" => p.type }
      if p.respond_to?(:fixed_array) && !p.fixed_array.nil?
        h["fixedArray"] = {
          "elementType" => p.fixed_array[:element_type],
          "length" => p.fixed_array[:length],
          "syntheticNames" => p.fixed_array[:synthetic_names],
        }
      end
      h
    end

    d = {
      "version" => artifact.version,
      "compilerVersion" => artifact.compiler_version,
      "contractName" => artifact.contract_name,
    }
    # parentClass (when present) sits right after contractName, matching the
    # other tiers' artifact field order. Omitted when empty (older fixtures).
    d["parentClass"] = artifact.parent_class if artifact.parent_class && !artifact.parent_class.empty?
    d.merge!({
      "abi" => {
        "constructor" => {
          "params" => artifact.abi.constructor.params.map(&abi_param_to_hash),
        },
        "methods" => artifact.abi.methods.map do |m|
          md = {
            "name" => m.name,
            "params" => m.params.map(&abi_param_to_hash),
            "isPublic" => m.is_public,
          }
          md["isTerminal"] = m.is_terminal unless m.is_terminal.nil?
          md["usesCodePart"] = m.uses_code_part unless m.uses_code_part.nil?
          # Issue #123: BIP-143 sighash type for a non-default @sighash mode.
          md["sigHashType"] = m.sig_hash_type if m.respond_to?(:sig_hash_type) && !m.sig_hash_type.nil?
          md
        end,
      },
      "script" => artifact.script,
      "asm" => artifact.asm,
    })

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
        if sf.respond_to?(:fixed_array) && !sf.fixed_array.nil?
          sfd["fixedArray"] = {
            "elementType" => sf.fixed_array[:element_type],
            "length" => sf.fixed_array[:length],
            "syntheticNames" => sf.fixed_array[:synthetic_names],
          }
        end
        sfd
      end
    end

    if artifact.constructor_slots && !artifact.constructor_slots.empty?
      d["constructorSlots"] = artifact.constructor_slots.map do |cs|
        { "paramIndex" => cs.param_index, "byteOffset" => cs.byte_offset }
      end
    end

    if artifact.code_sep_index_slots && !artifact.code_sep_index_slots.empty?
      d["codeSepIndexSlots"] = artifact.code_sep_index_slots.map do |slot|
        { "byteOffset" => slot.byte_offset, "codeSepIndex" => slot.code_sep_index }
      end
    end

    d["codeSeparatorIndex"] = artifact.code_separator_index unless artifact.code_separator_index.nil?
    d["codeSeparatorIndices"] = artifact.code_separator_indices unless artifact.code_separator_indices.nil?

    if artifact.raw_script_spans && !artifact.raw_script_spans.empty?
      d["rawScriptSpans"] = artifact.raw_script_spans.map do |span|
        {
          "offset" => span.offset,
          "length" => span.length,
          "inArity" => span.in_arity,
          "outArity" => span.out_arity,
        }
      end
    end

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
      d["results"] = v.results unless v.results.nil? || v.results.empty?
      d["count"] = v.count unless v.count.nil?
      d["iterVar"] = v.iter_var unless v.iter_var.nil?
      # Loop start/step (#121). Match the TS reference byte-for-byte: start is
      # emitted as a JS-style "Nn" bigint string, step as a plain integer.
      d["start"] = "#{v.start}n" unless v.start.nil?
      d["step"] = v.step unless v.step.nil?
      d["body"] = v.body.map { |b| ser_binding.call(b) } unless v.body.nil?
      d["value"] = v.value_ref unless v.value_ref.nil?
      d["isAutoInjectedStateCheck"] = true if v.kind == "assert" && v.is_auto_injected_state_check
      d["preimage"] = v.preimage unless v.preimage.nil?
      # Issue #123: a non-default @sighash mode threads the BIP-143 flag onto the
      # check_preimage node. Omitted for the default so existing ANF is unchanged.
      d["sighashFlag"] = v.sighash_flag if v.respond_to?(:sighash_flag) && !v.sighash_flag.nil?
      d["satoshis"] = v.satoshis unless v.satoshis.nil?
      d["stateValues"] = v.state_values unless v.state_values.nil?
      d["scriptBytes"] = v.script_bytes unless v.script_bytes.nil?
      if v.kind == "raw_script"
        # Opaque opcode-byte span -- emit bytes + arities explicitly so
        # in_arity 0 / out_arity 0 survive the round-trip.
        d["bytes"] = v.bytes || ""
        d["in_arity"] = v.in_arity || 0
        d["out_arity"] = v.out_arity || 0
      end
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

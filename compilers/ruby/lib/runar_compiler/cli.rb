# frozen_string_literal: true

# CLI entry point for the Runar Ruby compiler.
#
# Usage:
#   runar-compiler-ruby --source Contract.runar.rb --output artifact.json
#   runar-compiler-ruby --ir program.json --output artifact.json
#   runar-compiler-ruby --source Contract.runar.rb --hex
#   runar-compiler-ruby --source Contract.runar.rb --asm
#   runar-compiler-ruby --source Contract.runar.rb --emit-ir
#
# Direct port of compilers/python/runar_compiler/__main__.py.

require "optparse"
require "json"
require "set"

require_relative "compiler"

module RunarCompiler
  module CLI
    # Snake-case to camelCase mapping for ANF IR fields.
    SNAKE_TO_CAMEL = {
      "contract_name" => "contractName",
      "is_public" => "isPublic",
      "iter_var" => "iterVar",
      "state_values" => "stateValues",
      "initial_value" => "initialValue",
      "script_bytes" => "scriptBytes",
      "else_" => "else",
      "is_auto_injected_state_check" => "isAutoInjectedStateCheck",
      # These stay as snake_case to match Go/TS IR format
      "result_type" => "result_type",
      # Both raw_value and value_ref map to "value" in Go JSON (they never coexist)
      "value_ref" => "value",
      "raw_value" => "value",
    }.freeze

    # Fields that should be excluded from IR output (internal decoded fields).
    IR_EXCLUDED_FIELDS = Set.new(%w[
      const_string const_big_int const_bool const_int
      source_loc
      parent_class
    ]).freeze

    module_function

    # GAP-011: source-map sourceFile values must be repo-relative (POSIX) so
    # goldens stay stable across worktree paths and developer machines. Walk
    # up from the source file looking for pnpm-workspace.yaml (the canonical
    # repo root marker); fall back to the basename if no marker is found.
    # Strings that aren't absolute paths are returned unchanged.
    def repo_relative_file_name(src_path)
      return src_path unless src_path.is_a?(String) && File.absolute_path(src_path) == src_path
      d = File.dirname(src_path)
      loop do
        if File.exist?(File.join(d, "pnpm-workspace.yaml"))
          rel = src_path.sub(/\A#{Regexp.escape(d)}#{Regexp.escape(File::SEPARATOR)}?/, "")
          return rel.tr(File::SEPARATOR, "/")
        end
        parent = File.dirname(d)
        break if parent == d
        d = parent
      end
      File.basename(src_path)
    end

    def run(argv = ARGV)
      options = {}

      parser = OptionParser.new do |opts|
        opts.banner = "Usage: runar-compiler-ruby [options]"
        opts.separator ""
        opts.separator "Runar smart contract compiler (Ruby implementation)."
        opts.separator ""

        opts.on("--ir PATH", "Path to ANF IR JSON file") do |path|
          options[:ir] = path
        end

        opts.on("--source PATH", "Path to .runar.* source file") do |path|
          options[:source] = path
        end

        opts.on("--output PATH", "Output artifact path (default: stdout)") do |path|
          options[:output] = path
        end

        opts.on("--hex", "Output only the script hex (no artifact JSON)") do
          options[:hex] = true
        end

        opts.on("--asm", "Output only the script ASM (no artifact JSON)") do
          options[:asm] = true
        end

        opts.on("--emit-ir", "Output only the ANF IR JSON (requires --source)") do
          options[:emit_ir] = true
        end

        opts.on("--parse-only", "Stop after parse + validate; print 'parser ok' on success (requires --source)") do
          options[:parse_only] = true
        end

        opts.on("--disable-constant-folding", "Disable the ANF constant folding pass") do
          options[:disable_constant_folding] = true
        end

        opts.on("--emit-source-map PATH", "After a successful compile, write artifact.sourceMap JSON to PATH") do |path|
          options[:emit_source_map] = path
        end
      end

      parser.parse!(argv)

      if !options[:ir] && !options[:source]
        $stderr.puts(
          "Usage: runar-compiler-ruby [--ir <path> | --source <path>] " \
          "[--output <path>] [--hex] [--asm] [--emit-ir]"
        )
        $stderr.puts ""
        $stderr.puts "Phase 1: Compile from ANF IR JSON to Bitcoin Script (--ir)."
        $stderr.puts "Phase 2: Compile from source to Bitcoin Script (--source)."
        exit 1
      end

      disable_cf = options[:disable_constant_folding] || false

      # Handle --parse-only: read source, run parse + validate, print
      # "parser ok" on success or diagnostics + non-zero exit on failure.
      # Used by the conformance runner's --parser-only universal-frontend
      # coverage check.
      if options[:parse_only]
        unless options[:source]
          $stderr.puts "--parse-only requires --source"
          exit 1
        end
        begin
          RunarCompiler.parse_and_validate_only(options[:source])
        rescue RunarCompiler::CompilationError => e
          $stderr.puts "parse error: #{e.message}"
          exit 1
        rescue StandardError => e
          $stderr.puts "parse error: #{e.message}"
          exit 1
        end
        puts "parser ok"
        return
      end

      # Handle --emit-ir: dump ANF IR JSON and exit
      if options[:emit_ir]
        unless options[:source]
          $stderr.puts "--emit-ir requires --source"
          exit 1
        end

        begin
          program = RunarCompiler.compile_source_to_ir(
            options[:source],
            disable_constant_folding: disable_cf
          )
        rescue RunarCompiler::CompilationError => e
          $stderr.puts "Compilation error: #{e.message}"
          exit 1
        end

        # Serialize the ANFProgram to camelCase JSON (matching Go/TS output)
        ir_json = JSON.pretty_generate(_anf_to_camel_dict(program))
        puts ir_json
        return
      end

      begin
        if options[:source]
          artifact = RunarCompiler.compile_from_source(
            options[:source],
            disable_constant_folding: disable_cf
          )
        else
          artifact = RunarCompiler.compile_from_ir(
            options[:ir],
            disable_constant_folding: disable_cf
          )
        end
      rescue RunarCompiler::CompilationError => e
        $stderr.puts "Compilation error: #{e.message}"
        exit 1
      rescue StandardError => e
        $stderr.puts "Compilation error: #{e.message}"
        exit 1
      end

      # Determine output
      if options[:hex]
        output = artifact.script
      elsif options[:asm]
        output = artifact.asm
      else
        output = RunarCompiler.artifact_to_json(artifact)
      end

      # --emit-source-map: write the artifact's sourceMap field as canonical
      # JSON ({"mappings":[...]}) to the requested path. Always emit the
      # wrapper object so downstream tooling sees a uniform shape even when
      # the underlying mapping table is empty.
      if options[:emit_source_map]
        sm_path = options[:emit_source_map]
        sm = artifact.source_map
        mappings = if sm && !sm.empty?
          sm.map do |m|
            if m.is_a?(RunarCompiler::Codegen::SourceMapping)
              {
                "opcodeIndex" => m.opcode_index,
                # GAP-011: normalize sourceFile to repo-relative POSIX.
                "sourceFile" => repo_relative_file_name(m.source_file),
                "line" => m.line,
                "column" => m.column,
              }
            elsif m.is_a?(Hash) && m["sourceFile"]
              m.merge("sourceFile" => repo_relative_file_name(m["sourceFile"]))
            else
              m
            end
          end
        else
          []
        end
        require "fileutils"
        FileUtils.mkdir_p(File.dirname(sm_path)) if File.dirname(sm_path) != ""
        File.write(sm_path, JSON.pretty_generate({ "mappings" => mappings }) + "\n")
        $stderr.puts "Source map written to #{sm_path}"
      end

      # Write output
      if options[:output]
        File.write(options[:output], output)
        $stderr.puts "Output written to #{options[:output]}"
      else
        puts output
      end
    end

    # Convert a snake_case key to its camelCase equivalent using the mapping.
    def _snake_key(k)
      SNAKE_TO_CAMEL.fetch(k, k)
    end

    # Convert an ANF dataclass tree to a dict matching Go/TS IR JSON format.
    #
    # Works with RunarCompiler::IR struct-based objects by inspecting their
    # members, and handles arrays and primitives recursively.
    def _anf_to_camel_dict(obj)
      if obj.is_a?(Struct)
        d = {}
        has_raw_value = false

        obj.members.each do |member_name|
          name_str = member_name.to_s
          next if IR_EXCLUDED_FIELDS.include?(name_str)

          v = obj[member_name]
          next if v.nil?

          # raw_value is the canonical Go JSON "value" field -- parse and emit its content
          if name_str == "raw_value"
            begin
              d["value"] = JSON.parse(v)
            rescue JSON::ParserError, TypeError
              d["value"] = v
            end
            has_raw_value = true
            next
          end

          # Skip value_ref if raw_value was already emitted as "value"
          next if name_str == "value_ref" && has_raw_value

          key = _snake_key(name_str)
          d[key] = _anf_to_camel_dict(v)
        end

        # Handle ANFValue which is a plain class, not a Struct
        d
      elsif obj.is_a?(RunarCompiler::IR::ANFValue)
        d = {}
        has_raw_value = false

        # Get all instance variable names
        ivars = %i[
          kind name raw_value op left right result_type operand func args
          object method cond then else_ count iter_var body value_ref
          preimage satoshis state_values script_bytes elements
          bytes in_arity out_arity
          is_auto_injected_state_check
          const_string const_big_int const_bool const_int
        ]

        kind_val = obj.kind
        ivars.each do |ivar_name|
          name_str = ivar_name.to_s
          next if IR_EXCLUDED_FIELDS.include?(name_str)

          v = obj.send(ivar_name)
          next if v.nil?

          if name_str == "raw_value"
            begin
              d["value"] = v.is_a?(String) ? JSON.parse(v) : v
            rescue JSON::ParserError, TypeError
              d["value"] = v
            end
            has_raw_value = true
            next
          end

          next if name_str == "value_ref" && has_raw_value

          # Auto-injected stateful-continuation marker: emit only on
          # +assert+ nodes and only when true so checked-in fold-OFF
          # goldens stay stable for developer asserts.
          if name_str == "is_auto_injected_state_check"
            next unless v == true && kind_val == "assert"
          end

          key = _snake_key(name_str)
          d[key] = _anf_to_camel_dict(v)
        end

        d
      elsif obj.is_a?(Array)
        obj.map { |item| _anf_to_camel_dict(item) }
      else
        obj
      end
    end
  end
end

# Run the CLI when this file is executed directly (e.g.
# `ruby -Ilib lib/runar_compiler/cli.rb --source ...`). When merely required
# as a library, defining the module is all that should happen.
RunarCompiler::CLI.run if $PROGRAM_NAME == __FILE__

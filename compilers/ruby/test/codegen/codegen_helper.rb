# frozen_string_literal: true

# Shared helpers for Ruby codegen unit-vector tests.
#
# These tests mirror the spirit of the Go codegen test files
# (e.g. compilers/go/codegen/emit_test.go) by compiling a small TS contract
# that exercises a single specialised codegen module (Blake3, EC, P256/P384,
# Rabin, SHA-256 compress/finalize, WOTS, SLH-DSA) and asserting the emit
# pass produces the expected hallmark opcodes in the resulting script ASM.
#
# They are deliberately compile-only — they do not run the script against
# a Bitcoin VM. End-to-end script execution is exercised by the
# integration/ruby/spec/* regtest tests.

require_relative '../test_helper'

module CodegenTestHelpers
  def compile_ts_source(source, file_name)
    parse_result = RunarCompiler.send(:_parse_source, source, file_name)
    raise "parse errors: #{parse_result.error_strings.join('; ')}" if parse_result.errors.any?
    raise 'no contract found' if parse_result.contract.nil?

    val_result = RunarCompiler.send(:_validate, parse_result.contract)
    unless val_result.errors.empty?
      raise "validation errors: #{val_result.errors.map(&:format_message).join('; ')}"
    end

    tc_result = RunarCompiler.send(:_type_check, parse_result.contract)
    unless tc_result.errors.empty?
      raise "type check errors: #{tc_result.errors.map(&:format_message).join('; ')}"
    end

    program = RunarCompiler.send(:_lower_to_anf, parse_result.contract)
    RunarCompiler.compile_from_program(program, disable_constant_folding: true)
  end
end

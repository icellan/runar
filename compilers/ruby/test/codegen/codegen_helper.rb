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

  # Walk a hex-encoded script byte-by-byte, skipping over push-data payloads,
  # and return only the bytes that are actually interpreted as opcodes.
  #
  # F-329: a plain `hex.include?('ae')` substring search is not aligned to
  # opcode boundaries. Hex digits from the END of one push-data byte and the
  # START of the next can spell out "ae" or "af" (e.g. the byte sequence
  # 0x1a, 0xe3 encodes as the string "1ae3", which contains "ae" even though
  # neither byte equals 0xae and no OP_CHECKMULTISIG is present). Callers
  # that need to confirm an opcode byte is actually present must scan at
  # opcode-aligned positions, which requires decoding Bitcoin Script's push
  # encodings (direct push, OP_PUSHDATA1/2/4) to know how many following
  # bytes are data rather than the next opcode.
  def aligned_opcode_bytes(hex)
    bytes = hex.scan(/../).map { |b| b.to_i(16) }
    opcodes = []
    i = 0
    while i < bytes.length
      b = bytes[i]
      if b >= 1 && b <= 75 # direct push of b bytes
        i += 1 + b
      elsif b == 0x4c # OP_PUSHDATA1
        i += 2 + bytes[i + 1]
      elsif b == 0x4d # OP_PUSHDATA2 (little-endian 2-byte length)
        i += 3 + (bytes[i + 1] | (bytes[i + 2] << 8))
      elsif b == 0x4e # OP_PUSHDATA4 (little-endian 4-byte length)
        i += 5 + (bytes[i + 1] | (bytes[i + 2] << 8) | (bytes[i + 3] << 16) | (bytes[i + 4] << 24))
      else
        opcodes << b
        i += 1
      end
    end
    opcodes
  end
end

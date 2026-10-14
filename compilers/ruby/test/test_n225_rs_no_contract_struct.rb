# frozen_string_literal: true

# N-225 — Ruby's .runar.rs parser returns an empty "UnnamedContract" placeholder
# with NO diagnostic when the source has no `#[runar::contract]` struct, instead
# of refusing like the reference shape (Go/Rust/Zig: nil contract + one error
# "no Rúnar contract struct found in Rust source"; TestParseRustMacro_InvalidSyntax_Error
# in compilers/go/frontend/parser_rustmacro_test.go pins Go's shape for the same
# input).
#
# What this proves: given Rust-DSL source with no contract struct (just a bare
# `fn main() {}`), RunarCompiler::Frontend.parse_rust returns a nil contract and
# at least one error, matching Go's ParseSource-level shape for this input.
# What it does NOT prove: Python and Java emit a DIFFERENT error string and
# return a non-nil `name: ""` contract instead of nil for the same input (their
# own divergence from Go, out of scope for this item); nor does it prove
# anything about the full compile_check/validate pipeline (Ruby's own
# "no public methods" validation diagnostic already rejects this input farther
# down the pipeline regardless of this parser-level fix — see validator.rb).

require_relative "test_helper"
require "runar_compiler/frontend/input_limits"
require "runar_compiler/frontend/parser_rust"

class TestN225RsNoContractStruct < Minitest::Test
  def test_non_contract_source_yields_nil_contract_and_error
    source = <<~RS
      fn main() {
          println!("hello world");
      }
    RS

    result = RunarCompiler::Frontend.parse_rust(source, "notacontract.runar.rs")

    assert_nil result.contract, "expected nil contract for non-contract source"
    refute_empty result.errors, "expected at least one error for non-contract source"
  end
end

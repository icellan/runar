# frozen_string_literal: true

# N-069: load_ir checks every required ANF field for presence and JSON type.
#
# Before: a public method with no `body` loaded with zero bindings and
# `--ir --hex` exited 0 with an EMPTY (anyone-can-spend) locking script;
# `params: {}` was accepted; `body: "x"` died as a raw NoMethodError.
#
# Proves: each single-field corruption in the shared corpus
# (conformance/negatives/ir-required-fields-cases.json) is refused with the
# exact diagnostic every tier prints, and the control loads. Does not prove:
# full schema conformance (deliberately defaulted optional fields are not
# required).

require_relative "test_helper"
require "json"
require "runar_compiler/ir/loader"

class TestN069IRRequiredFields < Minitest::Test
  CORPUS = JSON.parse(
    File.read(File.expand_path("../../../conformance/negatives/ir-required-fields-cases.json", __dir__))
  )

  def test_control_loads
    RunarCompiler::IR.load_ir(JSON.generate(CORPUS["control"]))
  end

  def test_corpus_is_not_empty
    assert_operator CORPUS["cases"].length, :>=, 20
  end

  CORPUS["cases"].each do |c|
    define_method("test_refuses_#{c['name'].tr('-', '_')}") do
      err = assert_raises(ArgumentError) { RunarCompiler::IR.load_ir(JSON.generate(c["ir"])) }
      assert_equal c["error"], err.message
    end
  end
end

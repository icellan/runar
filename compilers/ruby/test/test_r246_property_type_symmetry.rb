# frozen_string_literal: true

require_relative 'test_helper'

require 'runar_compiler/frontend/ast_nodes'
require 'runar_compiler/frontend/diagnostic'
require 'runar_compiler/frontend/validator'

# R-246 (CL-GAP-084), the Ruby half.
#
# +validate_property_type+ refuses any CustomType and accepts a PrimitiveType
# whose name is not in VALID_PROP_TYPES -- unless it is spelled "void":
#
#   if type_node.is_a?(PrimitiveType)
#     unless VALID_PROP_TYPES.include?(type_node.name)
#       if type_node.name == "void"
#         add_error(...)                      # and nothing else
#
# One property, two spellings of the same unknown name, two answers. The finding
# was filed against the Python tier; ts, go and this one share it verbatim, while
# rust, java and zig already refuse both.
#
# No parser produces a PrimitiveType with an unknown name today -- they all map
# an unrecognised name to CustomType -- but +validate+ takes an AST, and the
# frontend is not the only thing that builds one.
class TestR246PropertyTypeSymmetry < Minitest::Test
  include RunarCompiler::Frontend

  LOC = SourceLocation.new(file: 'Probe.runar.ts', line: 1, column: 1)

  def contract_with(type_node)
    ContractNode.new(
      name: 'Probe',
      parent_class: 'SmartContract',
      properties: [
        PropertyNode.new(name: 'p', type: type_node, readonly: true, source_location: LOC)
      ],
      constructor: MethodNode.new(name: 'constructor', params: [], body: [], source_location: LOC),
      methods: [],
      source_file: 'Probe.runar.ts'
    )
  end

  # Only the diagnostics about the property's TYPE: a minimal hand-built
  # contract trips other rules, and filtering keeps this about the branch it is
  # named for.
  def type_errors(type_node)
    RunarCompiler::Frontend
      .validate(contract_with(type_node))
      .errors
      .map(&:message)
      .select { |m| m.downcase.include?('type') }
  end

  # Control: without it, "refuse everything" passes every case below.
  def test_valid_primitive_is_accepted
    assert_empty type_errors(PrimitiveType.new(name: 'bigint'))
  end

  def test_unknown_custom_type_is_refused
    assert_includes type_errors(CustomType.new(name: 'Foobarium')).join("\n"), 'Foobarium'
  end

  def test_void_is_refused
    assert_includes type_errors(PrimitiveType.new(name: 'void')).join("\n"), 'void'
  end

  def test_unknown_primitive_is_refused_too
    errs = type_errors(PrimitiveType.new(name: 'Foobarium'))
    assert_includes errs.join("\n"), 'Foobarium',
                    'an unknown PrimitiveType passed validation while the identical ' \
                    'name as a CustomType is refused'
  end

  def test_reaches_fixed_array_element_type
    errs = type_errors(FixedArrayType.new(element: PrimitiveType.new(name: 'Foobarium'), length: 3))
    assert_includes errs.join("\n"), 'Foobarium'
  end

  def test_valid_fixed_array_still_accepted
    assert_empty type_errors(FixedArrayType.new(element: PrimitiveType.new(name: 'bigint'), length: 3))
  end
end

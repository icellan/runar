# frozen_string_literal: true

require_relative 'test_helper'

# Edge-case coverage for the .runar.rs (Rust DSL) surface parser.

class TestParserRsEdges < Minitest::Test
  require 'runar_compiler/frontend/parser_rust'
  include RunarCompiler::Frontend

  def parse(source, file_name = 'Test.runar.rs')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  def test_stateful_contract_attribute
    source = <<~RS
      use runar::prelude::*;

      #[runar::stateful_contract]
      pub struct Counter {
          pub count: Bigint,
      }

      impl Counter {
          pub fn bump(&mut self) {
              self.count = self.count + 1;
          }
      }
    RS

    result = parse(source, 'Counter.runar.rs')
    assert_empty result.errors.map(&:format_message)
    assert_equal 'StatefulSmartContract', result.contract.parent_class
  end

  def test_multiple_methods_in_impl
    source = <<~RS
      use runar::prelude::*;

      #[runar::contract]
      pub struct Multi {
          #[readonly]
          pub x: Bigint,
      }

      impl Multi {
          pub fn one(&self) { assert!(self.x > 0); }
          pub fn two(&self) { assert!(self.x > 1); }
          pub fn three(&self) { assert!(self.x > 2); }
      }
    RS

    result = parse(source, 'Multi.runar.rs')
    assert_empty result.errors.map(&:format_message)
    names = result.contract.methods.map(&:name)
    assert_equal %w[one two three], names
  end

  def test_pascal_method_names_become_camel_case
    source = <<~RS
      use runar::prelude::*;

      #[runar::contract]
      pub struct PascalCase {
          #[readonly]
          pub target: Bigint,
      }

      impl PascalCase {
          pub fn do_check_thing(&self, a: Bigint) {
              assert!(a == self.target);
          }
      }
    RS

    result = parse(source, 'PascalCase.runar.rs')
    assert_empty result.errors.map(&:format_message)
    method = result.contract.methods.first
    assert_equal 'doCheckThing', method.name
  end

  def test_multiple_readonly_properties
    source = <<~RS
      use runar::prelude::*;

      #[runar::contract]
      pub struct Three {
          #[readonly]
          pub alpha: Bigint,
          #[readonly]
          pub beta: Bigint,
          #[readonly]
          pub gamma: Bigint,
      }

      impl Three {
          pub fn check(&self) {
              assert!(self.alpha + self.beta + self.gamma > 0);
          }
      }
    RS

    result = parse(source, 'Three.runar.rs')
    assert_empty result.errors.map(&:format_message)
    props = result.contract.properties
    assert_equal %w[alpha beta gamma], props.map(&:name)
    assert(props.all?(&:readonly), 'all marked readonly')
  end

  def test_garbage_input_does_not_crash
    begin
      parse('@@@ not rust !!!', 'garbage.runar.rs')
    rescue StandardError => e
      flunk "parser crashed: #{e.class}: #{e.message}"
    end
  end

  def test_no_contract_attribute_emits_no_methods
    # A plain Rust struct (no #[runar::contract]) without an impl block is
    # parsed as a methodless contract — downstream validation rejects it for
    # missing public methods. The parser is intentionally lenient here.
    source = <<~RS
      use runar::prelude::*;

      pub struct Plain {
          pub x: Bigint,
      }
    RS

    result = parse(source, 'Plain.runar.rs')
    refute_nil result.contract
    assert_empty result.contract.methods,
                 'plain struct without impl must produce no methods'
  end
end

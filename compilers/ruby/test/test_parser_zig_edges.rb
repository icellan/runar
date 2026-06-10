# frozen_string_literal: true

require_relative 'test_helper'

# Edge-case coverage for the .runar.zig surface parser.

class TestParserZigEdges < Minitest::Test
  require 'runar_compiler/frontend/parser_zig'
  include RunarCompiler::Frontend

  def parse(source, file_name = 'Test.runar.zig')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  def test_multiple_properties_preserve_order
    source = <<~ZIG
      const runar = @import("runar");

      pub const Three = struct {
          pub const Contract = runar.SmartContract;

          alpha: runar.Bigint,
          beta:  runar.Bigint,
          gamma: runar.Bigint,

          pub fn check(self: Three) void {
              runar.assert(self.alpha + self.beta + self.gamma > 0);
          }
      };
    ZIG

    result = parse(source, 'Three.runar.zig')
    assert_empty result.errors.map(&:format_message)
    assert_equal %w[alpha beta gamma], result.contract.properties.map(&:name)
  end

  def test_self_filtered_from_method_params
    source = <<~ZIG
      const runar = @import("runar");

      pub const Adder = struct {
          pub const Contract = runar.SmartContract;

          target: runar.Bigint,

          pub fn verify(self: Adder, a: runar.Bigint, b: runar.Bigint) void {
              runar.assert(a + b == self.target);
          }
      };
    ZIG

    result = parse(source, 'Adder.runar.zig')
    assert_empty result.errors.map(&:format_message)
    method = result.contract.methods.first
    refute(method.params.any? { |p| p.name == 'self' },
           "'self' must be filtered from method params")
    assert_equal %w[a b], method.params.map(&:name)
  end

  def test_bool_initializer
    source = <<~ZIG
      const runar = @import("runar");

      pub const F = struct {
          pub const Contract = runar.SmartContract;

          value: runar.Bigint,
          flag:  runar.Bool = true,

          pub fn check(self: F) void {
              runar.assert(self.flag);
          }
      };
    ZIG

    result = parse(source, 'F.runar.zig')
    assert_empty result.errors.map(&:format_message)
    flag = result.contract.properties.find { |p| p.name == 'flag' }
    refute_nil flag
    refute_nil flag.initializer
    assert_instance_of BoolLiteral, flag.initializer
  end

  def test_stateful_with_multiple_methods
    source = <<~ZIG
      const runar = @import("runar");

      pub const Counter = struct {
          pub const Contract = runar.StatefulSmartContract;

          count: runar.Bigint,

          pub fn up(self: *Counter) void {
              self.count += 1;
          }

          pub fn down(self: *Counter) void {
              runar.assert(self.count > 0);
              self.count -= 1;
          }

          pub fn zero(self: *Counter) void {
              self.count = 0;
          }
      };
    ZIG

    result = parse(source, 'Counter.runar.zig')
    assert_empty result.errors.map(&:format_message)
    assert_equal %w[up down zero], result.contract.methods.map(&:name)
  end

  def test_garbage_input_does_not_crash
    begin
      parse('@@@ not zig !!!', 'garbage.runar.zig')
    rescue StandardError => e
      flunk "parser crashed: #{e.class}: #{e.message}"
    end
  end

  def test_public_marker_pub_required
    source = <<~ZIG
      const runar = @import("runar");

      pub const Mixed = struct {
          pub const Contract = runar.SmartContract;

          x: runar.Bigint,

          fn helper(self: Mixed) runar.Bigint {
              return self.x + 1;
          }

          pub fn check(self: Mixed) void {
              runar.assert(helper(self) > 0);
          }
      };
    ZIG

    result = parse(source, 'Mixed.runar.zig')
    assert_empty result.errors.map(&:format_message)
    by_name = result.contract.methods.each_with_object({}) { |m, h| h[m.name] = m }
    assert_equal 'private', by_name['helper'].visibility
    assert_equal 'public', by_name['check'].visibility
  end
end

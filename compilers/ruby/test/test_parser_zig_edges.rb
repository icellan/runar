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

  # -- F-207: bare `&`, `[_]T{...}`, and the stale property-initializer
  # strip -------------------------------------------------------------

  def test_bare_ampersand_strips_to_operand
    # A bare `&` (not part of `&.{...}`) is Zig's address-of operator used
    # for slice coercion. It must be stripped and the real operand parsed
    # -- exactly like `&.{...}`, like the TS reference, and like
    # parse_zig.zig -- never manufacture a garbage `Identifier(name: '&')`
    # or desync the token stream.
    source = <<~ZIG
      const runar = @import("runar");

      pub const AmpPrefix = struct {
          pub const Contract = runar.SmartContract;

          t: i64,

          pub fn init(t: i64) AmpPrefix {
              return .{ .t = t };
          }

          pub fn unlock(self: AmpPrefix, x: i64) void {
              runar.assert(&x == self.t);
          }
      };
    ZIG

    result = parse(source, 'AmpPrefix.runar.zig')
    assert_empty result.errors.map(&:format_message)
    unlock = result.contract.methods.find { |m| m.name == 'unlock' }
    call = unlock.body[0].expr
    assert_instance_of CallExpr, call
    cond = call.args[0]
    assert_instance_of BinaryExpr, cond
    assert_instance_of Identifier, cond.left
    assert_equal 'x', cond.left.name
  end

  def test_inferred_length_array_literal
    # `[_]T{...}` is Zig's typed array literal with inferred length. It
    # must parse as a single ArrayLiteralExpr with the given elements --
    # not decompose into unrelated garbage statements.
    source = <<~ZIG
      const runar = @import("runar");

      pub const InferredArray = struct {
          pub const Contract = runar.SmartContract;

          pk1: runar.PubKey,
          pk2: runar.PubKey,
          pk3: runar.PubKey,

          pub fn init(pk1: runar.PubKey, pk2: runar.PubKey, pk3: runar.PubKey) InferredArray {
              return .{ .pk1 = pk1, .pk2 = pk2, .pk3 = pk3 };
          }

          pub fn unlock(self: *const InferredArray, sig1: runar.Sig, sig2: runar.Sig) void {
              runar.assert(runar.checkMultiSig(
                  &[_]runar.Sig{ sig1, sig2 },
                  &.{ self.pk1, self.pk2, self.pk3 },
              ));
          }
      };
    ZIG

    result = parse(source, 'InferredArray.runar.zig')
    assert_empty result.errors.map(&:format_message)
    unlock = result.contract.methods.find { |m| m.name == 'unlock' }
    assert_equal 1, unlock.body.length
    call = unlock.body[0].expr
    multisig_call = call.args[0]
    sig_array = multisig_call.args[0]
    assert_instance_of ArrayLiteralExpr, sig_array
    assert_equal 2, sig_array.elements.length
  end

  def test_ctor_param_name_collision_does_not_strip_unrelated_property
    # The parser must not strip a property's initializer merely because
    # its NAME matches some constructor PARAMETER name. The centralized
    # rule (anf_lower.rb's _constructor_assigned_properties) is keyed on
    # the actual constructor ASSIGNMENT, not a name coincidence --
    # matching the TS reference, which removed this parser-level strip
    # for exactly this reason. Here ctor param `lo` is assigned to the
    # DIFFERENT property `renamed`; the `lo` PROPERTY is never touched by
    # the constructor at all and must keep its own literal initializer.
    source = <<~ZIG
      const runar = @import("runar");

      pub const InitSurvives = struct {
          pub const Contract = runar.StatefulSmartContract;

          lo: i64 = 99,
          renamed: i64 = 0,

          pub fn init(lo: i64) InitSurvives {
              return .{ .renamed = lo };
          }

          pub fn bump(self: *InitSurvives, delta: i64) void {
              self.renamed = self.renamed + delta;
              self.addOutput(1000, self.lo, self.renamed);
          }
      };
    ZIG

    result = parse(source, 'InitSurvives.runar.zig')
    assert_empty result.errors.map(&:format_message)
    lo_prop = result.contract.properties.find { |p| p.name == 'lo' }
    refute_nil lo_prop.initializer
    assert_instance_of BigIntLiteral, lo_prop.initializer
    assert_equal 99, lo_prop.initializer.value
  end
end

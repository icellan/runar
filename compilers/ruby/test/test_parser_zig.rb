# frozen_string_literal: true

require_relative 'test_helper'

# Tests for the .runar.zig parser. Mirrors the Go suite at
# compilers/go/frontend/parser_zig_test.go so all 7 compilers exercise the
# same surface shape on the same inputs.

class TestParserZig < Minitest::Test
  require 'runar_compiler/frontend/parser_zig'
  include RunarCompiler::Frontend

  def parse(source, file_name = 'Test.runar.zig')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  # ---------------------------------------------------------------------------
  # Basic stateless P2PKH
  # ---------------------------------------------------------------------------

  def test_parses_p2pkh_contract
    source = <<~ZIG
      const runar = @import("runar");

      pub const P2PKH = struct {
          pub const Contract = runar.SmartContract;

          pubKeyHash: runar.Addr,

          pub fn init(self: P2PKH, pubKeyHash: runar.Addr) void {
              _ = self;
              return .{ .pubKeyHash = pubKeyHash };
          }

          pub fn unlock(self: P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
              runar.assert(runar.hash160(pubKey) == self.pubKeyHash);
              runar.assert(runar.checkSig(sig, pubKey));
          }
      };
    ZIG

    result = parse(source, 'P2PKH.runar.zig')
    assert_empty result.errors.map(&:format_message),
                 'P2PKH should parse without errors'
    refute_nil result.contract

    c = result.contract
    assert_equal 'P2PKH', c.name
    assert_equal 'SmartContract', c.parent_class

    assert_equal 1, c.properties.length
    pkh = c.properties.first
    assert_equal 'pubKeyHash', pkh.name
    assert pkh.readonly, 'stateless property must be readonly'

    assert_equal 1, c.methods.length
    unlock = c.methods.first
    assert_equal 'unlock', unlock.name
    assert_equal 'public', unlock.visibility
    # 'self' must be filtered out; only sig + pubKey remain.
    assert_equal 2, unlock.params.length
    assert_equal 'sig',    unlock.params[0].name
    assert_equal 'pubKey', unlock.params[1].name
  end

  # ---------------------------------------------------------------------------
  # Stateful counter
  # ---------------------------------------------------------------------------

  def test_stateful_contract
    source = <<~ZIG
      const runar = @import("runar");

      pub const Counter = struct {
          pub const Contract = runar.StatefulSmartContract;

          count: runar.Bigint,

          pub fn init(self: Counter, count: runar.Bigint) void {
              _ = self;
              return .{ .count = count };
          }

          pub fn increment(self: *Counter) void {
              self.count += 1;
          }

          pub fn decrement(self: *Counter) void {
              runar.assert(self.count > 0);
              self.count -= 1;
          }
      };
    ZIG

    result = parse(source, 'Counter.runar.zig')
    assert_empty result.errors.map(&:format_message)

    c = result.contract
    refute_nil c
    assert_equal 'Counter', c.name
    assert_equal 'StatefulSmartContract', c.parent_class
    assert_equal 1, c.properties.length
    assert_equal 2, c.methods.length
    assert_equal 'increment', c.methods[0].name
    assert_equal 'decrement', c.methods[1].name
  end

  # ---------------------------------------------------------------------------
  # Public vs private visibility
  # ---------------------------------------------------------------------------

  def test_public_and_private_methods
    source = <<~ZIG
      const runar = @import("runar");

      pub const Vis = struct {
          pub const Contract = runar.SmartContract;

          x: runar.Bigint,

          pub fn doPublic(self: Vis) void {
              runar.assert(self.x > 0);
          }

          fn doPrivate(self: Vis) runar.Bigint {
              return self.x + 1;
          }
      };
    ZIG

    result = parse(source, 'Vis.runar.zig')
    assert_empty result.errors.map(&:format_message)

    c = result.contract
    refute_nil c
    assert_equal 2, c.methods.length
    assert_equal 'doPublic', c.methods[0].name
    assert_equal 'public',   c.methods[0].visibility
    assert_equal 'doPrivate', c.methods[1].name
    assert_equal 'private',  c.methods[1].visibility
  end

  # ---------------------------------------------------------------------------
  # Property initializer is captured
  # ---------------------------------------------------------------------------

  def test_property_initializer
    source = <<~ZIG
      const runar = @import("runar");

      pub const MyContract = struct {
          pub const Contract = runar.SmartContract;

          value: runar.Bigint,
          limit: runar.Bigint = 100,

          pub fn check(self: MyContract) void {
              runar.assert(self.value < self.limit);
          }
      };
    ZIG

    result = parse(source, 'MyContract.runar.zig')
    assert_empty result.errors.map(&:format_message)

    c = result.contract
    refute_nil c
    assert_equal 2, c.properties.length

    assert_nil c.properties[0].initializer, "value should have no initializer"

    init = c.properties[1].initializer
    refute_nil init, 'limit should carry its literal initializer'
    assert_instance_of BigIntLiteral, init
    assert_equal 100, init.value
  end

  # ---------------------------------------------------------------------------
  # Auto-generated fallback constructor
  # ---------------------------------------------------------------------------

  def test_fallback_constructor
    source = <<~ZIG
      const runar = @import("runar");

      pub const NoInit = struct {
          pub const Contract = runar.SmartContract;

          a: runar.Bigint,
          b: runar.Bigint,

          pub fn check(self: NoInit) void {
              runar.assert(self.a + self.b > 0);
          }
      };
    ZIG

    result = parse(source, 'NoInit.runar.zig')
    assert_empty result.errors.map(&:format_message)

    c = result.contract
    refute_nil c
    ctor = c.constructor
    refute_nil ctor
    assert_equal 2, ctor.params.length
    assert_equal 'a', ctor.params[0].name
    assert_equal 'b', ctor.params[1].name
  end
end

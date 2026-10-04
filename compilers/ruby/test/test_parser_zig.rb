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

  # ---------------------------------------------------------------------------
  # N-090: runar.hexToBytes("...") lowers to a ByteString literal
  # ---------------------------------------------------------------------------
  #
  # Proves: the Ruby Zig-surface parser lowers `runar.hexToBytes("<hex>")` to a
  # ByteStringLiteral carrying the hex verbatim (as 01-parse-zig.ts, the Zig
  # tier and Python do), so it is accepted as a property initializer; a
  # non-literal argument is refused with TS's diagnostic; the checked-in
  # Zig-surface TicTacToe compiles to the same script as the TS-surface
  # TicTacToe in this tier.
  # Does NOT prove: identity with the TS compiler (pinned by the
  # hex-to-bytes-initializer conformance fixture and the remediation sweep),
  # or that the hex payload is well-formed (TS does not check it either).

  HEX_TO_BYTES_SOURCE = <<~ZIG
    const runar = @import("runar");

    pub const H = struct {
        pub const Contract = runar.SmartContract;

        prefix: runar.Readonly(runar.ByteString) = runar.hexToBytes("1976a914"),
        x: runar.ByteString,

        pub fn init(x: runar.ByteString) H {
            return .{ .x = x };
        }

        pub fn verify(self: *const H, b: runar.ByteString) void {
            runar.assert(runar.bytesEq(runar.cat(self.prefix, self.x), b));
        }
    };
  ZIG

  def test_hex_to_bytes_initializer_is_bytestring_literal
    result = parse(HEX_TO_BYTES_SOURCE, 'H.runar.zig')
    assert_empty result.errors.map(&:format_message)
    prefix = result.contract.properties.find { |p| p.name == 'prefix' }
    refute_nil prefix
    assert_instance_of ByteStringLiteral, prefix.initializer
    assert_equal '1976a914', prefix.initializer.value
  end

  def test_hex_to_bytes_non_literal_argument_is_refused
    source = HEX_TO_BYTES_SOURCE.sub('runar.hexToBytes("1976a914")', 'runar.hexToBytes(x)')
    result = parse(source, 'H.runar.zig')
    msgs = result.errors.map(&:format_message)
    assert msgs.any? { |m| m.include?('runar.hexToBytes expects a string literal argument') },
           "expected TS's diagnostic, got #{msgs.inspect}"
  end

  def test_tic_tac_toe_zig_example_compiles_like_the_ts_surface
    examples = File.expand_path('../../../examples', __dir__)
    zig = RunarCompiler.compile_from_source(File.join(examples, 'zig/tic-tac-toe/TicTacToe.runar.zig'))
    ts = RunarCompiler.compile_from_source(File.join(examples, 'ts/tic-tac-toe/TicTacToe.runar.ts'))
    refute_empty zig.script
    assert_equal ts.script, zig.script
  end
end

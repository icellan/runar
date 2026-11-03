# frozen_string_literal: true

require_relative "../test_helper"

# Port of the TypeScript reference test
# `packages/runar-compiler/src/__tests__/n205-rabin-key-write-provenance.test.ts`.
#
# N-205 (a) -- a stateful method must not write a spender-supplied value into a
# MUTABLE property that verifyRabinSig uses as its public key. F-286 trusts a
# property read as the 4th argument, but a mutable property is state the
# previous spend chose: `this.key = newKey` lets a spender set the next UTXO's
# modulus to 1 and forge any message one spend later. Rule (user decision
# R80): every property whose value reaches a verifyRabinSig 4th argument is a
# KEY property, closed under "is written into a key property"; outside the
# constructor a mutable key property may only be written (assignment,
# compound assignment, ++/--, its addOutput slot) with a value F-286 trusts.
#
# What this proves: the Ruby tier's validator refuses the write shapes below
# and accepts literal / property writes, non-key writes and the key in its own
# addOutput slot, on the TS surface plus the `.runar.rb` surface and the bare
# Solidity `key = x` form.
# What it does NOT prove: the other tiers, or the `--ir` path (that is
# conformance/negatives/ir-rabin-key-provenance.test.ts).
class TestN205RabinKeyWriteProvenance < Minitest::Test
  def self.msg(prop)
    "verifyRabinSig public key property '#{prop}' may only be assigned a contract property or a literal " \
      "outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature"
  end

  SETTER = <<~TS
      private setKey(v: RabinPubKey): void {
        this.key = v;
      }
  TS

  HELPER = <<~TS
      private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
        return verifyRabinSig(m, s, p, k);
      }
  TS

  def self.wrap(rotate_body, extra_methods = "", settle_check = "verifyRabinSig(msg, sig, padding, this.key)")
    <<~TS
      import { StatefulSmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

      class C extends StatefulSmartContract {
        key: RabinPubKey;
        other: RabinPubKey;
        count: bigint;
        readonly backup: RabinPubKey;

        constructor(key: RabinPubKey, other: RabinPubKey, count: bigint, backup: RabinPubKey) {
          super(key, other, count, backup);
          this.key = key;
          this.other = other;
          this.count = count;
          this.backup = backup;
        }

        public settle(msg: ByteString, sig: RabinSig, padding: ByteString) {
          assert(#{settle_check});
        }

        public rotate(newKey: RabinPubKey, n: bigint) {
      #{rotate_body}
          assert(true);
        }
      #{extra_methods}
      }
    TS
  end

  REFUSED = {
    "assigned a public parameter" => [wrap("this.key = newKey;"), "key"],
    "assigned a const alias of a parameter" => [wrap("const k = newKey;\nthis.key = k;"), "key"],
    "compound assignment from a parameter" => [wrap("this.key += n;"), "key"],
    "incremented" => [wrap("this.key++;"), "key"],
    "assigned inside an if" => [wrap("if (n > 0n) {\n  this.key = newKey;\n}"), "key"],
    "passed a parameter in its addOutput slot" =>
      [wrap("this.addOutput(1000n, newKey, this.other, this.count);"), "key"],
    "written by a private setter fed a parameter" => [wrap("this.setKey(newKey);", SETTER), "key"],
    "key reached through a private helper, then written from a parameter" =>
      [wrap("this.key = newKey;", HELPER, "this.check(msg, sig, padding, this.key)"), "key"],
    "a property that feeds the key is itself written from a parameter" =>
      [wrap("this.key = this.other;\nthis.other = newKey;"), "other"],
  }.freeze

  ACCEPTED = {
    "assigned a bigint literal" => wrap("this.key = 1000003n;"),
    "assigned a readonly property" => wrap("this.key = this.backup;"),
    "assigned another property that is only written from literals" =>
      wrap("this.key = this.other;\nthis.other = 7n;"),
    "non-key state written from a parameter" => wrap("this.count = this.count + n;"),
    "non-Rabin mutable property written from a parameter" => wrap("this.other = newKey;"),
    "the key in its own addOutput slot" => wrap("this.addOutput(1000n, this.key, this.other, n);"),
    "written by a private setter fed a property at every call site" => wrap("this.setKey(this.backup);", SETTER),
  }.freeze

  RB_TEMPLATE = <<~RB
    require 'runar'

    class C < Runar::StatefulSmartContract
      prop :key, RabinPubKey

      def initialize(key)
        super(key)
        @key = key
      end

      runar_public msg: ByteString, sig: RabinSig, padding: ByteString
      def settle(msg, sig, padding)
        assert verify_rabin_sig(msg, sig, padding, @key)
      end

      runar_public new_key: RabinPubKey
      def rotate(new_key)
        @key = $V
        assert true
      end
    end
  RB

  # Bare property name on the left: an identifier target, not a local.
  SOL_BARE_TEMPLATE = <<~SOL
    pragma runar ^0.1.0;
    contract C is StatefulSmartContract {
        RabinPubKey key;
        constructor(RabinPubKey _key) { key = _key; }
        function settle(bytes msg, RabinSig sig, bytes padding) public {
            require(verifyRabinSig(msg, sig, padding, this.key));
        }
        function rotate(RabinPubKey newKey) public {
            key = $V;
            require(true);
        }
    }
  SOL

  def validation_errors(source, file_name = "C.runar.ts")
    parse_result = RunarCompiler.send(:_parse_source, source, file_name)
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil parse_result.contract, "fixture did not parse"
    RunarCompiler.send(:_validate, parse_result.contract).errors.map(&:message)
  end

  REFUSED.each_with_index do |(label, (src, prop)), i|
    define_method("test_refuses_#{i}_#{label.gsub(/\W+/, '_')}") do
      assert_includes validation_errors(src), self.class.msg(prop), label
    end
  end

  ACCEPTED.each_with_index do |(label, src), i|
    define_method("test_accepts_#{i}_#{label.gsub(/\W+/, '_')}") do
      assert_empty validation_errors(src), label
    end
  end

  def test_rb_surface_literal_write_accepted
    assert_empty validation_errors(RB_TEMPLATE.gsub("$V", "1000003"), "C.runar.rb")
  end

  def test_rb_surface_parameter_write_refused
    assert_includes validation_errors(RB_TEMPLATE.gsub("$V", "new_key"), "C.runar.rb"), self.class.msg("key")
  end

  def test_sol_bare_literal_write_accepted
    assert_empty validation_errors(SOL_BARE_TEMPLATE.gsub("$V", "1000003"), "C.runar.sol")
  end

  def test_sol_bare_parameter_write_refused
    assert_includes validation_errors(SOL_BARE_TEMPLATE.gsub("$V", "newKey"), "C.runar.sol"), self.class.msg("key")
  end
end

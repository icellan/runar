# frozen_string_literal: true

require_relative "../test_helper"

# Port of the TypeScript reference test
# `packages/runar-compiler/src/__tests__/f286-rabin-pubkey-provenance.test.ts`.
#
# F-286 -- verifyRabinSig's public key must come from the contract, not the
# spender. If the modulus `n` is a spending-method argument the spender picks
# it and forges any message (`n = 1`, `sig = 0` passes real Spend). The rule
# (user decision R78): the 4th argument must be a contract property or a
# literal, followed through local aliases and through private helpers whose
# parameter is bound to such a value at EVERY call site. One shared diagnostic.
#
# What this proves: the Ruby tier's validator refuses the spender-chosen
# modulus shapes below and still accepts the property / literal / alias /
# helper shapes, on the TS surface and on the `.runar.rb` surface.
# What it does NOT prove: the other tiers (conformance/negatives N220-N228),
# or a hostile `--ir` JSON naming a parameter as the modulus (`--ir` skips the
# frontend).
class TestF286RabinPubkeyProvenance < Minitest::Test
  MSG = "verifyRabinSig public key (4th argument) must be a contract property or a literal; " \
        "a spender-supplied Rabin modulus lets anyone forge a signature"

  HELPER = <<~TS
      private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
        return verifyRabinSig(m, s, p, k);
      }
  TS

  CHAIN = <<~TS
      private outer(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
        const kk = k;
        return this.inner(m, s, p, kk);
      }
      private inner(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
        return verifyRabinSig(m, s, p, k);
      }
  TS

  def self.wrap(body, extra_params = "", extra_methods = "")
    <<~TS
      import { SmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

      class C extends SmartContract {
        readonly pk: RabinPubKey;
        readonly pk2: RabinPubKey;

        constructor(pk: RabinPubKey, pk2: RabinPubKey) {
          super(pk, pk2);
          this.pk = pk;
          this.pk2 = pk2;
        }

        public settle(msg: ByteString, sig: RabinSig, padding: ByteString#{extra_params}) {
      #{body}
        }
      #{extra_methods}
      }
    TS
  end

  P = ", n: RabinPubKey"

  REFUSED = {
    "public method parameter" =>
      wrap("assert(verifyRabinSig(msg, sig, padding, n));", P),
    "const alias of a parameter" =>
      wrap("const k = n;\nassert(verifyRabinSig(msg, sig, padding, k));", P),
    "let alias initialised from a property, then reassigned from a parameter" =>
      wrap("let k = this.pk;\nk = n;\nassert(verifyRabinSig(msg, sig, padding, k));", P),
    "private helper whose parameter is bound to a public parameter" =>
      wrap("assert(this.check(msg, sig, padding, n));", P, HELPER),
    "private helper bound to a property at one call site and to a parameter at another" =>
      wrap("assert(this.check(msg, sig, padding, this.pk));\nassert(this.check(msg, sig, padding, n));", P, HELPER),
    "ternary between a property and a parameter" =>
      wrap("assert(verifyRabinSig(msg, sig, padding, sig > 0n ? this.pk : n));", P),
    "computed from a property" =>
      wrap("assert(verifyRabinSig(msg, sig, padding, this.pk + 1n));"),
    "parameter, inside a for loop nested in an if" =>
      wrap("if (sig > 0n) {\n  for (let i = 0n; i < 2n; i++) {\n    assert(verifyRabinSig(msg, sig, padding, n));\n  }\n}\nassert(true);", P),
  }.freeze

  ACCEPTED = {
    "this.<prop>" =>
      wrap("assert(verifyRabinSig(msg, sig, padding, this.pk));"),
    "bigint literal" =>
      wrap("assert(verifyRabinSig(msg, sig, padding, 1000003n));"),
    "const alias of a property" =>
      wrap("const k = this.pk;\nassert(verifyRabinSig(msg, sig, padding, k));"),
    "let alias reassigned only from properties" =>
      wrap("let k = this.pk;\nif (sig > 0n) { k = this.pk2; }\nassert(verifyRabinSig(msg, sig, padding, k));"),
    "private helper bound to a property at every call site" =>
      wrap("assert(this.check(msg, sig, padding, this.pk));\nassert(this.check(msg, sig, padding, this.pk2));", "", HELPER),
    "two-level private helper chain rooted in a property" =>
      wrap("assert(this.outer(msg, sig, padding, this.pk));", "", CHAIN),
  }.freeze

  RB_TEMPLATE = <<~RB
    require 'runar'

    class C < Runar::SmartContract
      prop :pk, RabinPubKey

      def initialize(pk)
        super(pk)
        @pk = pk
      end

      runar_public msg: ByteString, sig: RabinSig, padding: ByteString$P
      def settle(msg, sig, padding$Q)
        assert verify_rabin_sig(msg, sig, padding, $K)
      end
    end
  RB

  def validation_errors(source, file_name = "C.runar.ts")
    parse_result = RunarCompiler.send(:_parse_source, source, file_name)
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil parse_result.contract, "fixture did not parse"
    RunarCompiler.send(:_validate, parse_result.contract).errors.map(&:message)
  end

  REFUSED.each_with_index do |(label, src), i|
    define_method("test_refuses_#{i}_#{label.gsub(/\W+/, '_')}") do
      assert_includes validation_errors(src), MSG, label
    end
  end

  ACCEPTED.each_with_index do |(label, src), i|
    define_method("test_accepts_#{i}_#{label.gsub(/\W+/, '_')}") do
      assert_empty validation_errors(src), label
    end
  end

  def test_rb_surface_property_accepted
    src = RB_TEMPLATE.gsub("$P", "").gsub("$Q", "").gsub("$K", "@pk")
    assert_empty validation_errors(src, "C.runar.rb")
  end

  def test_rb_surface_method_parameter_refused
    src = RB_TEMPLATE.gsub("$P", ", n: RabinPubKey").gsub("$Q", ", n").gsub("$K", "n")
    assert_includes validation_errors(src, "C.runar.rb"), MSG
  end
end

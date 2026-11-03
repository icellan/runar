# frozen_string_literal: true

# N-050 (external StaticSiphon) — a static / class-level method is not a
# contract method and must never become a spending entry point.
#
# Before the fix this tier refused `public static` on .runar.ts only by
# accident ("Contract has no public methods"), and compiled `@Public static`
# on .runar.java, `@public @staticmethod` / `@classmethod` on .runar.py and a
# receiver-less `pub fn` on .runar.rs / .runar.zig into dispatch selectors
# (unsigned spend paths).
#
# The rule (TS reference, `staticMethodMessage` in errors.ts): every surface
# that can spell a static method refuses it, public or private, with
#
#   static methods are not allowed in Rúnar contracts; method '<m>' is declared static
#
# (<m> as written in the source). On .runar.rs / .runar.zig the spelling is a
# `pub fn` without a self receiver; a private receiver-less `fn` stays a
# helper, like a Go free function (R9).
#
# What this proves: the Ruby tier's frontend refuses every spelling with the
# reference text, and the non-static spellings still compile with the same
# public entry points.
# What it does NOT prove: the other tiers (their own suites, the runar-testing
# n050 spend test and conformance/negatives/N104-N111), or anything on chain.
#
# The compiler is invoked via subprocess for the same reason as
# test_f017_identifier_collision.rb: the parsers share a constant namespace.

require 'json'
require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class N050StaticMethodsTest < Minitest::Test
  RUBY_CLI = File.expand_path('../bin/runar-compiler-ruby', __dir__)

  def msg(name)
    "static methods are not allowed in Rúnar contracts; method '#{name}' is declared static"
  end

  def ts(decl)
    "import { SmartContract, Sig, PubKey, assert, checkSig } from 'runar-lang';\n" \
      "export class Vault extends SmartContract {\n" \
      "  readonly owner: PubKey;\n" \
      "  constructor(owner: PubKey) { super(owner); this.owner = owner; }\n" \
      "  #{decl} requirePositive(amount: bigint) { assert(amount > 0n); }\n" \
      "  public withdraw(sig: Sig) { assert(checkSig(sig, this.owner)); }\n" \
      "}\n"
  end

  def java(decl)
    "package x;\n" \
      "import runar.lang.SmartContract;\n" \
      "import runar.lang.annotations.Public;\n" \
      "import runar.lang.annotations.Readonly;\n" \
      "import runar.lang.types.PubKey;\n" \
      "import runar.lang.types.Sig;\n" \
      "import java.math.BigInteger;\n" \
      "import static runar.lang.Builtins.assertThat;\n" \
      "import static runar.lang.Builtins.checkSig;\n" \
      "class Vault extends SmartContract {\n" \
      "    @Readonly PubKey owner;\n" \
      "    Vault(PubKey owner) { super(owner); this.owner = owner; }\n" \
      "    #{decl} void requirePositive(BigInteger amount) { assertThat(amount.compareTo(BigInteger.ZERO) > 0); }\n" \
      "    @Public\n" \
      "    void withdraw(Sig sig) { assertThat(checkSig(sig, owner)); }\n" \
      "}\n"
  end

  def py(decorators, params)
    "from runar import SmartContract, Sig, PubKey, public, assert_, check_sig\n\n" \
      "class Vault(SmartContract):\n" \
      "    owner: PubKey\n\n" \
      "    def __init__(self, owner: PubKey):\n" \
      "        super().__init__(owner)\n" \
      "        self.owner = owner\n\n" \
      "#{decorators}\n" \
      "    def require_positive(#{params}):\n" \
      "        assert_(amount > 0)\n\n" \
      "    @public\n" \
      "    def withdraw(self, sig: Sig):\n" \
      "        assert_(check_sig(sig, self.owner))\n"
  end

  def rb(marker, name)
    "require 'runar'\n\n" \
      "class Vault < Runar::SmartContract\n" \
      "  prop :owner, PubKey\n\n" \
      "  def initialize(owner)\n" \
      "    super(owner)\n" \
      "    @owner = owner\n" \
      "  end\n" \
      "#{marker}\n" \
      "  def #{name}(amount)\n" \
      "    assert amount > 0\n" \
      "  end\n\n" \
      "  runar_public sig: Sig\n" \
      "  def withdraw(sig)\n" \
      "    assert check_sig(sig, @owner)\n" \
      "  end\n" \
      "end\n"
  end

  def rs(fn)
    "use runar::prelude::*;\n\n" \
      "#[runar::contract]\n" \
      "struct Vault {\n" \
      "    #[readonly]\n" \
      "    owner: PubKey,\n" \
      "}\n\n" \
      "impl Vault {\n" \
      "    #{fn}\n\n" \
      "    pub fn withdraw(&self, sig: &Sig) {\n" \
      "        assert!(check_sig(sig, &self.owner));\n" \
      "    }\n" \
      "}\n"
  end

  def zig(fn)
    "const runar = @import(\"runar\");\n\n" \
      "pub const Vault = struct {\n" \
      "    pub const Contract = runar.SmartContract;\n\n" \
      "    owner: runar.PubKey,\n\n" \
      "    pub fn init(owner: runar.PubKey) Vault {\n" \
      "        return .{ .owner = owner };\n" \
      "    }\n\n" \
      "    #{fn}\n\n" \
      "    pub fn withdraw(self: *const Vault, sig: runar.Sig) void {\n" \
      "        runar.assert(runar.checkSig(sig, self.owner));\n" \
      "    }\n" \
      "};\n"
  end

  RS_NO_SELF = "pub fn require_positive(amount: Int) {\n        assert!(amount > 0);\n    }"
  ZIG_NO_SELF = "pub fn requirePositive(amount: i64) void {\n        runar.assert(amount > 0);\n    }"

  def run_cli(source, file_name, *flags)
    Dir.mktmpdir do |dir|
      path = File.join(dir, file_name)
      File.write(path, source)
      Open3.capture3(RbConfig.ruby, RUBY_CLI, '--source', path, *flags)
    end
  end

  def assert_refused(source, file_name, name)
    stdout, stderr, status = run_cli(source, file_name, '--parse-only')
    refute_equal 0, status.exitstatus, "#{file_name} was accepted; it must be refused"
    assert_includes "#{stderr}\n#{stdout}", msg(name)
  end

  def assert_public(source, file_name, expected)
    stdout, stderr, status = run_cli(source, file_name)
    assert_equal 0, status.exitstatus, "#{file_name} was refused: #{stderr}"
    methods = JSON.parse(stdout).fetch('abi').fetch('methods')
    assert_equal expected, methods.reject { |m| m['isPublic'] == false }.map { |m| m['name'] }
  end

  def test_ts_static_refused
    ['public static', 'private static', 'static'].each do |decl|
      assert_refused(ts(decl), 'Vault.runar.ts', 'requirePositive')
    end
  end

  def test_java_static_refused
    ['@Public static', '@Public public static', 'static', 'private static', '@Public static final'].each do |decl|
      assert_refused(java(decl), 'Vault.runar.java', 'requirePositive')
    end
  end

  def test_py_staticmethod_and_classmethod_refused
    assert_refused(py("    @public\n    @staticmethod", 'amount: int'), 'Vault.runar.py', 'require_positive')
    assert_refused(py("    @staticmethod\n    @public", 'amount: int'), 'Vault.runar.py', 'require_positive')
    assert_refused(py('    @staticmethod', 'amount: int'), 'Vault.runar.py', 'require_positive')
    assert_refused(py("    @public\n    @classmethod", 'cls, amount: int'), 'Vault.runar.py', 'require_positive')
    assert_refused(py('    @classmethod', 'cls, amount: int'), 'Vault.runar.py', 'require_positive')
  end

  def test_rb_singleton_method_refused
    assert_refused(rb('  runar_public amount: Bigint', 'self.require_positive'), 'Vault.runar.rb', 'require_positive')
    assert_refused(rb('  params amount: Bigint', 'self.require_positive'), 'Vault.runar.rb', 'require_positive')
    assert_refused(rb('  runar_public amount: Bigint', 'Vault.require_positive'), 'Vault.runar.rb', 'require_positive')
  end

  def test_rs_zig_pub_fn_without_receiver_refused
    assert_refused(rs(RS_NO_SELF), 'Vault.runar.rs', 'require_positive')
    assert_refused(zig(ZIG_NO_SELF), 'Vault.runar.zig', 'requirePositive')
  end

  def test_non_static_spellings_still_compile
    both = %w[requirePositive withdraw]
    assert_public(ts('public'), 'Vault.runar.ts', both)
    assert_public(ts('private'), 'Vault.runar.ts', ['withdraw'])
    assert_public(java('@Public'), 'Vault.runar.java', both)
    assert_public(java('private'), 'Vault.runar.java', ['withdraw'])
    assert_public(py('    @public', 'self, amount: int'), 'Vault.runar.py', both)
    assert_public(rb('  runar_public amount: Bigint', 'require_positive'), 'Vault.runar.rb', both)
    assert_public(rs("pub fn require_positive(&self, amount: Int) {\n        assert!(amount > 0);\n    }"), 'Vault.runar.rs', both)
    assert_public(rs("fn require_positive(amount: Int) {\n        assert!(amount > 0);\n    }"), 'Vault.runar.rs', ['withdraw'])
    assert_public(zig("pub fn requirePositive(self: *const Vault, amount: i64) void {\n        _ = self;\n        runar.assert(amount > 0);\n    }"), 'Vault.runar.zig', both)
    assert_public(zig("fn requirePositive(amount: i64) void {\n        runar.assert(amount > 0);\n    }"), 'Vault.runar.zig', ['withdraw'])
  end
end

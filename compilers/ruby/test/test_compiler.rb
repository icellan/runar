# frozen_string_literal: true

require 'ostruct'
require_relative 'test_helper'

class TestCompiler < Minitest::Test
  # Conformance test directory relative to repo root
  CONFORMANCE_DIR = File.expand_path('../../../conformance/tests', __dir__)

  def compile_ts_source(source, file_name = 'Test.runar.ts')
    parse_result = RunarCompiler.send(:_parse_source, source, file_name)
    raise "parse errors: #{parse_result.error_strings.join('; ')}" if parse_result.errors.any?
    raise "no contract found" if parse_result.contract.nil?

    val_result = RunarCompiler.send(:_validate, parse_result.contract)
    assert_empty val_result.errors.map(&:format_message), "validation errors"

    tc_result = RunarCompiler.send(:_type_check, parse_result.contract)
    assert_empty tc_result.errors.map(&:format_message), "type check errors"

    program = RunarCompiler.send(:_lower_to_anf, parse_result.contract)
    RunarCompiler.compile_from_program(program, disable_constant_folding: true)
  end

  # NOTE: The Ruby compiler's TS and Ruby parsers share a namespace for token
  # constants. Loading both in the same process causes constant collisions that
  # can corrupt tokenization. We compile Ruby-format sources via subprocess to
  # avoid this. This is a known pre-existing issue in the Ruby compiler.
  def compile_rb_source(source, file_name = 'Test.runar.rb')
    require 'tempfile'
    require 'json'

    tmpfile = Tempfile.new([File.basename(file_name, '.*'), '.runar.rb'])
    tmpfile.write(source)
    tmpfile.close

    lib_dir = File.expand_path('../lib', __dir__)
    out = `ruby -I#{lib_dir} -e "
      require 'runar_compiler'
      require 'json'
      a = RunarCompiler.compile_from_source('#{tmpfile.path}', disable_constant_folding: true)
      puts JSON.generate({ name: a.contract_name, script: a.script })
    " 2>&1`

    tmpfile.unlink

    unless $?.success?
      flunk "Ruby compilation failed: #{out}"
    end

    data = JSON.parse(out.lines.last)
    OpenStruct.new(contract_name: data['name'], script: data['script'])
  end

  # ------------------------------------------------------------------
  # Basic compilation tests
  # ------------------------------------------------------------------

  def test_compile_p2pkh_ts
    source = <<~TS
      import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

      class P2PKH extends SmartContract {
        readonly pubKeyHash: Addr;

        constructor(pubKeyHash: Addr) {
          super(pubKeyHash);
          this.pubKeyHash = pubKeyHash;
        }

        public unlock(sig: Sig, pubKey: PubKey): void {
          assert(hash160(pubKey) === this.pubKeyHash);
          assert(checkSig(sig, pubKey));
        }
      }
    TS

    artifact = compile_ts_source(source, 'P2PKH.runar.ts')
    assert_equal 'P2PKH', artifact.contract_name
    assert artifact.script.length > 0, "script should be non-empty"
    # P2PKH script contains OP_DUP, OP_HASH160, OP_CHECKSIG — use ASM to avoid
    # spurious matches inside push data bytes
    assert_includes artifact.asm, 'OP_DUP'
    assert_includes artifact.asm, 'OP_HASH160'
    assert_includes artifact.asm, 'OP_CHECKSIG'
  end

  def test_compile_p2pkh_rb
    source = <<~RB
      class P2PKH < Runar::SmartContract
        prop :pub_key_hash, Addr

        def initialize(pub_key_hash)
          super(pub_key_hash)
          @pub_key_hash = pub_key_hash
        end

        runar_public sig: Sig, pub_key: PubKey
        def unlock(sig, pub_key)
          assert hash160(pub_key) == @pub_key_hash
          assert check_sig(sig, pub_key)
        end
      end
    RB

    artifact = compile_rb_source(source, 'P2PKH.runar.rb')
    assert_equal 'P2PKH', artifact.contract_name
    assert artifact.script.length > 0, "script should be non-empty"
  end

  def test_ts_and_rb_produce_same_script
    ts_source = <<~TS
      import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

      class P2PKH extends SmartContract {
        readonly pubKeyHash: Addr;

        constructor(pubKeyHash: Addr) {
          super(pubKeyHash);
          this.pubKeyHash = pubKeyHash;
        }

        public unlock(sig: Sig, pubKey: PubKey): void {
          assert(hash160(pubKey) === this.pubKeyHash);
          assert(checkSig(sig, pubKey));
        }
      }
    TS

    rb_source = <<~RB
      class P2PKH < Runar::SmartContract
        prop :pub_key_hash, Addr

        def initialize(pub_key_hash)
          super(pub_key_hash)
          @pub_key_hash = pub_key_hash
        end

        runar_public sig: Sig, pub_key: PubKey
        def unlock(sig, pub_key)
          assert hash160(pub_key) == @pub_key_hash
          assert check_sig(sig, pub_key)
        end
      end
    RB

    ts_artifact = compile_ts_source(ts_source, 'P2PKH.runar.ts')
    rb_artifact = compile_rb_source(rb_source, 'P2PKH.runar.rb')
    assert_equal ts_artifact.script.downcase, rb_artifact.script.downcase,
                 "TS and Ruby parsers should produce identical script"
  end

  # ------------------------------------------------------------------
  # Conformance golden-file tests
  # ------------------------------------------------------------------

  def test_conformance_basic_p2pkh_ts
    ts_path = ConformanceFixture.resolve('basic-p2pkh', '.runar.ts')
    expected_hex = File.read(File.join(CONFORMANCE_DIR, 'basic-p2pkh', 'expected-script.hex')).strip

    artifact = RunarCompiler.compile_from_source(ts_path, disable_constant_folding: true)
    assert_equal expected_hex.downcase, artifact.script.downcase,
                 "compiled script should match conformance golden file"
  end

  def test_conformance_basic_p2pkh_rb
    rb_path = ConformanceFixture.resolve('basic-p2pkh', '.runar.rb')
    expected_hex = File.read(File.join(CONFORMANCE_DIR, 'basic-p2pkh', 'expected-script.hex')).strip

    artifact = RunarCompiler.compile_from_source(rb_path, disable_constant_folding: true)
    assert_equal expected_hex.downcase, artifact.script.downcase,
                 "compiled script should match conformance golden file"
  end

  # ------------------------------------------------------------------
  # Conformance golden-file tests (F-328)
  # ------------------------------------------------------------------
  # Each test compiles the fixture's .runar.ts source via the Ruby
  # compiler's in-process API and compares the hex output to
  # expected-script.hex.
  #
  # F-328: the fixture list used to be a hand-maintained, 28-entry
  # hard-coded hash that silently excluded every conformance fixture
  # added after it was written (56 of 84 ruby-eligible fixtures untested
  # by the time this was fixed; the corpus has grown from 72 to 88 since
  # the gap was reported). CONFORMANCE_TESTS is now derived from the
  # conformance/tests corpus itself, honoring each fixture's source.json
  # "compilers" allowlist (conformance/README.md "Per-fixture compiler
  # allowlist") the same way test_conformance_goldens.rb's
  # read_compiler_allowlist (F-264) and the TS runner do: a fixture that
  # opts ruby out is skipped (no test generated), not silently dropped by
  # omission from an unrelated list.
  #
  # Every fixture in the corpus ships a .runar.ts source (verified across
  # all 88 as of this fix), so there is no longer a need for the old
  # per-fixture extension table or its .runar.zig fallback -- that
  # fallback predated the source.json migration that gave every fixture a
  # TS source and is no longer reachable.
  CONFORMANCE_TESTS = Dir.children(CONFORMANCE_DIR)
                          .select { |name| File.directory?(File.join(CONFORMANCE_DIR, name)) }
                          .reject { |name| ConformanceFixture.compiler_excluded?(name, 'ruby') }
                          .sort
                          .freeze

  CONFORMANCE_TESTS.each do |test_dir|
    method_name = "test_conformance_#{test_dir.gsub('-', '_')}"

    define_method(method_name) do
      hex_path = File.join(CONFORMANCE_DIR, test_dir, 'expected-script.hex')
      assert File.exist?(hex_path), "expected-script.hex missing for #{test_dir}"

      source_path = ConformanceFixture.resolve(test_dir, '.runar.ts')
      expected_hex = File.read(hex_path).strip

      artifact = RunarCompiler.compile_from_source(source_path, disable_constant_folding: true)
      assert_equal expected_hex.downcase, artifact.script.downcase,
                   "#{test_dir}: compiled script should match conformance golden file"
    end
  end

  # ------------------------------------------------------------------
  # Error handling tests
  # ------------------------------------------------------------------

  def test_parse_error_for_invalid_source
    assert_raises(RuntimeError) do
      compile_ts_source("this is not valid typescript", 'bad.runar.ts')
    end
  end

  def test_artifact_has_expected_structure
    source = <<~TS
      import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

      class P2PKH extends SmartContract {
        readonly pubKeyHash: Addr;

        constructor(pubKeyHash: Addr) {
          super(pubKeyHash);
          this.pubKeyHash = pubKeyHash;
        }

        public unlock(sig: Sig, pubKey: PubKey): void {
          assert(hash160(pubKey) === this.pubKeyHash);
          assert(checkSig(sig, pubKey));
        }
      }
    TS

    artifact = compile_ts_source(source, 'P2PKH.runar.ts')
    assert_respond_to artifact, :contract_name
    assert_respond_to artifact, :script
    assert_respond_to artifact, :abi
    assert_respond_to artifact, :asm
    assert_equal 'P2PKH', artifact.contract_name
    assert_kind_of String, artifact.script

    # ABI should have constructor and methods
    assert artifact.abi.constructor
    assert_kind_of Array, artifact.abi.methods
    assert_equal 1, artifact.abi.methods.length
    assert_equal 'unlock', artifact.abi.methods.first.name
    assert artifact.abi.methods.first.is_public
  end

  # Regression: the `Bool` type alias must compile through the full pipeline
  # (parse -> validate -> typecheck -> emit) exactly like `Boolean`. The cross-
  # tier IR fuzzer's Ruby renderer emits `prop :x, Bool` / `param: Bool`, and
  # the TS reference (plus all other 6 tiers) accept boolean properties/params.
  # Ruby only mapped `Boolean`, so `Bool` fell through to a CustomType and the
  # validator/typechecker rejected it, over-rejecting contracts the other tiers
  # accept.
  def test_compile_bool_alias_rb
    source = <<~RB
      class BoolAlias < Runar::SmartContract
        prop :flag1, Bool
        prop :flag2, Bool

        def initialize(flag1, flag2)
          super(flag1, flag2)
          @flag1 = flag1
          @flag2 = flag2
        end

        runar_public a: Bool, b: Bool
        def check(a, b)
          assert (a && b) || (!(@flag1) || @flag2)
        end
      end
    RB

    artifact = compile_rb_source(source, 'BoolAlias.runar.rb')
    assert_equal 'BoolAlias', artifact.contract_name
    assert artifact.script.length > 0, "script should be non-empty"
  end

  # F-328 regression guard: every ruby-eligible conformance fixture must
  # have a generated test_conformance_<fixture> method in this file. This
  # is the permanent check that CONFORMANCE_TESTS can't silently regress
  # back into a stale hard-coded subset (the original defect) -- e.g. if
  # someone reverts to a literal array/hash, or the glob/allowlist logic
  # breaks and quietly drops fixtures.
  #
  # What this proves: for every fixture directory under conformance/tests
  # whose source.json "compilers" allowlist does not exclude "ruby", a
  # test_conformance_<fixture> method is defined on this class -- i.e.
  # the corpus, not a hand-maintained list, determines what gets tested.
  #
  # What this does NOT prove: that those generated tests pass (that's
  # test_conformance_<fixture> itself, run elsewhere in this same file),
  # nor anything about the .runar.rb format or ANF IR for these fixtures
  # -- that full-corpus, allowlist-aware, IR+hex comparison is
  # test_conformance_goldens.rb's test_conformance_goldens_ruby (F-264),
  # which this test deliberately does not duplicate.
  def test_conformance_tests_covers_every_ruby_eligible_fixture
    eligible = Dir.children(CONFORMANCE_DIR)
                   .select { |name| File.directory?(File.join(CONFORMANCE_DIR, name)) }
                   .reject { |name| ConformanceFixture.compiler_excluded?(name, 'ruby') }
                   .sort

    missing = eligible.reject do |name|
      self.class.method_defined?("test_conformance_#{name.gsub('-', '_')}")
    end

    assert_empty missing,
                 "ruby-eligible conformance fixtures with no generated test_compiler.rb test: #{missing.join(', ')}"
  end
end

# frozen_string_literal: true

require_relative 'test_helper'
require 'ostruct'

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
    # P2PKH script contains OP_DUP (76), OP_HASH160 (a9), OP_CHECKSIG (ac)
    assert_includes artifact.script.downcase, '76'
    assert_includes artifact.script.downcase, 'a9'
    assert_includes artifact.script.downcase, 'ac'
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
    return skip("conformance dir not found") unless File.directory?(CONFORMANCE_DIR)

    ts_path = File.join(CONFORMANCE_DIR, 'basic-p2pkh', 'basic-p2pkh.runar.ts')
    expected_hex = File.read(File.join(CONFORMANCE_DIR, 'basic-p2pkh', 'expected-script.hex')).strip
    return skip("conformance files not found") unless File.exist?(ts_path)

    artifact = RunarCompiler.compile_from_source(ts_path, disable_constant_folding: true)
    assert_equal expected_hex.downcase, artifact.script.downcase,
                 "compiled script should match conformance golden file"
  end

  def test_conformance_basic_p2pkh_rb
    return skip("conformance dir not found") unless File.directory?(CONFORMANCE_DIR)

    rb_path = File.join(CONFORMANCE_DIR, 'basic-p2pkh', 'basic-p2pkh.runar.rb')
    expected_hex = File.read(File.join(CONFORMANCE_DIR, 'basic-p2pkh', 'expected-script.hex')).strip
    return skip("conformance files not found") unless File.exist?(rb_path)

    # Compile via subprocess to avoid in-process token-constant collision
    # between parser_ruby and parser_ts (see comment on compile_rb_source).
    artifact = compile_rb_source(File.read(rb_path), 'basic-p2pkh.runar.rb')
    assert_equal expected_hex.downcase, artifact.script.downcase,
                 "compiled script should match conformance golden file"
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
end

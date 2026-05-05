# frozen_string_literal: true

require_relative "test_helper"

# Multi-format compilation tests.
#
# Verifies that the same contract compiled from different source formats
# produces identical hex output. The Ruby compiler supports .runar.ts,
# .runar.sol, .runar.move, .runar.go, .runar.rs, .runar.py, .runar.rb,
# and .runar.zig.

class TestMultiFormat < Minitest::Test
  CONFORMANCE_DIR = File.expand_path("../../../conformance/tests", __dir__)
  BASIC_P2PKH_DIR = File.join(CONFORMANCE_DIR, "basic-p2pkh")

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Compile the basic-p2pkh fixture for a given extension (resolved via
  # source.json). Uses subprocess for .runar.rb to avoid tokenizer namespace
  # collision with the .runar.ts parser.
  def compile_conformance_ext(ext)
    path = ConformanceFixture.resolve("basic-p2pkh", ext)
    if ext == ".runar.rb"
      compile_rb_subprocess(path)
    else
      artifact = RunarCompiler.compile_from_source(path, disable_constant_folding: true)
      artifact.script.downcase
    end
  end

  # Compile a .runar.rb file via subprocess to avoid token constant collision.
  def compile_rb_subprocess(path)
    require "json"
    lib_dir = File.expand_path("../lib", __dir__)
    out = `ruby -I#{lib_dir} -e "
      require 'runar_compiler'
      require 'json'
      a = RunarCompiler.compile_from_source('#{path}', disable_constant_folding: true)
      puts a.script
    " 2>&1`

    unless $?.success?
      flunk "Ruby compilation failed: #{out}"
    end

    out.strip.downcase
  end

  def expected_hex
    hex_path = File.join(BASIC_P2PKH_DIR, "expected-script.hex")
    assert File.exist?(hex_path), "expected-script.hex missing"
    File.read(hex_path).strip.downcase
  end

  # ---------------------------------------------------------------------------
  # 1. TypeScript format matches golden file
  # ---------------------------------------------------------------------------

  def test_ts_matches_golden
    hex = compile_conformance_ext(".runar.ts")
    assert_equal expected_hex, hex, ".runar.ts should match expected hex"
  end

  # ---------------------------------------------------------------------------
  # 2. Solidity format matches golden file
  # ---------------------------------------------------------------------------

  def test_sol_matches_golden
    hex = compile_conformance_ext(".runar.sol")
    assert_equal expected_hex, hex, ".runar.sol should match expected hex"
  end

  # ---------------------------------------------------------------------------
  # 3. Move format matches golden file
  # ---------------------------------------------------------------------------

  def test_move_matches_golden
    hex = compile_conformance_ext(".runar.move")
    assert_equal expected_hex, hex, ".runar.move should match expected hex"
  end

  # ---------------------------------------------------------------------------
  # 4. Go format matches golden file
  # ---------------------------------------------------------------------------

  def test_go_matches_golden
    hex = compile_conformance_ext(".runar.go")
    assert_equal expected_hex, hex, ".runar.go should match expected hex"
  end

  # ---------------------------------------------------------------------------
  # 5. Rust format matches golden file
  # ---------------------------------------------------------------------------

  def test_rs_matches_golden
    hex = compile_conformance_ext(".runar.rs")
    assert_equal expected_hex, hex, ".runar.rs should match expected hex"
  end

  # ---------------------------------------------------------------------------
  # 6. Python format matches golden file
  # ---------------------------------------------------------------------------

  def test_py_matches_golden
    hex = compile_conformance_ext(".runar.py")
    assert_equal expected_hex, hex, ".runar.py should match expected hex"
  end

  # ---------------------------------------------------------------------------
  # 7. Ruby format matches golden file
  # ---------------------------------------------------------------------------

  def test_rb_matches_golden
    hex = compile_conformance_ext(".runar.rb")
    assert_equal expected_hex, hex, ".runar.rb should match expected hex"
  end

  # ---------------------------------------------------------------------------
  # 8. Zig format matches golden file
  # ---------------------------------------------------------------------------

  def test_zig_matches_golden
    zig_file = ConformanceFixture.resolve("basic-p2pkh", ".runar.zig")

    artifact = RunarCompiler.compile_from_source(zig_file, disable_constant_folding: true)
    hex = artifact.script.downcase
    assert_equal expected_hex, hex, ".runar.zig should match expected hex"
  end

  # ---------------------------------------------------------------------------
  # 9. All non-Ruby formats produce identical output
  # ---------------------------------------------------------------------------

  def test_all_non_rb_formats_identical
    exts = %w[.runar.ts .runar.sol .runar.move .runar.go .runar.rs .runar.py]

    scripts = {}
    exts.each do |ext|
      path = ConformanceFixture.resolve("basic-p2pkh", ext)
      artifact = RunarCompiler.compile_from_source(path, disable_constant_folding: true)
      scripts[ext] = artifact.script.downcase
    end

    reference_ext, reference_hex = scripts.first
    scripts.each do |ext, hex|
      assert_equal reference_hex, hex,
                   "#{ext} should produce identical script to #{reference_ext}"
    end
  end

  # ---------------------------------------------------------------------------
  # 10. Unsupported extension raises error
  # ---------------------------------------------------------------------------

  def test_unsupported_extension_raises
    assert_raises(ArgumentError) do
      RunarCompiler.send(:_parse_source, "anything", "test.runar.xyz")
    end
  end
end

# frozen_string_literal: true

# GK-GAP-005 / GK-GAP-006 -- one file-extension dispatch rule in every tier.
#
# The rule (user decision): the nine .runar.* suffixes match ignoring ASCII
# case, any other suffix is refused with the shared unsupported-extension
# diagnostic, and NO file name (nil or "") means the TypeScript surface.
#
# Proves: upper- and lower-case spellings of a suffix compile to the same hex
# through the CLI; a valid TypeScript contract saved as .runar.xyz is refused
# by the library dispatcher and the CLI with the shared diagnostic; the
# library dispatcher parses TypeScript when given no file name.
# Does not prove: the other six tiers (conformance/negatives covers them).
#
# Everything runs in child processes: this tier's TS and Ruby parsers share a
# constant namespace (see test_conformance_goldens.rb).

require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class GK005ExtensionDispatchTest < Minitest::Test
  DIR = File.expand_path('..', __dir__)
  CLI = File.join(DIR, 'bin/runar-compiler-ruby')
  REPO = File.expand_path('../../..', __dir__)
  TS = File.read(File.join(REPO, 'examples/ts/p2pkh/P2PKH.runar.ts'))
  PY = File.read(File.join(REPO, 'examples/python/p2pkh/P2PKH.runar.py'))
  EXPECTED = '(expected .runar.ts, .runar.sol, .runar.move, .runar.go, .runar.rs, ' \
             '.runar.py, .runar.rb, .runar.zig, or .runar.java)'

  def cli(file, src)
    Dir.mktmpdir do |d|
      path = File.join(d, file)
      File.write(path, src)
      out, err, st = Open3.capture3(RbConfig.ruby, CLI, '--source', path, '--hex')
      [st.success?, out, "#{out}\n#{err}"]
    end
  end

  # Runs the library dispatcher in a child: prints the contract name or the
  # error message. `name_expr` is Ruby source for the file-name argument.
  def library(src, name_expr)
    Dir.mktmpdir do |d|
      path = File.join(d, 'src')
      File.write(path, src)
      script = <<~RUBY
        require_relative #{File.join(DIR, 'lib/runar_compiler').inspect}
        begin
          r = RunarCompiler.send(:_parse_source, File.read(#{path.inspect}), #{name_expr})
          puts(r.contract ? "NAME:\#{r.contract.name}" : "ERRS:\#{r.errors.map(&:message).join('|')}")
        rescue StandardError => e
          puts "RAISED:\#{e.class}:\#{e.message}"
        end
      RUBY
      out, err, _st = Open3.capture3(RbConfig.ruby, '-e', script)
      "#{out}#{err}".strip
    end
  end

  [%w[P2PKH.runar.ts P2PKH.RUNAR.TS ts], %w[P2PKH.runar.py P2PKH.RUNAR.PY py]].each do |lower, upper, kind|
    define_method("test_case_insensitive_#{kind}") do
      src = kind == 'ts' ? TS : PY
      ok_a, hex_a, diag_a = cli(lower, src)
      ok_b, hex_b, diag_b = cli(upper, src)
      assert ok_a, diag_a
      assert ok_b, diag_b
      refute_empty hex_a.strip
      assert_equal hex_a, hex_b
    end
  end

  def test_unknown_suffix_refused_by_cli
    ok, _out, diag = cli('P2PKH.runar.xyz', TS)
    refute ok
    assert_includes diag, 'unsupported file extension: '
    assert_includes diag, EXPECTED
  end

  def test_unknown_suffix_refused_by_library
    assert_equal "RAISED:ArgumentError:unsupported file extension: P2PKH.runar.xyz #{EXPECTED}",
                 library(TS, "'P2PKH.runar.xyz'")
  end

  def test_no_file_name_is_typescript
    assert_equal 'NAME:P2PKH', library(TS, 'nil')
    assert_equal 'NAME:P2PKH', library(TS, "''")
  end
end

# frozen_string_literal: true

# GK-GAP-013 -- ANF lowering refuses malformed intent-intrinsic calls.
#
# extractPrevOutputScript with the wrong arity or a non-literal index / prefix
# length, and requireOutputP2PKH with the wrong arity or a non-literal index,
# used to lower to `load_const ""`, silently dropping the hash assertion or
# output pin. Typecheck refuses every shape first, but lower_to_anf is a public
# entry point (R-012). Corpus: conformance/negatives/intent-shape-cases.json.
#
# Proves: lower_to_anf on each parsed, un-typechecked shape raises the case's
# message; the CLI still refuses each shape at typecheck.
# Does not prove: the other six tiers.

require 'json'
require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class GK013IntentShapeBackstopTest < Minitest::Test
  DIR = File.expand_path('..', __dir__)
  CLI = File.join(DIR, 'bin/runar-compiler-ruby')
  CASES = JSON.parse(File.read(File.expand_path(
    '../../../conformance/negatives/intent-shape-cases.json', __dir__
  )))['cases']

  def lower(src)
    Dir.mktmpdir do |d|
      path = File.join(d, 'Bad.runar.ts')
      File.write(path, src)
      script = <<~RUBY
        require_relative #{File.join(DIR, 'lib/runar_compiler').inspect}
        r = RunarCompiler.send(:_parse_source, File.read(#{path.inspect}), 'Bad.runar.ts')
        abort("PARSE: \#{r.errors.map(&:message)}") if r.contract.nil? || !r.errors.empty?
        begin
          RunarCompiler::Frontend.lower_to_anf(r.contract)
          puts 'LOWERED'
        rescue StandardError => e
          puts "REFUSED: \#{e.message}"
        end
      RUBY
      out, err, _st = Open3.capture3(RbConfig.ruby, '-e', script)
      "#{out}#{err}".strip
    end
  end

  def cli(src)
    Dir.mktmpdir do |d|
      path = File.join(d, 'Bad.runar.ts')
      File.write(path, src)
      out, err, st = Open3.capture3(RbConfig.ruby, CLI, '--source', path, '--hex')
      [st.success?, "#{out}\n#{err}"]
    end
  end

  CASES.each do |c|
    define_method("test_lowerer_refuses_#{c['name'].tr('-', '_')}") do
      assert_equal "REFUSED: #{c['lowerError']}", lower(c['src'])
    end

    define_method("test_cli_still_refuses_#{c['name'].tr('-', '_')}") do
      ok, out = cli(c['src'])
      refute ok, out
      refute_includes out, c['lowerError'], 'typecheck must answer before the lowerer'
    end
  end
end

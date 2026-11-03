# frozen_string_literal: true

require "open3"
require_relative "test_helper"

# N-136-FU: regression on N-136 (c1af8cdd), which added
# `RunarCompiler::Frontend::InputLimits.assert_source_bytes_under_limit(source)`
# as the first statement of every format parser's `parse_<fmt>` entry point
# (parser_ts.rb, parser_sol.rb, parser_move.rb, parser_go.rb, parser_rust.rb,
# parser_ruby.rb, parser_zig.rb, parser_python.rb, parser_java.rb).
#
# None of those nine files `require_relative "input_limits"` themselves. The
# constant is only ever loaded as a side effect of `RunarCompiler._parse_source`
# in compiler.rb, which does `require_relative "frontend/input_limits"` before
# dispatching to a format parser. Any caller that requires a parser file
# directly -- as seven existing test files in this suite do, each run in its
# own subprocess by the Rakefile -- gets
# `NameError: uninitialized constant RunarCompiler::Frontend::InputLimits`
# the moment it calls a `parse_<fmt>` method, before a single byte of the
# source is tokenized.
#
# This test proves the standalone-require path for EACH of the nine parsers in
# a fresh `ruby -Ilib` subprocess that requires ONLY that one parser file (no
# compiler.rb, no other parser) and then calls its `parse_<fmt>` method. Before
# the fix, every one of the nine fails with that NameError. The fix is a
# one-line `require_relative "input_limits"` added to each of the nine parser
# files, mirroring what `ir/loader.rb` already does for
# `RunarCompiler::IR::InputLimits` (checked here too, as a non-regression
# control: the loader was never broken this way).
class TestN136FuParserInputLimitsStandaloneRequire < Minitest::Test
  LIB_DIR = File.expand_path("../lib", __dir__)

  # file => [parse method name, a file_name extension accepted by that parser]
  PARSERS = {
    "runar_compiler/frontend/parser_ts" => "parse_ts",
    "runar_compiler/frontend/parser_sol" => "parse_sol",
    "runar_compiler/frontend/parser_move" => "parse_move",
    "runar_compiler/frontend/parser_go" => "parse_go",
    "runar_compiler/frontend/parser_rust" => "parse_rust",
    "runar_compiler/frontend/parser_ruby" => "parse_ruby",
    "runar_compiler/frontend/parser_zig" => "parse_zig",
    "runar_compiler/frontend/parser_python" => "parse_python",
    "runar_compiler/frontend/parser_java" => "parse_java",
  }.freeze

  # Run `require "<require_path>"` in a brand-new interpreter and call
  # `RunarCompiler::Frontend.<method>("", "x")` -- the empty source is enough
  # because InputLimits.assert_source_bytes_under_limit is the FIRST statement
  # in every parse_<fmt> method, so it executes (and would raise the NameError)
  # before the real tokenizer ever looks at the content.
  def run_parser_standalone(require_path, method)
    program = <<~RUBY
      require #{require_path.inspect}
      begin
        RunarCompiler::Frontend.#{method}("", "x")
        print "OK"
      rescue NameError => e
        print "NAME_ERROR: " + e.message
      end
    RUBY
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, "-I", LIB_DIR, "-e", program)
    [stdout, stderr, status]
  end

  PARSERS.each do |require_path, method|
    define_method("test_#{method}_standalone_require_does_not_raise_name_error") do
      stdout, stderr, status = run_parser_standalone(require_path, method)

      refute_match(/NAME_ERROR/, stdout,
                   "#{require_path} must require its own InputLimits dependency; " \
                   "requiring it standalone and calling #{method} raised " \
                   "a NameError instead of running the DoS-bound size guard.\n" \
                   "stdout: #{stdout}\nstderr: #{stderr}")
      assert status.success?,
             "#{require_path} subprocess exited non-zero unexpectedly.\n" \
             "stdout: #{stdout}\nstderr: #{stderr[-2000..] || stderr}"
      assert_equal "OK", stdout
    end
  end

  # Non-regression control: ir/loader.rb already requires its own
  # `RunarCompiler::IR::InputLimits` dependency (ir/input_limits.rb) and was
  # never affected by this bug. Pinned here so the fix does not mask a future
  # regression in the loader by accident.
  def test_ir_loader_standalone_require_does_not_raise_name_error
    program = <<~RUBY
      require "runar_compiler/ir/loader"
      begin
        RunarCompiler::IR.load_ir("{}")
        print "OK"
      rescue NameError => e
        print "NAME_ERROR: " + e.message
      rescue StandardError
        # Any other error (e.g. missing required IR fields) means the
        # InputLimits guard itself resolved fine -- that's all this control
        # checks.
        print "OK"
      end
    RUBY
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, "-I", LIB_DIR, "-e", program)

    refute_match(/NAME_ERROR/, stdout,
                 "ir/loader.rb unexpectedly raised a NameError for its own " \
                 "InputLimits dependency.\nstdout: #{stdout}\nstderr: #{stderr}")
    assert status.success?, "ir/loader.rb subprocess exited non-zero.\nstderr: #{stderr}"
  end
end

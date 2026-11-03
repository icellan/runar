# frozen_string_literal: true

# F-210 / CL-BUG-034 — the Rakefile's `rake test` task counted a test file
# that registers ZERO minitest tests as a PASS (it only checked
# `$?.success?`, and a file with no `test_*` methods still exits 0), and
# `$?.success?` raised NoMethodError instead of reporting a failure when
# `system` could not spawn the subprocess at all (`$?` is `nil`, not
# `false`, in that case).
#
# What this proves: RunarCompiler::TestRunner (rakelib/test_runner.rb, which
# the Rakefile's :test task now calls) reports FAILED, naming the offending
# file, for (a) a file that runs zero tests and (b) a spawn failure — and
# does NOT raise. The end-to-end test additionally drives the real Rakefile
# copied into a scratch directory and asserts `rake test` exits non-zero
# when one of its test files runs zero tests.
# What this does NOT prove: that every CURRENT test file under
# compilers/ruby/test runs at least one test (that is a property of this
# repo's test suite, not of the runner) — see test_glob_excludes_test_helper
# below for the one legitimate zero-test file this glob used to pick up.
require_relative "test_helper"
require_relative "../rakelib/test_runner"

require "stringio"
require "tmpdir"
require "fileutils"

class TestRakeTestRunner < Minitest::Test
  def test_zero_test_file_is_reported_as_failed_naming_the_file
    Dir.mktmpdir("runar-rake-test-runner") do |dir|
      path = File.join(dir, "test_zero.rb")
      File.write(path, <<~RUBY)
        require 'minitest/autorun'
        class ZeroTests < Minitest::Test
          # intentionally defines no test_* method
        end
      RUBY

      result = RunarCompiler::TestRunner.run_file(path, out: StringIO.new)

      assert result.failed, "a file that registers zero minitest tests must be reported as FAILED"
      assert_equal 0, result.runs
      assert_includes result.reason, path
    end
  end

  def test_passing_file_is_not_reported_as_failed
    Dir.mktmpdir("runar-rake-test-runner") do |dir|
      path = File.join(dir, "test_pass.rb")
      File.write(path, <<~RUBY)
        require 'minitest/autorun'
        class PassingTest < Minitest::Test
          def test_truth
            assert true
          end
        end
      RUBY

      result = RunarCompiler::TestRunner.run_file(path, out: StringIO.new)

      refute result.failed
      assert_equal 1, result.runs
      assert_equal 1, result.assertions
    end
  end

  def test_spawn_failure_is_reported_as_failed_and_does_not_raise
    nonexistent_binary = "/nonexistent/path/to/a/ruby-binary-that-does-not-exist"

    result = RunarCompiler::TestRunner.run_file(
      "irrelevant.rb",
      command: [nonexistent_binary, "-e", "1"],
      out: StringIO.new
    )

    assert result.failed
    assert_includes result.reason, "could not spawn"
  end

  def test_rake_test_task_exits_nonzero_when_a_file_runs_zero_tests
    Dir.mktmpdir("runar-rake-integration") do |dir|
      FileUtils.mkdir_p(File.join(dir, "test"))
      FileUtils.mkdir_p(File.join(dir, "lib"))
      FileUtils.mkdir_p(File.join(dir, "rakelib"))

      File.write(File.join(dir, "test", "test_zero.rb"), <<~RUBY)
        require 'minitest/autorun'
        class ZeroTests < Minitest::Test
        end
      RUBY

      File.write(File.join(dir, "test", "test_pass.rb"), <<~RUBY)
        require 'minitest/autorun'
        class PassingTest < Minitest::Test
          def test_truth
            assert true
          end
        end
      RUBY

      FileUtils.cp(
        File.expand_path("../Rakefile", __dir__),
        File.join(dir, "Rakefile")
      )
      FileUtils.cp(
        File.expand_path("../rakelib/test_runner.rb", __dir__),
        File.join(dir, "rakelib", "test_runner.rb")
      )

      out_path = File.join(dir, "rake_output.txt")
      system("cd #{dir} && rake test > #{out_path} 2>&1")
      exit_status = $?.exitstatus
      output = File.read(out_path)

      refute_equal 0, exit_status,
                   "rake test must fail (non-zero exit) when one of its test files runs zero tests:\n" \
                   "#{output}"

      # A nonzero exit alone does not prove rake failed for the RIGHT reason:
      # a Rakefile that raises before running any test file also exits
      # nonzero, and `refute_equal 0, exit_status` above cannot tell the two
      # apart (mutation-proven: making the :test task raise immediately
      # leaves that assertion green). Require evidence that test_pass.rb
      # actually ran, and that the failure is attributed to test_zero.rb by
      # name via the "ran zero tests" reason -- not some other crash.
      assert_includes output, "Running test/test_pass.rb...",
                      "test_pass.rb must actually run before the task fails:\n#{output}"
      assert_includes output, "FAILED: test/test_zero.rb: ran zero tests",
                      "the failure must be attributed to test_zero.rb by the zero-tests reason, " \
                      "not an unrelated crash:\n#{output}"
    end
  end

  # The glob `FileList['test/test_*.rb', 'test/**/test_*.rb']` also matches
  # test/test_helper.rb itself (it starts with "test_"). test_helper.rb is a
  # shared support module required by every other test file via
  # `require_relative 'test_helper'`; it defines no Minitest::Test subclass
  # and legitimately runs zero tests. The Rakefile excludes it by name so
  # that (a) above does not turn this one legitimate case into a permanent
  # failure.
  def test_glob_excludes_test_helper
    test_dir = File.expand_path("..", __dir__)
    files = Dir.glob(File.join(test_dir, "test", "test_*.rb")) +
            Dir.glob(File.join(test_dir, "test", "**", "test_*.rb"))

    assert_includes files.uniq, File.join(test_dir, "test", "test_helper.rb"),
                     "this assumption no longer holds — test_helper.rb moved or was renamed"
  end

  # test_glob_excludes_test_helper above only proves the PREMISE: that the
  # raw glob picks up test_helper.rb. It says nothing about whether the
  # Rakefile's actual `.exclude('test/test_helper.rb')` works end-to-end
  # (mutation-proven: dropping that `.exclude(...)` call from the Rakefile
  # leaves every existing test in this file green, including the other
  # end-to-end test above, because its scratch dir never contains a
  # test_helper.rb to begin with). Run the real Rakefile against a scratch
  # dir that DOES contain a zero-test test_helper.rb, and require the task
  # to succeed -- which only happens if the exclusion actually takes effect.
  def test_rake_test_task_passes_when_test_helper_runs_zero_tests
    Dir.mktmpdir("runar-rake-integration") do |dir|
      FileUtils.mkdir_p(File.join(dir, "test"))
      FileUtils.mkdir_p(File.join(dir, "lib"))
      FileUtils.mkdir_p(File.join(dir, "rakelib"))

      File.write(File.join(dir, "test", "test_helper.rb"), <<~RUBY)
        require 'minitest/autorun'
        # shared support module, no Minitest::Test subclass -- legitimately
        # registers zero tests, same shape as the real test_helper.rb
      RUBY

      File.write(File.join(dir, "test", "test_pass.rb"), <<~RUBY)
        require 'minitest/autorun'
        class PassingTest < Minitest::Test
          def test_truth
            assert true
          end
        end
      RUBY

      FileUtils.cp(
        File.expand_path("../Rakefile", __dir__),
        File.join(dir, "Rakefile")
      )
      FileUtils.cp(
        File.expand_path("../rakelib/test_runner.rb", __dir__),
        File.join(dir, "rakelib", "test_runner.rb")
      )

      out_path = File.join(dir, "rake_output.txt")
      system("cd #{dir} && rake test > #{out_path} 2>&1")
      exit_status = $?.exitstatus

      assert_equal 0, exit_status,
                   "rake test must still succeed when the only zero-test file is " \
                   "test_helper.rb, which the Rakefile excludes by name:\n" \
                   "#{File.read(out_path)}"
    end
  end
end

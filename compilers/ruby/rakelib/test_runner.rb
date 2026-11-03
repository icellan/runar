# frozen_string_literal: true

require "open3"

# The `rake test` runner logic, extracted from the Rakefile so it can be
# driven directly from a test (F-210 / CL-BUG-034).
#
# Before this existed, the Rakefile shelled out to each test file with
# `system(...)` and only checked `$?.success?`. That has two bugs:
#   1. a test file that registers zero minitest tests (a typo'd class name,
#      a helper file matched by the glob, ...) exits 0 and is counted as a
#      PASS — the suite silently stops testing whatever that file covered.
#   2. if `system` cannot spawn the subprocess at all, `$?` is `nil` (not
#      `false`), so `$?.success?` raises `NoMethodError` instead of
#      reporting a failure.
module RunarCompiler
  module TestRunner
    # Minitest's final summary line, e.g.
    #   "3 runs, 5 assertions, 0 failures, 0 errors, 0 skips"
    SUMMARY_LINE = /^(\d+) runs, (\d+) assertions, (\d+) failures, (\d+) errors, (\d+) skips/.freeze

    Result = Struct.new(:file, :failed, :reason, :runs, :assertions, :failures, :errors, :skips)

    # Runs a single test file as a subprocess, streaming its combined
    # stdout/stderr to +out+ line by line as it arrives (so a long test file
    # still shows live progress), while also parsing minitest's summary line
    # out of that same stream.
    #
    # A file counts as FAILED when minitest reports failures/errors, when it
    # reports zero runs, when no summary line is found at all (e.g. the
    # process crashed before minitest could report), or when the subprocess
    # could not be spawned in the first place.
    def self.run_file(file, command: ["ruby", "-Ilib", "-Itest", file], out: $stdout)
      summary = nil

      status =
        begin
          Open3.popen2e(*command) do |stdin, stdout_and_stderr, wait_thr|
            stdin.close
            stdout_and_stderr.each_line do |line|
              out.print(line)
              matched = SUMMARY_LINE.match(line)
              summary = matched if matched
            end
            wait_thr.value
          end
        rescue SystemCallError => e
          return Result.new(file, true, "#{file}: could not spawn test subprocess (#{e.message})",
                             nil, nil, nil, nil, nil)
        end

      if summary.nil?
        return Result.new(file, true, "#{file}: no minitest summary line in output (exit #{status.exitstatus.inspect})",
                           nil, nil, nil, nil, nil)
      end

      runs, assertions, failures, errors, skips = summary.captures.map(&:to_i)
      failed = !status.success? || failures > 0 || errors > 0 || runs.zero?
      reason =
        if runs.zero?
          "#{file}: ran zero tests"
        elsif failed
          "#{file}: #{failures} failures, #{errors} errors"
        end

      Result.new(file, failed, reason, runs, assertions, failures, errors, skips)
    end

    # Runs every file in +files+ (via run_file) and returns the list of
    # Results plus the totals the Rakefile's final summary line reports.
    SuiteResult = Struct.new(:results, :failed_results, :total_runs, :total_assertions)

    def self.run_suite(files, out: $stdout)
      results = files.map do |f|
        out.puts "Running #{f}..."
        run_file(f, out: out)
      end

      SuiteResult.new(
        results,
        results.select(&:failed),
        results.sum { |r| r.runs || 0 },
        results.sum { |r| r.assertions || 0 }
      )
    end
  end
end

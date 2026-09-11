# frozen_string_literal: true

# CL-BUG-104: the Ruby CLI must not swallow validator warnings.
#
# ValidationResult has carried #warnings / #warning_strings since the
# validator was written (lib/runar_compiler/frontend/validator.rb), but
# lib/runar_compiler/cli.rb contained zero occurrences of the string
# "warning" — so the SP1 FRI unsoundness disclosure, the @embedAlways DCE
# notices and the sighash advisories were invisible to anyone driving the
# compiler from the command line.
#
# Reference behaviour is the Rust (compilers/rust/src/main.rs:
# `eprintln!("warning: {}", w)`) and Zig (compilers/zig/src/main.zig:
# printDiagnostics) tiers: warnings go to STDERR, one per line, prefixed
# "warning: ", and they change neither the exit code nor the bytes on stdout.
#
# The warning driven here is a real one — V26, "StatefulSmartContract has no
# mutable properties", emitted by the Ruby validator. Nothing synthetic is
# injected.

require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class TestCliWarnings < Minitest::Test
  RUBY_COMPILER_DIR = File.expand_path('..', __dir__)
  RUBY_CLI = File.join(RUBY_COMPILER_DIR, 'bin/runar-compiler-ruby')

  WARNING_SOURCE = <<~TS
    import { StatefulSmartContract, assert } from 'runar-lang';

    export class WarnStateful extends StatefulSmartContract {
      readonly limit: bigint;

      constructor(limit: bigint) {
        super(limit);
        this.limit = limit;
      }

      public unlock(x: bigint): void {
        assert(x < this.limit);
      }
    }
  TS

  CLEAN_SOURCE = <<~TS
    import { SmartContract, assert } from 'runar-lang';

    export class CleanStateless extends SmartContract {
      readonly limit: bigint;

      constructor(limit: bigint) {
        super(limit);
        this.limit = limit;
      }

      public unlock(x: bigint): void {
        assert(x < this.limit);
      }
    }
  TS

  def run_cli(*args)
    Open3.capture3('ruby', RUBY_CLI, *args, chdir: RUBY_COMPILER_DIR)
  end

  def with_source(name, body)
    Dir.mktmpdir do |dir|
      path = File.join(dir, name)
      File.write(path, body)
      yield path
    end
  end

  def test_validator_warning_reaches_stderr
    with_source('WarnStateful.runar.ts', WARNING_SOURCE) do |path|
      stdout, stderr, status = run_cli('--source', path, '--hex')
      assert status.success?, "compile must succeed: #{stderr}"
      assert_includes stderr, 'StatefulSmartContract has no mutable properties',
                      "validator warning did not reach stderr; stderr=#{stderr.inspect}"
      assert_includes stderr, 'warning: ',
                      "warning line must carry the 'warning: ' prefix used by Rust/Zig; " \
                      "stderr=#{stderr.inspect}"
      refute_empty stdout.strip, 'stdout must still carry the script hex'
      refute_includes stdout, 'warning', "warning leaked into stdout: #{stdout.inspect}"
    end
  end

  # --parse-only runs the validator, so it has warnings to report. This is
  # the path where the Rust tier prints its warnings
  # (compilers/rust/src/main.rs:148-150) and where the Zig tier's
  # printDiagnostics also runs. Dropping them here would leave the two CLI
  # paths disagreeing about whether the compiler talks.
  def test_parse_only_also_prints_warnings
    with_source('WarnStateful.runar.ts', WARNING_SOURCE) do |path|
      stdout, stderr, status = run_cli('--parse-only', '--source', path)
      assert status.success?, "--parse-only must exit 0: #{stderr}"
      assert_equal 'parser ok', stdout.strip,
                   "--parse-only stdout must stay exactly 'parser ok', got #{stdout.inspect}"
      assert_includes stderr, 'warning: ', "--parse-only dropped the warning: #{stderr.inspect}"
      assert_includes stderr, 'StatefulSmartContract has no mutable properties'
    end
  end

  def test_clean_compile_prints_no_warning_and_exits_zero
    with_source('CleanStateless.runar.ts', CLEAN_SOURCE) do |path|
      stdout, stderr, status = run_cli('--source', path, '--hex')
      assert status.success?, "clean compile must exit 0: #{stderr}"
      refute_includes stderr, 'warning',
                      "clean compile must print no warning line; stderr=#{stderr.inspect}"
      refute_empty stdout.strip, 'clean compile produced no hex'
    end
  end
end

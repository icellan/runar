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

require 'json'
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

  # F-220: --emit-ir printed the IR and returned before the full compile,
  # which is where the warnings above are printed, so it dropped all of them,
  # the H2 locktime-bypass advisory included. The TS CLI prints every
  # warning-severity diagnostic to stderr before any output mode; these tests
  # hold --emit-ir to that rule by comparing it with this CLI's --hex run.
  #
  # What they prove: for a contract carrying the H2 locktime warning and one
  # carrying the issue-#109 DCE notice, --emit-ir exits 0, prints exactly the
  # stderr --hex prints, and keeps stdout to the IR JSON (no "script" key).
  # With --emit-source-map as well (the F-255 fall-through into the full
  # compile) the warning is printed exactly once.
  # What they do not prove: the --ir input path (no validator runs there),
  # other tiers' CLIs, or the warning text itself (the validator tests own it).
  F220_LOCKTIME_SOURCE = <<~TS
    import { StatefulSmartContract, assert, extractLocktime } from 'runar-lang';

    class TimeLock extends StatefulSmartContract {
        count: bigint;
        readonly deadline: bigint;
        constructor(count: bigint, deadline: bigint) {
            super(count, deadline);
            this.count = count;
            this.deadline = deadline;
        }
        public unlock() {
            assert(extractLocktime(this.txPreimage) >= this.deadline);
            this.count++;
        }
    }
  TS

  F220_DCE_SOURCE = <<~TS
    import { SmartContract, assert, PubKey, Sig, Addr, checkSig, hash160 } from 'runar-lang';

    class Unused extends SmartContract {
        readonly pubKeyHash: Addr;
        readonly memo: bigint;
        constructor(pubKeyHash: Addr, memo: bigint) {
            super(pubKeyHash, memo);
            this.pubKeyHash = pubKeyHash;
            this.memo = memo;
        }
        public unlock(sig: Sig, pubKey: PubKey) {
            assert(hash160(pubKey) === this.pubKeyHash);
            assert(checkSig(sig, pubKey));
        }
    }
  TS

  F220_LOCKTIME_NEEDLE = 'does not assert extractSequence'

  def test_f220_emit_ir_prints_the_same_warnings_as_hex
    [
      ['TimeLock.runar.ts', F220_LOCKTIME_SOURCE, F220_LOCKTIME_NEEDLE],
      ['Unused.runar.ts', F220_DCE_SOURCE, "readonly field 'memo' is not referenced"]
    ].each do |name, body, needle|
      with_source(name, body) do |path|
        _, hex_err, hex_status = run_cli('--source', path, '--hex')
        assert hex_status.success?, "--hex must exit 0: #{hex_err}"
        assert_includes hex_err, needle, "sanity: --hex must warn: #{hex_err.inspect}"

        ir_out, ir_err, ir_status = run_cli('--source', path, '--emit-ir')
        assert ir_status.success?, "--emit-ir must exit 0: #{ir_err}"
        assert_equal hex_err, ir_err,
                     "#{name}: --emit-ir must print the same warnings as --hex (F-220)"
        ir = JSON.parse(ir_out)
        assert ir.key?('contractName'), "stdout must be ANF IR: #{ir_out}"
        refute ir.key?('script'), "stdout must carry only the IR: #{ir_out}"
      end
    end
  end

  def test_f220_emit_ir_with_emit_source_map_prints_the_warning_once
    with_source('TimeLock.runar.ts', F220_LOCKTIME_SOURCE) do |path|
      sm = File.join(File.dirname(path), 'source-map.json')
      _, stderr, status = run_cli('--source', path, '--emit-ir', '--emit-source-map', sm)
      assert status.success?, "must exit 0: #{stderr}"
      assert File.exist?(sm), 'F-255: the source map must still be written'
      assert_equal 1, stderr.scan(F220_LOCKTIME_NEEDLE).length,
                   "the warning must be printed exactly once; stderr=#{stderr.inspect}"
    end
  end
end

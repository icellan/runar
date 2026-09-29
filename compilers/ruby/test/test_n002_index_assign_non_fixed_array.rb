# frozen_string_literal: true

# N-002 (CL-BUG-214, the cross-tier half of F-013): an index assignment is only
# a write when its root is a FixedArray contract property.
#
# expand_fixed_arrays rewrites `this.arr[i] = v` only when `arr` is a FixedArray
# property. Every other index target (a ByteString property, a local, a
# parameter, a member-chained root) survived to ANF lowering, which lowered it
# as a READ. In this tier that READ then failed in stack lowering ("call to
# unknown function '__array_access'"), so Ruby was fail-closed by accident, with
# a diagnostic naming an internal helper and no source location -- while TS, Go,
# Rust and Zig emitted a script that drops the write (remediation-logs/N-002).
#
# What this proves: the Ruby tier refuses every non-FixedArray index-write shape
# below in the VALIDATOR, with F-013's shared diagnostic and a source location,
# on the TS surface and on the Ruby surface; FixedArray index writes (literal,
# runtime, compound, ++, nested literal) still compile.
# What it does NOT prove: the other tiers (their own suites and
# conformance/negatives/N81-N94 cover that), or byte-identity of the FixedArray
# goldens (the conformance golden + multi-format runs do).
#
# The compiler is invoked via subprocess for the same reason as
# test_f017_identifier_collision.rb: the parsers share a constant namespace, so
# running several of them in-process corrupts tokenization.

require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class N002IndexAssignNonFixedArrayTest < Minitest::Test
  RUBY_CLI = File.expand_path('../bin/runar-compiler-ruby', __dir__)
  NEEDLE = 'index assignment is only supported on FixedArray contract properties; ' \
           'the target here is not a FixedArray property'

  def blob(body)
    <<~TS
      import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

      class Blob extends StatefulSmartContract {
        blob: ByteString;

        constructor(blob: ByteString) {
          super(blob);
          this.blob = blob;
        }

        public poke(i: bigint) {
          #{body}
          assert(true);
        }
      }
    TS
  end

  TS_LOCAL = <<~TS
    import { SmartContract, ByteString, assert } from 'runar-lang';

    class Loc extends SmartContract {
      readonly h: ByteString;

      constructor(h: ByteString) {
        super(h);
        this.h = h;
      }

      public unlock(b: ByteString) {
        let c: ByteString = b;
        c[0n] = 7n;
        assert(c == this.h);
      }
    }
  TS

  TS_PARAM = <<~TS
    import { SmartContract, ByteString, assert } from 'runar-lang';

    class Par extends SmartContract {
      readonly h: ByteString;

      constructor(h: ByteString) {
        super(h);
        this.h = h;
      }

      public unlock(b: ByteString) {
        b[0n] = 7n;
        assert(b == this.h);
      }
    }
  TS

  RB_PROP = <<~RB
    require 'runar'

    class Blob < Runar::StatefulSmartContract
      prop :blob, ByteString

      def initialize(blob)
        super(blob)
        @blob = blob
      end

      runar_public
      def poke
        @blob[0] = 7
        assert true
      end
    end
  RB

  RB_LOCAL_PARAM = <<~RB
    require 'runar'

    class Loc < Runar::SmartContract
      prop :h, ByteString

      def initialize(h)
        super(h)
        @h = h
      end

      runar_public b: ByteString
      def unlock(b)
        c = b
        c[0] = 7
        b[1] = 7
        assert c == @h
      end
    end
  RB

  FIXED_ARRAY_WRITES = <<~TS
    import { StatefulSmartContract, FixedArray, assert } from 'runar-lang';

    class Board extends StatefulSmartContract {
      board: FixedArray<bigint, 3> = [0n, 0n, 0n];
      grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];

      constructor() {
        super();
      }

      public set(i: bigint, v: bigint) {
        this.board[i] = v;
        this.board[0n] = v;
        this.board[1n] += v;
        this.board[2n]++;
        this.grid[0n][1n] = v;
        assert(true);
      }
    }
  TS

  def compile(source, file_name)
    Dir.mktmpdir do |dir|
      path = File.join(dir, file_name)
      File.write(path, source)
      stdout, stderr, status = Open3.capture3(RbConfig.ruby, RUBY_CLI, '--source', path, '--hex')
      [status.exitstatus, stdout + stderr]
    end
  end

  def assert_refused(source, file_name, want)
    code, out = compile(source, file_name)
    refute_equal 0, code, "#{file_name} compiled a script that silently drops the write:\n#{out}"
    located = out.scan(/:(\d+):\d+: #{Regexp.escape(NEEDLE)}/).map { |m| m[0].to_i }
    assert_equal want, located.size, "#{file_name}: expected #{want} located N-002 diagnostic(s):\n#{out}"
    located.each { |line| assert_operator line, :>, 0 }
  end

  def test_ts_surface_shapes_refused
    [
      'this.blob[0n] = 7n;',
      'this.blob[i] = 7n;',
      'this.blob[0n] += 7n;',
      'this.blob[0n] -= 7n;',
      'this.blob[0n] *= 7n;',
      'this.blob[0n] /= 7n;',
      'this.blob[0n] %= 7n;',
      'this.blob[0n][1n] = 7n;',
      'this.blob.x[0n] = 7n;'
    ].each { |body| assert_refused(blob(body), 'Blob.runar.ts', 1) }
    assert_refused(TS_LOCAL, 'Loc.runar.ts', 1)
    assert_refused(TS_PARAM, 'Par.runar.ts', 1)
  end

  def test_ruby_surface_refused
    assert_refused(RB_PROP, 'Blob.runar.rb', 1)
    assert_refused(RB_LOCAL_PARAM, 'Loc.runar.rb', 2)
  end

  def test_fixed_array_index_writes_still_compile
    code, out = compile(FIXED_ARRAY_WRITES, 'Board.runar.ts')
    assert_equal 0, code, "FixedArray index writes must compile:\n#{out}"
    refute_includes out, NEEDLE
  end
end

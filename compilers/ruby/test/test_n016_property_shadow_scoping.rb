# frozen_string_literal: true

require_relative "test_helper"

require "tmpdir"
require "runar_compiler/compiler"

# N-016 — a local that shares a contract property's name must never capture a
# later `this.<prop>` read or write (user decision R8: correct scoping). Port of
# packages/runar-compiler/src/__tests__/n016-property-shadow-scoping.test.ts.
#
# `const target = n + 1n; assert(target == this.target);` compiled to 8b769c
# (OP_1ADD OP_DUP OP_NUMEQUAL): the property read resolved by name to the
# local's stack slot, an always-true self-comparison.
#
# Oracle: alpha-equivalence, from the source language rather than compiler
# output. Renaming a local / private-helper param / public param to a fresh name
# cannot change the program's meaning, so each template compiled with `$L` = the
# property's name must produce exactly the bytes of `$L` = `lcl`, in both
# constant-folding modes.
#
# Proves: in the Ruby tier, property-named locals (top level, if-arm, nested
# block, loop variable, ++, byte-typed, inside a private helper), a private
# helper's param and a public param never capture `this.<prop>`; stateful
# property reads/writes and the continuation are unaffected by a same-named
# local, including an if whose arms rebind the local and write the property.
# Does NOT prove: on-chain behaviour (see
# packages/runar-testing/src/__tests__/n016-property-shadow-spend.test.ts) or
# local-vs-compiler-temp collisions (a local literally named `t3`).
class TestN016PropertyShadowScoping < Minitest::Test
  def self.stateless(body, prop_type = "bigint")
    <<~SRC
      import { SmartContract, assert, cat, ByteString } from 'runar-lang';

      class Shadow extends SmartContract {
        readonly target: #{prop_type};
        constructor(target: #{prop_type}) {
          super(target);
          this.target = target;
        }

      #{body}
      }
    SRC
  end

  def self.stateful(body)
    <<~SRC
      import { StatefulSmartContract, assert } from 'runar-lang';

      class Shadow extends StatefulSmartContract {
        count: bigint;

        constructor(count: bigint) {
          super(count);
          this.count = count;
        }

      #{body}
      }
    SRC
  end

  SHAPES = [
    ["local at method top level", "target", stateless(<<~B)],
      public unlock(n: bigint) {
        const $L = n + 1n;
        assert($L == this.target);
      }
    B
    ["local inside an if-arm", "target", stateless(<<~B)],
      public unlock(n: bigint) {
        if (n > 0n) {
          const $L = n + 1n;
          assert($L == this.target);
        } else {
          assert(n == this.target);
        }
      }
    B
    ["local inside a nested block", "target", stateless(<<~B)],
      public unlock(n: bigint) {
        if (n > 0n) {
          if (n > 1n) {
            const $L = n + 1n;
            assert($L == this.target);
          } else {
            assert(n + 2n == this.target);
          }
        } else {
          assert(false);
        }
      }
    B
    ["loop variable", "target", stateless(<<~B)],
      public unlock(n: bigint) {
        let acc = 0n;
        for (let $L = 0n; $L < 2n; $L++) {
          acc = acc + this.target - $L;
        }
        assert(acc == n);
      }
    B
    ["local mutated with ++", "target", stateless(<<~B)],
      public unlock(n: bigint) {
        let $L = n;
        $L++;
        assert($L == this.target);
      }
    B
    ["byte-typed local", "target", stateless(<<~B, "ByteString")],
      public unlock(a: ByteString) {
        const $L = cat(a, a);
        assert($L == this.target);
      }
    B
    ["local inside a private helper", "target", stateless(<<~B)],
      private chk(n: bigint): boolean {
        const $L = n + 1n;
        return $L == this.target;
      }

      public unlock(n: bigint) {
        assert(this.chk(n));
      }
    B
    ["private helper parameter", "target", stateless(<<~B)],
      private chk($L: bigint): boolean {
        return this.target == $L + 1n;
      }

      public unlock(n: bigint) {
        assert(this.chk(n));
      }
    B
    ["public parameter, property read first", "target", stateless(<<~B)],
      public unlock($L: bigint) {
        assert(this.target == $L + 1n);
      }
    B
    ["stateful: local, then property read + write", "count", stateful(<<~B)],
      public bump(n: bigint) {
        const $L = n * 2n;
        this.count = this.count + $L;
        assert($L > 0n);
      }
    B
    ["stateful: local live across a property write", "count", stateful(<<~B)],
      public bump(n: bigint) {
        let $L = n;
        this.count = this.count + 1n;
        assert(this.count > $L);
      }
    B
    # The TS/Go/Rust/Python/Zig/Java ports also carry "stateful: if-arms rebind
    # the local and write the property" (the lifted conditional-update shape).
    # Ruby is excluded from that one shape: at HEAD it cannot compile even the
    # NON-shadowing spelling ("value 't15' referenced by 't45' is not on the
    # stack" -- a pre-existing Ruby lift-remap defect, reported separately), so
    # the alpha-equivalence oracle has no control to compare against.
    ["stateful: an if-arm writes the property, then rebinds the local read after the if", "count", stateful(<<~B)],
    public bump(n: bigint) {
      let $L = n;
      if (n > 3n) {
        this.count = this.count + $L;
        $L = $L + 1n;
      } else {
        this.count = this.count + 1n;
      }
      assert($L > 0n);
    }
    B
  ].freeze

  def script_hex(source, disable_constant_folding)
    Dir.mktmpdir do |dir|
      path = File.join(dir, "Shadow.runar.ts")
      File.write(path, source)
      RunarCompiler.compile_from_source(path, disable_constant_folding: disable_constant_folding).script
    end
  end

  def test_probe_no_longer_self_compares
    assert_equal "8b009c", script_hex(SHAPES[0][2].gsub("$L", "target"), true)
  end

  def test_shadowing_compiles_like_renamed_spelling
    failures = []
    SHAPES.each do |name, prop, template|
      [true, false].each do |disable|
        begin
          shadow = script_hex(template.gsub("$L", prop), disable)
        rescue StandardError => e
          failures << "#{name} (disable_fold=#{disable}): shadowing spelling failed: #{e.message[0, 160]}"
          next
        end
        control = script_hex(template.gsub("$L", "lcl"), disable)
        failures << "#{name} (disable_fold=#{disable}): shadowing #{shadow} != renamed #{control}" if shadow != control
      end
    end
    assert_empty failures, failures.join("\n")
  end
end

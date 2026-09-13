# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "runar_compiler"

# R-237 (CL-GAP-013): this tier emitted no warning when DCE dropped an
# un-annotated readonly field.
#
# The finding names Ruby. Measured across all seven, three tiers were silent:
# rust, python and ruby. The other four (ts, go, zig, java) told the author that
# a field they declared had been eliminated from the locking script entirely.
#
# Ruby genuinely had no check at all — this adds it, ported from
# compilers/go/frontend/embed_always_dce.go. (Rust and Python already HAD the
# check and dropped it at the CLI boundary; those are fixed in their own tiers.)
class TestR237DceWarning < Minitest::Test
  UNREAD = <<~TS
    import { SmartContract, assert } from 'runar-lang';

    export class UnreadField extends SmartContract {
      readonly unused: bigint;
      readonly limit: bigint;

      constructor(unused: bigint, limit: bigint) {
        super(unused, limit);
        this.unused = unused;
        this.limit = limit;
      }

      public unlock(x: bigint): void {
        assert(x < this.limit);
      }
    }
  TS

  READ = UNREAD.sub("assert(x < this.limit);", "assert(x < this.limit + this.unused);")

  def compile_with_warnings(source)
    Dir.mktmpdir do |dir|
      path = File.join(dir, "UnreadField.runar.ts")
      File.write(path, source)
      _artifact, warnings = RunarCompiler.compile_from_source_collecting_warnings(path)
      warnings
    end
  end

  def test_warns_when_a_readonly_field_is_dropped
    warnings = compile_with_warnings(UNREAD)
    matching = warnings.grep(/readonly field 'unused'.*eliminated by DCE/)
    refute_empty matching,
                 "a readonly field no method reads is eliminated from the locking " \
                 "script; the author must hear about it. Got: #{warnings.inspect}"
  end

  def test_does_not_warn_when_the_field_is_read
    warnings = compile_with_warnings(READ)
    assert_empty warnings.grep(/readonly field 'unused'.*eliminated by DCE/),
                 "a field that IS referenced must not warn: #{warnings.inspect}"
  end

  def test_does_not_warn_for_the_field_that_is_used
    warnings = compile_with_warnings(UNREAD)
    assert_empty warnings.grep(/readonly field 'limit'/),
                 "'limit' is read by unlock and must not warn: #{warnings.inspect}"
  end
end

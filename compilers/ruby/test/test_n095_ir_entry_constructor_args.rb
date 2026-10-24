# frozen_string_literal: true

# N-095: the IR / direct-program entry points bake and validate constructor
# args, as Rust F-103 and the TS reference compileFromANF do.
#
# compile_from_ir / compile_from_ir_bytes / compile_from_program took no
# constructor_args at all, so a caller holding an ANF program (IR JSON or an
# in-memory IR::ANFProgram) could not bake a readonly property: the HashLock
# hash stayed an OP_0 placeholder slot. They now accept constructor_args and
# run the same unknown-key / F-101 type+width / unbaked-readonly checks the
# source pipeline runs, before folding and the EC optimizer.
#
# Proves: HashLock compiled from IR bytes, an IR file and an in-memory program
# with { "hashValue" => <32 bytes> } is byte-identical to the source compile
# with the same args and carries no constructor slot; an unknown key, a width
# mismatch and an unbaked referenced readonly property are refused on every IR
# entry point; baking does not mutate the caller's program; with no args the
# slotted artifact is unchanged.
# Does not prove: the --ir JSON loader's own validation, or any CLI flag (this
# tier's CLI has no constructor-args flag).

require_relative "test_helper"
require "json"
require "tmpdir"

class TestN095IREntryConstructorArgs < Minitest::Test
  HASH_LOCK_SOURCE = <<~TS
    class HashLock extends SmartContract {
      readonly hashValue: Sha256;

      constructor(hashValue: Sha256) {
        super(hashValue);
        this.hashValue = hashValue;
      }

      public unlock(preimage: ByteString) {
        assert(sha256(preimage) === this.hashValue);
      }
    }
  TS

  HASH = "aa" * 32

  def setup
    @dir = Dir.mktmpdir("n095")
    @src_path = File.join(@dir, "HashLock.runar.ts")
    File.write(@src_path, HASH_LOCK_SOURCE)
    @program = RunarCompiler.compile_source_to_ir(@src_path, disable_constant_folding: true)
    @ir_bytes = JSON.generate(RunarCompiler::CLI._anf_to_camel_dict(@program))
    @ir_path = File.join(@dir, "HashLock.ir.json")
    File.write(@ir_path, @ir_bytes)
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def entry_points
    {
      "compile_from_ir_bytes" => ->(args) { RunarCompiler.compile_from_ir_bytes(@ir_bytes, constructor_args: args) },
      "compile_from_ir" => ->(args) { RunarCompiler.compile_from_ir(@ir_path, constructor_args: args) },
      "compile_from_program" => lambda { |args|
        RunarCompiler.compile_from_program(@program, disable_constant_folding: true, constructor_args: args)
      }
    }
  end

  def test_ir_entry_points_bake_like_the_source_compile
    expected = RunarCompiler.compile_from_source(
      @src_path, disable_constant_folding: true, constructor_args: { "hashValue" => HASH }
    )
    entry_points.each do |name, run|
      got = run.call({ "hashValue" => HASH })
      assert_equal expected.script, got.script, name
      assert_includes got.script, HASH, name
      slots = got.constructor_slots
      assert(slots.nil? || slots.empty?, "#{name}: expected no constructor slots")
    end
  end

  def test_ir_entry_points_refuse_bad_args
    entry_points.each do |name, run|
      err = assert_raises(RunarCompiler::CompilationError, name) { run.call({ "hashVal" => HASH }) }
      assert_includes err.message, "'hashVal'", name
      err = assert_raises(RunarCompiler::CompilationError, name) { run.call({ "hashValue" => "aabb" }) }
      assert_includes err.message, "hashValue", name
      err = assert_raises(RunarCompiler::CompilationError, name) { run.call({ "other" => HASH }) }
      assert_includes err.message, "other", name
    end
  end

  def test_no_args_keeps_the_slot_and_baking_does_not_mutate_the_program
    baked = RunarCompiler.compile_from_program(
      @program, disable_constant_folding: true, constructor_args: { "hashValue" => HASH }
    )
    assert(baked.constructor_slots.nil? || baked.constructor_slots.empty?)
    assert(@program.properties.all? { |p| p.initial_value.nil? }, "caller's program was baked in place")
    plain = RunarCompiler.compile_from_ir_bytes(@ir_bytes)
    assert_equal 1, plain.constructor_slots.length
    refute_includes plain.script, HASH
  end
end

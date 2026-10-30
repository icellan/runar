# frozen_string_literal: true

require_relative "test_helper"
require "runar_compiler/compiler"
require "tmpdir"

# N-351 (F-193 in the Ruby tier) -- the SHA-256 / BLAKE3 compression op caches
# must not carry one call site's source location into another compilation.
#
# codegen/sha256.rb and codegen/blake3.rb build their compression bodies once
# per process and hand the SAME op Hashes to StackLower#emit_op, which used to
# stamp :source_loc on the Hash it was given. The first call site compiled in
# the process pinned its location on the cache for good. Emitted bytes were
# never affected -- only the source map.
#
# What this proves: compiling contract A then contract B (different files and
# call lines) in one process, every compression-body source-map entry of B names
# B's file and call line, none names A, and recompiling A still maps to A.
#
# What this does not prove: the TS tier (own test), other caches in the
# compiler, or that the hex is unchanged (the conformance goldens gate that).
class TestN351CryptoOpCacheSourceLoc < Minitest::Test
  CASES = {
    "sha256Compress" => ["const result = sha256Compress(state, block);", 15_000],
    "sha256Finalize" => ["const result = sha256Finalize(state, remaining, n);", 15_000],
    "blake3Compress" => ["const result = blake3Compress(state, block);", 5_000]
  }.freeze

  def source(name, body, pad)
    "#{"\n" * pad}class #{name} extends SmartContract {\n" \
      "  readonly expected: ByteString;\n\n" \
      "  constructor(expected: ByteString) {\n    super(expected);\n    this.expected = expected;\n  }\n\n" \
      "  public verify(state: ByteString, block: ByteString, remaining: ByteString, n: bigint) {\n" \
      "    #{body}\n    assert(result === this.expected);\n  }\n}\n"
  end

  def build(dir, body, name, pad, file)
    src = source(name, body, pad)
    path = File.join(dir, file)
    File.write(path, src)
    call_line = src.split("\n", -1).index { |l| l.include?("const result =") } + 1
    artifact = RunarCompiler.compile_from_source(path, disable_constant_folding: true)
    [path, call_line, artifact.source_map || []]
  end

  CASES.each do |intrinsic, (body, min_ops)|
    define_method("test_#{intrinsic}") do
      Dir.mktmpdir do |dir|
        file_a, line_a, map_a = build(dir, body, "ContractA", 0, "A.runar.ts")
        file_b, line_b, map_b = build(dir, body, "ContractB", 7, "B.runar.ts")
        refute_equal line_a, line_b

        assert_operator map_a.count { |m| m.source_file == file_a && m.line == line_a }, :>=, min_ops

        leaked = map_b.reject { |m| m.source_file == file_b }
        assert_equal 0, leaked.size, "#{leaked.size} of #{map_b.size} entries in B's map point at A"
        assert_operator map_b.count { |m| m.line == line_b }, :>=, min_ops

        file_a2, line_a2, map_a2 = build(dir, body, "ContractA", 0, "A.runar.ts")
        assert(map_a2.all? { |m| m.source_file == file_a2 })
        assert_operator map_a2.count { |m| m.line == line_a2 }, :>=, min_ops
      end
    end
  end
end

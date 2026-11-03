# frozen_string_literal: true

require_relative "test_helper"

# F-326 (CX-GAP-020): Ruby's "Pass 4.75" DCE wrapper was defined and never
# invoked, and the DCE module called itself standalone.
#
# `Compiler._eliminate_dead_code` was documented as a discrete named pass
# ("Dead Code Elimination -- discrete named pass (Pass 4.75)") that "runs as a
# safety net for any post-EC residual dead bindings". Neither pipeline entry
# point (compile_from_program / compile_from_source_collecting_warnings)
# called it, so it ran never and guarded nothing.
#
# The real sweep lives in `Frontend::ANFOptimize.optimize_ec`, AFTER its
# `return program unless any_changed` gate (anf_optimize.rb:49-50) -- so a
# program with no EC calls is not DCE'd at all by that path. This mirrors
# R-240 (Python) and R-194 (TypeScript): the fix there was documentation plus
# deleting the dead wrapper, not wiring the standalone pass in, because wiring
# it in unconditionally broke conformance fixtures (N-140 is the open defect
# in DCE itself that would need to land first). This item does the same for
# Ruby: correct the documented call graph, delete the dead wrapper, keep the
# gate exactly where it is.
#
# This test pins the shape so the wiring cannot quietly regress: the gate
# stays in front of the sweep, no module claims DCE is standalone while it is
# not, and the unreachable wrapper does not come back.
class TestF326DceInvocation < Minitest::Test
  LIB_DIR = File.expand_path("../lib/runar_compiler", __dir__)

  def test_the_any_changed_gate_still_precedes_the_dce_sweep
    src = File.read(File.join(LIB_DIR, "frontend", "anf_optimize.rb"))

    gate = src.index("return program unless any_changed")
    # The call site inside optimize_method (line ~197), not the
    # eliminate_dead_bindings method definition further down the file.
    sweep = src.index("eliminate_dead_bindings(method)")

    refute_nil gate, "the any_changed gate is missing from optimize_ec"
    refute_nil sweep, "the eliminate_dead_bindings call site is missing from optimize_method"
    assert gate < sweep,
           "the dead-binding sweep now runs before the any_changed gate. That " \
           "makes DCE standalone on this path, which is exactly what R-194/" \
           "R-240/N-140 measured as breaking conformance fixtures in two other " \
           "tiers. Fix DCE's binding-removal rules first, then move this."
  end

  def test_no_module_claims_a_standalone_dce_pass
    offenders = []
    Dir.glob(File.join(LIB_DIR, "**", "*.rb")).each do |path|
      lines = File.readlines(path)
      lines.each_with_index do |line, idx|
        next unless line =~ /standalone DCE pass/

        # The corrected docstring quotes the old (wrong) claim as part of
        # explaining why it was wrong -- allow that quote, same trick R-240
        # used for Python.
        context = lines[[0, idx - 2].max..idx].join
        next if context.include?("used to say")

        offenders << "#{File.basename(path)}:#{idx + 1}: #{line.strip}"
      end
    end

    assert_empty offenders,
                 "a module calls its DCE standalone; the only sweep in this tier " \
                 "runs behind optimize_ec's any_changed gate: #{offenders.inspect}"
  end

  def test_the_unreachable_pass_475_wrapper_is_gone
    compiler_src = File.read(File.join(LIB_DIR, "compiler.rb"))

    assert_nil compiler_src[/def self\._eliminate_dead_code\(/],
               "the Pass 4.75 wrapper is back; it has no pipeline callers and " \
               "documents a safety net that does not run"

    # The whole-program DCE entry it wrapped is still used directly where it
    # really is needed: the two @embedAlways probes that deep-copy a program
    # to compute which readonly fields DCE would eliminate.
    embed_always_src = File.read(File.join(LIB_DIR, "frontend", "embed_always_dce.rb"))
    refute_nil compiler_src[/eliminate_dead_code\(probe\)/],
               "the compiler.rb @embedAlways probe (_collect_referenced_props) " \
               "no longer runs DCE on its deep copy"
    refute_nil embed_always_src[/eliminate_dead_code\(probe\)/],
               "the embed_always_dce.rb probe no longer runs DCE on its deep copy"
  end
end

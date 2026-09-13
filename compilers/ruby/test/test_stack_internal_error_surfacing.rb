# frozen_string_literal: true

require_relative "test_helper"

require "runar_compiler/codegen/stack"

# R-171 / CL-BUG-159 — a blanket +rescue => e+ turned internal Ruby errors into
# location-less "compile errors".
#
# +lower_to_stack+ re-raises RuntimeError and UnknownANFKindError untouched --
# those are the tier's deliberate refusals -- and then catches EVERYTHING else
# with +rescue => e; raise RuntimeError, "stack lowering: #{e}"+. A TypeError or
# NoMethodError from a genuine bug in the lowering therefore reached the user as
# a bare sentence, with no backtrace, no binding, and no hint that it was the
# COMPILER that broke rather than their contract. Zig and Java surface typed
# errors; this tier flattened everything into one shape.
#
# The distinction matters in exactly the way R-138 made it matter for Rust: a
# refusal means "your contract cannot be emitted", an internal error means "file
# a bug". Reporting the second as the first sends the author to rewrite working
# code.
#
# Everything reaching the blanket rescue is, by construction, an internal error:
# the deliberate refusals are already re-raised above it.
class TestStackInternalErrorSurfacing < Minitest::Test
  def setup
    @mod = RunarCompiler::Codegen
  end

  # Replace the inner entry point with one that raises, then restore.
  def with_injected_failure(error_class, message)
    original = @mod.method(:_lower_to_stack_inner)
    @mod.define_singleton_method(:_lower_to_stack_inner) do |_program|
      raise error_class, message
    end
    yield
  ensure
    @mod.define_singleton_method(:_lower_to_stack_inner, original)
  end

  def test_an_internal_error_says_it_is_internal
    with_injected_failure(NoMethodError, "undefined method `boom' for nil") do
      err = assert_raises(RuntimeError) { @mod.lower_to_stack(nil) }
      assert_match(/internal/i, err.message,
                   "an internal error must say so; the author should not be " \
                   "sent to rewrite a contract that is fine. Got: #{err.message}")
      assert_match(/NoMethodError/, err.message,
                   "the error CLASS is the most useful single fact for a bug " \
                   "report and was being discarded. Got: #{err.message}")
    end
  end

  # NOTE: this one passed BEFORE the fix too -- a bare `raise` inside a rescue
  # still produces a usable trace, and Ruby sets `cause` either way. It is kept
  # as a guard against a future rewrite that drops the trace, not as evidence of
  # the defect. The two assertions that were actually red are the ones above:
  # the message said nothing about being internal and discarded the error CLASS.
  def test_an_internal_error_carries_a_backtrace_and_a_cause
    with_injected_failure(TypeError, "no implicit conversion of nil into String") do
      err = assert_raises(RuntimeError) { @mod.lower_to_stack(nil) }
      refute_nil err.backtrace, "the backtrace was dropped entirely"
      assert_instance_of TypeError, err.cause,
                         "the original exception must remain reachable as `cause`"
    end
  end

  def test_the_original_message_survives
    with_injected_failure(TypeError, "a very specific cause") do
      err = assert_raises(RuntimeError) { @mod.lower_to_stack(nil) }
      assert_match(/a very specific cause/, err.message)
    end
  end

  # Controls: the two deliberate-refusal channels must pass through UNCHANGED.
  # Without these the change could "fix" internal errors by relabelling every
  # refusal as a compiler bug.
  def test_a_deliberate_RuntimeError_refusal_passes_through_untouched
    with_injected_failure(RuntimeError, "Refusing to emit a silent OP_0 placeholder") do
      err = assert_raises(RuntimeError) { @mod.lower_to_stack(nil) }
      assert_equal "Refusing to emit a silent OP_0 placeholder", err.message
      refute_match(/internal/i, err.message)
    end
  end

  def test_the_typed_unknown_kind_guard_passes_through_untouched
    original = @mod.method(:_lower_to_stack_inner)
    @mod.define_singleton_method(:_lower_to_stack_inner) do |_program|
      raise ::RunarCompiler::IR::UnknownANFKindError.new("ghost_kind", "test")
    end
    err = assert_raises(::RunarCompiler::IR::UnknownANFKindError) { @mod.lower_to_stack(nil) }
    assert_match(/ghost_kind/, err.message)
  ensure
    @mod.define_singleton_method(:_lower_to_stack_inner, original)
  end
end

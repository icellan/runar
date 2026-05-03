require 'runar'

# PrivateHelperOutputs -- Audit regression: private helpers must
# propagate their side effects to the public method's continuation
# hash.
#
# == Background
#
# The 2026-04-30 TypeScript compiler audit
# (docs/ts-compiler-audit-2026-04-30.md) found that the compiler's
# auto-injection of stateful continuation parameters (_changePKH,
# _changeAmount, _newAmount, txPreimage) used a shallow scan of the
# public method body. A public method that delegated its side effect
# to a private helper -- mutating state, emitting state outputs via
# add_output / add_raw_output, or emitting data outputs via
# add_data_output -- would silently be classified as terminal, the ABI
# would omit the change params, and the deployed locking script would
# carry no hashOutputs continuation. Findings F1 (Critical) and F3
# (High) of the audit.
#
# This contract is the regression artifact: every public method below
# delegates its side effect to a private helper. A correct compiler
# must recognise the side effect and produce the same continuation
# shape as if the public method called the intrinsic directly.
#
# == Behavior
#
# - +commit+ calls private +_bump+ which mutates +counter+. The
#   continuation must carry the new counter value forward via the
#   single-output state-continuation path.
# - +log+ calls private +_record+ which emits add_data_output. The
#   continuation must hash the data output bytes between the state
#   output and the change output.
# - +partition+ calls private +_fork_output+ which emits add_output.
#   The continuation must hash the explicit state output via the
#   multi-output path.
#
# == Compiler behavior
#
# ANF lowering uses a recursive side-effect summary (computed once
# per contract, shared with the ABI assembler) that walks the
# private-method call graph. When a public stateful method calls a
# private helper with output side effects, ANF lowering inlines the
# helper's body into the public's binding stream so its add_output /
# add_data_output ANF nodes register on the public's
# +addOutputRefs+ / +addDataOutputRefs+. The continuation hash
# construction then sees the correct output set and matches the
# runtime transaction's hashOutputs.
#
# == Cross-compiler scope
#
# All seven Rúnar compilers (TypeScript, Go, Rust, Python, Zig,
# Ruby, Java) must produce identical Bitcoin Script for this
# contract; the fix and its tests live in the conformance suite to
# lock that invariant in.
class PrivateHelperOutputs < Runar::StatefulSmartContract
  prop :counter, Bigint

  def initialize(counter)
    super(counter)
    @counter = counter
  end

  private

  # Pure state mutation, exposed through a private helper.
  params
  def _bump
    @counter = @counter + 1
  end

  # add_data_output called from a private helper.
  params payload: ByteString
  def _record(payload)
    add_data_output(0, payload)
  end

  # add_output called from a private helper.
  params amount: Bigint, leftover: Bigint
  def _fork_output(amount, leftover)
    add_output(amount, leftover)
  end

  public

  # Calls a private state-mutating helper.
  runar_public
  def commit
    _bump()
    assert true
  end

  # Routes a data output through a private helper.
  runar_public payload: ByteString
  def log(payload)
    _record(payload)
    assert true
  end

  # Routes a state output through a private helper.
  runar_public amount: Bigint, leftover: Bigint
  def partition(amount, leftover)
    _fork_output(amount, leftover)
    assert true
  end
end

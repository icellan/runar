# frozen_string_literal: true

# Dead Code Elimination pass for ANF IR.
#
# Removes bindings whose results are never referenced by other bindings,
# preserving bindings with observable side effects (assert, update_prop,
# check_preimage, add_output, add_raw_output, add_data_output, call,
# method_call, raw_script). Iterates to a fixed point so transitively
# dead bindings are also removed.
#
# "Results" is plural on purpose (N-140). A binding does not only define
# its own +name+: an +if+ that merges branch locals also defines every
# name in +results+, and both an +if+ and a +loop+ define the names their
# nested bindings bind. Liveness used to test +used.include?(binding.name)+
# alone, so an +if+ named +t9+ carrying +results ["a","b"]+ -- a name
# nothing ever references, because callers reference +a+ and +b+ -- was
# deleted whenever its arms happened to be pure, and the merged locals kept
# their pre-branch values. See +conformance/dce/live-if.test.ts+.
#
# F-326: this used to say "the canonical, standalone DCE pass for the
# Ruby compiler". It is canonical -- every dead-binding sweep in this
# tier comes from here -- but it is NOT standalone. Its only pipeline
# caller is +Frontend::ANFOptimize.optimize_ec+, which runs it (via
# +eliminate_dead_bindings+, per method) only when the program contains
# EC calls -- see the +return program unless any_changed+ gate. A
# program with no EC calls is never swept by this path at all.
# +eliminate_dead_code+ (the whole-program entry) has two other
# callers, +Compiler._collect_referenced_props+ and
# +Frontend::EmbedAlwaysDCE.collect_warnings+, each running on a
# deep-copied probe purely to compute the @embedAlways warning.
#
# The gate is load-bearing, measured rather than assumed: forcing the
# sweep to run unconditionally (bypassing +any_changed+) makes this
# tier diverge from the golden/cross-tier IR and script hex for
# `all-readonly-cleanstack` -- 1 of 87 conformance fixtures. Smaller
# than the 11 TypeScript (R-194) and Python (R-240) fail under the same
# probe, because this tier's deep-copy already carries the fuller
# +IR::ANFValue::FIELDS+ list (see +anf_optimize.rb+'s N-140 comment
# above +deep_copy_value+), but still a real, measured divergence and
# not zero. "Make DCE standalone" remains a defect to fix inside DCE
# before it is a wiring change, same as the other two tiers.
#
# This mirrors the Zig reference implementation in
# +compilers/zig/src/passes/dce.zig+. The earlier inline implementation
# in +anf_optimize.rb+ has been surgically extracted here.
#
# Behaviour: byte-for-byte identical, at the time of that extraction, to
# the previous inline DCE in +anf_optimize.rb+. Verified by the
# conformance suite (cross-tier hex parity) and the unknown-kind
# exhaustiveness tests.
#
# N-140 is a deliberate behaviour change since: liveness considers
# the names a binding DEFINES, not only its own +name+. F-108 is the other:
# a private method's last binding (its return value) is a liveness root.

require "set"
require_relative "../ir/types"

module RunarCompiler
  module Frontend
    module DCE
      # R-140: +if+ and +loop+ are NOT in this list. They are effectful iff some
      # NESTED binding is, and +has_side_effect?+ recurses for them. They used
      # to sit here unconditionally, so an unreferenced branch or loop whose
      # bodies are entirely pure was kept in this tier and deleted by the Go,
      # Java, Rust and TypeScript tiers -- three tiers against four on the same
      # predicate, measured on the predicate itself because no shipped path
      # reaches DCE with that shape today.
      SIDE_EFFECT_KINDS = %w[
        assert update_prop check_preimage deserialize_state
        add_output add_raw_output add_data_output
        raw_script
        call method_call
      ].to_set.freeze

      # Kinds known to have no observable side effects.  Listed explicitly
      # so an unknown kind raises UnknownANFKindError instead of silently
      # being treated as side-effect-free (which would cause DCE to drop
      # a new side-effecting variant).
      # bin_op operators whose opcode can fail at runtime (see +has_side_effect?+).
      PARTIAL_BIN_OPS = %w[/ % & | ^ << >>].freeze

      SIDE_EFFECT_FREE_KINDS = %w[
        load_param load_prop load_const get_state_script
        bin_op unary_op array_literal
      ].freeze

      # ---------------------------------------------------------------
      # Public API
      # ---------------------------------------------------------------

      # Eliminate dead bindings across every method in the program.
      # Mutates the program in place and returns it.
      def self.eliminate_dead_code(program)
        program.methods.each { |m| eliminate_dead_bindings(m) }
        program
      end

      # Remove bindings whose results are never referenced.
      #
      # Uses iterative elimination to handle transitive dead code
      # (e.g., if A references B and A is dead, B may also become dead).
      #
      # N-138: when +candidates+ (a Set of names) is given, only a binding
      # whose name is in it may be removed; every other binding is kept as if
      # live. The constant folder uses this to drop the operand bindings its
      # own rewrites orphaned (the +1+ under a folded +-1n+) without also
      # deleting bindings that were already dead before folding, so fold-ON
      # output does not move for a program the folder did not change.
      def self.eliminate_dead_bindings(method, candidates = nil)
        keep_last = returns_last_binding?(method)
        current = method.body
        changed = true

        while changed
          changed = false
          own_refs = current.map do |binding|
            own = Set.new
            collect_refs(binding.value, own)
            own
          end
          ref_count = Hash.new(0)
          own_refs.each { |own| own.each { |name| ref_count[name] += 1 } }

          filtered = []
          current.each_with_index do |binding, i|
            if (keep_last && i == current.length - 1) ||
               (!candidates.nil? && !candidates.include?(binding.name)) ||
               referenced_externally?(binding, own_refs[i], ref_count) ||
               has_side_effect?(binding.value)
              filtered << binding
            else
              changed = true
            end
          end

          current = filtered

          # N-446: the fold also orphans operands INSIDE +if+ arms and loop
          # bodies (+-5n+ in an else arm). Filtering only the top level left
          # them there, stack lowering pushed them, and the arms ended at
          # different depths. Prune the nested scopes too, then re-filter the
          # top level (a nested removal can orphan a top-level operand).
          if !changed && !candidates.nil?
            pruned = prune_nested_orphans(current, candidates)
            unless pruned.equal?(current)
              current = pruned
              changed = true
            end
          end
        end

        method.body = current
      end

      # N-446: remove fold-orphaned pure bindings from every nested scope
      # (+if+ arms, +loop+ bodies, recursively); returns +bindings+ itself
      # when nothing was removed.
      #
      # A nested binding is removed only if it is a candidate (referenced
      # before folding), is referenced by NO binding anywhere in the method
      # now (arm bindings can be read after the +if+ by name, so an arm is
      # never filtered against its own references alone), is not one of its
      # +if+'s declared +results+ (stack lowering requires those slots in both
      # arms), is side-effect free, and is not itself an +if+ / +loop+ (those
      # are recursed into instead). Only the candidate-restricted fold prune
      # calls this; the EC-gated DCE stays top-level, so fold-OFF output
      # cannot move. Changed bindings are copied, never edited in place.
      def self.prune_nested_orphans(bindings, candidates)
        current = bindings
        loop do
          refs = Set.new
          current.each { |b| collect_refs(b.value, refs) }
          changed = false

          filter_scope = lambda do |scope, nested, protect|
            out = []
            scope_changed = false
            scope.each do |b|
              v = b.value
              if v.kind == "if"
                res = Set.new(v.results || [])
                then_src = v.then || []
                else_src = v.else_ || []
                then_b = filter_scope.call(then_src, true, res)
                else_b = filter_scope.call(else_src, true, res)
                if !then_b.equal?(then_src) || !else_b.equal?(else_src)
                  nv = v.dup
                  nv.then = then_b unless then_b.equal?(then_src)
                  nv.else_ = else_b unless else_b.equal?(else_src)
                  nb = b.dup
                  nb.value = nv
                  out << nb
                  scope_changed = true
                else
                  out << b
                end
              elsif v.kind == "loop"
                body_src = v.body || []
                body = filter_scope.call(body_src, true, Set.new)
                if !body.equal?(body_src)
                  nv = v.dup
                  nv.body = body
                  nb = b.dup
                  nb.value = nv
                  out << nb
                  scope_changed = true
                else
                  out << b
                end
              elsif nested && candidates.include?(b.name) && !refs.include?(b.name) &&
                    !protect.include?(b.name) && !has_side_effect?(v)
                scope_changed = true
              else
                out << b
              end
            end
            next scope unless scope_changed

            changed = true
            out
          end

          nxt = filter_scope.call(current, false, Set.new)
          return current unless changed

          current = nxt
        end
      end

      # F-108: whether +method+'s LAST binding is its return value. Stack
      # lowering inlines a private method at each +method_call+ and takes that
      # binding as the call's result, so it is a liveness root even though
      # nothing inside the method references it; without the root a pure
      # return expression (+return n + 1n+) was deleted and the helper emptied.
      # The predicate is the one stack lowering uses to collect inlinable
      # private methods. A public method's last binding is never a return value.
      def self.returns_last_binding?(method)
        method.name != "constructor" && !method.is_public
      end

      # Collect every SSA name a binding brings into scope: its own +name+,
      # plus -- for the two nesting kinds -- an +if+'s declared +results+ (the
      # merged branch locals / property slots both arms leave behind) and the
      # names bound inside +then+, +else_+ and a +loop+ body, recursively.
      #
      # +iter_var+ is deliberately absent: it is the loop's own induction
      # variable, referenced only from inside the body, so counting it as
      # defined would make every non-trivial loop unconditionally live.
      def self.collect_defined_names(binding, out)
        out.add(binding.name)
        v = binding.value
        case v.kind
        when "if"
          v.results&.each { |r| out.add(r) }
          v.then&.each  { |b| collect_defined_names(b, out) }
          v.else_&.each { |b| collect_defined_names(b, out) }
        when "loop"
          v.body&.each { |b| collect_defined_names(b, out) }
        end
      end

      # Is any name this binding defines referenced by some OTHER binding?
      #
      # +ref_count+ maps a name to the number of DISTINCT bindings referencing
      # it; +own_refs+ is this binding's own contribution. Subtracting it is
      # what keeps the rule from degenerating into "never delete an +if+ or a
      # +loop+": an arm's bindings almost always reference each other, and
      # counting those self-references would make every nesting node immortal.
      #
      # For a non-nesting binding this is exactly the old
      # +used.include?(binding.name)+: ANF has no self-reference, so +own_refs+
      # never holds the binding's own name.
      def self.referenced_externally?(binding, own_refs, ref_count)
        defined_names = Set.new
        collect_defined_names(binding, defined_names)
        defined_names.any? do |name|
          ref_count[name] - (own_refs.include?(name) ? 1 : 0) > 0
        end
      end

      # Walk an ANFValue and collect all binding name references.
      #
      # Explicit kind dispatch so an unknown variant raises
      # UnknownANFKindError instead of silently contributing zero refs
      # (which would cause DCE to drop a live binding).
      def self.collect_refs(v, used)
        case v.kind
        when "load_param"
          # N-356: a reassigned parameter is bound under its own name and read
          # back as `load_param <name>`; count the read so DCE keeps the
          # rebinding. Matches TS collectRefsFromValue.
          used.add(v.name) if v.name
        when "load_prop", "get_state_script"
          # No refs.
        when "load_const"
          if v.const_string && v.const_string.start_with?("@ref:")
            used.add(v.const_string[5..])
          end
        when "bin_op"
          used.add(v.left)  if v.left
          used.add(v.right) if v.right
        when "unary_op"
          used.add(v.operand) if v.operand
        when "call"
          v.args&.each { |a| used.add(a) }
        when "method_call"
          used.add(v.object) if v.object
          v.args&.each { |a| used.add(a) }
        when "if"
          used.add(v.cond) if v.cond
          v.then&.each  { |b| collect_refs(b.value, used) }
          v.else_&.each { |b| collect_refs(b.value, used) }
        when "loop"
          v.body&.each { |b| collect_refs(b.value, used) }
        when "assert", "update_prop"
          used.add(v.value_ref) if v.value_ref
        when "check_preimage", "deserialize_state"
          used.add(v.preimage) if v.preimage
        when "add_output"
          used.add(v.satoshis) if v.satoshis
          v.state_values&.each { |sv| used.add(sv) }
          used.add(v.preimage) if v.preimage
        when "add_raw_output", "add_data_output"
          used.add(v.satoshis)     if v.satoshis
          used.add(v.script_bytes) if v.script_bytes
        when "array_literal"
          v.elements&.each { |e| used.add(e) }
        when "raw_script"
          # Opaque: no SSA operand refs.
        else
          # Exhaustiveness guard.  A silent no-op would let DCE drop a
          # live binding because its refs go uncollected.
          raise ::RunarCompiler::IR::UnknownANFKindError.new(v.kind, "anf-optimize.collectRefs")
        end
      end

      def self.has_side_effect?(v)
        kind = v.kind
        # Issue #109 (+@embedAlways+): a +load_prop+ injected to force a readonly
        # field into the deployed locking script carries +preserve = true+, so
        # DCE must keep it even though nothing references it. Ordinary
        # load_props (preserve = false) remain freely eliminable. Mirrors
        # compilers/zig/src/passes/dce.zig.
        return v.preserve == true if kind == "load_prop"

        # A bin_op that can ABORT the script is not removable: purity is not
        # totality (spec/semantics.md §3.7). +& | ^+ fail on operands of
        # unequal byte length, +<< >>+ on a negative count, +/ %+ on a zero
        # divisor; deleting the binding turns an abort into an accept
        # (execution-fuzzer seed 1351961626). Mirrors
        # packages/runar-compiler/src/optimizer/dce.ts.
        return PARTIAL_BIN_OPS.include?(v.op) if kind == "bin_op"

        # R-140: recursion is what makes retention both safe and precise.
        # Nested bindings live inside the parent node rather than flattened into
        # the method body, so dropping an effectful +if+ would take every nested
        # assert / check_preimage / add_output with it -- retention is
        # all-or-nothing. Mirrors packages/runar-compiler/src/optimizer/dce.ts
        # and compilers/go/frontend/dce.go.
        if kind == "if"
          return (v.then || []).any? { |b| has_side_effect?(b.value) } ||
                 (v.else_ || []).any? { |b| has_side_effect?(b.value) }
        end
        return (v.body || []).any? { |b| has_side_effect?(b.value) } if kind == "loop"

        return true  if SIDE_EFFECT_KINDS.include?(kind)
        return false if SIDE_EFFECT_FREE_KINDS.include?(kind)

        raise ::RunarCompiler::IR::UnknownANFKindError.new(kind, "anf-optimize.hasSideEffect")
      end
    end
  end
end

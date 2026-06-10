# frozen_string_literal: true

# Dead Code Elimination pass for ANF IR.
#
# Removes bindings whose results are never referenced by other bindings,
# preserving bindings with observable side effects (assert, update_prop,
# check_preimage, add_output, add_raw_output, add_data_output, call,
# method_call, raw_script). Iterates to a fixed point so transitively
# dead bindings are also removed.
#
# This module is the canonical, standalone DCE pass for the Ruby
# compiler. It mirrors the Zig reference implementation in
# +compilers/zig/src/passes/dce.zig+. The earlier inline implementation
# in +anf_optimize.rb+ has been surgically extracted here.
#
# Behaviour: byte-for-byte identical to the previous inline DCE in
# +anf_optimize.rb+. Verified by the conformance suite (cross-tier hex
# parity) and the unknown-kind exhaustiveness tests.

require "set"
require_relative "../ir/types"

module RunarCompiler
  module Frontend
    module DCE
      SIDE_EFFECT_KINDS = %w[
        assert update_prop check_preimage deserialize_state
        add_output add_raw_output add_data_output
        raw_script
        if loop call method_call
      ].to_set.freeze

      # Kinds known to have no observable side effects.  Listed explicitly
      # so an unknown kind raises UnknownANFKindError instead of silently
      # being treated as side-effect-free (which would cause DCE to drop
      # a new side-effecting variant).
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
      def self.eliminate_dead_bindings(method)
        current = method.body
        changed = true

        while changed
          changed = false
          used = Set.new
          current.each { |binding| collect_refs(binding.value, used) }

          filtered = []
          current.each do |binding|
            if used.include?(binding.name) || has_side_effect?(binding.value)
              filtered << binding
            else
              changed = true
            end
          end

          current = filtered
        end

        method.body = current
      end

      # Walk an ANFValue and collect all binding name references.
      #
      # Explicit kind dispatch so an unknown variant raises
      # UnknownANFKindError instead of silently contributing zero refs
      # (which would cause DCE to drop a live binding).
      def self.collect_refs(v, used)
        case v.kind
        when "load_param", "load_prop", "get_state_script"
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
        return true  if SIDE_EFFECT_KINDS.include?(kind)
        return false if SIDE_EFFECT_FREE_KINDS.include?(kind)

        raise ::RunarCompiler::IR::UnknownANFKindError.new(kind, "anf-optimize.hasSideEffect")
      end
    end
  end
end

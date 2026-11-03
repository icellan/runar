# frozen_string_literal: true

# F-017 — the identifier-collision rule.
#
# Five surfaces rename identifiers on the way into the AST: .runar.py,
# .runar.rb, .runar.rs, .runar.move (snake_case -> camelCase) and .runar.go
# (PascalCase -> camelCase). None of those mappings is injective: +tmp+ and
# +tmp_+, +a_b+ and +aB+, +_tmp+ and +tmp+ (.py/.rb), +Tmp+ and +tmp+ (.go)
# each land on one Rúnar name. Before this rule both spellings were bound to
# ONE variable, so <tt>tmp = n + 1; tmp_ = n + 2; assert_(tmp == tmp_)</tt> —
# always false in the source language — compiled to a self-comparison that
# always passes.
#
# While parsing one contract, the surface parser records (source spelling,
# Rúnar name) for every identifier it DECLARES: properties / struct fields,
# method names (not the constructor), parameters (not receivers), locals at
# every declaration or bare-name assignment target, and loop variables. If two
# recorded pairs share a Rúnar name but differ in spelling, the contract is
# refused with exactly one error whose text is identical in all seven tiers.
# Mirrors +identifierCollisionMessage+ in
# packages/runar-compiler/src/passes/snake-to-camel.ts.

require_relative "diagnostic"

module RunarCompiler
  module Frontend
    module IdentifierCollision
      # The collision with the smallest Rúnar name and, for it, the two
      # smallest source spellings (byte order), so the report does not depend
      # on declaration order. +nil+ when every name has one spelling.
      def self.message(decls)
        spellings = Hash.new { |h, k| h[k] = [] }
        decls.each { |raw, name| spellings[name] << raw unless spellings[name].include?(raw) }
        colliding = spellings.keys.select { |name| spellings[name].length >= 2 }
        return nil if colliding.empty?

        name = colliding.min
        a, b = spellings[name].sort.first(2)
        "identifier collision: '#{a}' and '#{b}' both convert to '#{name}'; rename one of them"
      end

      # The single F-017 error as a diagnostic list (empty when none).
      def self.diagnostics(decls)
        msg = message(decls)
        msg.nil? ? [] : [Diagnostic.new(message: msg, severity: Severity::ERROR)]
      end
    end
  end
end

# frozen_string_literal: true

# `@bindingVariant` directive parsing.
#
# A public method may carry a `/** @bindingVariant <VARIANT> */` comment
# directive selecting which Any-S OP_PUSH_TX preimage-binding construction its
# auto-injected covenant emits: "lowS" (default; low-S fixup, safe under the
# LOW_S rule that applies to nVersion = 1) or "all" (compact non-low-S, ~50
# bytes smaller, valid only for spends with nVersion != 1).
#
# Direct port of packages/runar-compiler/src/passes/bindingvariant-directive.ts.
# The parser owns *detection* of the directive comment; this module owns the
# *variant grammar* (name -> validity). Mirrors SighashDirective.
module RunarCompiler
  module Frontend
    module BindingVariantDirective
      module_function

      # The construction used when no directive is present.
      BINDING_VARIANT_DEFAULT = "lowS"

      # The recognised variant names (as written). Case-sensitive.
      BINDING_VARIANT_VALUES = %w[lowS all].freeze

      # Regex extracting the value following an `@bindingVariant` token in a
      # block of comment text. Mirrors the TS BINDING_VARIANT_RE.
      BINDING_VARIANT_RE = /@bindingVariant\s+([A-Za-z0-9_]*?)(?:\*\/|\n|\r|\s|$)/

      # Parse the value text of a `@bindingVariant` directive.
      #
      # `variant_text` is the raw text following `@bindingVariant` (e.g. `"all"`).
      #
      # Case-sensitive: only "lowS" and "all" are accepted, so a typo is rejected
      # rather than silently defaulted (a mis-declared binding is an exploit
      # class).
      #
      # @return [Hash] {value: String} on success, or {error: String} on failure
      def parse_binding_variant(variant_text)
        raw = variant_text.strip
        if raw.empty?
          return { error: "@bindingVariant directive requires a value (`@bindingVariant all` or `@bindingVariant lowS`)" }
        end
        unless BINDING_VARIANT_VALUES.include?(raw)
          return { error: "@bindingVariant: unknown variant \"#{raw}\" (valid: lowS, all)" }
        end

        { value: raw }
      end

      # Extract and parse an `@bindingVariant` directive from a block of comment
      # text. Returns nil when no `@bindingVariant` token is present, otherwise
      # the parse result ({value:} or {error:}).
      def extract_binding_variant_directive(comment_text)
        m = BINDING_VARIANT_RE.match(comment_text)
        return nil if m.nil?

        parse_binding_variant(m[1] || "")
      end
    end
  end
end

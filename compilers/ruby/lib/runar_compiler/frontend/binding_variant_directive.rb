# frozen_string_literal: true

module RunarCompiler
  module Frontend
    # `@bindingVariant` directive parsing (ports #170; original design:
    # brendan-elas, #167). Mirrors
    # packages/runar-compiler/src/passes/bindingvariant-directive.ts; diagnostic
    # text is identical in all seven tiers.
    #
    # A public `.runar.ts` method may carry `/** @bindingVariant <lowS|all> */`,
    # selecting the Any-S OP_PUSH_TX binding construction its checkPreimage
    # emits. `lowS` (default) is valid at every tx nVersion; `all` is the
    # compact non-low-S blob, spendable only when the spending tx has
    # nVersion > 1. Same marker rules as `@sighash` (F-039 / N-039): one marker
    # per method, and anything other than ` lowS` / ` all` after it is an error.
    module BindingVariantDirective
      MARKER = "@bindingVariant"

      MALFORMED_ERROR =
        "@bindingVariant: malformed directive; expected `@bindingVariant lowS` or `@bindingVariant all`"
      MULTIPLE_ERROR =
        "@bindingVariant: more than one @bindingVariant directive on this method; declare exactly one"

      module_function

      def parse_binding_variant(text)
        raw = text.gsub(/\A[ \t]+|[ \t]+\z/, "")
        return { value: raw } if %w[lowS all].include?(raw)
        return { error: MALFORMED_ERROR } if raw.empty?

        { error: "@bindingVariant: unknown variant \"#{raw}\" (valid: lowS, all)" }
      end

      # Extract and parse a `@bindingVariant` directive from a method's
      # leading-comment text. nil only when no marker occurs.
      def extract_binding_variant_directive(comment_text)
        first = comment_text.index(MARKER)
        return nil if first.nil?

        after = comment_text[(first + MARKER.length)..]
        return { error: MULTIPLE_ERROR } if after.include?(MARKER)

        end_idx = after.length
        after.each_char.with_index do |c, i|
          if c == "\n" || c == "\r" || (c == "*" && after[i + 1] == "/")
            end_idx = i
            break
          end
        end
        seg = after[0...end_idx]
        return { error: MALFORMED_ERROR } unless seg.match?(/\A[ \t][A-Za-z0-9_ \t]*\z/)

        parse_binding_variant(seg)
      end

      # The non-TS surfaces' refusal, identical in all seven tiers.
      def unsupported_message(surface_name)
        "@bindingVariant directive is not supported by the #{surface_name} surface parser; " \
          "write the contract in TypeScript (.runar.ts), where @bindingVariant is honoured"
      end
    end
  end
end

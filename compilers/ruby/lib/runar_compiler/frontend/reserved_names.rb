# frozen_string_literal: true

# N-065 / N-060 -- compiler-reserved names. Port of
# packages/runar-compiler/src/passes/reserved-names.ts (read it for the
# families and for why each one is, or is not, reserved).
#
# A user name spelled like one a pass mints aliases two values, because every
# later pass resolves names by string equality. A program that declares one is
# refused with ONE sentence shared verbatim by all seven tiers.

module RunarCompiler
  module Frontend
    module ReservedNames
      # 05-stack-lower: _codePart, __param_<name>, __shadowed_<n>_<name>, _pub_<n>
      STACK_LOWERING_RESERVED = [
        /\A_codePart\z/,
        /\A__param_/,
        /\A__shadowed_/,
        /\A_pub_[0-9]+\z/
      ].freeze

      # 04-anf-lower: t<digits>, __merge$<digits>
      ANF_BINDING_RESERVED = [
        /\At[0-9]+\z/,
        /\A__merge\$[0-9]+\z/
      ].freeze

      # 03b fixed-array slots / temps and the auto-injected parameters.
      SOURCE_ONLY_RESERVED = [
        /\A.+__[0-9]+\z/m,
        /\A__idx_[0-9]+\z/,
        /\A__val_[0-9]+\z/,
        /\A_changePKH\z/,
        /\A_changeAmount\z/,
        /\A_newAmount\z/,
        /\A_serialisedOutputs\z/,
        /\A_prevOutScript_[0-9]+\z/
      ].freeze

      # The diagnostic, shared verbatim by all seven tiers (source and --ir).
      def self.message(name)
        "'" + name + "' is reserved for compiler-generated names and cannot be used as an identifier"
      end

      def self.matches_any?(name, res)
        res.any? { |r| r.match?(name) }
      end

      # True if a SOURCE program may not declare +name+ (after name mapping).
      def self.reserved_source_name?(name, stateful)
        matches_any?(name, STACK_LOWERING_RESERVED) ||
          matches_any?(name, ANF_BINDING_RESERVED) ||
          matches_any?(name, SOURCE_ONLY_RESERVED) ||
          (stateful && name == "txPreimage")
      end

      # --ir rule. +declaration+ is true for a property / method / parameter /
      # loop-variable name and for the name a load_param / load_prop /
      # update_prop addresses; false for a binding name or reference.
      def self.reserved_ir_name?(name, declaration)
        matches_any?(name, STACK_LOWERING_RESERVED) ||
          (declaration && matches_any?(name, ANF_BINDING_RESERVED))
      end

      REF_FIELDS = %w[left right operand cond object preimage satoshis scriptBytes].freeze
      REF_LIST_FIELDS = %w[args stateValues elements].freeze

      # Mirror of TS assertNoReservedIrNames, on the parsed IR JSON hash.
      # Raises ArgumentError with the shared message.
      def self.assert_no_reserved_ir_names!(d)
        check = lambda do |name, declaration|
          if name.is_a?(String) && reserved_ir_name?(name, declaration)
            raise ArgumentError, message(name)
          end
        end
        walk = lambda do |bindings|
          return unless bindings.is_a?(Array)

          bindings.each do |b|
            next unless b.is_a?(Hash)

            check.call(b["name"], false)
            v = b["value"]
            next unless v.is_a?(Hash)

            case v["kind"]
            when "load_param", "load_prop"
              check.call(v["name"], true)
            when "update_prop"
              check.call(v["name"], true)
              check.call(v["value"], false)
            when "load_const"
              val = v["value"]
              check.call(val[5..], false) if val.is_a?(String) && val.start_with?("@ref:")
            when "loop"
              check.call(v["iterVar"], true)
            else
              REF_FIELDS.each { |k| check.call(v[k], false) }
              check.call(v["value"], false) if v["kind"] == "assert"
              REF_LIST_FIELDS.each do |k|
                list = v[k]
                list.each { |r| check.call(r, false) } if list.is_a?(Array)
              end
            end
            %w[body then else].each { |k| walk.call(v[k]) }
          end
        end

        (d["properties"] || []).each { |p| check.call(p["name"], true) if p.is_a?(Hash) }
        (d["methods"] || []).each do |m|
          next unless m.is_a?(Hash)

          check.call(m["name"], true)
          (m["params"] || []).each { |p| check.call(p["name"], true) if p.is_a?(Hash) }
          walk.call(m["body"])
        end
      end
    end
  end
end

# frozen_string_literal: true

require "set"
require_relative "../frontend/validator"

# N-205 (b): F-286's verifyRabinSig key-provenance rule, and N-205 (a)'s rule
# for writes to a key property, re-asserted on --ir input. Port of
# packages/runar-compiler/src/ir/rabin-key-provenance.ts: same rule, same
# order, same words (conformance/negatives/ir-rabin-key-provenance.test.ts).
#
# A ref is trusted when EVERY binding of that name in the method (flattened in
# pre-order: a binding, then its then / else / body) is:
#   - load_prop;
#   - an integer load_const;
#   - load_const "@ref:<x>" with <x> trusted;
#   - load_param of a PRIVATE method whose every method_call site (at least
#     one) passes a trusted ref in that position (least fixed point);
#   - an if with no results, both arms non-empty and each arm's last binding
#     trusted.
# KEY properties are the load_prop names a verifyRabinSig 4th argument can
# come from, closed under trusted writes into a key property. Writes (outside
# the constructor): update_prop, and add_output state_values[i] -> the i-th
# non-readonly property. Method by method, first refusal wins: every
# verifyRabinSig call with an untrusted key, then every untrusted write of a
# mutable key property.
module RunarCompiler
  module IR
    module RabinKeyProvenance
      def self.flatten(bindings, out)
        (bindings || []).each do |b|
          out << b
          v = b.value
          flatten(v.then, out)
          flatten(v.else_, out)
          flatten(v.body, out)
        end
      end

      def self.assert!(program)
        pubkey_msg = Frontend::ValidationContext::RABIN_PUBKEY_PROVENANCE_MESSAGE
        flat = {}.compare_by_identity
        by_name = {}.compare_by_identity
        program.methods.each do |m|
          list = []
          flatten(m.body, list)
          flat[m] = list
          names = {}
          list.each { |b| (names[b.name] ||= []) << b.value }
          by_name[m] = names
        end

        is_private = ->(m) { !m.is_public && m.name != "constructor" }
        privates = {}
        program.methods.each { |m| privates[m.name] = m if is_private.call(m) }

        call_sites = {}
        privates.each_key { |n| call_sites[n] = [] }
        program.methods.each do |m|
          flat[m].each do |b|
            v = b.value
            call_sites[v.method] << { args: v.args || [], method: m } if v.kind == "method_call" && privates.key?(v.method)
          end
        end

        trusted_params = {}
        privates.each_key { |n| trusted_params[n] = Set.new }

        trusted = nil
        trusted = lambda do |ref, m, visiting|
          values = by_name[m][ref]
          return false if values.nil? || visiting.include?(ref)

          visiting.add(ref)
          ok = values.all? do |v|
            case v.kind
            when "load_prop"
              true
            when "load_const"
              if !v.const_big_int.nil?
                true
              else
                s = v.const_string
                s.is_a?(String) && s.start_with?("@ref:") && trusted.call(s[5..], m, visiting)
              end
            when "load_param"
              if is_private.call(m)
                idx = m.params.index { |p| p.name == v.name }
                !idx.nil? && trusted_params[m.name].include?(idx)
              else
                false
              end
            when "if"
              if !v.results.nil? && !v.results.empty?
                false
              else
                a = (v.then || []).last
                b = (v.else_ || []).last
                !a.nil? && !b.nil? && trusted.call(a.name, m, visiting) && trusted.call(b.name, m, visiting)
              end
            else
              false
            end
          end
          visiting.delete(ref)
          ok
        end

        changed = true
        while changed
          changed = false
          privates.each do |name, m|
            sites = call_sites[name]
            next if sites.empty?

            tp = trusted_params[name]
            m.params.each_index do |i|
              next if tp.include?(i)

              if sites.all? { |s| !s[:args][i].nil? && trusted.call(s[:args][i], s[:method], Set.new) }
                tp.add(i)
                changed = true
              end
            end
          end
        end

        sources_of = nil
        sources_of = lambda do |ref, m, out, visiting|
          key = [m.name, ref]
          next if visiting.include?(key)

          visiting.add(key)
          (by_name[m][ref] || []).each do |v|
            case v.kind
            when "load_prop"
              out.add(v.name)
            when "load_const"
              s = v.const_string
              sources_of.call(s[5..], m, out, visiting) if v.const_big_int.nil? && s.is_a?(String) && s.start_with?("@ref:")
            when "if"
              [v.then, v.else_].each do |arm|
                last = (arm || []).last
                sources_of.call(last.name, m, out, visiting) unless last.nil?
              end
            when "load_param"
              if is_private.call(m)
                idx = m.params.index { |p| p.name == v.name }
                (call_sites[m.name] || []).each do |site|
                  arg = idx.nil? ? nil : site[:args][idx]
                  sources_of.call(arg, site[:method], out, visiting) unless arg.nil?
                end
              end
            end
          end
        end

        key_props = Set.new
        program.methods.each do |m|
          flat[m].each do |b|
            v = b.value
            if v.kind == "call" && v.func == "verifyRabinSig" && (v.args || []).length >= 4
              sources_of.call(v.args[3], m, key_props, Set.new)
            end
          end
        end

        mutable_props = program.properties.reject(&:readonly).map(&:name)
        writes = []
        program.methods.each do |m|
          next if m.name == "constructor"

          flat[m].each do |b|
            v = b.value
            writes << { prop: v.name, value: v.value_ref, method: m } if v.kind == "update_prop"
            next unless v.kind == "add_output"

            (v.state_values || []).each_with_index do |value, i|
              prop = mutable_props[i]
              writes << { prop: prop, value: value, method: m } unless prop.nil?
            end
          end
        end

        loop do
          before = key_props.size
          writes.each do |w|
            next unless key_props.include?(w[:prop]) && trusted.call(w[:value], w[:method], Set.new)

            sources_of.call(w[:value], w[:method], key_props, Set.new)
          end
          break if key_props.size == before
        end

        mutable = Set.new(mutable_props)
        program.methods.each do |m|
          flat[m].each do |b|
            v = b.value
            next unless v.kind == "call" && v.func == "verifyRabinSig" && (v.args || []).length >= 4
            next if trusted.call(v.args[3], m, Set.new)

            raise ArgumentError, "IR validation: method '#{m.name}': #{pubkey_msg}"
          end
          writes.each do |w|
            next unless w[:method].equal?(m) && key_props.include?(w[:prop]) && mutable.include?(w[:prop])
            next if trusted.call(w[:value], m, Set.new)

            raise ArgumentError,
                  "IR validation: method '#{m.name}': #{Frontend::ValidationContext.rabin_key_write_message(w[:prop])}"
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

# N-101: the scaffolding StatefulSmartContract lowering injects, re-derived for
# --ir input.
#
# --ir skips the frontend, so a program labelled (or, per N-087, inferred)
# StatefulSmartContract could omit or fake the scaffolding ANF lowering injects
# into every public method and compile to an anyone-can-spend script: F-107's
# attack body compiled to 76767b8777. For each public method this re-derives
# what the frontend would inject (the TypeScript reference is
# packages/runar-compiler/src/passes/stateful-scaffold.ts):
#
#   prologue      assert(checkPreimage(txPreimage)), the sighash-type assert
#                 and, when the contract has mutable properties,
#                 deserialize_state
#   user code     free
#   continuation  when the method mutates state or declares outputs: the
#                 _newAmount floor (single-output form), the change output and
#                 the hashOutputs comparison over every output in order
#
# and reports, with the diagnostics all seven tiers share
# (conformance/negatives/ir-stateful-scaffold-cases.json), the first of: (1)
# the auto-injected parameters, (2) the prologue or (3) the continuation
# differ, or (4) a scaffolding binding, or an output the continuation commits
# to, is bound more than once or shares a property or parameter name.

require "json"
require "set"
require_relative "types"

module RunarCompiler
  module IR
    module StatefulScaffold
      SIGHASH_DEFAULT = 0x41
      STATE_OUTPUT_KINDS = %w[add_output add_raw_output].freeze
      DATA_OUTPUT_KINDS = %w[add_data_output].freeze

      class Emitter
        attr_reader :out

        def initialize(taken, counter)
          @taken = taken
          @counter = counter
          @out = []
        end

        def emit(value)
          name = nil
          loop do
            name = "$scaffold#{@counter[0]}"
            @counter[0] += 1
            break unless @taken.include?(name)
          end
          @out << ANFBinding.new(name: name, value: value)
          name
        end

        def sub
          Emitter.new(@taken, @counter)
        end
      end

      def self.value(kind, **fields)
        v = ANFValue.new(kind: kind)
        fields.each { |k, val| v.public_send(:"#{k}=", val) }
        v
      end

      def self.param(name)
        value("load_param", name: name)
      end

      def self.call(func, *args)
        value("call", func: func, args: args)
      end

      def self.assert_of(ref)
        value("assert", value_ref: ref)
      end

      def self.bin(op, left, right, result_type = nil)
        value("bin_op", op: op, left: left, right: right, result_type: result_type)
      end

      def self.prologue(e, sighash_mode, has_mutable_state)
        pre = e.emit(param("txPreimage"))
        flag = sighash_mode == SIGHASH_DEFAULT ? nil : sighash_mode
        e.emit(assert_of(e.emit(value("check_preimage", preimage: pre, sighash_flag: flag))))
        p2 = e.emit(param("txPreimage"))
        typ = e.emit(call("extractSigHashType", p2))
        want = e.emit(value("load_const", const_big_int: sighash_mode))
        e.emit(assert_of(e.emit(bin("===", typ, want))))
        return unless has_mutable_state

        p3 = e.emit(param("txPreimage"))
        e.emit(value("deserialize_state", preimage: p3))
      end

      def self.continuation(e, needs_change, includes_change, state_refs, data_refs)
        return unless needs_change

        if state_refs.empty?
          p = e.emit(param("txPreimage"))
          amount = e.emit(call("extractAmount", p))
          new_amount = e.emit(param("_newAmount"))
          e.emit(assert_of(e.emit(bin(">=", new_amount, amount))))
        end
        # N-038: under a SIGHASH_SINGLE base no change segment exists.
        change = nil
        if includes_change
          pkh = e.emit(param("_changePKH"))
          amt = e.emit(param("_changeAmount"))
          zero = e.emit(value("load_const", const_big_int: 0))
          non_zero = e.emit(bin("!==", amt, zero))
          then_e = e.sub
          then_e.emit(call("buildChangeOutput", pkh, amt))
          else_e = e.sub
          else_e.emit(value("load_const", const_string: ""))
          change = e.emit(value("if", cond: non_zero, then: then_e.out, else_: else_e.out))
        end
        if state_refs.empty?
          script = e.emit(value("get_state_script"))
          p = e.emit(param("txPreimage"))
          new_amount = e.emit(param("_newAmount"))
          acc = e.emit(call("computeStateOutput", p, script, new_amount))
        else
          acc = state_refs[0]
          state_refs[1..].each { |r| acc = e.emit(call("cat", acc, r)) }
        end
        data_refs.each { |r| acc = e.emit(call("cat", acc, r)) }
        acc = e.emit(call("cat", acc, change)) unless change.nil?
        digest = e.emit(call("hash256", acc))
        p = e.emit(param("txPreimage"))
        out_hash = e.emit(call("extractOutputHash", p))
        eq = e.emit(bin("===", digest, out_hash, "bytes"))
        e.emit(value("assert", value_ref: eq, is_auto_injected_state_check: true))
      end

      def self.nested(v)
        [v.then, v.else_, v.body].compact.reject(&:empty?)
      end

      def self.contains?(bindings, kinds)
        bindings.any? { |b| kinds.include?(b.value.kind) || nested(b.value).any? { |n| contains?(n, kinds) } }
      end

      # The frontend's side-effect summary, read off the IR (update_prop is a
      # state mutation, add_output / add_raw_output a state output,
      # add_data_output a data output) at any depth and through method_calls to
      # private methods.
      def self.shape(program, method)
        privates = program.methods.reject { |m| m.is_public || m.name == "constructor" }.to_h { |m| [m.name, m] }
        mutates = state = data = false
        visited = Set.new
        walk = lambda do |bindings|
          bindings.each do |b|
            v = b.value
            if v.kind == "update_prop"
              mutates = true
            elsif STATE_OUTPUT_KINDS.include?(v.kind)
              state = true
            elsif v.kind == "add_data_output"
              data = true
            elsif v.kind == "method_call"
              target = privates[v.method.to_s]
              if target && !visited.include?(target.name)
                visited << target.name
                walk.call(target.body)
              end
            end
            nested(v).each { |n| walk.call(n) }
          end
        end
        walk.call(method.body)
        needs_change = mutates || state || data
        # N-038: a SIGHASH_SINGLE base commits no change output.
        mode = method.sighash_type.nil? ? SIGHASH_DEFAULT : method.sighash_type
        includes_change = needs_change && (mode & 0x1F) != 0x03
        [needs_change, includes_change, (mutates || data) && !state]
      end

      def self.describe(v)
        case v.kind
        when "load_param" then "load_param #{v.name}"
        when "load_const"
          v.const_string.nil? ? "load_const #{v.const_big_int}" : "load_const #{JSON.generate(v.const_string)}"
        when "call" then "call #{v.func}"
        when "bin_op" then "bin_op #{v.op}"
        else v.kind
        end
      end

      def self.const_int(v)
        return nil unless v.const_bool.nil? && v.const_string.nil?

        v.const_big_int.nil? ? v.const_int : v.const_big_int
      end

      class Matcher
        def initialize
          @map = {}
          @mapped = Set.new
        end

        def ref(e, a)
          @map.key?(e) ? @map[e] == a : e == a
        end

        def binding(exp, act)
          e = exp.value
          a = act.value
          return false unless e.kind == a.kind

          ok =
            case e.kind
            when "load_param" then e.name == a.name
            when "load_const"
              if e.const_string.nil?
                StatefulScaffold.const_int(a) == e.const_big_int
              else
                a.const_string == e.const_string && a.const_bool.nil?
              end
            when "check_preimage"
              ref(e.preimage, a.preimage) &&
                (e.sighash_flag || SIGHASH_DEFAULT) == (a.sighash_flag || SIGHASH_DEFAULT)
            when "assert" then ref(e.value_ref, a.value_ref)
            when "call"
              ea = e.args || []
              aa = a.args || []
              e.func == a.func && ea.length == aa.length && ea.zip(aa).all? { |x, y| ref(x, y) }
            when "bin_op"
              e.op == a.op && ref(e.left, a.left) && ref(e.right, a.right) &&
                (e.result_type.nil? || e.result_type.empty? ? nil : e.result_type) ==
                  (a.result_type.nil? || a.result_type.empty? ? nil : a.result_type)
            when "deserialize_state" then ref(e.preimage, a.preimage)
            when "get_state_script" then true
            when "if"
              ref(e.cond, a.cond) && (a.results.nil? || a.results.empty?) &&
                sequence(e.then || [], a.then || []) == -1 && sequence(e.else_ || [], a.else_ || []) == -1
            else false
            end
          return false if !ok || @mapped.include?(act.name)

          @map[exp.name] = act.name
          @mapped << act.name
          true
        end

        # Index of the first binding that differs (a missing one included), or -1.
        def sequence(exp, act)
          exp.each_with_index do |e, i|
            return i if i >= act.length || !binding(e, act[i])
          end
          act.length == exp.length ? -1 : exp.length
        end
      end

      def self.collect_names(bindings, counts)
        bindings.each do |b|
          counts[b.name] += 1
          (b.value.results || []).each { |r| counts[r] += 1 }
          counts[b.value.iter_var] += 1 if b.value.kind == "loop" && b.value.iter_var && !b.value.iter_var.empty?
          nested(b.value).each { |n| collect_names(n, counts) }
        end
      end

      def self.scaffold(method, detail)
        "stateful method '#{method}' does not carry the scaffolding " \
          "StatefulSmartContract lowering injects: #{detail}"
      end

      # The first scaffolding divergence, without the "IR validation: " prefix
      # load_ir adds, or nil.
      def self.error(program)
        has_mutable = program.properties.any? { |p| !p.readonly }
        props = program.properties.map(&:name).to_set
        program.methods.each do |m|
          next if !m.is_public || m.name == "constructor"

          needs_change, includes_change, needs_new_amount = shape(program, m)

          # (1) the parameters, contiguous and once each.
          required = []
          required += [%w[_changePKH Ripemd160], %w[_changeAmount bigint]] if includes_change
          required << %w[_newAmount bigint] if needs_new_amount
          required << %w[txPreimage SigHashPreimage]
          names = m.params.map(&:name)
          start = names.index(required[0][0])
          params_ok = !start.nil? && required.each_with_index.all? do |(n, t), i|
            p = m.params[start + i]
            !p.nil? && p.name == n && p.type == t && names.count(n) == 1
          end
          unless params_ok
            listed = required.map { |n, t| "#{n}: #{t}" }.join(", ")
            return "stateful method '#{m.name}' must declare the auto-injected parameters " \
                   "(#{listed}) contiguously and once each, as StatefulSmartContract lowering does"
          end

          counts = Hash.new(0)
          collect_names(m.body, counts)
          taken = counts.keys.to_set
          counter = [0]
          match = Matcher.new

          # (2) the prologue.
          pro = Emitter.new(taken, counter)
          prologue(pro, m.sighash_type.nil? ? SIGHASH_DEFAULT : m.sighash_type, has_mutable)
          head = m.body[0, pro.out.length] || []
          i = match.sequence(pro.out, head)
          return scaffold(m.name, "prologue binding #{i} must be #{describe(pro.out[i].value)}") if i != -1

          # (3) the continuation, over the outputs the method's own top-level
          # bindings declare (an `if` counts once, as a state output when either
          # arm holds one, else as a data output), in order.
          rest = m.body[pro.out.length..] || []
          state_out = []
          data_out = []
          rest.each do |b|
            k = b.value.kind
            if STATE_OUTPUT_KINDS.include?(k)
              state_out << b
            elsif k == "add_data_output"
              data_out << b
            elsif k == "if"
              if nested(b.value).any? { |n| contains?(n, STATE_OUTPUT_KINDS) }
                state_out << b
              elsif nested(b.value).any? { |n| contains?(n, DATA_OUTPUT_KINDS) }
                data_out << b
              end
            end
          end
          tail = Emitter.new(taken, counter)
          continuation(tail, needs_change, includes_change, state_out.map(&:name), data_out.map(&:name))
          offset = rest.length - tail.out.length
          tail.out.each_with_index do |e, j|
            if offset + j < 0 || !match.binding(e, rest[offset + j])
              return scaffold(m.name, "continuation binding #{j} must be #{describe(e.value)}")
            end
          end

          # (4) unique, unshadowed names for what the scaffolding binds or
          # commits to. A binding's own arms may reuse its name (an
          # output-carrying `if` is named after its arm's last binding).
          params = names.to_set
          checked = []
          preorder = lambda do |bindings|
            bindings.each do |b|
              checked << b
              nested(b.value).each { |n| preorder.call(n) }
            end
          end
          preorder.call(head)
          preorder.call(rest[offset..]) if offset >= 0
          checked.concat(state_out, data_out)
          checked.each do |b|
            inner = Hash.new(0)
            nested(b.value).each { |n| collect_names(n, inner) }
            next unless counts[b.name] - inner[b.name] != 1 || props.include?(b.name) || params.include?(b.name)

            return "stateful method '#{m.name}' must bind '#{b.name}' exactly once, under a name " \
                   "no property or parameter uses: the injected scaffolding binds it or the " \
                   "continuation commits to it"
          end
        end
        nil
      end
    end
  end
end

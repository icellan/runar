# frozen_string_literal: true

# D26: a block-height locktime gate must pin the locktime domain. Port of
# packages/runar-compiler/src/passes/locktime-domain.ts (same rule and text in
# all seven tiers; see its header for the full rationale).
#
# Consensus reads an nLockTime below 500,000,000 as a block height and one at
# or above it as a Unix timestamp, so extractLocktime(p) >= H for a height H is
# passed at once by any timestamp-domain locktime.
#
# A GATE is a lower-bound compare on a locktime read (extractLocktime(...), a
# local bound to it, or a private helper's parameter a call passes it: a DIRECT
# read; currentBlockHeight() is not one, it asserts its own value < 500000000
# at the call, so it is a height by construction), unless the other side is a timestamp-domain
# literal (it pins the domain itself) or the vacuous >= 0. A value DERIVED
# from a read (arithmetic, bitwise, shift,
# unary - / ~, a ternary arm, a builtin taking a read, or a local some of whose
# bindings are not direct reads) is a gate under any lower bound and never a
# pin. A PIN is an asserted domain bound on a direct read: the asserted
# condition itself or a top-level && conjunct.
#
# The rule is PER PATH, with D18's walk shape (continuation_rules.rb) and two
# bits, gate seen / pin seen: every path through a public method that carries
# a gate must also carry a pin. The --ir path re-derives it in
# ir/locktime_domain.rb.

require "set"
require_relative "ast_nodes"

module RunarCompiler
  module Frontend
    module LocktimeDomain
      # D26: the shared error text.
      def self.locktime_domain_message(method)
        "method '#{method}' compares extractLocktime against a lower bound without pinning the locktime domain: " \
          "consensus reads an nLockTime of 500000000 or more as a Unix timestamp, so on that path any such locktime " \
          "passes a block-height gate at once. On every path that compares, assert(extractLocktime(preimage) < " \
          "500000000n) for a block-height gate, or assert(extractLocktime(preimage) >= 500000000n) for a timestamp gate"
      end

      # The first nLockTime value consensus reads as a Unix timestamp.
      LOCKTIME_THRESHOLD = 500_000_000

      # Path-state bits: gate seen / pin seen.
      G = 1
      P = 2
      FRESH = Set[0].freeze

      # Taint level: not a locktime read / a direct read / derived from one.
      NONE = 0
      DIRECT = 1
      DERIVED = 2
      # Operators whose result derives from their operands (compares and logic do not).
      PROPAGATE = Set["+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"].freeze
      PROPAGATE_UNARY = Set["-", "~"].freeze
      FLIP = { "<" => ">", "<=" => ">=", ">" => "<", ">=" => "<=" }.freeze

      def self.unpinned?(states)
        states.any? { |x| (x & G) != 0 && (x & P).zero? }
      end

      def self.or_all(states, bits)
        states.map { |x| x | bits }.to_set
      end

      def self.compose(a, b)
        out = Set.new
        a.each { |x| b.each { |y| out.add(x | y) } }
        out
      end

      # Classify +lt op other+ (the locktime read on the left); +other+ is the
      # literal's value, or nil when it is not a bigint literal.
      def self.classify(op, other)
        if op == ">=" || op == ">"
          # `>= 0n` is vacuous (every locktime passes it): no gate. Only literal
          # 0: a negative bound is a negation in source but may be a literal in IR.
          return :none if op == ">=" && other == 0

          ts = !other.nil? && (op == ">=" ? other >= LOCKTIME_THRESHOLD : other >= LOCKTIME_THRESHOLD - 1)
          return ts ? :pin : :gate
        end
        return :none if other.nil?

        height = op == "<" ? other.positive? && other <= LOCKTIME_THRESHOLD : other >= 0 && other < LOCKTIME_THRESHOLD
        height ? :pin : :none
      end

      # Least fixpoint for the tainted names, then greatest fixpoint (within
      # it) for the names all of whose bindings are direct reads.
      def self.solve_taint(binds, tainted, direct)
        t = Set.new
        loop do
          changed = false
          binds.each do |name, b|
            next if t.include?(name) || !tainted.call(b, t)

            t.add(name)
            changed = true
          end
          break unless changed
        end
        d = t.dup
        loop do
          changed = false
          binds.each do |name, b|
            next if !d.include?(name) || direct.call(b, d)

            d.delete(name)
            changed = true
          end
          break unless changed
        end
        t.to_h { |n| [n, d.include?(n) ? DIRECT : DERIVED] }
      end

      # Each tainted side is read as the left one. A direct read classifies
      # against the other side's literal; a derived value is a gate under any
      # lower bound and never a pin. A gate on either side wins over a pin.
      def self.classify_compare(op, left, right, level, literal)
        return :none unless FLIP.key?(op)

        side = lambda do |lv, o, other|
          if lv == DIRECT then classify(o, literal.call(other))
          elsif lv == DERIVED then o == ">=" || o == ">" ? :gate : :none
          else :none
          end
        end
        a = side.call(level.call(left), op, right)
        b = side.call(level.call(right), FLIP[op], left)
        return :gate if a == :gate || b == :gate

        a == :pin || b == :pin ? :pin : :none
      end

      # A helper's tainted parameters from its call's argument levels, and the
      # cache-key signature (the level of every parameter).
      def self.helper_params(params, arg_levels)
        out = {}
        (params || []).each_with_index do |p, i|
          lv = arg_levels[i] || NONE
          out[p.name] = lv if lv != NONE
        end
        [out, (params || []).map { |p| out[p.name] || NONE }]
      end

      # -----------------------------------------------------------------
      # Source path
      # -----------------------------------------------------------------

      def self.call_to?(e, name)
        e.is_a?(CallExpr) && e.callee.is_a?(Identifier) && e.callee.name == name
      end

      # currentBlockHeight() pins itself (anf_lower.rb); mirrors locktime-domain.ts.
      def self.read?(e)
        call_to?(e, "extractLocktime")
      end

      # Prefilter: does any method call extractLocktime?
      # Without a read there is no gate, so the path walk is skipped.
      def self.contract_reads_locktime?(contract)
        seen = lambda do |node|
          return true if read?(node)

          node.to_h.each_value do |v|
            if v.is_a?(Array)
              return true if v.any? { |x| x.is_a?(Struct) && seen.call(x) }
            elsif v.is_a?(Struct) && seen.call(v)
              return true
            end
          end
          false
        end
        (contract.methods || []).any? { |m| (m.body || []).any? { |st| seen.call(st) } }
      end

      # The shared error text for a currentBlockHeight() compare against a
      # timestamp-domain bound.
      def self.current_block_height_timestamp_message(method)
        "method '#{method}' compares currentBlockHeight() against a Unix-timestamp bound: currentBlockHeight() asserts " \
          "its value is below 500000000 (a block height), so this compare can never pass and an output gated on it " \
          "could never be spent. Use extractLocktime(this.txPreimage) for a timestamp gate"
      end

      # True iff +method+ contains, anywhere, a lower-bound compare of a direct
      # currentBlockHeight() call (or a local every binding of which is one)
      # against a timestamp-domain bigint literal
      # (>= N, N >= 500000000; > N, N >= 499999999; or reversed).
      # currentBlockHeight() asserts its value is below 500000000, so such a
      # compare can never pass. Mirrors comparesCurrentBlockHeightToTimestamp.
      def self.compares_current_block_height_to_timestamp?(method)
        lit = ->(x) { x.is_a?(BigIntLiteral) ? x.value : nil }
        # Locals bound only to currentBlockHeight() (every declaration/assignment).
        cbh_only = {}
        bind = lambda do |name, value|
          cbh_only[name] = cbh_only.fetch(name, true) && call_to?(value, "currentBlockHeight")
        end
        collect = lambda do |stmts|
          (stmts || []).each do |st|
            case st
            when VariableDeclStmt then bind.call(st.name, st.init)
            when AssignmentStmt then bind.call(st.target.name, st.value) if st.target.is_a?(Identifier)
            when IfStmt
              collect.call(st.then)
              collect.call(st.else_) if st.else_
            when ForStmt
              collect.call([st.init]) if st.init
              collect.call(st.body)
            end
          end
        end
        collect.call(method.body)
        is_cbh = ->(e) { call_to?(e, "currentBlockHeight") || (e.is_a?(Identifier) && cbh_only.fetch(e.name, false)) }
        hit = lambda do |e|
          return false unless e.is_a?(BinaryExpr) && FLIP.key?(e.op)
          return true if is_cbh.call(e.left) && [">=", ">"].include?(e.op) &&
                         classify(e.op, lit.call(e.right)) == :pin

          f = FLIP[e.op]
          is_cbh.call(e.right) && [">=", ">"].include?(f) && classify(f, lit.call(e.left)) == :pin
        end
        seen = lambda do |node|
          return true if hit.call(node)

          node.to_h.each_value do |v|
            if v.is_a?(Array)
              return true if v.any? { |x| x.is_a?(Struct) && seen.call(x) }
            elsif v.is_a?(Struct) && seen.call(v)
              return true
            end
          end
          false
        end
        (method.body || []).any? { |st| seen.call(st) }
      end

      # D26 (source path): some path through public +method+ carries an unpinned gate.
      def self.unpinned_gate?(contract, method)
        unpinned?(SourceGates.new(contract).exits(method, {}))
      end

      # Taint level of a source expression, given the taint of the names in
      # scope. +helper_return+ (name, arg_levels) is a private helper's return
      # level (nil when +name+ is no private helper).
      def self.expr_level(e, names, helper_return = nil)
        return NONE if e.nil?
        return DIRECT if read?(e)

        any = ->(*xs) { xs.any? { |x| expr_level(x, names, helper_return) != NONE } ? DERIVED : NONE }
        case e
        when Identifier then names[e.name] || NONE
        when BinaryExpr then PROPAGATE.include?(e.op) ? any.call(e.left, e.right) : NONE
        when UnaryExpr then PROPAGATE_UNARY.include?(e.op) ? any.call(e.operand) : NONE
        when TernaryExpr then any.call(e.consequent, e.alternate)
        when CallExpr
          # A builtin (identifier callee) derives from its arguments.
          next_level = nil
          if e.callee.is_a?(Identifier)
            next_level = any.call(*(e.args || []))
          else
            # A private helper's return carries the locktime taint into the
            # caller (inlined, this.height() IS its returned expression).
            callee = e.callee
            name = callee.is_a?(PropertyAccessExpr) || callee.is_a?(MemberExpr) ? callee.property : nil
            if name && helper_return
              lv = helper_return.call(name, (e.args || []).map { |a| expr_level(a, names, helper_return) })
              next_level = lv
            end
          end
          next_level || NONE
        else NONE
        end
      end

      # Every return expression of a method body (if arms and loop bodies included).
      def self.return_expressions(body)
        out = []
        work = [body || []]
        until work.empty?
          work.pop.each do |st|
            case st
            when ReturnStmt then out << st.value unless st.value.nil?
            when IfStmt
              work << (st.then || [])
              work << st.else_ if st.else_
            when ForStmt then work << (st.body || [])
            end
          end
        end
        out
      end

      # Taint of the method's locals and parameters, from every binding in the
      # body (declaration or assignment, anywhere) plus one binding per tainted
      # parameter. Order-blind on purpose, as the ANF names every binding the same.
      def self.collect_locktime_locals(body, params, helper_return = nil)
        binds = params.map { |n, lv| [n, lv] }
        visit = lambda do |stmts|
          (stmts || []).each do |st|
            case st
            when VariableDeclStmt then binds << [st.name, st.init]
            when AssignmentStmt then binds << [st.target.name, st.value] if st.target.is_a?(Identifier)
            when IfStmt
              visit.call(st.then)
              visit.call(st.else_) if st.else_
            when ForStmt
              visit.call([st.init]) if st.init
              visit.call(st.body)
            end
          end
        end
        visit.call(body)
        tainted = lambda do |b, t|
          next b != NONE if b.is_a?(Integer)

          expr_level(b, t.to_h { |n| [n, DIRECT] }, helper_return) != NONE
        end
        direct = lambda do |b, d|
          next b == DIRECT if b.is_a?(Integer)
          if b.is_a?(CallExpr) && !b.callee.is_a?(Identifier)
            next expr_level(b, d.to_h { |n| [n, DIRECT] }, helper_return) == DIRECT
          end

          read?(b) || (b.is_a?(Identifier) && d.include?(b.name))
        end
        solve_taint(binds, tainted, direct)
      end

      class SourceGates
        def initialize(contract)
          @privates = {}
          (contract.methods || []).each { |m| @privates[m.name] = m if m.visibility == "private" }
          # Helper exits, by helper name and the taint level of each parameter.
          @helper_exits = {}
          @in_progress = Set.new
          @locals = {}
          # Helper return levels, by helper key (name + argument levels).
          @return_levels = {}
          @return_in_progress = Set.new
          @helper_return = method(:helper_return)
        end

        # Level of a private helper's return value: DIRECT when every return
        # expression is a direct read, DERIVED when some is tainted, else NONE
        # (the rule a local with several bindings follows). A call cycle
        # contributes NONE. Mirrors SourceGates.helperReturn.
        def helper_return(name, arg_levels)
          m = @privates[name]
          return nil unless m

          params, sig = LocktimeDomain.helper_params(m.params, arg_levels)
          key = [m.name, sig]
          return @return_levels[key] if @return_levels.key?(key)
          return NONE if @return_in_progress.include?(key)

          @return_in_progress.add(key)
          locals = LocktimeDomain.collect_locktime_locals(m.body || [], params, @helper_return)
          levels = LocktimeDomain.return_expressions(m.body).map { |r| LocktimeDomain.expr_level(r, locals, @helper_return) }
          @return_in_progress.delete(key)
          lv = if levels.all? { |l| l == NONE } then NONE
               elsif levels.all? { |l| l == DIRECT } then DIRECT
               else DERIVED
               end
          @return_levels[key] = lv
        end

        def exits(method, params)
          saved = @locals
          @locals = LocktimeDomain.collect_locktime_locals(method.body || [], params, @helper_return)
          live, returned = stmts(method.body, FRESH)
          @locals = saved
          live | returned
        end

        private

        def level(e)
          LocktimeDomain.expr_level(e, @locals, @helper_return)
        end

        def compare(e)
          return :none unless e.is_a?(BinaryExpr)

          LocktimeDomain.classify_compare(
            e.op, e.left, e.right, method(:level),
            ->(x) { x.is_a?(BigIntLiteral) ? x.value : nil }
          )
        end

        def asserted_pin?(e)
          return true if compare(e) == :pin
          return asserted_pin?(e.left) || asserted_pin?(e.right) if e.is_a?(BinaryExpr) && e.op == "&&"

          false
        end

        def stmts(list, states)
          live = states
          returned = Set.new
          (list || []).each do |st|
            break if live.empty?

            l, r = stmt(st, live)
            returned |= r
            live = l
          end
          [live, returned]
        end

        def stmt(st, states)
          none = Set.new
          case st
          when AssignmentStmt then [expr(st.value, expr(st.target, states)), none]
          when ExpressionStmt then [expr(st.expr, states), none]
          when VariableDeclStmt then [expr(st.init, states), none]
          when ReturnStmt then [none, st.value ? expr(st.value, states) : states]
          when IfStmt
            c = expr(st.condition, states)
            tl, tr = stmts(st.then, c)
            el, er = st.else_ ? stmts(st.else_, c) : [c, none]
            [tl | el, tr | er]
          when ForStmt
            il, ir = st.init ? stmt(st.init, states) : [states, none]
            c = expr(st.condition, il)
            bl, br = stmts(st.body, c)
            ul, ur = st.update ? stmt(st.update, bl) : [bl, none]
            [c | ul, ir | br | ur]
          else [states, none]
          end
        end

        def expr(e, states)
          case e
          when CallExpr
            s = states
            s = expr(e.callee, s) if e.callee && !e.callee.is_a?(Identifier)
            args = e.args || []
            args.each { |a| s = expr(a, s) }
            return LocktimeDomain.or_all(s, P) if LocktimeDomain.call_to?(e, "assert") && args[0] && asserted_pin?(args[0])

            callee = e.callee
            name = callee.is_a?(PropertyAccessExpr) || callee.is_a?(MemberExpr) ? callee.property : nil
            h = name && @privates[name]
            h ? LocktimeDomain.compose(s, helper(h, args.map { |a| level(a) })) : s
          when BinaryExpr
            s = expr(e.right, expr(e.left, states))
            compare(e) == :gate ? LocktimeDomain.or_all(s, G) : s
          when UnaryExpr, IncrementExpr, DecrementExpr then expr(e.operand, states)
          when TernaryExpr
            c = expr(e.condition, states)
            expr(e.consequent, c) | expr(e.alternate, c)
          when IndexAccessExpr then expr(e.index, expr(e.object, states))
          when MemberExpr then expr(e.object, states)
          when ArrayLiteralExpr
            s = states
            (e.elements || []).each { |el| s = expr(el, s) }
            s
          else states
          end
        end

        def helper(m, arg_levels)
          params, sig = LocktimeDomain.helper_params(m.params, arg_levels)
          key = [m.name, sig]
          cached = @helper_exits[key]
          return cached if cached
          # Recursion is refused by the validator; a cycle contributes nothing.
          return FRESH if @in_progress.include?(m.name)

          @in_progress.add(m.name)
          ex = exits(m, params)
          @in_progress.delete(m.name)
          @helper_exits[key] = ex
        end
      end
    end
  end
end

# frozen_string_literal: true

# DoS-bound input limits + typed errors for the Ruby compiler frontend.
#
# Mirrors InputLimits from packages/runar-ir-schema/src/input-limits.ts.
# See compilers/go/frontend/input_limits.go for the reference shape.

require_relative "ast_nodes"
require_relative "diagnostic"
require_relative "parse_result"

module RunarCompiler
  module Frontend
    module InputLimits
      # Mirrors InputLimits.MAX_SOURCE_BYTES (4 MiB) from the TS schema package.
      # Rúnar source files larger than this are rejected at the parser entry
      # point (Compiler._parse_source) BEFORE any tokenizer touches the input.
      # BUG-008 follow-up.
      MAX_SOURCE_BYTES = 4 * 1024 * 1024

      # Mirrors InputLimits.MAX_SOURCE_NESTING (128) from
      # packages/runar-ir-schema/src/input-limits.ts (F-213). A source is
      # refused when (A) the parse-nesting counter the parsers keep
      # (NestingCounter) or (B) the AST nesting of the parsed contract
      # (ast_nesting_violation) exceeds it.
      MAX_SOURCE_NESTING = 128

      # The one diagnostic every tier emits for an over-nested source.
      SOURCE_NESTING_MESSAGE = "source nesting depth exceeds MAX_SOURCE_NESTING (limit=#{MAX_SOURCE_NESTING})"

      # Raised when a source payload exceeds MAX_SOURCE_BYTES at a public
      # parser entry point. Distinct typed exception so callers can
      # distinguish DoS-bound rejection from generic syntax errors.
      class SourceSizeExceededError < StandardError
        attr_reader :limit, :actual

        def initialize(limit:, actual:)
          super("source exceeds MAX_SOURCE_BYTES (limit=#{limit}, actual=#{actual})")
          @limit = limit
          @actual = actual
        end
      end

      # Raise SourceSizeExceededError if source.bytesize > MAX_SOURCE_BYTES.
      def self.assert_source_bytes_under_limit(source)
        n = source.bytesize
        return if n <= MAX_SOURCE_BYTES

        raise SourceSizeExceededError.new(limit: MAX_SOURCE_BYTES, actual: n)
      end

      # -----------------------------------------------------------------
      # F-213: source nesting limit (the TS reference's source-limits.ts)
      # -----------------------------------------------------------------

      # Raised by NestingCounter / assert_ast_nesting! to unwind a parser at
      # the limit; with_nesting_limit turns it into the shared diagnostic.
      class SourceNestingError < StandardError
        attr_reader :loc

        def initialize(loc = nil)
          super(SOURCE_NESTING_MESSAGE)
          @loc = loc
        end
      end

      # Measure (A): the parse-nesting counter, mixed into every parser. The
      # parser wraps each counted construct (a statement, a full-expression
      # parse, a prefix-unary operand, a nested type argument) in +nested+;
      # going past the limit raises SourceNestingError, so the parsers'
      # recursion never gets deeper than MAX_SOURCE_NESTING counted frames.
      module NestingCounter
        def nested
          @source_nesting = (@source_nesting || 0) + 1
          raise SourceNestingError.new(loc) if @source_nesting > MAX_SOURCE_NESTING

          yield
        ensure
          @source_nesting -= 1
        end
      end

      # Measure (B): the AST nesting of a parsed contract. Returns nil when
      # it is within the limit, else the location to report (a SourceLocation,
      # or false when the offending node carries none). Never recurses more
      # than MAX_SOURCE_NESTING + 1 frames deep into an expression: it stops
      # the moment the running level passes the limit.
      def self.ast_nesting_violation(contract)
        (contract.properties || []).each do |p|
          bad = type_too_deep?(p.type) || (p.initializer && expr_too_deep?(p.initializer, 1))
          return p.source_location || false if bad
        end
        ([contract.constructor] + (contract.methods || [])).compact.each do |m|
          return m.source_location || false if (m.params || []).any? { |p| type_too_deep?(p.type) }

          bad = stmts_too_deep(m.body || [], 1)
          return bad.source_location || m.source_location || false if bad
        end
        nil
      end

      # Raise SourceNestingError when +contract+ breaks measure (B). For
      # parsers that run a recursive pass over their own AST before handing
      # it back.
      def self.assert_ast_nesting!(contract)
        at = ast_nesting_violation(contract)
        raise SourceNestingError.new(at || nil) unless at.nil?
      end

      # Run a parser (the block returns a ParseResult) under both measures:
      # a SourceNestingError from measure (A) becomes the shared diagnostic,
      # and so does a SystemStackError -- with (A) bounding the parsers' own
      # recursion, the stack can only run out in a recursive pass over a tree
      # thousands of levels deep, far past the limit, before (B) ran. On
      # success, (B) is checked before the AST is handed back.
      def self.with_nesting_limit(file_name)
        result = yield
        if result.contract
          at = ast_nesting_violation(result.contract)
          unless at.nil?
            result.errors = result.errors + [nesting_diagnostic(at || nil)]
            result.contract = nil
          end
        end
        result
      rescue SourceNestingError => e
        ParseResult.new(errors: [nesting_diagnostic(e.loc)])
      rescue SystemStackError
        ParseResult.new(errors: [nesting_diagnostic(SourceLocation.new(file: file_name, line: 1, column: 0))])
      end

      def self.nesting_diagnostic(loc)
        Diagnostic.new(message: SOURCE_NESTING_MESSAGE, severity: Severity::ERROR, loc: loc)
      end

      # Children of an expression node, as [child, extra depth] pairs. A
      # MethodCallExpr is the TS reference's call_expr over a member_expr
      # callee, so its object sits one level deeper than its arguments.
      def self.expr_children(e)
        case e
        when BinaryExpr then [[e.left, 1], [e.right, 1]]
        when UnaryExpr, IncrementExpr, DecrementExpr then [[e.operand, 1]]
        when CallExpr then [[e.callee, 1]] + (e.args || []).map { |a| [a, 1] }
        when MethodCallExpr then [[e.object, 2]] + (e.args || []).map { |a| [a, 1] }
        when MemberExpr then [[e.object, 1]]
        when TernaryExpr then [[e.condition, 1], [e.consequent, 1], [e.alternate, 1]]
        when IndexAccessExpr then [[e.object, 1], [e.index, 1]]
        when ArrayLiteralExpr then (e.elements || []).map { |x| [x, 1] }
        else []
        end
      end

      # True iff some node of +e+, sitting at nesting +level+, is deeper
      # than the limit.
      def self.expr_too_deep?(e, level)
        return false if e.nil?
        return true if level > MAX_SOURCE_NESTING

        expr_children(e).any? { |c, d| expr_too_deep?(c, level + d) }
      end

      # Type nesting: a fixed-array type is one deeper than its element.
      def self.type_too_deep?(t)
        depth = 0
        while t
          depth += 1
          return true if depth > MAX_SOURCE_NESTING

          t = t.is_a?(FixedArrayType) ? t.element : nil
        end
        false
      end

      # The statement whose subtree breaks the limit, or nil.
      def self.stmts_too_deep(stmts, level)
        stmts.each do |st|
          next if st.nil?
          return st if level > MAX_SOURCE_NESTING
          return st if st.is_a?(VariableDeclStmt) && type_too_deep?(st.type)

          slots = []
          nested = []
          case st
          when VariableDeclStmt then slots << st.init
          when AssignmentStmt then slots.push(st.target, st.value)
          when ExpressionStmt then slots << st.expr
          when ReturnStmt then slots << st.value
          when IfStmt
            slots << st.condition
            nested << [st.then || [], level + 1]
            nested << [st.else_, level + 1] if st.else_
          when ForStmt
            slots << st.condition
            nested << [[st.init, st.update], level + 1]
            nested << [st.body || [], level + 1]
          end
          return st if slots.any? { |e| expr_too_deep?(e, level + 1) }

          nested.each do |list, lvl|
            bad = stmts_too_deep(list, lvl)
            return bad if bad
          end
        end
        nil
      end
    end
  end
end

# frozen_string_literal: true

# Validation pass for the Runar compiler.
#
# Checks the AST against language subset constraints WITHOUT modifying it.
# Direct port of compilers/python/runar_compiler/frontend/validator.py.

require_relative "ast_nodes"
require_relative "diagnostic"

module RunarCompiler
  module Frontend
    # Output of the validation pass.
    class ValidationResult
      attr_reader :errors, :warnings

      def initialize(errors: [], warnings: [])
        @errors = errors
        @warnings = warnings
      end

      # Return formatted error messages as plain strings.
      def error_strings
        @errors.map(&:format_message)
      end

      # Return formatted warning messages as plain strings.
      def warning_strings
        @warnings.map(&:format_message)
      end
    end

    # Valid property types (excluding void).
    VALID_PROP_TYPES = %w[
      bigint
      boolean
      ByteString
      PubKey
      Sig
      Sha256
      Ripemd160
      Addr
      SigHashPreimage
      RabinSig
      RabinPubKey
      Point
    ].to_set.freeze

    # Validate a Runar AST against language subset constraints.
    #
    # Does NOT modify the AST; only reports errors and warnings.
    #
    # @param contract [ContractNode]
    # @return [ValidationResult]
    def self.validate(contract)
      ctx = ValidationContext.new(contract)

      ctx.validate_properties
      ctx.validate_constructor
      ctx.validate_methods
      ctx.check_no_recursion

      ValidationResult.new(errors: ctx.errors, warnings: ctx.warnings)
    end

    # @api private
    class ValidationContext
      attr_reader :errors, :warnings

      def initialize(contract)
        @contract = contract
        @errors = []
        @warnings = []
      end

      # -------------------------------------------------------------------
      # Property validation
      # -------------------------------------------------------------------

      def validate_properties
        @contract.properties.each do |prop|
          validate_property_type(prop.type, prop.source_location)

          # V27: txPreimage is an implicit property of StatefulSmartContract
          if @contract.parent_class == "StatefulSmartContract" && prop.name == "txPreimage"
            add_error(
              "'txPreimage' is an implicit property of StatefulSmartContract " \
              "and must not be declared",
              loc: prop.source_location
            )
          end
        end

        # SmartContract requires all properties to be readonly
        if @contract.parent_class == "SmartContract"
          @contract.properties.each do |prop|
            unless prop.readonly
              add_error(
                "Property '#{prop.name}' in SmartContract must be declared readonly",
                loc: prop.source_location
              )
            end
          end
        end

        # V26: Warn if StatefulSmartContract has no mutable properties
        if @contract.parent_class == "StatefulSmartContract"
          has_mutable = @contract.properties.any? { |p| !p.readonly }
          unless has_mutable
            @warnings << Diagnostic.new(
              message: "StatefulSmartContract has no mutable properties; " \
                       "consider using SmartContract instead",
              severity: Severity::WARNING,
              loc: @contract.constructor.source_location
            )
          end
        end
      end

      # -------------------------------------------------------------------
      # Constructor validation
      # -------------------------------------------------------------------

      def validate_constructor
        ctor = @contract.constructor
        prop_names = @contract.properties.map(&:name).to_set

        # Check super() as first statement
        if ctor.body.empty?
          add_error("constructor must call super() as its first statement", loc: ctor.source_location)
          return
        end

        unless super_call?(ctor.body[0])
          add_error("constructor must call super() as its first statement", loc: ctor.source_location)
        end

        # Check all properties are assigned
        assigned_props = Set.new
        ctor.body.each do |stmt|
          if stmt.is_a?(AssignmentStmt) && stmt.target.is_a?(PropertyAccessExpr)
            assigned_props.add(stmt.target.property)
          end
        end

        # Properties with initializers don't need constructor assignments
        props_with_init = @contract.properties
          .select { |p| !p.initializer.nil? }
          .map(&:name)
          .to_set

        prop_names.each do |name|
          if !assigned_props.include?(name) && !props_with_init.include?(name)
            add_error(
              "property '#{name}' must be assigned in the constructor",
              loc: ctor.source_location
            )
          end
        end

        # Validate constructor body
        ctor.body.each { |stmt| validate_statement(stmt) }
      end

      # -------------------------------------------------------------------
      # Method validation
      # -------------------------------------------------------------------

      def validate_methods
        @contract.methods.each { |method| validate_method(method) }
      end

      # -------------------------------------------------------------------
      # Recursion detection
      # -------------------------------------------------------------------

      def check_no_recursion
        call_graph = {}
        method_names = Set.new

        @contract.methods.each do |method|
          method_names.add(method.name)
          calls = Set.new
          collect_method_calls(method.body, calls)
          call_graph[method.name] = calls
        end

        # Check for cycles using DFS
        @contract.methods.each do |method|
          visited = Set.new
          stack = Set.new
          if has_cycle?(method.name, call_graph, method_names, visited, stack)
            add_error(
              "recursion detected: method '#{method.name}' calls itself " \
              "directly or indirectly",
              loc: method.source_location
            )
          end
        end
      end

      private

      def add_error(msg, loc: nil)
        @errors << Diagnostic.new(message: msg, severity: Severity::ERROR, loc: loc)
      end

      # -------------------------------------------------------------------
      # Property type validation (private)
      # -------------------------------------------------------------------

      def validate_property_type(type_node, loc)
        return if type_node.nil?

        if type_node.is_a?(PrimitiveType)
          unless VALID_PROP_TYPES.include?(type_node.name)
            if type_node.name == "void"
              add_error(
                "property type 'void' is not valid at #{loc.file}:#{loc.line}",
                loc: loc
              )
            end
          end
        elsif type_node.is_a?(FixedArrayType)
          if type_node.length <= 0
            add_error(
              "FixedArray length must be a positive integer at #{loc.file}:#{loc.line}",
              loc: loc
            )
          end
          if type_node.element.is_a?(PrimitiveType) && type_node.element.name == "void"
            add_error(
              "FixedArray element type 'void' is not valid at #{loc.file}:#{loc.line}",
              loc: loc
            )
          end
          validate_property_type(type_node.element, loc)
        elsif type_node.is_a?(CustomType)
          add_error(
            "unsupported type '#{type_node.name}' in property declaration at #{loc.file}:#{loc.line}",
            loc: loc
          )
        end
      end

      # -------------------------------------------------------------------
      # Method validation (private)
      # -------------------------------------------------------------------

      def validate_method(method)
        # Public methods must end with assert() (unless StatefulSmartContract,
        # where the compiler auto-injects the final assert)
        if method.visibility == "public" && @contract.parent_class != "StatefulSmartContract"
          unless ends_with_assert?(method.body)
            add_error(
              "public method '#{method.name}' must end with an assert() call",
              loc: method.source_location
            )
          end
        end

        # V24/V25: Warn on manual preimage/state-script boilerplate in StatefulSmartContract
        if @contract.parent_class == "StatefulSmartContract" && method.visibility == "public"
          warn_manual_preimage_usage(method)
        end

        # FixedArray is not allowed as a method parameter type.  The SDK
        # accepts FixedArray constructor args and flattens them on behalf of
        # the caller, but method params carry no expansion pass.
        method.params.each do |param|
          if param.type.is_a?(FixedArrayType)
            add_error(
              "FixedArray is not allowed as a parameter type for method '#{method.name}' (param '#{param.name}')",
              loc: method.source_location
            )
          end
        end

        # Validate statements
        method.body.each { |stmt| validate_statement(stmt) }
      end

      # -------------------------------------------------------------------
      # Statement validation (private)
      # -------------------------------------------------------------------

      def validate_statement(stmt)
        case stmt
        when VariableDeclStmt
          if stmt.type.is_a?(FixedArrayType)
            add_error(
              "FixedArray is not allowed as a local variable type (variable '#{stmt.name}')",
              loc: stmt.source_location
            )
          end
          validate_expression(stmt.init)
        when AssignmentStmt
          validate_expression(stmt.target)
          validate_expression(stmt.value)
        when IfStmt
          validate_expression(stmt.condition)
          stmt.then.each { |s| validate_statement(s) }
          stmt.else_.each { |s| validate_statement(s) }
        when ForStmt
          validate_for_statement(stmt)
        when ExpressionStmt
          validate_expression(stmt.expr)
        when ReturnStmt
          validate_expression(stmt.value) unless stmt.value.nil?
        end
      end

      def validate_for_statement(stmt)
        validate_expression(stmt.condition)

        # Check constant bounds
        if stmt.condition.is_a?(BinaryExpr)
          unless compile_time_constant?(stmt.condition.right)
            add_error("for loop bound must be a compile-time constant")
          end
        end

        validate_expression(stmt.init.init)
        stmt.body.each { |s| validate_statement(s) }
      end

      # -------------------------------------------------------------------
      # Expression validation (private)
      # -------------------------------------------------------------------

      def validate_expression(expr)
        return if expr.nil?

        case expr
        when BinaryExpr
          validate_expression(expr.left)
          validate_expression(expr.right)
        when UnaryExpr
          validate_expression(expr.operand)
        when CallExpr
          validate_expression(expr.callee)
          # assert() message (2nd arg) is a human-readable string, not hex -- skip validation
          is_assert = expr.callee.is_a?(Identifier) && expr.callee.name == "assert"
          expr.args.each_with_index do |arg, i|
            next if is_assert && i >= 1
            validate_expression(arg)
          end
        when MemberExpr
          validate_expression(expr.object)
        when TernaryExpr
          validate_expression(expr.condition)
          validate_expression(expr.consequent)
          validate_expression(expr.alternate)
        when IndexAccessExpr
          validate_expression(expr.object)
          validate_expression(expr.index)
        when IncrementExpr
          validate_expression(expr.operand)
        when DecrementExpr
          validate_expression(expr.operand)
        when ByteStringLiteral
          val = expr.value
          if val.length > 0
            if val.length.odd?
              add_error(
                "ByteString literal '#{val}' has odd length (#{val.length}) " \
                "\u2014 hex strings must have an even number of characters"
              )
            elsif !val.match?(/\A[0-9a-fA-F]*\z/)
              add_error(
                "ByteString literal '#{val}' contains non-hex characters " \
                "\u2014 only 0-9, a-f, A-F are allowed"
              )
            end
          end
        end
      end

      # -------------------------------------------------------------------
      # Helper: super() call detection
      # -------------------------------------------------------------------

      def super_call?(stmt)
        return false unless stmt.is_a?(ExpressionStmt)
        return false unless stmt.expr.is_a?(CallExpr)

        callee = stmt.expr.callee
        # Accept both Identifier("super") and MemberExpr(Identifier("super"), "")
        if callee.is_a?(Identifier)
          return callee.name == "super"
        end
        if callee.is_a?(MemberExpr)
          return callee.object.is_a?(Identifier) && callee.object.name == "super"
        end

        false
      end

      # -------------------------------------------------------------------
      # Helper: ends_with_assert?
      # -------------------------------------------------------------------

      def ends_with_assert?(body)
        return false if body.empty?

        last = body.last

        if last.is_a?(ExpressionStmt)
          return assert_call?(last.expr)
        end

        if last.is_a?(IfStmt)
          then_ends = ends_with_assert?(last.then)
          else_ends = !last.else_.empty? && ends_with_assert?(last.else_)
          return then_ends && else_ends
        end

        false
      end

      def assert_call?(expr)
        return false unless expr.is_a?(CallExpr)
        return false unless expr.callee.is_a?(Identifier)

        expr.callee.name == "assert"
      end

      # -------------------------------------------------------------------
      # Helper: compile-time constant check
      # -------------------------------------------------------------------

      def compile_time_constant?(expr)
        return false if expr.nil?
        return true if expr.is_a?(BigIntLiteral)
        return true if expr.is_a?(BoolLiteral)
        return true if expr.is_a?(Identifier) # trust it's a const

        if expr.is_a?(UnaryExpr) && expr.op == "-"
          return compile_time_constant?(expr.operand)
        end

        false
      end

      # -------------------------------------------------------------------
      # V24/V25: warn on manual preimage/state-script usage
      # -------------------------------------------------------------------

      def warn_manual_preimage_usage(method)
        method_loc = method.source_location

        visitor = proc do |expr|
          if expr.is_a?(CallExpr)
            # V24: bare checkPreimage(...) call
            if expr.callee.is_a?(Identifier) && expr.callee.name == "checkPreimage"
              @warnings << Diagnostic.new(
                message: "StatefulSmartContract auto-injects checkPreimage(); calling it manually " \
                         "in '#{method.name}' will cause a duplicate verification",
                severity: Severity::WARNING,
                loc: method_loc
              )
            end
            # V24: this.checkPreimage(...) call via PropertyAccessExpr or MemberExpr
            callee_prop = callee_property(expr.callee)
            if callee_prop == "checkPreimage"
              @warnings << Diagnostic.new(
                message: "StatefulSmartContract auto-injects checkPreimage(); calling it manually " \
                         "in '#{method.name}' will cause a duplicate verification",
                severity: Severity::WARNING,
                loc: method_loc
              )
            end
            # V25: this.getStateScript() call
            if callee_prop == "getStateScript"
              @warnings << Diagnostic.new(
                message: "StatefulSmartContract auto-injects state continuation; calling " \
                         "getStateScript() manually in '#{method.name}' is redundant",
                severity: Severity::WARNING,
                loc: method_loc
              )
            end
          end
        end

        walk_expressions_in_body(method.body, visitor)
      end

      def callee_property(callee)
        return nil if callee.nil?
        return callee.property if callee.is_a?(PropertyAccessExpr)
        return callee.property if callee.is_a?(MemberExpr)

        nil
      end

      # -------------------------------------------------------------------
      # Expression tree walkers
      # -------------------------------------------------------------------

      def walk_expressions_in_body(stmts, visitor)
        stmts.each { |stmt| walk_expressions_in_stmt(stmt, visitor) }
      end

      def walk_expressions_in_stmt(stmt, visitor)
        case stmt
        when ExpressionStmt
          walk_expr(stmt.expr, visitor)
        when VariableDeclStmt
          walk_expr(stmt.init, visitor)
        when AssignmentStmt
          walk_expr(stmt.target, visitor)
          walk_expr(stmt.value, visitor)
        when IfStmt
          walk_expr(stmt.condition, visitor)
          walk_expressions_in_body(stmt.then, visitor)
          walk_expressions_in_body(stmt.else_, visitor)
        when ForStmt
          walk_expr(stmt.condition, visitor)
          walk_expressions_in_body(stmt.body, visitor)
        when ReturnStmt
          walk_expr(stmt.value, visitor) unless stmt.value.nil?
        end
      end

      def walk_expr(expr, visitor)
        return if expr.nil?

        visitor.call(expr)

        case expr
        when BinaryExpr
          walk_expr(expr.left, visitor)
          walk_expr(expr.right, visitor)
        when UnaryExpr
          walk_expr(expr.operand, visitor)
        when CallExpr
          walk_expr(expr.callee, visitor)
          expr.args.each { |arg| walk_expr(arg, visitor) }
        when MemberExpr
          walk_expr(expr.object, visitor)
        when TernaryExpr
          walk_expr(expr.condition, visitor)
          walk_expr(expr.consequent, visitor)
          walk_expr(expr.alternate, visitor)
        when IndexAccessExpr
          walk_expr(expr.object, visitor)
          walk_expr(expr.index, visitor)
        when IncrementExpr
          walk_expr(expr.operand, visitor)
        when DecrementExpr
          walk_expr(expr.operand, visitor)
        end
      end

      # -------------------------------------------------------------------
      # Recursion detection helpers
      # -------------------------------------------------------------------

      def collect_method_calls(stmts, calls)
        stmts.each { |stmt| collect_method_calls_in_stmt(stmt, calls) }
      end

      def collect_method_calls_in_stmt(stmt, calls)
        case stmt
        when ExpressionStmt
          collect_method_calls_in_expr(stmt.expr, calls)
        when VariableDeclStmt
          collect_method_calls_in_expr(stmt.init, calls)
        when AssignmentStmt
          collect_method_calls_in_expr(stmt.target, calls)
          collect_method_calls_in_expr(stmt.value, calls)
        when IfStmt
          collect_method_calls_in_expr(stmt.condition, calls)
          collect_method_calls(stmt.then, calls)
          collect_method_calls(stmt.else_, calls)
        when ForStmt
          collect_method_calls_in_expr(stmt.condition, calls)
          collect_method_calls(stmt.body, calls)
        when ReturnStmt
          collect_method_calls_in_expr(stmt.value, calls) unless stmt.value.nil?
        end
      end

      def collect_method_calls_in_expr(expr, calls)
        return if expr.nil?

        case expr
        when CallExpr
          if expr.callee.is_a?(PropertyAccessExpr)
            calls.add(expr.callee.property)
          end
          if expr.callee.is_a?(MemberExpr)
            if expr.callee.object.is_a?(Identifier) && expr.callee.object.name == "this"
              calls.add(expr.callee.property)
            end
          end
          collect_method_calls_in_expr(expr.callee, calls)
          expr.args.each { |arg| collect_method_calls_in_expr(arg, calls) }
        when BinaryExpr
          collect_method_calls_in_expr(expr.left, calls)
          collect_method_calls_in_expr(expr.right, calls)
        when UnaryExpr
          collect_method_calls_in_expr(expr.operand, calls)
        when MemberExpr
          collect_method_calls_in_expr(expr.object, calls)
        when TernaryExpr
          collect_method_calls_in_expr(expr.condition, calls)
          collect_method_calls_in_expr(expr.consequent, calls)
          collect_method_calls_in_expr(expr.alternate, calls)
        when IndexAccessExpr
          collect_method_calls_in_expr(expr.object, calls)
          collect_method_calls_in_expr(expr.index, calls)
        when IncrementExpr
          collect_method_calls_in_expr(expr.operand, calls)
        when DecrementExpr
          collect_method_calls_in_expr(expr.operand, calls)
        end
      end

      def has_cycle?(name, call_graph, method_names, visited, stack)
        return true if stack.include?(name)
        return false if visited.include?(name)

        visited.add(name)
        stack.add(name)

        (call_graph[name] || Set.new).each do |callee|
          if method_names.include?(callee)
            return true if has_cycle?(callee, call_graph, method_names, visited, stack)
          end
        end

        stack.delete(name)
        false
      end
    end
  end
end

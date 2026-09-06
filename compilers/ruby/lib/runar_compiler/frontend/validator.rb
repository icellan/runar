# frozen_string_literal: true

# Validation pass for the Runar compiler.
#
# Checks the AST against language subset constraints WITHOUT modifying it.
# Direct port of compilers/python/runar_compiler/frontend/validator.py.

require_relative "ast_nodes"
require_relative "diagnostic"
require_relative "sighash_validate"

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
      P256Point
      P384Point
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

      # Issue #123: reject preimage-field reads / output bindings that are
      # unsound under a method's declared @sighash mode (security core). This
      # pass emits both errors (unsound usages) and warnings (e.g. an explicit
      # single-output SINGLE covenant whose same-index value cannot be pinned
      # statically), so route each diagnostic to the matching bucket.
      SighashValidate.validate_sighash_usage(contract).each do |d|
        (d.severity == Severity::WARNING ? ctx.warnings : ctx.errors) << d
      end

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

          # Validate initializer if present. FixedArray properties accept an
          # array literal of literal elements (recursively, for nested
          # arrays); other properties accept a plain literal value. Mirrors
          # the TS validator in `02-validate.ts` and the Go peer in
          # `validator.go`.
          next if prop.initializer.nil?

          if prop.type.is_a?(FixedArrayType)
            unless array_literal_of_literals?(prop.initializer)
              add_error(
                "property '#{prop.name}' initializer must be an array literal of literal values",
                loc: prop.source_location
              )
            end
          elsif !literal_expression?(prop.initializer)
            add_error(
              "property '#{prop.name}' initializer must be a literal value",
              loc: prop.source_location
            )
          end
        end

        # SmartContract (and the asm-escape-hatch UnsafeSmartContract) require
        # all properties to be readonly.
        if @contract.parent_class == "SmartContract" || @contract.parent_class == "UnsafeSmartContract"
          @contract.properties.each do |prop|
            unless prop.readonly
              add_error(
                "Property '#{prop.name}' in #{@contract.parent_class} must be declared readonly",
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

        validate_constructor_slot_bijection
      end

      # Enforce the NEW-002 invariant: every constructor parameter initialises
      # exactly one property that needs a deploy-time value, and the i-th
      # parameter initialises the i-th such property.
      #
      # A property's deploy-time value comes from a constructor ARGUMENT, and
      # the artifact addresses those arguments POSITIONALLY: the ABI
      # constructor params come from the constructor SIGNATURE while a
      # constructor slot's paramIndex is an index into the properties with no
      # initial_value, and the SDK splices constructorArgs[slot.paramIndex]
      # into the slot's bytes. Two independently built lists, assumed to line
      # up. Where they disagree a deploy argument lands in ANOTHER property's
      # slot, silently -- a deployed contract authorising a value the developer
      # never passed for that property.
      #
      # "Needs a deploy-time value" mirrors _constructor_assigned_properties in
      # anf_lower.rb exactly: a property carries a compile-time initial_value
      # iff it has an initializer the constructor does NOT override by
      # assigning it a bare parameter.
      def validate_constructor_slot_bijection
        ctor = @contract.constructor
        param_index = {}
        ctor.params.each_with_index { |p, i| param_index[p.name] = i }

        # property -> distinct bare parameters assigned to it; a property with
        # any non-parameter assignment is recorded with an EMPTY list.
        prop_to_params = {}
        param_to_props = {}
        ctor.body.each do |stmt|
          next unless stmt.is_a?(AssignmentStmt)
          next unless stmt.target.is_a?(PropertyAccessExpr)

          prop = stmt.target.property
          value = stmt.value
          unless value.is_a?(Identifier) && param_index.key?(value.name)
            prop_to_params[prop] = []
            next
          end
          (prop_to_params[prop] ||= []) << value.name
          (param_to_props[value.name] ||= []) << prop
        end

        before = @errors.length

        # (a) One parameter feeding several properties: only one of them could
        # own the argument, so the rest keep a default or deploy undefined.
        ctor.params.each do |param|
          props = (param_to_props[param.name] || []).uniq
          next unless props.length > 1

          add_error(
            "constructor parameter '#{param.name}' initialises more than one property " \
            "(#{props.sort.join(', ')}). Each constructor parameter is spliced into " \
            "exactly one property's deploy-time slot, so only the first would receive " \
            "the argument. Declare one parameter per property.",
            loc: ctor.source_location
          )
        end

        # (b) One property fed by several parameters -- no single argument owns it.
        @contract.properties.each do |prop|
          params = (prop_to_params[prop.name] || []).uniq
          next unless params.length > 1

          add_error(
            "property '#{prop.name}' is assigned more than one constructor parameter " \
            "(#{params.sort.join(', ')}). Each property that needs a deploy-time value " \
            "corresponds to exactly one constructor parameter.",
            loc: ctor.source_location
          )
        end

        # (c) A property that needs a deploy-time value but whose constructor
        # assignment is not a parameter. A property assigned NOTHING is already
        # reported above, so it is skipped here rather than double-reported.
        @contract.properties.each do |prop|
          next unless prop.initializer.nil?

          params = prop_to_params[prop.name]
          next if params.nil? || !params.uniq.empty?

          add_error(
            "property '#{prop.name}' has no initializer and is not assigned a constructor " \
            "parameter, so it has no deploy-time value. The constructor body is not " \
            "compiled into the locking script — give the property a literal initializer " \
            "or assign it a constructor parameter (this.#{prop.name} = #{prop.name}).",
            loc: ctor.source_location
          )
        end

        # (d) A parameter that initialises nothing: its argument is dropped and,
        # because slots are positional, every later argument lands in the wrong slot.
        ctor.params.each do |param|
          next if param_to_props.key?(param.name)

          add_error(
            "constructor parameter '#{param.name}' does not initialise any property. " \
            "Constructor arguments are spliced into property slots positionally, so an " \
            "unused parameter drops its own argument and shifts every later one into the " \
            "wrong property's slot. Assign it (this.#{param.name} = #{param.name}) or " \
            "remove the parameter.",
            loc: ctor.source_location
          )
        end

        # (e) Order. Only meaningful once (a)-(d) hold, otherwise the positions
        # being compared are themselves the thing that is broken.
        return unless @errors.length == before

        slot = 0
        @contract.properties.each do |prop|
          params = (prop_to_params[prop.name] || []).uniq
          single = params.length == 1 ? params.first : nil
          next if !prop.initializer.nil? && single.nil?

          unless single.nil?
            declared = param_index[single]
            if declared != slot
              abi_name = slot < ctor.params.length ? ctor.params[slot].name : "?"
              add_error(
                "property '#{prop.name}' occupies deploy-time slot #{slot}, but the " \
                "constructor parameter that initialises it ('#{single}') is declared at " \
                "position #{declared}. Constructor arguments are spliced positionally, so " \
                "the deployed script would carry argument #{slot} — advertised by the ABI " \
                "as parameter '#{abi_name}' — in this property's slot. Declare the " \
                "parameters in the same order as the properties they initialise.",
                loc: ctor.source_location
              )
            end
          end
          slot += 1
        end
      end

      # -------------------------------------------------------------------
      # Method validation
      # -------------------------------------------------------------------

      def validate_methods
        # A contract with no public methods has no spending entry points and
        # compiles to an empty script -- never what the author meant (usually a
        # missing `public` modifier; methods default to private).
        unless @contract.methods.any? { |m| m.visibility == "public" }
          add_error(
            "Contract '#{@contract.name}' has no public methods — no spending entry points; " \
            "add 'public' to at least one method"
          )
        end

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

      # Resolve the contract property an assignment target writes to, if any.
      # Unwraps IndexAccessExpr chains so `this.grid[i][j] = v` resolves to
      # `grid`.
      def written_property(target)
        node = target
        node = node.object while node.is_a?(IndexAccessExpr)
        node.is_a?(PropertyAccessExpr) ? node.property : nil
      end

      # Whether the expression is a literal allowed as a property initializer
      # (bigint, bool, bytestring, or a negated bigint literal). Mirrors the
      # TS/Go validator helpers.
      def literal_expression?(expr)
        return true if expr.is_a?(BigIntLiteral) || expr.is_a?(BoolLiteral) || expr.is_a?(ByteStringLiteral)
        return expr.operand.is_a?(BigIntLiteral) if expr.is_a?(UnaryExpr) && expr.op == "-"

        false
      end

      # Whether the expression is an array literal whose elements are all
      # literal values (recursively, for nested FixedArray initializers).
      def array_literal_of_literals?(expr)
        return false unless expr.is_a?(ArrayLiteralExpr)

        expr.elements.all? do |el|
          el.is_a?(ArrayLiteralExpr) ? array_literal_of_literals?(el) : literal_expression?(el)
        end
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
        # `return` is a PRIVATE-helper construct only (NEW-012).
        reject_return_in_public_method(method) if method.visibility == "public"

        # Public methods must end with an assert() call (unless
        # StatefulSmartContract, where the compiler auto-injects the final
        # assert; or UnsafeSmartContract, where a terminal asm({..., out_arity:
        # 1}) provides the truthy stack value).
        if method.visibility == "public" && @contract.parent_class == "SmartContract"
          unless ends_with_assert?(method.body)
            add_error(
              "public method '#{method.name}' must end with an assert() call",
              loc: method.source_location
            )
          end
        end

        # UnsafeSmartContract public methods must end with either an assert()
        # call or a terminal asm({..., out_arity: 1}) -- either way the script
        # has to leave a truthy value on the stack.
        if method.visibility == "public" && @contract.parent_class == "UnsafeSmartContract"
          unless ends_with_assert?(method.body) || ends_with_terminal_asm?(method.body)
            add_error(
              "public method '#{method.name}' must end with an assert() call " \
              "or a terminal asm({...}) with out_arity 1",
              loc: method.source_location
            )
          end
        end

        # V24/V25: Warn on manual preimage/state-script boilerplate in StatefulSmartContract
        if @contract.parent_class == "StatefulSmartContract" && method.visibility == "public"
          warn_manual_preimage_usage(method)
        end

        # #131: warn when a public method gates on extractLocktime but never
        # asserts the spending tx is non-final (extractSequence < 0xffffffff).
        # Advisory only.
        if method.visibility == "public"
          warn_locktime_without_sequence_guard(method)
        end

        # Gate asm({...}) calls on UnsafeSmartContract and check the structural args.
        validate_asm_usage(method)

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

        # readonly properties may only be assigned in the constructor.
        check_readonly_writes(method)

        # Validate statements
        method.body.each { |stmt| validate_statement(stmt) }
      end

      # -------------------------------------------------------------------
      # Readonly property writes (private)
      # -------------------------------------------------------------------

      # Report every write to a readonly contract property in a method body.
      #
      #   spec/semantics.md:
      #     <this.p = e, env, sigma> ==> ERROR: cannot assign to readonly property
      #
      # The constructor is exempt -- that is where every contract initialises
      # its readonly properties -- so this runs per METHOD only
      # (validate_constructor never calls in here).
      #
      # Three AST shapes reach update_prop in ANF lowering and are all
      # covered: `this.p = e`, `this.p++` / `this.p--`, and `this.arr[i] = e`.
      def check_readonly_writes(method)
        readonly = @contract.properties.select(&:readonly).map(&:name).to_set
        return if readonly.empty?

        report = lambda do |name, loc|
          add_error(
            "cannot assign to readonly property '#{name}' in method " \
            "'#{method.name}'. readonly properties may only be assigned " \
            "in the constructor.",
            loc: loc
          )
        end

        visit_expr = lambda do |expr, loc|
          next if expr.nil?

          visitor = proc do |e|
            next unless e.is_a?(IncrementExpr) || e.is_a?(DecrementExpr)

            name = written_property(e.operand)
            report.call(name, loc) if !name.nil? && readonly.include?(name)
          end
          walk_expr(expr, visitor)
        end

        visit_statements = nil
        visit_statements = lambda do |stmts|
          stmts.each do |stmt|
            case stmt
            when AssignmentStmt
              name = written_property(stmt.target)
              report.call(name, stmt.source_location) if !name.nil? && readonly.include?(name)
              visit_expr.call(stmt.target, stmt.source_location)
              visit_expr.call(stmt.value, stmt.source_location)
            when VariableDeclStmt
              visit_expr.call(stmt.init, stmt.source_location)
            when ExpressionStmt
              visit_expr.call(stmt.expr, stmt.source_location)
            when ReturnStmt
              visit_expr.call(stmt.value, stmt.source_location)
            when IfStmt
              visit_expr.call(stmt.condition, stmt.source_location)
              visit_statements.call(stmt.then)
              visit_statements.call(stmt.else_ || [])
            when ForStmt
              visit_statements.call([stmt.init, stmt.update].compact)
              visit_expr.call(stmt.condition, stmt.source_location)
              visit_statements.call(stmt.body)
            end
          end
        end

        visit_statements.call(method.body)
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

        # Check that the loop bound is a compile-time constant. Non-zero starts
        # and countdown loops (`i--` with `>`/`>=`) are supported: the ANF loop
        # node carries an explicit start value and step direction (#121), so
        # lowering binds iterVar = start + i*step on each unrolled iteration.
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
      # Helper: reject_return_in_public_method
      # -------------------------------------------------------------------

      # Enforces spec/grammar.md:161 ("Public methods MUST return `void`") and
      # :162 ("Public methods MUST end with an `assert(...)` call as their final
      # statement").
      #
      # spec/semantics.md gives `return` no early-exit meaning at all: 4.6
      # defines it ONLY as "the value of this method is v" (the private-helper
      # inlining semantics), while 4.7 sequences statements UNCONDITIONALLY --
      # there is no rule under which the statements after a `return` are
      # skipped.
      #
      # Lowering it as if it were the tail of an inlined helper produced two
      # different broken scripts (NEW-012):
      #
      #   - `return;`      the enclosing branch had no result to contribute, so
      #                    its arm yielded OP_0 and the whole script evaluated
      #                    FALSE -- an unspendable UTXO from source that
      #                    compiled clean.
      #   - `return expr;` the returned value became the branch result and hence
      #                    the script's final truthiness, so any truthy expr
      #                    spent the contract WITHOUT reaching the guarding
      #                    assert. Fail-OPEN.
      #
      # The Java tier has always rejected the valued form; this brings the rule
      # to every tier and covers the bare form too.
      def reject_return_in_public_method(method)
        find_return_statements(method.body).each do |ret|
          add_error(
            "public method '#{method.name}' must not use `return`: public methods " \
            "are spending entry points, they return void (spec/grammar.md:161) " \
            "and must end with an assert() that encodes the spending condition " \
            "(spec/grammar.md:162). R\u00fanar has no early exit \u2014 restructure " \
            "the guard as an if/else, or move the logic into a private helper, " \
            "where `return` is allowed.",
            loc: ret.source_location
          )
        end
      end

      # Every `return` in +body+, at any nesting depth (arms, loop bodies).
      def find_return_statements(body)
        found = []
        walk = lambda do |stmts|
          Array(stmts).each do |stmt|
            case stmt
            when ReturnStmt then found << stmt
            when IfStmt
              walk.call(stmt.then)
              walk.call(stmt.else_)
            when ForStmt then walk.call(stmt.body)
            end
          end
        end
        walk.call(body)
        found
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
      # Helper: asm({...}) intrinsic validation
      # -------------------------------------------------------------------

      # Return true if +expr+ is a call to the asm compiler intrinsic.
      def asm_call?(expr)
        return false unless expr.is_a?(CallExpr)
        return false unless expr.callee.is_a?(Identifier)

        expr.callee.name == "asm"
      end

      # Return true if the last statement of +body+ is an asm({...}) call with
      # the parser-normalised positional args (body, in_arity, out_arity) and
      # an out_arity literal equal to 1.
      #
      # If/else branches that both terminate in a terminal asm (or assert)
      # also count, mirroring the asserts-on-both-branches rule.
      def ends_with_terminal_asm?(body)
        return false if body.empty?

        last = body.last

        if last.is_a?(ExpressionStmt)
          return false unless asm_call?(last.expr)

          call = last.expr
          # The parser always rewrites asm({...}) into positional
          # (body, in_arity, out_arity).
          if call.args.length == 3
            out_arity = call.args[2]
            return out_arity.is_a?(BigIntLiteral) && out_arity.value.to_i == 1
          end
          return false
        end

        if last.is_a?(IfStmt)
          then_ends = ends_with_terminal_asm?(last.then) || ends_with_assert?(last.then)
          else_ends = !last.else_.empty? &&
                      (ends_with_terminal_asm?(last.else_) || ends_with_assert?(last.else_))
          return then_ends && else_ends
        end

        false
      end

      # Walk a method body and validate every asm({...}) call:
      #
      #   - Reject any asm() outside an UnsafeSmartContract.
      #   - Confirm the parser-normalised arg shape: (body, in_arity,
      #     out_arity) where body is a ByteString literal with even-length
      #     hex and the arities are non-negative bigint literals.
      #   - Expression-form asm<T>({...}) must have out_arity 1.
      #
      # The parser already pushes most hex diagnostics; this pass is the
      # back-stop that runs even when the parser shape is well-formed and is
      # the only layer that knows about the contract's parentClass.
      def validate_asm_usage(method)
        walk_expressions_in_body(method.body, proc do |expr|
          next unless asm_call?(expr)

          call = expr

          if @contract.parent_class != "UnsafeSmartContract"
            add_error(
              "'asm' is only available in contracts extending UnsafeSmartContract; " \
              "got #{@contract.parent_class}. Move the call into a class that extends " \
              "UnsafeSmartContract (and import { UnsafeSmartContract } from 'runar-lang')."
            )
            next
          end

          if call.args.length != 3
            add_error("asm() expects exactly one object-literal argument { body, in_arity?, out_arity? }")
            next
          end

          body_arg = call.args[0]
          unless body_arg.is_a?(ByteStringLiteral)
            add_error("asm() body must be a hex string literal")
            next
          end
          body = body_arg.value
          if body.empty?
            add_error("asm() body must be a non-empty hex string literal")
          elsif body.length.odd?
            add_error(
              "asm() body has odd hex length (#{body.length}); " \
              "each opcode byte requires two hex characters"
            )
          elsif !body.match?(/\A[0-9a-fA-F]*\z/)
            add_error("asm() body contains non-hex characters; only 0-9, a-f, A-F are allowed")
          end

          in_arity = call.args[1]
          if !in_arity.is_a?(BigIntLiteral) || in_arity.value.to_i < 0
            add_error("asm() in_arity must be a non-negative integer literal")
          end

          out_arity = call.args[2]
          if !out_arity.is_a?(BigIntLiteral) || out_arity.value.to_i < 0
            add_error("asm() out_arity must be a non-negative integer literal")
          end

          # Expression-form asm<T>({...}) returns a value that flows into a
          # let-binding -- exactly ONE stack value, so out_arity must be 1.
          if call.asm_return_type && out_arity.is_a?(BigIntLiteral) && out_arity.value.to_i != 1
            add_error(
              "Expression-form asm<#{call.asm_return_type}>() must have out_arity 1 " \
              "(got #{out_arity.value}); only a single stack value can be bound to " \
              "the result variable."
            )
          end
        end)
      end

      # -------------------------------------------------------------------
      # Helper: compile-time constant check
      # -------------------------------------------------------------------

      # Only integer literals (and their negation) can be unrolled into fixed
      # Bitcoin Script by anf-lower. A bare identifier bound (e.g. `const N`) or
      # a runtime member access (`this.x`) is NOT resolvable and must be
      # rejected here with a graceful diagnostic — anf-lower's
      # _extract_loop_shape would otherwise raise. Mirrors the reference TS
      # compiler's observable behavior: only literal loop bounds compile.
      def compile_time_constant?(expr)
        return false if expr.nil?
        return true if expr.is_a?(BigIntLiteral)

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
      # #131: locktime soundness -- extractLocktime needs an extractSequence guard
      # -------------------------------------------------------------------

      # Sentinel maximum nSequence: a tx is FINAL (ignores locktime) at this value.
      SEQUENCE_FINAL = 0xffffffff

      # True when +expr+ is a direct call to the named intrinsic, e.g. +f(...)+.
      def call_to_named?(expr, name)
        expr.is_a?(CallExpr) &&
          expr.callee.is_a?(Identifier) &&
          expr.callee.name == name
      end

      # True when +expr+ reads the transaction locktime. Both the raw intrinsic
      # +extractLocktime(preimage)+ and its ergonomic sugar
      # +currentBlockHeight()+ (which the ANF pass desugars to
      # +extractLocktime(txPreimage)+) count -- either read is unsound without a
      # sequence-finality guard.
      def locktime_read?(expr)
        call_to_named?(expr, "extractLocktime") || call_to_named?(expr, "currentBlockHeight")
      end

      # True when +expr+ is an +extractSequence(...) < <final>+-style comparison
      # (the guard that makes a locktime gate consensus-enforced). Accepts the
      # two natural spellings: +extractSequence(pre) < N+ / +<= N+, and the
      # reversed +N > extractSequence(pre)+ / +>= ...+. +N+ must be a bigint
      # literal no greater than the finality sentinel, so the guard genuinely
      # forces non-finality.
      def sequence_finality_guard?(expr)
        return false unless expr.is_a?(BinaryExpr)

        bound_ok = ->(e) { e.is_a?(BigIntLiteral) && e.value <= SEQUENCE_FINAL }

        if ["<", "<="].include?(expr.op) &&
           call_to_named?(expr.left, "extractSequence") && bound_ok.call(expr.right)
          return true
        end
        if [">", ">="].include?(expr.op) &&
           call_to_named?(expr.right, "extractSequence") && bound_ok.call(expr.left)
          return true
        end

        false
      end

      # #131: warn when +method+ (transitively, through the private-helper call
      # graph) reads the tx locktime but never asserts the tx is non-final. A
      # locktime gate is not consensus-enforced unless
      # +extractSequence < 0xffffffff+ is also asserted -- otherwise an
      # all-final-sequence spend bypasses it. Advisory (warning) only -- no
      # effect on emitted bytecode.
      def warn_locktime_without_sequence_guard(method)
        private_methods = {}
        @contract.methods.each do |m|
          private_methods[m.name] = m if m.visibility == "private"
        end

        reads_locktime = false
        has_sequence_guard = false
        visited = Set.new([method.name])
        queue = [method]

        until queue.empty?
          current = queue.shift
          walk_expressions_in_body(current.body, proc do |expr|
            reads_locktime = true if locktime_read?(expr)
            has_sequence_guard = true if sequence_finality_guard?(expr)
          end)

          # Follow calls into private helpers so a guard (or locktime read)
          # supplied by an inlined helper is seen by the public entry point.
          calls = Set.new
          collect_method_calls(current.body, calls)
          calls.each do |callee|
            next if visited.include?(callee) || !private_methods.key?(callee)

            visited.add(callee)
            queue << private_methods[callee]
          end
        end

        return unless reads_locktime && !has_sequence_guard

        @warnings << Diagnostic.new(
          message: "method '#{method.name}' reads extractLocktime but does not assert " \
                   "extractSequence < 0xffffffff; a locktime gate is not consensus-enforced " \
                   "unless the tx is non-final — add " \
                   "assert(extractSequence(this.txPreimage) < 0xffffffffn)",
          severity: Severity::WARNING,
          loc: method.source_location
        )
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

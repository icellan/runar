# frozen_string_literal: true

# Pass 3b: Expand fixed-size array properties into scalar sibling fields.
#
# Direct Ruby port of
# +packages/runar-compiler/src/passes/03b-expand-fixed-arrays.ts+.  Runs after
# typecheck and before ANF lowering, consuming and producing a
# +Frontend::ContractNode+ (AST level, not the ANF IR).
#
# Scope & rules (matching the TypeScript reference):
#
#   * Only properties may have +FixedArrayType+.  Array types are NOT allowed
#     as method parameters or local variables — the typecheck pass handles
#     those; this pass does not attempt to expand anything other than
#     properties.
#   * Nested arrays expand recursively.  Names use double underscore to avoid
#     colliding with user-written +Board_0+ identifiers: +Board__0+,
#     +Board__0__0+, +Grid__2__2+, and so on.
#   * Literal index access (+this.board[3]+) rewrites to a direct
#     +this.board__3+ property access.  Out-of-range literal indices are a
#     hard compile error.
#   * Runtime index read in a pure expression context rewrites to a nested
#     ternary chain.  At statement level (+const v = this.board[idx]+ or
#     +target = this.board[idx]+) we emit a shorter +if / else if+ chain that
#     reassigns a single target; the terminal slot is the fallback, so
#     out-of-range indices fall through.
#   * Runtime index write (+this.board[idx] = v+) rewrites to an +if / else if+
#     statement chain, one branch per legal index, with a final
#     +else { assert(false); }+ bounds-check.
#   * Side-effectful index and value expressions are hoisted to fresh
#     +__idx_K+ / +__val_K+ +const+ declarations before the dispatch so each
#     branch reads the value exactly once.
#   * Array literal initializers are distributed element-wise to the synthetic
#     siblings; length mismatch is a hard compile error.
#   * +FixedArray<void, N>+ is rejected.

require_relative "ast_nodes"
require_relative "diagnostic"

module RunarCompiler
  module Frontend
    # Output of the FixedArray expansion pass.
    class ExpandFixedArraysResult
      attr_reader :contract, :errors

      def initialize(contract:, errors: [])
        @contract = contract
        @errors = errors
      end

      # Return formatted error messages as plain strings.
      def error_strings
        @errors.map(&:format_message)
      end
    end

    # Public entry point.  Expand FixedArray properties and rewrite every
    # index_access on such properties.  On errors the original contract is
    # returned along with the accumulated diagnostics.
    #
    # @param contract [ContractNode]
    # @return [ExpandFixedArraysResult]
    def self.expand_fixed_arrays(contract)
      ctx = ExpandContext.new(contract)
      unless ctx.collect_arrays
        return ExpandFixedArraysResult.new(contract: contract, errors: ctx.errors)
      end

      return ExpandFixedArraysResult.new(contract: contract, errors: ctx.errors) if ctx.errors.any?

      if ctx.array_map.empty?
        # No FixedArray properties — return contract unchanged so later passes
        # see an identical AST.
        return ExpandFixedArraysResult.new(contract: contract, errors: [])
      end

      new_properties = ctx.rewrite_properties
      return ExpandFixedArraysResult.new(contract: contract, errors: ctx.errors) if ctx.errors.any?

      new_constructor = ctx.rewrite_constructor(contract.constructor)
      new_methods = contract.methods.map { |m| ctx.rewrite_method(m) }

      return ExpandFixedArraysResult.new(contract: contract, errors: ctx.errors) if ctx.errors.any?

      rewritten = ContractNode.new(
        name: contract.name,
        parent_class: contract.parent_class,
        properties: new_properties,
        constructor: new_constructor,
        methods: new_methods,
        source_file: contract.source_file
      )
      ExpandFixedArraysResult.new(contract: rewritten, errors: [])
    end

    # Metadata for a top-level array property — the "root" of an expansion
    # tree.  Per outer slot, either a scalar leaf name or a nested +ArrayMeta+
    # is tracked.
    #
    # @!attribute [rw] root_name
    #   @return [String]
    # @!attribute [rw] type
    #   @return [FixedArrayType] outer-most fixed_array_type node
    # @!attribute [rw] slot_names
    #   @return [Array<String>]
    # @!attribute [rw] slot_is_array
    #   @return [Boolean] true if each outer slot is itself an expanded array
    # @!attribute [rw] element_type
    #   @return [TypeNode]
    # @!attribute [rw] nested
    #   @return [Hash{String => ArrayMeta}, nil] nested metadata keyed by slot name
    ArrayMeta = Struct.new(
      :root_name, :type, :slot_names, :slot_is_array, :element_type, :nested,
      keyword_init: true
    )

    # Internal rewriter state.  @api private
    class ExpandContext
      attr_reader :contract, :errors, :array_map, :synthetic_arrays

      def initialize(contract)
        @contract = contract
        @errors = []
        @array_map = {}           # root property name => ArrayMeta
        @synthetic_scalars = {}   # synthetic scalar name => element type node
        @synthetic_arrays = {}    # synthetic intermediate array name => ArrayMeta
        @temp_counter = 0
      end

      def fresh_idx_name
        n = @temp_counter
        @temp_counter += 1
        "__idx_#{n}"
      end

      def fresh_val_name
        n = @temp_counter
        @temp_counter += 1
        "__val_#{n}"
      end

      # Scan top-level properties for FixedArrayType entries and build the
      # +array_map+ + synthetic tables.  Returns +false+ on fatal errors.
      def collect_arrays
        @contract.properties.each do |prop|
          next unless prop.type.is_a?(FixedArrayType)

          meta = build_array_meta(prop.name, prop.type, prop.source_location)
          return false if meta.nil?

          @array_map[prop.name] = meta
        end
        true
      end

      # Build metadata for an array with the given logical root name.
      def build_array_meta(root_name, type, loc)
        # Reject FixedArray<void, N>.
        if type.element.is_a?(PrimitiveType) && type.element.name == "void"
          add_error("FixedArray element type cannot be 'void' (property '#{root_name}')", loc: loc)
          return nil
        end

        length = type.length
        if length <= 0
          add_error("FixedArray length must be a positive integer (property '#{root_name}')", loc: loc)
          return nil
        end

        slot_names = (0...length).map { |i| "#{root_name}__#{i}" }
        elem_is_array = type.element.is_a?(FixedArrayType)
        meta = ArrayMeta.new(
          root_name: root_name,
          type: type,
          slot_names: slot_names,
          slot_is_array: elem_is_array,
          element_type: type.element,
          nested: nil
        )

        if elem_is_array
          meta.nested = {}
          slot_names.each do |slot|
            nested_meta = build_array_meta(slot, type.element, loc)
            return nil if nested_meta.nil?

            meta.nested[slot] = nested_meta
            @synthetic_arrays[slot] = nested_meta
          end
        else
          slot_names.each { |slot| @synthetic_scalars[slot] = type.element }
        end

        meta
      end

      # -----------------------------------------------------------------
      # Property rewriting (initializer distribution)
      # -----------------------------------------------------------------

      def rewrite_properties
        out = []
        @contract.properties.each do |prop|
          unless prop.type.is_a?(FixedArrayType)
            out << prop
            next
          end

          meta = @array_map[prop.name]
          next if meta.nil? # already reported

          expanded = expand_property_root(prop, meta)
          out.concat(expanded)
        end
        out
      end

      def expand_property_root(prop, meta)
        init_elements = extract_array_literal_elements(prop, meta)
        return [] if init_elements == :error

        expand_array_meta(meta, prop.readonly, prop.source_location, init_elements, [])
      end

      # Returns the element-wise initializer list, +nil+ if the property has
      # no initializer, or +:error+ on invalid input (diagnostic pushed).
      #
      # Several format parsers (TypeScript, Solidity, Go, Rust, Move, Python)
      # wrap array literals as +CallExpr(FixedArray, args)+ rather than emitting
      # a dedicated +ArrayLiteralExpr+ node.  Treat both shapes as equivalent.
      def extract_array_literal_elements(prop, meta)
        return nil if prop.initializer.nil?

        elements = array_literal_elements(prop.initializer)
        if elements.nil?
          add_error(
            "Property '#{prop.name}' of type FixedArray must use an array literal initializer",
            loc: prop.source_location
          )
          return :error
        end

        if elements.length != meta.type.length
          add_error(
            "Initializer length #{elements.length} does not match FixedArray length " \
            "#{meta.type.length} for property '#{prop.name}'",
            loc: prop.source_location
          )
          return :error
        end

        elements
      end

      # Return the element list for an expression that represents an array
      # literal, normalising across parser dialects.  +nil+ on any other
      # expression shape.
      def array_literal_elements(expr)
        return expr.elements if expr.is_a?(ArrayLiteralExpr)
        if expr.is_a?(CallExpr) && expr.callee.is_a?(Identifier) && expr.callee.name == "FixedArray"
          return expr.args
        end

        nil
      end

      # Recursively emit scalar leaf properties.  Nested arrays descend; a
      # non-array-literal element at a nested level is a compile error.  Each
      # leaf PropertyNode receives the full +synthetic_array_chain+,
      # outermost first.
      def expand_array_meta(meta, readonly, loc, initializer, parent_chain)
        out = []

        meta.slot_names.each_with_index do |slot, i|
          slot_init = initializer.nil? ? nil : initializer[i]
          chain_entry = {
            base: meta.root_name,
            index: i,
            length: meta.slot_names.length
          }
          chain_here = parent_chain + [chain_entry]

          if meta.slot_is_array
            nested_meta = meta.nested[slot]
            nested_init = nil
            unless slot_init.nil?
              elems = array_literal_elements(slot_init)
              if elems.nil?
                add_error("Nested FixedArray element must be an array literal", loc: loc)
                next
              end
              if elems.length != nested_meta.type.length
                add_error(
                  "Nested FixedArray initializer length #{elems.length} " \
                  "does not match expected length #{nested_meta.type.length}",
                  loc: loc
                )
                next
              end
              nested_init = elems
            end
            out.concat(expand_array_meta(nested_meta, readonly, loc, nested_init, chain_here))
          else
            out << PropertyNode.new(
              name: slot,
              type: meta.element_type,
              readonly: readonly,
              initializer: slot_init,
              source_location: loc,
              synthetic_array_chain: chain_here
            )
          end
        end

        out
      end

      # -----------------------------------------------------------------
      # Method body rewriting
      # -----------------------------------------------------------------

      def rewrite_constructor(ctor)
        new_body = rewrite_statements(ctor.body)
        ConstructorNode.new(params: ctor.params, body: new_body, source_location: ctor.source_location)
      end

      def rewrite_method(method)
        new_body = rewrite_statements(method.body)
        MethodNode.new(
          name: method.name,
          params: method.params,
          body: new_body,
          visibility: method.visibility,
          source_location: method.source_location
        )
      end

      def rewrite_statements(stmts)
        out = []
        stmts.each do |stmt|
          out.concat(rewrite_statement(stmt))
        end
        out
      end

      def rewrite_statement(stmt)
        case stmt
        when VariableDeclStmt
          rewrite_variable_decl(stmt)
        when AssignmentStmt
          rewrite_assignment(stmt)
        when IfStmt
          rewrite_if_statement(stmt)
        when ForStmt
          rewrite_for_statement(stmt)
        when ReturnStmt
          rewrite_return_statement(stmt)
        when ExpressionStmt
          rewrite_expression_statement(stmt)
        else
          [stmt]
        end
      end

      def rewrite_variable_decl(stmt)
        # Statement-form dispatch: `const v = this.board[i]` where `i` is a
        # runtime-index expression.  Produces a shorter Bitcoin Script because
        # each branch only materialises one field instead of stacking N-1
        # nested ternaries.
        stmt_form = try_rewrite_read_as_statements(
          stmt.init,
          Identifier.new(name: stmt.name),
          stmt.source_location
        )
        unless stmt_form.nil?
          replacement = VariableDeclStmt.new(
            name: stmt.name,
            type: stmt.type,
            mutable: true,
            init: stmt_form[:fallback_init],
            source_location: stmt.source_location
          )
          return stmt_form[:prelude] + [replacement] + stmt_form[:dispatch]
        end

        prelude = []
        new_init = rewrite_expression(stmt.init, prelude)
        new_stmt = VariableDeclStmt.new(
          name: stmt.name,
          type: stmt.type,
          mutable: stmt.mutable,
          init: new_init,
          source_location: stmt.source_location
        )
        prelude + [new_stmt]
      end

      def rewrite_assignment(stmt)
        prelude = []

        # Writes to `this.board[...]` — the only place index_access appears as
        # an assignment target.
        if stmt.target.is_a?(IndexAccessExpr)
          resolved = try_resolve_literal_index_chain(stmt.target)
          if resolved == :error
            return prelude
          elsif !resolved.nil?
            rewritten_value = rewrite_expression(stmt.value, prelude)
            return prelude + [
              AssignmentStmt.new(
                target: PropertyAccessExpr.new(property: resolved),
                value: rewritten_value,
                source_location: stmt.source_location
              )
            ]
          end

          target_object = stmt.target.object
          if target_object.is_a?(PropertyAccessExpr) && @array_map.key?(target_object.property)
            return rewrite_array_write(stmt, prelude)
          end
          # Writes to non-fixed-array index targets — rewrite sub-expressions
          # but otherwise leave the shape alone (typechecker rejected any
          # non-ByteString/non-array cases earlier).
          new_index = rewrite_expression(stmt.target.index, prelude)
          new_obj = rewrite_expression(target_object, prelude)
          new_value = rewrite_expression(stmt.value, prelude)
          return prelude + [
            AssignmentStmt.new(
              target: IndexAccessExpr.new(object: new_obj, index: new_index),
              value: new_value,
              source_location: stmt.source_location
            )
          ]
        end

        # Statement-form dispatch for `target = this.board[i]` where target is
        # an identifier or a property_access (not index_access — those are
        # array writes handled above).
        if stmt.target.is_a?(Identifier) || stmt.target.is_a?(PropertyAccessExpr)
          stmt_form = try_rewrite_read_as_statements(stmt.value, stmt.target, stmt.source_location)
          unless stmt_form.nil?
            fallback_assign = AssignmentStmt.new(
              target: clone_expr(stmt.target),
              value: stmt_form[:fallback_init],
              source_location: stmt.source_location
            )
            return stmt_form[:prelude] + [fallback_assign] + stmt_form[:dispatch]
          end
        end

        new_target = rewrite_expression(stmt.target, prelude)
        new_value = rewrite_expression(stmt.value, prelude)
        prelude + [
          AssignmentStmt.new(
            target: new_target,
            value: new_value,
            source_location: stmt.source_location
          )
        ]
      end

      def rewrite_if_statement(stmt)
        prelude = []
        new_cond = rewrite_expression(stmt.condition, prelude)
        new_then = rewrite_statements(stmt.then)
        new_else = rewrite_statements(stmt.else_)
        prelude + [
          IfStmt.new(
            condition: new_cond,
            then: new_then,
            else_: new_else,
            source_location: stmt.source_location
          )
        ]
      end

      def rewrite_for_statement(stmt)
        prelude = []
        new_cond = rewrite_expression(stmt.condition, prelude)

        init_prelude = []
        new_init_init = rewrite_expression(stmt.init.init, init_prelude)
        prelude.concat(init_prelude) if init_prelude.any?

        new_update_list = rewrite_statement(stmt.update)
        new_body = rewrite_statements(stmt.body)
        new_update = nil
        if new_update_list.length == 1
          new_update = new_update_list[0]
        else
          new_update = new_update_list.last
          new_body.concat(new_update_list[0..-2])
        end

        new_init = VariableDeclStmt.new(
          name: stmt.init.name,
          type: stmt.init.type,
          mutable: stmt.init.mutable,
          init: new_init_init,
          source_location: stmt.init.source_location
        )
        prelude + [
          ForStmt.new(
            init: new_init,
            condition: new_cond,
            update: new_update,
            body: new_body,
            source_location: stmt.source_location
          )
        ]
      end

      def rewrite_return_statement(stmt)
        return [stmt] if stmt.value.nil?

        prelude = []
        new_value = rewrite_expression(stmt.value, prelude)
        prelude + [ReturnStmt.new(value: new_value, source_location: stmt.source_location)]
      end

      def rewrite_expression_statement(stmt)
        prelude = []
        new_expr = rewrite_expression(stmt.expr, prelude)
        prelude + [ExpressionStmt.new(expr: new_expr, source_location: stmt.source_location)]
      end

      # -----------------------------------------------------------------
      # Expression rewriting
      # -----------------------------------------------------------------

      def rewrite_expression(expr, prelude)
        return expr if expr.nil?

        case expr
        when IndexAccessExpr
          rewrite_index_access(expr, prelude)
        when BinaryExpr
          BinaryExpr.new(
            op: expr.op,
            left: rewrite_expression(expr.left, prelude),
            right: rewrite_expression(expr.right, prelude)
          )
        when UnaryExpr
          UnaryExpr.new(op: expr.op, operand: rewrite_expression(expr.operand, prelude))
        when CallExpr
          CallExpr.new(
            callee: rewrite_expression(expr.callee, prelude),
            args: expr.args.map { |a| rewrite_expression(a, prelude) }
          )
        when MethodCallExpr
          MethodCallExpr.new(
            object: rewrite_expression(expr.object, prelude),
            method: expr.method,
            args: expr.args.map { |a| rewrite_expression(a, prelude) }
          )
        when MemberExpr
          MemberExpr.new(object: rewrite_expression(expr.object, prelude), property: expr.property)
        when TernaryExpr
          TernaryExpr.new(
            condition: rewrite_expression(expr.condition, prelude),
            consequent: rewrite_expression(expr.consequent, prelude),
            alternate: rewrite_expression(expr.alternate, prelude)
          )
        when IncrementExpr
          IncrementExpr.new(operand: rewrite_expression(expr.operand, prelude), prefix: expr.prefix)
        when DecrementExpr
          DecrementExpr.new(operand: rewrite_expression(expr.operand, prelude), prefix: expr.prefix)
        when ArrayLiteralExpr
          ArrayLiteralExpr.new(elements: expr.elements.map { |e| rewrite_expression(e, prelude) })
        else
          # BigIntLiteral, BoolLiteral, ByteStringLiteral, Identifier,
          # PropertyAccessExpr — pass through unchanged.
          expr
        end
      end

      def rewrite_index_access(expr, prelude)
        # Nested fully-literal chains like `this.grid[0][1]` resolve in a
        # single hop to `this.grid__0__1`.  This is the ONLY way nested
        # FixedArray reads compile — runtime indices on nested arrays are
        # rejected below.
        nested = try_resolve_literal_index_chain(expr)
        return BigIntLiteral.new(value: 0) if nested == :error
        return PropertyAccessExpr.new(property: nested) unless nested.nil?

        base_name = try_resolve_array_base(expr.object)
        if base_name.nil?
          object = rewrite_expression(expr.object, prelude)
          index = rewrite_expression(expr.index, prelude)
          return IndexAccessExpr.new(object: object, index: index)
        end

        meta = @array_map[base_name] || @synthetic_arrays[base_name]
        if meta.nil?
          object = rewrite_expression(expr.object, prelude)
          index = rewrite_expression(expr.index, prelude)
          return IndexAccessExpr.new(object: object, index: index)
        end

        loc = expr_source_location(expr)
        literal = as_literal_index(expr.index)
        unless literal.nil?
          if literal < 0 || literal >= meta.type.length
            add_error(
              "Index #{literal} is out of range for FixedArray of length #{meta.type.length}",
              loc: loc
            )
            return BigIntLiteral.new(value: 0)
          end
          slot = meta.slot_names[literal]
          return PropertyAccessExpr.new(property: slot)
        end

        rewritten_index = rewrite_expression(expr.index, prelude)
        index_ref = hoist_if_impure(rewritten_index, prelude, loc, :idx)

        if meta.slot_is_array
          add_error(
            "Runtime index access on a nested FixedArray is not supported",
            loc: loc
          )
          return BigIntLiteral.new(value: 0)
        end

        build_read_dispatch_ternary(meta, index_ref, loc)
      end

      # Try to rewrite a runtime-index read on a top-level FixedArray property
      # as a fallback-init + if-chain statement pair.  Returns a Hash
      # +{prelude:, fallback_init:, dispatch:}+ on success, +nil+ otherwise.
      def try_rewrite_read_as_statements(init_expr, target, loc)
        return nil unless init_expr.is_a?(IndexAccessExpr)

        base_name = try_resolve_array_base(init_expr.object)
        return nil if base_name.nil?

        meta = @array_map[base_name] || @synthetic_arrays[base_name]
        return nil if meta.nil?
        # Literal indices are already handled by the expression rewriter.
        return nil unless as_literal_index(init_expr.index).nil?
        # Nested-array runtime indices fall outside scope — defer to the
        # expression rewriter, which will emit a diagnostic.
        return nil if meta.slot_is_array

        prelude = []
        rewritten_index = rewrite_expression(init_expr.index, prelude)
        index_ref = hoist_if_impure(rewritten_index, prelude, loc, :idx)

        n = meta.slot_names.length
        if n < 2
          # Length-1 arrays: the single slot IS the fallback, no dispatch.
          fallback_init = PropertyAccessExpr.new(property: meta.slot_names[0])
          return { prelude: prelude, fallback_init: fallback_init, dispatch: [] }
        end

        fallback_init = PropertyAccessExpr.new(property: meta.slot_names[n - 1])

        dispatch = []
        tail_else = nil
        (n - 2).downto(0) do |i|
          slot = meta.slot_names[i]
          cond = BinaryExpr.new(
            op: "===",
            left: clone_expr(index_ref),
            right: BigIntLiteral.new(value: i)
          )
          assign = AssignmentStmt.new(
            target: clone_expr(target),
            value: PropertyAccessExpr.new(property: slot),
            source_location: loc
          )
          if_stmt = IfStmt.new(
            condition: cond,
            then: [assign],
            else_: tail_else.nil? ? [] : tail_else,
            source_location: loc
          )
          tail_else = [if_stmt]
        end
        dispatch.concat(tail_else) unless tail_else.nil?

        { prelude: prelude, fallback_init: fallback_init, dispatch: dispatch }
      end

      # Build a nested ternary that reads the scalar slot whose index matches
      # +index_ref+.  The terminal branch is the Nth slot — runtime reads do
      # NOT bounds-check in this form (matches TicTacToe semantics).
      def build_read_dispatch_ternary(meta, index_ref, loc)
        chain = PropertyAccessExpr.new(property: meta.slot_names.last)

        (meta.slot_names.length - 2).downto(0) do |i|
          slot = meta.slot_names[i]
          cond = BinaryExpr.new(
            op: "===",
            left: clone_expr(index_ref),
            right: BigIntLiteral.new(value: i)
          )
          branch = PropertyAccessExpr.new(property: slot)
          chain = TernaryExpr.new(
            condition: cond,
            consequent: branch,
            alternate: chain
          )
          _ = loc
        end

        chain
      end

      # Rewrite `this.board[idx] = v`.
      def rewrite_array_write(stmt, prelude)
        index_access = stmt.target
        object = index_access.object
        base_name = object.property
        meta = @array_map[base_name]
        return [stmt] if meta.nil?

        rewritten_value = rewrite_expression(stmt.value, prelude)
        rewritten_index = rewrite_expression(index_access.index, prelude)
        loc = stmt.source_location

        literal = as_literal_index(rewritten_index)
        unless literal.nil?
          if literal < 0 || literal >= meta.type.length
            add_error(
              "Index #{literal} is out of range for FixedArray of length #{meta.type.length}",
              loc: loc
            )
            return prelude.dup
          end
          if meta.slot_is_array
            add_error("Cannot assign to a nested FixedArray sub-array as a whole", loc: loc)
            return prelude.dup
          end
          slot = meta.slot_names[literal]
          return prelude + [
            AssignmentStmt.new(
              target: PropertyAccessExpr.new(property: slot),
              value: rewritten_value,
              source_location: loc
            )
          ]
        end

        if meta.slot_is_array
          add_error("Runtime index assignment on a nested FixedArray is not supported", loc: loc)
          return prelude.dup
        end

        index_ref = hoist_if_impure(rewritten_index, prelude, loc, :idx)
        value_ref = hoist_if_impure(rewritten_value, prelude, loc, :val)

        if_stmt = build_write_dispatch_if(meta, index_ref, value_ref, loc)
        prelude + [if_stmt]
      end

      def build_write_dispatch_if(meta, index_ref, value_ref, loc)
        assert_false = ExpressionStmt.new(
          expr: CallExpr.new(
            callee: Identifier.new(name: "assert"),
            args: [BoolLiteral.new(value: false)]
          ),
          source_location: loc
        )

        tail = [assert_false]
        (meta.slot_names.length - 1).downto(0) do |i|
          slot = meta.slot_names[i]
          cond = BinaryExpr.new(
            op: "===",
            left: clone_expr(index_ref),
            right: BigIntLiteral.new(value: i)
          )
          branch_assign = AssignmentStmt.new(
            target: PropertyAccessExpr.new(property: slot),
            value: clone_expr(value_ref),
            source_location: loc
          )
          tail = [
            IfStmt.new(
              condition: cond,
              then: [branch_assign],
              else_: tail,
              source_location: loc
            )
          ]
        end

        tail[0]
      end

      # -----------------------------------------------------------------
      # Helpers
      # -----------------------------------------------------------------

      def try_resolve_literal_index_chain(expr)
        literal_indices = []
        cursor = expr
        while cursor.is_a?(IndexAccessExpr)
          lit = as_literal_index(cursor.index)
          return nil if lit.nil?

          literal_indices << lit
          cursor = cursor.object
        end
        return nil unless cursor.is_a?(PropertyAccessExpr)

        root_name = cursor.property
        root_meta = @array_map[root_name]
        return nil if root_meta.nil?

        literal_indices.reverse!

        meta = root_meta
        literal_indices.each_with_index do |idx, level|
          if idx < 0 || idx >= meta.type.length
            add_error(
              "Index #{idx} is out of range for FixedArray of length #{meta.type.length}",
              loc: expr_source_location(expr)
            )
            return :error
          end
          slot = meta.slot_names[idx]
          if level == literal_indices.length - 1
            return nil if meta.slot_is_array
            return slot
          end
          return nil unless meta.slot_is_array

          meta = meta.nested[slot]
        end
        nil
      end

      def try_resolve_array_base(obj)
        return nil unless obj.is_a?(PropertyAccessExpr)
        return obj.property if @array_map.key?(obj.property)
        return obj.property if @synthetic_arrays.key?(obj.property)

        nil
      end

      # Return the literal value for a bigint index (optionally wrapped in a
      # unary minus).  Otherwise +nil+.
      def as_literal_index(index)
        return index.value if index.is_a?(BigIntLiteral)
        if index.is_a?(UnaryExpr) && index.op == "-" && index.operand.is_a?(BigIntLiteral)
          return -index.operand.value
        end

        nil
      end

      def hoist_if_impure(expr, prelude, loc, tag)
        return expr if pure_reference?(expr)

        name = tag == :idx ? fresh_idx_name : fresh_val_name
        safe_loc = loc || SourceLocation.new
        decl = VariableDeclStmt.new(
          name: name,
          type: nil,
          mutable: false,
          init: expr,
          source_location: safe_loc
        )
        prelude << decl
        Identifier.new(name: name)
      end

      def pure_reference?(expr)
        case expr
        when Identifier, BigIntLiteral, BoolLiteral, ByteStringLiteral, PropertyAccessExpr
          true
        when UnaryExpr
          expr.op == "-" && expr.operand.is_a?(BigIntLiteral)
        else
          false
        end
      end

      def expr_source_location(expr)
        expr.respond_to?(:source_location) ? expr.source_location : nil
      end

      def clone_expr(expr)
        return nil if expr.nil?

        case expr
        when BigIntLiteral
          BigIntLiteral.new(value: expr.value)
        when BoolLiteral
          BoolLiteral.new(value: expr.value)
        when ByteStringLiteral
          ByteStringLiteral.new(value: expr.value)
        when Identifier
          Identifier.new(name: expr.name)
        when PropertyAccessExpr
          PropertyAccessExpr.new(property: expr.property)
        when BinaryExpr
          BinaryExpr.new(op: expr.op, left: clone_expr(expr.left), right: clone_expr(expr.right))
        when UnaryExpr
          UnaryExpr.new(op: expr.op, operand: clone_expr(expr.operand))
        when CallExpr
          CallExpr.new(callee: clone_expr(expr.callee), args: expr.args.map { |a| clone_expr(a) })
        when MethodCallExpr
          MethodCallExpr.new(
            object: clone_expr(expr.object),
            method: expr.method,
            args: expr.args.map { |a| clone_expr(a) }
          )
        when MemberExpr
          MemberExpr.new(object: clone_expr(expr.object), property: expr.property)
        when TernaryExpr
          TernaryExpr.new(
            condition: clone_expr(expr.condition),
            consequent: clone_expr(expr.consequent),
            alternate: clone_expr(expr.alternate)
          )
        when IndexAccessExpr
          IndexAccessExpr.new(object: clone_expr(expr.object), index: clone_expr(expr.index))
        when IncrementExpr
          IncrementExpr.new(operand: clone_expr(expr.operand), prefix: expr.prefix)
        when DecrementExpr
          DecrementExpr.new(operand: clone_expr(expr.operand), prefix: expr.prefix)
        when ArrayLiteralExpr
          ArrayLiteralExpr.new(elements: expr.elements.map { |e| clone_expr(e) })
        else
          expr
        end
      end

      def add_error(msg, loc: nil)
        @errors << Diagnostic.new(message: msg, severity: Severity::ERROR, loc: loc)
      end
    end
  end
end

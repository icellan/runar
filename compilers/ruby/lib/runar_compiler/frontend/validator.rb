# frozen_string_literal: true

# Validation pass for the Runar compiler.
#
# Checks the AST against language subset constraints WITHOUT modifying it.
# Direct port of compilers/python/runar_compiler/frontend/validator.py.

require "set"
require_relative "ast_nodes"
require_relative "diagnostic"
require_relative "sighash_validate"
require_relative "reserved_names"
require_relative "input_limits"

module RunarCompiler
  module Frontend
    # Whether the expression is the `toByteString(<literal>)` ByteStringLiteral
    # production (spec/grammar.md section 11).
    #
    # Literal argument ONLY -- `toByteString(x)` for a non-literal `x` is not
    # this production and stays a non-literal initializer. Peer of the TS
    # helper of the same name in `02-validate.ts`. Shared with `anf_lower.rb`,
    # which must UNWRAP exactly the shape this accepts.
    def self.to_byte_string_literal?(expr)
      expr.is_a?(CallExpr) &&
        expr.callee.is_a?(Identifier) &&
        expr.callee.name == "toByteString" &&
        expr.args.length == 1 &&
        expr.args[0].is_a?(ByteStringLiteral)
    end

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
      call_depth_exceeded = ctx.check_no_recursion
      ctx.check_reserved_names
      # N-180: the Rabin-provenance and sighash passes walk the private-method
      # call graph; past MAX_CALL_DEPTH that walk is the very depth the limit
      # refuses, so stop here.
      return ValidationResult.new(errors: ctx.errors, warnings: ctx.warnings) if call_depth_exceeded

      ctx.check_rabin_pubkey_provenance

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

          # N-414 (peer of TS F-265): the shape checks above never validate a
          # ByteStringLiteral's HEX FORMAT; that lives in validate_expression,
          # which a property initializer never reached. An odd-length literal
          # used to surface two passes later as an opaque stack-lowering error.
          validate_expression(prop.initializer)
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

        # N-092: a FixedArray may not be a constructor PARAMETER.
        #
        # A property's deploy-time value reaches the script through a
        # constructor SLOT, and expand_fixed_arrays is what turns a FixedArray
        # PROPERTY into the scalar siblings those slots can address. A
        # constructor PARAMETER has no such expansion, so the argument has
        # nowhere to be spliced: before this check the tier compiled such a
        # contract to a full stateful locking script with NO constructor slots
        # at all -- deployable, with state its own ABI claims to take an
        # argument for (it even names xs__0 / xs__1 / xs__2) and can never
        # receive.
        #
        # The rule keys on the parameter's TYPE alone, not on the parent class:
        # ts / go / rust / python / java all refuse it on stateless contracts
        # too. Spelled to match the ts / rust / python / java wording verbatim,
        # since the cross-tier rejection gate compares diagnostics.
        ctor.params.each do |param|
          if param.type.is_a?(FixedArrayType)
            add_error(
              "Constructor parameter '#{param.name}' cannot be a FixedArray. " \
              "Use initialized properties or pass each element as a separate parameter.",
              loc: ctor.source_location
            )
          end
          reject_unknown_param_type(param, "constructor", ctor.source_location)
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

      # Reports recursion and the N-180 call depth; true iff MAX_CALL_DEPTH
      # was exceeded.
      def check_no_recursion
        call_graph = {}
        method_names = Set.new

        @contract.methods.each do |method|
          method_names.add(method.name)
          calls = Set.new
          collect_method_calls(method.body, calls, true)
          call_graph[method.name] = calls
        end

        # N-180: one iterative pass answers, for every method, whether it
        # reaches a cycle and how deep its call chain is, in O(methods +
        # calls). The old per-method DFS restarted for each method (quadratic
        # on a chain) and recursed once per link (SystemStackError at ~2000).
        reaches_cycle, depth = analyze_call_graph(call_graph, method_names)

        @contract.methods.each do |method|
          next unless reaches_cycle[method.name]

          add_error(
            "recursion detected: method '#{method.name}' calls itself " \
            "directly or indirectly",
            loc: method.source_location
          )
        end

        # N-180: private methods are inlined at every call site, so the call
        # depth is the inlining depth. Report the first method (declaration
        # order) past it.
        @contract.methods.each do |method|
          next if reaches_cycle[method.name] || depth[method.name] <= InputLimits::MAX_CALL_DEPTH

          add_error(InputLimits.call_depth_message(method.name), loc: method.source_location)
          return true
        end
        false
      end

      # N-180: for every method, whether it reaches a call cycle, and (when it
      # does not) its call depth: 0 if it calls no contract method, else 1 +
      # the largest call depth among the contract methods it calls. Iterative
      # three-colour DFS with memoisation: O(methods + calls), no recursion.
      # reaches_cycle matches what a fresh DFS from each method reports.
      def analyze_call_graph(call_graph, method_names)
        reaches_cycle = {}
        depth = {}
        on_stack = Set.new

        @contract.methods.each do |root|
          next if reaches_cycle.key?(root.name)

          # frame: [name, callees, next, cyc, depth]
          stack = [[root.name, (call_graph[root.name] || Set.new).to_a, 0, false, 0]]
          on_stack.add(root.name)
          until stack.empty?
            top = stack.last
            if top[2] < top[1].length
              callee = top[1][top[2]]
              top[2] += 1
              next unless method_names.include?(callee)

              if on_stack.include?(callee)
                top[3] = true
              elsif reaches_cycle.key?(callee)
                if reaches_cycle[callee]
                  top[3] = true
                else
                  top[4] = [top[4], 1 + depth[callee]].max
                end
              else
                on_stack.add(callee)
                stack << [callee, (call_graph[callee] || Set.new).to_a, 0, false, 0]
              end
              next
            end
            stack.pop
            name, _callees, _next, cyc, d = top
            on_stack.delete(name)
            reaches_cycle[name] = cyc
            depth[name] = d
            parent = stack.last
            next if parent.nil?

            if cyc
              parent[3] = true
            else
              parent[4] = [parent[4], 1 + d].max
            end
          end
        end
        [reaches_cycle, depth]
      end

      # F-286: the one diagnostic every tier emits (user decision R78).
      RABIN_PUBKEY_PROVENANCE_MESSAGE =
        "verifyRabinSig public key (4th argument) must be a contract property or a literal; " \
        "a spender-supplied Rabin modulus lets anyone forge a signature"

      # F-286: verifyRabinSig's modulus must not be chosen by the spender.
      # A spender who picks +n+ forges any message (+n = 1+, +sig = 0+ passes
      # on chain). Port of +checkRabinPubKeyProvenance+ in the TS reference
      # (02-validate.ts). Trusted values for the 4th argument:
      #   - a property read (+PropertyAccessExpr+, or +MemberExpr+ on +this+),
      #     or a bare identifier naming a property that no parameter or local
      #     of the method shadows (the Java surface's bare field);
      #   - a bigint literal;
      #   - a local whose initialiser AND every assignment to it are trusted
      #     (+++/--+ on it makes it untrusted; the +mutable+ flag is irrelevant);
      #   - a parameter of a PRIVATE method that every call site (at least one)
      #     binds to a trusted value in the caller (least fixed point).
      # Everything else -- public and constructor parameters, arithmetic,
      # ternaries, calls -- is refused.
      def check_rabin_pubkey_provenance
        property_names = Set.new(@contract.properties.map(&:name))
        private_methods = {}
        @contract.methods.each do |m|
          private_methods[m.name] = m if m.visibility == "private"
        end

        scopes = [rabin_scope_of(@contract.constructor, true)]
        @contract.methods.each { |m| scopes << rabin_scope_of(m, false) }

        trusted_params = {}
        private_methods.each_key { |name| trusted_params[name] = Set.new }

        call_sites = {}
        private_methods.each_key { |name| call_sites[name] = [] }
        scopes.each do |scope|
          rabin_walk_body(scope[:method].body, lambda { |e|
            callee = rabin_private_callee(e, private_methods)
            call_sites[callee] << { args: e.args, scope: scope } unless callee.nil?
          })
        end

        # Least fixed point: a parameter becomes trusted once every call site
        # binds it to a trusted value. Monotone, so it terminates.
        changed = true
        while changed
          changed = false
          private_methods.each do |name, method|
            sites = call_sites[name]
            next if sites.empty?

            trusted = trusted_params[name]
            method.params.each_index do |i|
              next if trusted.include?(i)

              all_ok = sites.all? do |site|
                !site[:args][i].nil? &&
                  rabin_trusted?(site[:args][i], site[:scope], Set.new, property_names, trusted_params)
              end
              if all_ok
                trusted.add(i)
                changed = true
              end
            end
          end
        end

        scopes.each do |scope|
          rabin_walk_body(scope[:method].body, lambda { |e|
            next unless e.is_a?(CallExpr) &&
                        e.callee.is_a?(Identifier) &&
                        e.callee.name == "verifyRabinSig" &&
                        e.args.length >= 4
            next if rabin_trusted?(e.args[3], scope, Set.new, property_names, trusted_params)

            add_error(RABIN_PUBKEY_PROVENANCE_MESSAGE, loc: scope[:method].source_location)
          })
        end

        check_rabin_key_writes(scopes, property_names, private_methods, call_sites, trusted_params)
      end

      # N-205 (a): the diagnostic every tier emits when a mutable key property
      # is written, outside the constructor, with a value F-286 does not trust.
      def self.rabin_key_write_message(prop)
        "verifyRabinSig public key property '#{prop}' may only be assigned a contract property or a literal " \
          "outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature"
      end

      # N-205 (a): a MUTABLE property used as the key is state the previous
      # spend chose, so outside the constructor it may only be written with a
      # value +rabin_trusted?+ accepts. KEY properties: those whose value
      # reaches a 4th argument, closed under "is written into a key property".
      # Port of the N-205 block of +checkRabinPubKeyProvenance+ (02-validate.ts).
      def check_rabin_key_writes(scopes, property_names, private_methods, call_sites, trusted_params)
        key_props = Set.new
        scopes.each do |scope|
          rabin_walk_body(scope[:method].body, lambda { |e|
            next unless e.is_a?(CallExpr) &&
                        e.callee.is_a?(Identifier) &&
                        e.callee.name == "verifyRabinSig" &&
                        e.args.length >= 4

            rabin_sources_of(e.args[3], scope, key_props, Set.new, property_names, call_sites)
          })
        end

        mutable_props = @contract.properties.reject(&:readonly).map(&:name)
        # value nil = ++/--, which no value makes trusted.
        writes = []
        scopes.each do |scope|
          next if scope[:is_ctor]

          rabin_collect_assignments(scope[:method].body, scope, property_names, writes)
          rabin_walk_body(scope[:method].body, lambda { |e|
            loc = scope[:method].source_location
            if e.is_a?(IncrementExpr) || e.is_a?(DecrementExpr)
              prop = rabin_written_prop(e.operand, scope, property_names)
              writes << { prop: prop, value: nil, scope: scope, loc: loc } unless prop.nil?
            elsif e.is_a?(CallExpr) &&
                  (e.callee.is_a?(PropertyAccessExpr) || e.callee.is_a?(MemberExpr)) &&
                  e.callee.property == "addOutput"
              # addOutput(satoshis, ...values): values are positional over the
              # mutable properties in declaration order. A single array-literal
              # value list (the Zig tuple form) is unpacked, as ANF lowering's
              # _flatten_add_output_args does.
              values = e.args.length == 2 && e.args[1].is_a?(ArrayLiteralExpr) ? e.args[1].elements : e.args.drop(1)
              values.each_with_index do |value, i|
                prop = mutable_props[i]
                writes << { prop: prop, value: value, scope: scope, loc: loc } unless prop.nil?
              end
            end
          })
        end

        loop do
          before = key_props.size
          writes.each do |w|
            next unless key_props.include?(w[:prop]) && !w[:value].nil? &&
                        rabin_trusted?(w[:value], w[:scope], Set.new, property_names, trusted_params)

            rabin_sources_of(w[:value], w[:scope], key_props, Set.new, property_names, call_sites)
          end
          break if key_props.size == before
        end

        mutable = Set.new(mutable_props)
        writes.each do |w|
          next unless key_props.include?(w[:prop]) && mutable.include?(w[:prop])
          next if !w[:value].nil? && rabin_trusted?(w[:value], w[:scope], Set.new, property_names, trusted_params)

          add_error(self.class.rabin_key_write_message(w[:prop]), loc: w[:loc])
        end
      end

      # N-065 / N-060: refuse a declared identifier spelled like a name a
      # compiler pass mints (see reserved_names.rb). Checks properties, method
      # names, constructor and method parameters, locals and loop variables.
      # A stateful `txPreimage` PROPERTY keeps its older V27 diagnostic.
      def check_reserved_names
        stateful = @contract.parent_class == "StatefulSmartContract"
        check = lambda do |name, loc|
          if ReservedNames.reserved_source_name?(name, stateful)
            add_error(ReservedNames.message(name), loc: loc)
          end
        end
        walk = lambda do |stmts|
          (stmts || []).each do |st|
            case st
            when VariableDeclStmt
              check.call(st.name, st.source_location)
            when IfStmt
              walk.call(st.then)
              walk.call(st.else_)
            when ForStmt
              check.call(st.init.name, st.init.source_location) if st.init.is_a?(VariableDeclStmt)
              walk.call(st.body)
            end
          end
        end

        @contract.properties.each do |prop|
          next if stateful && prop.name == "txPreimage"

          check.call(prop.name, prop.source_location)
        end
        ctor = @contract.constructor
        if ctor
          (ctor.params || []).each { |pr| check.call(pr.name, ctor.source_location) }
          walk.call(ctor.body)
        end
        @contract.methods.each do |m|
          check.call(m.name, m.source_location) unless m.name == "constructor"
          (m.params || []).each { |pr| check.call(pr.name, m.source_location) }
          walk.call(m.body)
        end
      end

      private

      # -------------------------------------------------------------------
      # F-286 helpers
      # -------------------------------------------------------------------

      # Per method: local name -> every value bound to it (inits +
      # assignments), and names that are ever ++/-- (never trusted).
      def rabin_scope_of(method, is_ctor)
        scope = {
          method: method,
          is_ctor: is_ctor,
          params: method.params.map(&:name),
          bindings: {},
          mutated: Set.new,
          # N-205: names declared as locals (a bare property write also lands
          # in +bindings+).
          declared: Set.new,
        }
        bind = lambda do |name, value|
          (scope[:bindings][name] ||= []) << value
        end
        visit_expr = lambda do |expr|
          walk_expr(expr, lambda { |e|
            if (e.is_a?(IncrementExpr) || e.is_a?(DecrementExpr)) && e.operand.is_a?(Identifier)
              scope[:mutated].add(e.operand.name)
            end
          })
        end
        visit = nil
        visit = lambda do |stmts|
          (stmts || []).each do |stmt|
            case stmt
            when VariableDeclStmt
              scope[:declared].add(stmt.name)
              bind.call(stmt.name, stmt.init)
              visit_expr.call(stmt.init)
            when AssignmentStmt
              bind.call(stmt.target.name, stmt.value) if stmt.target.is_a?(Identifier)
              visit_expr.call(stmt.target)
              visit_expr.call(stmt.value)
            when ExpressionStmt
              visit_expr.call(stmt.expr)
            when IfStmt
              visit_expr.call(stmt.condition)
              visit.call(stmt.then)
              visit.call(stmt.else_)
            when ForStmt
              visit.call([stmt.init].compact)
              visit_expr.call(stmt.condition)
              visit.call([stmt.update].compact)
              visit.call(stmt.body)
            when ReturnStmt
              visit_expr.call(stmt.value) unless stmt.value.nil?
            end
          end
        end
        visit.call(method.body)
        scope
      end

      def rabin_trusted?(expr, scope, visiting, property_names, trusted_params)
        case expr
        when PropertyAccessExpr, BigIntLiteral
          true
        when MemberExpr
          expr.object.is_a?(Identifier) && expr.object.name == "this"
        when Identifier
          name = expr.name
          is_param = scope[:params].include?(name)
          locals = scope[:bindings][name]
          return property_names.include?(name) if !is_param && locals.nil?
          return false if scope[:mutated].include?(name)

          if is_param
            method = scope[:method]
            return false if scope[:is_ctor] || method.visibility != "private"

            idx = method.params.index { |p| p.name == name }
            return false unless trusted_params.fetch(method.name, Set.new).include?(idx)
          end
          unless locals.nil?
            return false if visiting.include?(name)

            visiting.add(name)
            ok = locals.all? { |v| rabin_trusted?(v, scope, visiting, property_names, trusted_params) }
            visiting.delete(name)
            return false unless ok
          end
          true
        else
          false
        end
      end

      # N-205: the property names a trusted value can come from, through
      # local aliases and private-helper call sites.
      def rabin_sources_of(expr, scope, out, visiting, property_names, call_sites)
        case expr
        when PropertyAccessExpr
          out.add(expr.property)
        when MemberExpr
          out.add(expr.property) if expr.object.is_a?(Identifier) && expr.object.name == "this"
        when Identifier
          name = expr.name
          is_param = scope[:params].include?(name)
          locals = scope[:bindings][name]
          if !is_param && locals.nil?
            out.add(name) if property_names.include?(name)
            return
          end
          key = [scope[:method].object_id, name]
          return if visiting.include?(key)

          visiting.add(key)
          (locals || []).each { |v| rabin_sources_of(v, scope, out, visiting, property_names, call_sites) }
          method = scope[:method]
          if is_param && !scope[:is_ctor] && method.visibility == "private"
            idx = method.params.index { |p| p.name == name }
            (call_sites[method.name] || []).each do |site|
              arg = site[:args][idx]
              rabin_sources_of(arg, site[:scope], out, visiting, property_names, call_sites) unless arg.nil?
            end
          end
        end
      end

      # N-205: the property an assignment / ++ / -- target writes, or nil.
      def rabin_written_prop(target, scope, property_names)
        case target
        when PropertyAccessExpr
          target.property
        when MemberExpr
          target.object.is_a?(Identifier) && target.object.name == "this" ? target.property : nil
        when Identifier
          name = target.name
          if property_names.include?(name) && !scope[:params].include?(name) && !scope[:declared].include?(name)
            name
          end
        end
      end

      def rabin_collect_assignments(stmts, scope, property_names, writes)
        (stmts || []).each do |stmt|
          case stmt
          when AssignmentStmt
            prop = rabin_written_prop(stmt.target, scope, property_names)
            writes << { prop: prop, value: stmt.value, scope: scope, loc: stmt.source_location } unless prop.nil?
          when IfStmt
            rabin_collect_assignments(stmt.then, scope, property_names, writes)
            rabin_collect_assignments(stmt.else_, scope, property_names, writes)
          when ForStmt
            rabin_collect_assignments([stmt.init, stmt.update].compact, scope, property_names, writes)
            rabin_collect_assignments(stmt.body, scope, property_names, writes)
          end
        end
      end

      def rabin_private_callee(expr, private_methods)
        return nil unless expr.is_a?(CallExpr)

        c = expr.callee
        name =
          if c.is_a?(PropertyAccessExpr)
            c.property
          elsif c.is_a?(MemberExpr) && c.object.is_a?(Identifier) && c.object.name == "this"
            c.property
          end
        !name.nil? && private_methods.key?(name) ? name : nil
      end

      # Like +walk_expressions_in_body+, but also visits every +for+ loop's
      # init and update, at any nesting depth.
      def rabin_walk_body(stmts, visitor)
        (stmts || []).each do |stmt|
          case stmt
          when IfStmt
            walk_expr(stmt.condition, visitor)
            rabin_walk_body(stmt.then, visitor)
            rabin_walk_body(stmt.else_, visitor)
          when ForStmt
            rabin_walk_body([stmt.init].compact, visitor)
            walk_expr(stmt.condition, visitor)
            rabin_walk_body([stmt.update].compact, visitor)
            rabin_walk_body(stmt.body, visitor)
          else
            walk_expressions_in_stmt(stmt, visitor)
          end
        end
      end

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

        # `toByteString('<hex>')` IS the ByteStringLiteral production -- see
        # spec/grammar.md section 11:
        #
        #     ByteStringLiteral = 'toByteString' '(' StringLiteral ')' ;
        #
        # 0e192af6 folded it in ANF lowering, which covers every EXPRESSION
        # position. This check runs on the AST, BEFORE ANF lowering, so an
        # initializer still arrives here as a call node and was refused -- in
        # the one position the `.runar.rs` surface needs it, since the Rust DSL
        # writes initializers as assignments inside `init()` that the parser
        # LIFTS into `PropertyNode.initializer`, and a bare `"1976a914"` is a
        # `&str` that cannot be assigned to a `ByteString` (`Vec<u8>`).
        #
        # Accepting it here is only half the job: `_extract_literal_value` in
        # anf_lower.rb must UNWRAP the same shape, or the property validates
        # and then loses its default entirely.
        Frontend.to_byte_string_literal?(expr)
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
            else
              # R-246: any other unrecognised primitive name used to fall
              # through in silence, while the identical name arriving as a
              # CustomType is refused below. No parser produces a PrimitiveType
              # with an unknown name today -- they all map an unrecognised name
              # to CustomType -- but +validate+ takes an AST, and the frontend
              # is not the only thing that builds one.
              add_error(
                "unsupported type '#{type_node.name}' in property declaration at #{loc.file}:#{loc.line}",
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

      # N-325: a parameter whose type is a name that is not a Rúnar type.
      # "unknown" is the missing-annotation case, diagnosed by the parser;
      # StatefulContext is the explicit context parameter of the Zig/Go/Move
      # stateful surfaces, dropped by ANF lowering.
      def reject_unknown_param_type(param, where, loc)
        t = param.type
        return unless t.is_a?(CustomType)
        return if t.name == "unknown" || t.name == "StatefulContext"

        add_error(
          "type '#{t.name}' of parameter '#{param.name}' in #{where} is not a Rúnar type",
          loc: loc
        )
      end

      def validate_method(method)
        method.params.each do |param|
          reject_unknown_param_type(param, "method '#{method.name}'", method.source_location)
        end

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
        # asserts the spending tx is non-final (extractSequence !== 0xffffffff).
        # Advisory only.
        if method.visibility == "public"
          warn_locktime_without_sequence_guard(method)
        end

        # Gate asm({...}) calls on UnsafeSmartContract and check the structural args.
        validate_asm_usage(method)

        # FixedArray is not allowed as a method parameter type: method params
        # carry no expansion pass.  Neither do CONSTRUCTOR params -- this
        # comment used to claim the SDK flattens FixedArray constructor args on
        # the caller's behalf, which the artifact refutes (such a contract
        # compiled with an EMPTY constructorSlots list, so nothing could be
        # spliced).  Constructor params are refused in validate_constructor
        # above (N-092), matching the other six tiers.
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
          validate_index_assignment_target(stmt)
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

      # N-002 (F-013's rule, shared verbatim by all seven tiers): only a
      # FixedArray property is index-writable. Any other index target (a
      # ByteString property, a local, a parameter, a member-chained root) is
      # left alone by expand_fixed_arrays and ANF lowering lowers it as a READ,
      # dropping the write. Reject it here with a location instead.
      def validate_index_assignment_target(stmt)
        return unless stmt.target.is_a?(IndexAccessExpr)

        root = stmt.target
        root = root.object while root.is_a?(IndexAccessExpr)
        fixed = root.is_a?(PropertyAccessExpr) && @contract.properties.any? do |p|
          p.name == root.property && p.type.is_a?(FixedArrayType)
        end
        return if fixed

        add_error(
          'index assignment is only supported on FixedArray contract properties; ' \
          'the target here is not a FixedArray property',
          loc: stmt.source_location
        )
      end

      def validate_for_statement(stmt)
        validate_expression(stmt.condition)

        # Check that the loop bound is a compile-time constant. Non-zero starts
        # and countdown loops (`i--` with `>`/`>=`) are supported: the ANF loop
        # node carries an explicit start value and step direction (#121), so
        # lowering binds iterVar = start + i*step on each unrolled iteration.
        if stmt.condition.is_a?(BinaryExpr)
          unless compile_time_constant?(stmt.condition.right)
            add_error(for_loop_bound_diagnostic(stmt.condition.right))
          end
        end

        validate_for_condition_tests_iterator(stmt)

        validate_expression(stmt.init.init)
        validate_for_update(stmt)
        validate_no_output_intrinsic_in_loop(stmt)
        stmt.body.each { |s| validate_statement(s) }
      end

      # Reject a for-loop whose condition does not test the iterator (W4).
      #
      # The bound check above reads only `condition.right`. Nothing required
      # `condition.left` to BE the iterator, and extract_loop_shape ignores
      # left entirely: it computes `count = bound - start`. So
      #
      #   for (let i = 0n; i + 1n < 2n; i++) { ... }
      #
      # runs ONCE in the source language and TWICE in the emitted script
      # (count = 2 - 0). The extra lap executes the `else` arm the source can
      # never reach. Measured on @bsv/sdk Spend.validate() with a vault whose
      # signature check sits in the first lap and whose second lap sets
      # `authorized = true`: the phantom-lap loop ACCEPTED an empty signature,
      # while the semantically identical `i < 1n` rejected it.
      #
      # Refusal rather than lowering: evaluating a general condition per
      # iteration means unrolling against a real interpreter at ANF time, a
      # language extension with no golden behind it. The diagnostic text is
      # shared verbatim with the other six tiers.
      def validate_for_condition_tests_iterator(stmt)
        iter = stmt.init.name
        cond = stmt.condition
        return if cond.is_a?(BinaryExpr) && cond.left.is_a?(Identifier) && cond.left.name == iter

        add_error(
          "For loop condition must compare the loop variable '#{iter}' to a compile-time " \
          "constant (`#{iter} < 10n`). The unrolled loop binds the iterator as " \
          "`start + k*step` and takes its trip count from the bound alone, so a condition " \
          "whose left-hand side is anything else -- a computed expression, or a different " \
          "variable -- is not the condition the loop actually evaluates",
          loc: stmt.source_location
        )
      end

      # The three intrinsics that register an output ref.
      OUTPUT_INTRINSIC_NAMES = %w[addOutput addRawOutput addDataOutput].freeze

      # Build the R-127 rejection. Shared verbatim with the other six
      # tiers and with the pass-4 backstop in anf_lower's
      # _lower_for_statement (N-006).
      def self.loop_output_intrinsic_msg(intrinsic, via)
        via_clause = via ? " (reached through private method '#{via}')" : ""
        "Output intrinsic '#{intrinsic}'#{via_clause} cannot be called inside a loop " \
          "body. A loop body lowers into its own scope whose declared outputs never reach " \
          "the method's output list, so the continuation hash would commit to fewer outputs " \
          "than the transaction actually creates: the spend is rejected by every shipped SDK " \
          "and any successor it produces is unspendable. Move the call out of the loop."
      end

      # Build the N-049 rejection. Shared verbatim with the other six tiers
      # (TS reference: ternaryOutputIntrinsicDiagnostic in 02-validate.ts) and
      # with the pass-4 backstop in anf_lower's _lower_ternary_expr.
      def self.ternary_output_intrinsic_msg(intrinsic, via)
        via_clause = via ? " (reached through private method '#{via}')" : ""
        "Output intrinsic '#{intrinsic}'#{via_clause} cannot be called inside a conditional " \
          "(ternary) expression arm. A ternary arm lowers into its own scope whose declared " \
          "outputs never reach the method's output list, so the continuation hash would commit " \
          "to fewer outputs than the transaction actually creates: a spender can drop the output " \
          "and the honest spend is rejected. Use an if/else statement instead."
      end

      # Reject an output intrinsic in either arm of a ternary (N-049).
      #
      # `anf_lower`'s _lower_ternary_expr lowers each arm into a sub-context
      # whose output refs are dropped -- unlike the if-statement lowering, which
      # merges each arm's refs into the parent -- so the continuation hash would
      # omit the arm's output (EXT-2 TernaryToll: a spend dropping the payout
      # was accepted on every tier). Private helpers are followed because they
      # are inlined into the arm. A ternary that only selects values is
      # untouched.
      def validate_no_output_intrinsic_in_ternary_arm(expr)
        [expr.consequent, expr.alternate].each do |arm|
          found = find_output_intrinsic_in_expr(arm, nil, Set.new)
          next if found.nil?

          intrinsic, via, = found
          add_error(self.class.ternary_output_intrinsic_msg(intrinsic, via))
          return
        end
      end

      # Reject an output intrinsic called inside a loop body (R-127).
      #
      # `anf_lower` lowers a loop body into its own sub-context, which starts
      # with a fresh empty add-output ref list, and nothing propagates that list
      # back to the method context -- unlike the if-statement lowering, which
      # concatenates each arm's outputs into one ref precisely so the parent
      # sees them. The continuation hash is then built from whatever `addOutput`
      # calls sit at the method's TOP level while the loop's outputs are still
      # emitted into the transaction. Measured on a two-iteration loop before
      # this check existed:
      #
      #   * loop only -- ts/go/rust/python blew up inside stack lowering
      #     ("method parameter '_newAmount' is not on the stack at a
      #     post-consumption reference"), zig/ruby emitted a covenant over the
      #     WRONG output set, java emitted none. THIS tier was one of the two
      #     that silently shipped the wrong covenant.
      #   * loop + one top-level call -- compiled clean in every tier, and the
      #     ANF continuation hashed exactly ONE leaf while three outputs were
      #     built.
      #
      # A continuation committing to fewer outputs than the transaction creates
      # is spendable only by a hand-crafted transaction, is rejected by every
      # shipped SDK, and the successor it produces is permanently unspendable
      # (CL-BUG-164).
      #
      # Refusal rather than lowering: propagating the refs cannot work by name,
      # because the loop is unrolled at stack-lowering time and one body binding
      # name denotes N physical slots. A correct lowering means unrolling at ANF
      # time, a language feature with no golden behind it; refusing removes
      # nothing that works today.
      def validate_no_output_intrinsic_in_loop(stmt)
        found = find_output_intrinsic(stmt.body, Set.new)
        return if found.nil?

        intrinsic, via, loc = found
        add_error(
          self.class.loop_output_intrinsic_msg(intrinsic, via),
          loc: loc || stmt.source_location,
        )
      end

      # The property/function name a call names, or nil. Distinct from the
      # `callee_property` further down, which takes the CALLEE node itself and
      # does not follow identifiers.
      def output_callee_property(expr)
        return nil unless expr.is_a?(CallExpr)

        callee = expr.callee
        return callee.property if callee.is_a?(PropertyAccessExpr)
        return callee.property if callee.is_a?(MemberExpr)
        return callee.name if callee.is_a?(Identifier)

        nil
      end

      def private_method_named(name)
        @contract.methods.find { |m| m.name == name && m.visibility == "private" }
      end

      # First output intrinsic reachable from `stmts`, following calls to
      # private methods: a public method that delegates `addOutput` to a private
      # helper has that helper INLINED at ANF time, so a helper called in a loop
      # lands its outputs in the loop's sub-context exactly as a direct call
      # would.
      def find_output_intrinsic(stmts, seen)
        stmts.each do |stmt|
          found = find_output_intrinsic_in_statement(stmt, seen)
          return found unless found.nil?
        end
        nil
      end

      def find_output_intrinsic_in_statement(stmt, seen)
        case stmt
        when ExpressionStmt
          find_output_intrinsic_in_expr(stmt.expr, stmt.source_location, seen)
        when VariableDeclStmt
          find_output_intrinsic_in_expr(stmt.init, stmt.source_location, seen)
        when AssignmentStmt
          find_output_intrinsic_in_expr(stmt.value, stmt.source_location, seen)
        when ReturnStmt
          find_output_intrinsic_in_expr(stmt.value, stmt.source_location, seen)
        when IfStmt
          found = find_output_intrinsic_in_expr(stmt.condition, stmt.source_location, seen)
          return found unless found.nil?

          find_output_intrinsic((stmt.then || []) + (stmt.else_ || []), seen)
        when ForStmt
          found = find_output_intrinsic_in_statement(stmt.init, seen) unless stmt.init.nil?
          return found unless found.nil?

          found = find_output_intrinsic_in_expr(stmt.condition, stmt.source_location, seen)
          return found unless found.nil?

          found = find_output_intrinsic_in_statement(stmt.update, seen) unless stmt.update.nil?
          return found unless found.nil?

          find_output_intrinsic(stmt.body, seen)
        end
      end

      def find_output_intrinsic_in_expr(expr, loc, seen)
        return nil if expr.nil?

        name = output_callee_property(expr)
        unless name.nil?
          return [name, nil, loc] if OUTPUT_INTRINSIC_NAMES.include?(name)

          helper = private_method_named(name)
          if helper && !seen.include?(name)
            seen << name
            nested = find_output_intrinsic(helper.body, seen)
            return [nested[0], name, loc] unless nested.nil?
          end
        end

        sub_expressions(expr).each do |child|
          found = find_output_intrinsic_in_expr(child, loc, seen)
          return found unless found.nil?
        end
        nil
      end

      # Direct sub-expressions of `expr`, for the intrinsic search above. An
      # intrinsic can sit inside an argument list or an operand, not only as a
      # bare expression statement.
      def sub_expressions(expr)
        case expr
        when CallExpr then expr.args || []
        when BinaryExpr then [expr.left, expr.right]
        when UnaryExpr then [expr.operand]
        when TernaryExpr then [expr.condition, expr.consequent, expr.alternate]
        when IndexAccessExpr then [expr.object, expr.index]
        when ArrayLiteralExpr then expr.elements || []
        else []
        end
      end

      # Shared verbatim with the other six tiers. Per-tier diagnostic drift on
      # the same rejection is a recurring defect in this repo, so the string is
      # mirrored, character for character, in
      # packages/runar-compiler/src/passes/02-validate.ts,
      # compilers/go/frontend/validator.go,
      # compilers/rust/src/frontend/validator.rs,
      # compilers/python/runar_compiler/frontend/validator.py,
      # compilers/zig/src/frontend/validator.zig and
      # compilers/java/src/main/java/runar/compiler/passes/Validate.java.
      LOOP_UPDATE_DIAGNOSTIC =
        "For loop update must advance the loop variable by one (`i++`, `i--`, " \
        "`i = i + 1n`, `i = i - 1n`). The unrolled loop carries only a start value and a " \
        "unit step, so any other update clause -- a function call, a state mutation, or a " \
        "non-unit step such as `i += 2` -- cannot be represented and would be discarded"

      # Reject any for-loop update clause the loop model cannot represent
      # (R-065).
      #
      # The ANF `loop` node carries exactly `{count, iterVar, start, step, body}`
      # and synthesizes the iterator on unrolled iteration k as
      # `start + k*step`. There is no slot for an arbitrary update statement,
      # and `extract_loop_step` only ever understood a unit step -- everything
      # else was silently coerced to `+1` (or `-1` from the comparison
      # direction) and the clause itself was discarded. That made three distinct
      # failures indistinguishable from a correct compile:
      #
      #   * `for (let i = 0n; i < 3n; undefinedFn())` produced byte-identical
      #     output. A nonexistent function name raised nothing.
      #   * `for (let i = 0n; i < 3n; this.count++)` dropped the state write.
      #   * `while (i < 5) : (i += 2)` unrolled 5 times over i = 0..4 instead of
      #     3 times over i = 0,2,4.
      #
      # spec/grammar.md's ForStatement production admits only
      # `Identifier ('++' | '--')`, and its Statement Restrictions say "The loop
      # variable MUST use simple increment (`++`) or decrement (`--`)". So
      # rejecting is the fix rather than lowering: appending the update's
      # lowering to the loop body would re-emit `i++` as a dead binding on every
      # loop that already compiles correctly, moving bytes across the whole
      # corpus to express nothing.
      #
      # The accepted set is every shape the nine frontends actually synthesize:
      # `i++`/`i--`/`++i`/`--i`; the assignment spelling `i = i + 1` /
      # `i = i - 1` / `i = 1 + i` that `i += 1` becomes in the Solidity, Zig and
      # Java parsers; and the effect-free no-op sentinel (a literal or a bare
      # identifier) that the while-shaped parsers synthesize when the source has
      # no continue expression at all -- but only on a loop whose condition
      # does not test its declared iterator (already refused by the condition
      # rule). On a real iterator a no-op update never advances it:
      # `var i = 3; while (i < 5) : (i)` compiled two laps over i = 3, 4
      # (N-116).
      #
      # The advanced variable must be the declared iterator or the identifier
      # the condition tests. Both are needed: the Zig parser only folds
      # `var i = 0; while (i < N) : (i += 1)` into a single ForStmt when the
      # declaration is the immediately preceding statement, so an unfolded loop
      # carries a placeholder init while the update advances the real `i` named
      # in the condition.
      def validate_for_update(stmt)
        allowed = []
        allowed << stmt.init.name unless stmt.init.nil?
        if stmt.condition.is_a?(BinaryExpr) && stmt.condition.left.is_a?(Identifier)
          allowed << stmt.condition.left.name
        end

        # N-116: the no-op sentinel is tolerated only on a loop the condition
        # rule already refuses (placeholder iterator). On a real iterator it
        # never advances, yet the unrolled loop would still step by one.
        cond_tests_iter = !stmt.init.nil? &&
                          stmt.condition.is_a?(BinaryExpr) &&
                          stmt.condition.left.is_a?(Identifier) &&
                          stmt.condition.left.name == stmt.init.name

        return if representable_for_update?(allowed, stmt.update, !cond_tests_iter)

        add_error(LOOP_UPDATE_DIAGNOSTIC, loc: stmt.source_location)
      end

      # True when `expr` names one of the identifiers the update is allowed to
      # advance. A property access, an index access or anything else is never
      # accepted: those are the side effects that used to be dropped.
      def allowed_loop_var?(allowed, expr)
        expr.is_a?(Identifier) && allowed.include?(expr.name)
      end

      def literal_one?(expr)
        expr.is_a?(BigIntLiteral) && expr.value == 1
      end

      def representable_for_update?(allowed, update, accept_no_op_sentinel)
        case update
        when ExpressionStmt
          e = update.expr
          return allowed_loop_var?(allowed, e.operand) if e.is_a?(IncrementExpr) || e.is_a?(DecrementExpr)

          # The no-op sentinel a while-shaped frontend synthesizes when the
          # source carries no continue expression: zig's `while (c) {}`, move's
          # `while (c) {}`, go's `for c {}`. Reading a literal or a bare
          # identifier has no effect, so discarding it loses nothing -- on a
          # loop the condition rule already refuses (N-116).
          accept_no_op_sentinel &&
            (e.is_a?(BigIntLiteral) || e.is_a?(BoolLiteral) || e.is_a?(Identifier))
        when AssignmentStmt
          # `i += 1` / `i -= 1` arrive here as `i = i + 1` / `i = i - 1`.
          return false unless allowed_loop_var?(allowed, update.target)

          v = update.value
          return false unless v.is_a?(BinaryExpr)

          case v.op
          when "+"
            (allowed_loop_var?(allowed, v.left) && literal_one?(v.right)) ||
              (literal_one?(v.left) && allowed_loop_var?(allowed, v.right))
          when "-"
            allowed_loop_var?(allowed, v.left) && literal_one?(v.right)
          else
            false
          end
        else
          false
        end
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
          validate_no_output_intrinsic_in_ternary_arm(expr)
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
        when ArrayLiteralExpr
          expr.elements.each { |el| validate_expression(el) }
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
      #
      # N-026: the sentence for a refused bound is the reference tier's. Its
      # validator trusts a bare identifier (or boolean literal, or a negation of
      # one) as "could be a const" and lets ANF lowering refuse it with the
      # "Cannot determine" sentence; every other non-literal shape (`this.x`, an
      # expression) gets the "must be a compile-time constant" sentence. Both
      # are shared verbatim by all seven tiers.
      def for_loop_bound_diagnostic(bound)
        bound = bound.operand while bound.is_a?(UnaryExpr) && bound.op == "-"
        if bound.is_a?(Identifier) || bound.is_a?(BoolLiteral)
          "Cannot determine loop bound at compile time. For-loop bounds must be integer literals."
        else
          "For loop bound must be a compile-time constant (literal or const variable)"
        end
      end

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

      # True when +expr+ is a comparison on +extractSequence(...)+ that
      # genuinely EXCLUDES the finality sentinel +0xffffffff+, reading the
      # field as the unsigned 32-bit wire value it is (see
      # +_emit_unsigned_bin2num+ in codegen/stack.rb).
      #
      # Accepted:
      #   extractSequence(pre) !== 0xffffffff   and the reversed spelling
      #   extractSequence(pre) <  N, 0 < N <= 0xffffffff   (reversed: N > ...)
      #   extractSequence(pre) <= N, N <  0xffffffff   (reversed: N >= ...)
      #
      # Deliberately NOT accepted: +<= 0xffffffff+ and +>= 0xffffffff+.
      # nSequence cannot exceed 0xffffffff, so those are true for every
      # transaction including the final one -- a tautology that used to silence
      # this warning on a contract with no guard at all (W1 / FinalCountdown).
      #
      # Also NOT accepted: +extractSequence(pre) < 0+. Unsigned nSequence is
      # never negative, so that comparison is vacuous.
      def sequence_finality_guard?(expr)
        return false unless expr.is_a?(BinaryExpr)

        final_sentinel = ->(e) { e.is_a?(BigIntLiteral) && e.value == SEQUENCE_FINAL }
        strict_bound_ok = ->(e) { e.is_a?(BigIntLiteral) && e.value > 0 && e.value <= SEQUENCE_FINAL }
        non_strict_bound_ok = ->(e) { e.is_a?(BigIntLiteral) && e.value < SEQUENCE_FINAL }

        case expr.op
        when "!=="
          (call_to_named?(expr.left, "extractSequence") && final_sentinel.call(expr.right)) ||
            (call_to_named?(expr.right, "extractSequence") && final_sentinel.call(expr.left))
        when "<"
          call_to_named?(expr.left, "extractSequence") && strict_bound_ok.call(expr.right)
        when "<="
          call_to_named?(expr.left, "extractSequence") && non_strict_bound_ok.call(expr.right)
        when ">"
          call_to_named?(expr.right, "extractSequence") && strict_bound_ok.call(expr.left)
        when ">="
          call_to_named?(expr.right, "extractSequence") && non_strict_bound_ok.call(expr.left)
        else
          false
        end
      end

      # True when asserting +expr+ logically implies a sequence-finality
      # guard. A matching comparison nested under +!+ (or +||+) does not
      # count: +assert(!(extractSequence !== 0xffffffff))+ requires a FINAL
      # sequence. +&&+ implies each conjunct.
      def assertion_implies_sequence_guard?(expr)
        return true if sequence_finality_guard?(expr)
        return false unless expr.is_a?(BinaryExpr) && expr.op == '&&'

        assertion_implies_sequence_guard?(expr.left) || assertion_implies_sequence_guard?(expr.right)
      end

      # #131: warn when +method+ (transitively, through the private-helper call
      # graph) reads the tx locktime but never asserts the tx is non-final. A
      # locktime gate is not consensus-enforced unless
      # +extractSequence !== 0xffffffff+ is also asserted -- otherwise an
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
            if assert_call?(expr)
              expr.args.each do |arg|
                has_sequence_guard = true if assertion_implies_sequence_guard?(arg)
              end
            end
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
                   "extractSequence is not 0xffffffff; a locktime gate is not consensus-enforced " \
                   "unless the tx is non-final — add " \
                   "assert(extractSequence(this.txPreimage) !== 0xffffffffn)",
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
          walk_expressions_in_stmt(stmt.init, visitor)
          walk_expr(stmt.condition, visitor)
          walk_expressions_in_stmt(stmt.update, visitor)
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
        when ArrayLiteralExpr
          expr.elements.each { |el| walk_expr(el, visitor) }
        end
      end

      # -------------------------------------------------------------------
      # Recursion detection helpers
      # -------------------------------------------------------------------

      def collect_method_calls(stmts, calls, bare = false)
        stmts.each { |stmt| collect_method_calls_in_stmt(stmt, calls, bare) }
      end

      def collect_method_calls_in_stmt(stmt, calls, bare = false)
        case stmt
        when ExpressionStmt
          collect_method_calls_in_expr(stmt.expr, calls, bare)
        when VariableDeclStmt
          collect_method_calls_in_expr(stmt.init, calls, bare)
        when AssignmentStmt
          collect_method_calls_in_expr(stmt.target, calls, bare)
          collect_method_calls_in_expr(stmt.value, calls, bare)
        when IfStmt
          collect_method_calls_in_expr(stmt.condition, calls, bare)
          collect_method_calls(stmt.then, calls, bare)
          collect_method_calls(stmt.else_, calls, bare)
        when ForStmt
          collect_method_calls_in_stmt(stmt.init, calls, bare) unless stmt.init.nil?
          collect_method_calls_in_expr(stmt.condition, calls, bare)
          collect_method_calls_in_stmt(stmt.update, calls, bare) unless stmt.update.nil?
          collect_method_calls(stmt.body, calls, bare)
        when ReturnStmt
          collect_method_calls_in_expr(stmt.value, calls, bare) unless stmt.value.nil?
        end
      end

      def collect_method_calls_in_expr(expr, calls, bare = false)
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
          # N-180: the Solidity, Move and Java surfaces may call a helper as a
          # bare `m(...)`. Counted only for the recursion / call-depth graph
          # (bare), and only names of contract methods count there
          # (analyze_call_graph filters by method_names), so builtins are
          # unaffected.
          calls.add(expr.callee.name) if bare && expr.callee.is_a?(Identifier)
          collect_method_calls_in_expr(expr.callee, calls, bare)
          expr.args.each { |arg| collect_method_calls_in_expr(arg, calls, bare) }
        when BinaryExpr
          collect_method_calls_in_expr(expr.left, calls, bare)
          collect_method_calls_in_expr(expr.right, calls, bare)
        when UnaryExpr
          collect_method_calls_in_expr(expr.operand, calls, bare)
        when MemberExpr
          collect_method_calls_in_expr(expr.object, calls, bare)
        when TernaryExpr
          collect_method_calls_in_expr(expr.condition, calls, bare)
          collect_method_calls_in_expr(expr.consequent, calls, bare)
          collect_method_calls_in_expr(expr.alternate, calls, bare)
        when IndexAccessExpr
          collect_method_calls_in_expr(expr.object, calls, bare)
          collect_method_calls_in_expr(expr.index, calls, bare)
        when IncrementExpr
          collect_method_calls_in_expr(expr.operand, calls, bare)
        when DecrementExpr
          collect_method_calls_in_expr(expr.operand, calls, bare)
        when ArrayLiteralExpr
          expr.elements.each { |el| collect_method_calls_in_expr(el, calls, bare) }
        end
      end
    end
  end
end

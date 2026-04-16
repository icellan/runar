# frozen_string_literal: true

# Type checking pass for the Runar compiler.
#
# Verifies type consistency of a validated Runar AST.
# Direct port of compilers/python/runar_compiler/frontend/typecheck.py.

require_relative "ast_nodes"
require_relative "diagnostic"

module RunarCompiler
  module Frontend
    # Output of the type checking pass.
    class TypeCheckResult
      attr_reader :contract, :errors

      def initialize(contract: nil, errors: [])
        @contract = contract
        @errors = errors
      end

      # Return formatted error messages as plain strings.
      def error_strings
        @errors.map(&:format_message)
      end
    end

    # Signature of a function: parameter types and return type.
    FuncSig = Struct.new(:params, :return_type, keyword_init: true)

    # All built-in Runar function signatures.
    BUILTIN_FUNCTIONS = {
      "sha256"            => FuncSig.new(params: ["ByteString"], return_type: "Sha256"),
      "ripemd160"         => FuncSig.new(params: ["ByteString"], return_type: "Ripemd160"),
      "hash160"           => FuncSig.new(params: ["ByteString"], return_type: "Ripemd160"),
      "hash256"           => FuncSig.new(params: ["ByteString"], return_type: "Sha256"),
      "checkSig"          => FuncSig.new(params: ["Sig", "PubKey"], return_type: "boolean"),
      "checkMultiSig"     => FuncSig.new(params: ["Sig[]", "PubKey[]"], return_type: "boolean"),
      "assert"            => FuncSig.new(params: ["boolean"], return_type: "void"),
      "len"               => FuncSig.new(params: ["ByteString"], return_type: "bigint"),
      "cat"               => FuncSig.new(params: ["ByteString", "ByteString"], return_type: "ByteString"),
      "substr"            => FuncSig.new(params: ["ByteString", "bigint", "bigint"], return_type: "ByteString"),
      "num2bin"           => FuncSig.new(params: ["bigint", "bigint"], return_type: "ByteString"),
      "bin2num"           => FuncSig.new(params: ["ByteString"], return_type: "bigint"),
      "checkPreimage"     => FuncSig.new(params: ["SigHashPreimage"], return_type: "boolean"),
      "verifyRabinSig"    => FuncSig.new(params: ["ByteString", "RabinSig", "ByteString", "RabinPubKey"], return_type: "boolean"),
      "verifyWOTS"        => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      "verifySLHDSA_SHA2_128s" => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      "verifySLHDSA_SHA2_128f" => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      "verifySLHDSA_SHA2_192s" => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      "verifySLHDSA_SHA2_192f" => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      "verifySLHDSA_SHA2_256s" => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      "verifySLHDSA_SHA2_256f" => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      "ecAdd"              => FuncSig.new(params: ["Point", "Point"], return_type: "Point"),
      "ecMul"              => FuncSig.new(params: ["Point", "bigint"], return_type: "Point"),
      "ecMulGen"           => FuncSig.new(params: ["bigint"], return_type: "Point"),
      "ecNegate"           => FuncSig.new(params: ["Point"], return_type: "Point"),
      "ecOnCurve"          => FuncSig.new(params: ["Point"], return_type: "boolean"),
      "ecModReduce"        => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "ecEncodeCompressed" => FuncSig.new(params: ["Point"], return_type: "ByteString"),
      "ecMakePoint"        => FuncSig.new(params: ["bigint", "bigint"], return_type: "Point"),
      "ecPointX"           => FuncSig.new(params: ["Point"], return_type: "bigint"),
      "ecPointY"           => FuncSig.new(params: ["Point"], return_type: "bigint"),
      # P-256 (secp256r1 / NIST P-256)
      "p256Add"              => FuncSig.new(params: ["P256Point", "P256Point"], return_type: "P256Point"),
      "p256Mul"              => FuncSig.new(params: ["P256Point", "bigint"], return_type: "P256Point"),
      "p256MulGen"           => FuncSig.new(params: ["bigint"], return_type: "P256Point"),
      "p256Negate"           => FuncSig.new(params: ["P256Point"], return_type: "P256Point"),
      "p256OnCurve"          => FuncSig.new(params: ["P256Point"], return_type: "boolean"),
      "p256EncodeCompressed" => FuncSig.new(params: ["P256Point"], return_type: "ByteString"),
      "verifyECDSA_P256"     => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      # P-384 (secp384r1 / NIST P-384)
      "p384Add"              => FuncSig.new(params: ["P384Point", "P384Point"], return_type: "P384Point"),
      "p384Mul"              => FuncSig.new(params: ["P384Point", "bigint"], return_type: "P384Point"),
      "p384MulGen"           => FuncSig.new(params: ["bigint"], return_type: "P384Point"),
      "p384Negate"           => FuncSig.new(params: ["P384Point"], return_type: "P384Point"),
      "p384OnCurve"          => FuncSig.new(params: ["P384Point"], return_type: "boolean"),
      "p384EncodeCompressed" => FuncSig.new(params: ["P384Point"], return_type: "ByteString"),
      "verifyECDSA_P384"     => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      "sha256Compress"     => FuncSig.new(params: ["ByteString", "ByteString"], return_type: "ByteString"),
      "sha256Finalize"     => FuncSig.new(params: ["ByteString", "ByteString", "bigint"], return_type: "ByteString"),
      "bbFieldAdd"         => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "bbFieldSub"         => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "bbFieldMul"         => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "bbFieldInv"         => FuncSig.new(params: ["bigint"], return_type: "bigint"),
      "bbExt4Mul0"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "bbExt4Mul1"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "bbExt4Mul2"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "bbExt4Mul3"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "bbExt4Inv0"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "bbExt4Inv1"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "bbExt4Inv2"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "bbExt4Inv3"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "merkleRootSha256"   => FuncSig.new(params: ["ByteString", "ByteString", "bigint", "bigint"], return_type: "ByteString"),
      "merkleRootHash256"  => FuncSig.new(params: ["ByteString", "ByteString", "bigint", "bigint"], return_type: "ByteString"),
      "blake3Compress"     => FuncSig.new(params: ["ByteString", "ByteString"], return_type: "ByteString"),
      "blake3Hash"         => FuncSig.new(params: ["ByteString"], return_type: "ByteString"),
      "abs"                => FuncSig.new(params: ["bigint"], return_type: "bigint"),
      "min"                => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "max"                => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "within"             => FuncSig.new(params: ["bigint", "bigint", "bigint"], return_type: "boolean"),
      "safediv"            => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "safemod"            => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "clamp"              => FuncSig.new(params: ["bigint", "bigint", "bigint"], return_type: "bigint"),
      "sign"               => FuncSig.new(params: ["bigint"], return_type: "bigint"),
      "pow"                => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "mulDiv"             => FuncSig.new(params: ["bigint", "bigint", "bigint"], return_type: "bigint"),
      "percentOf"          => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "sqrt"               => FuncSig.new(params: ["bigint"], return_type: "bigint"),
      "gcd"                => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "divmod"             => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "log2"               => FuncSig.new(params: ["bigint"], return_type: "bigint"),
      "bool"               => FuncSig.new(params: ["bigint"], return_type: "boolean"),
      "reverseBytes"       => FuncSig.new(params: ["ByteString"], return_type: "ByteString"),
      "left"               => FuncSig.new(params: ["ByteString", "bigint"], return_type: "ByteString"),
      "right"              => FuncSig.new(params: ["ByteString", "bigint"], return_type: "ByteString"),
      "split"              => FuncSig.new(params: ["ByteString", "bigint"], return_type: "ByteString"),
      "int2str"            => FuncSig.new(params: ["bigint", "bigint"], return_type: "ByteString"),
      "toByteString"       => FuncSig.new(params: ["ByteString"], return_type: "ByteString"),
      "exit"               => FuncSig.new(params: ["boolean"], return_type: "void"),
      "pack"               => FuncSig.new(params: ["bigint"], return_type: "ByteString"),
      "unpack"             => FuncSig.new(params: ["ByteString"], return_type: "bigint"),
      "extractVersion"        => FuncSig.new(params: ["SigHashPreimage"], return_type: "bigint"),
      "extractHashPrevouts"   => FuncSig.new(params: ["SigHashPreimage"], return_type: "Sha256"),
      "extractHashSequence"   => FuncSig.new(params: ["SigHashPreimage"], return_type: "Sha256"),
      "extractOutpoint"       => FuncSig.new(params: ["SigHashPreimage"], return_type: "ByteString"),
      "extractInputIndex"     => FuncSig.new(params: ["SigHashPreimage"], return_type: "bigint"),
      "extractScriptCode"     => FuncSig.new(params: ["SigHashPreimage"], return_type: "ByteString"),
      "extractAmount"         => FuncSig.new(params: ["SigHashPreimage"], return_type: "bigint"),
      "extractSequence"       => FuncSig.new(params: ["SigHashPreimage"], return_type: "bigint"),
      "extractOutputHash"     => FuncSig.new(params: ["SigHashPreimage"], return_type: "Sha256"),
      "extractOutputs"        => FuncSig.new(params: ["SigHashPreimage"], return_type: "Sha256"),
      "extractLocktime"       => FuncSig.new(params: ["SigHashPreimage"], return_type: "bigint"),
      "extractSigHashType"    => FuncSig.new(params: ["SigHashPreimage"], return_type: "bigint"),
      "buildChangeOutput"     => FuncSig.new(params: ["ByteString", "bigint"], return_type: "ByteString"),
      "computeStateOutput"    => FuncSig.new(params: ["ByteString", "bigint"], return_type: "ByteString"),
    }.freeze

    # -------------------------------------------------------------------
    # Subtyping
    # -------------------------------------------------------------------

    BYTESTRING_SUBTYPES = %w[
      ByteString PubKey Sig Sha256 Ripemd160 Addr SigHashPreimage Point P256Point P384Point
    ].to_set.freeze

    BIGINT_SUBTYPES = %w[
      bigint RabinSig RabinPubKey
    ].to_set.freeze

    # Return true if +actual+ is a subtype of +expected+.
    def self.subtype?(actual, expected)
      return true if actual == expected

      # <inferred> and <unknown> are compatible with anything
      return true if actual == "<inferred>" || actual == "<unknown>"
      return true if expected == "<inferred>" || expected == "<unknown>"

      return true if expected == "ByteString" && BYTESTRING_SUBTYPES.include?(actual)
      return true if expected == "bigint" && BIGINT_SUBTYPES.include?(actual)

      if expected.end_with?("[]") && actual.end_with?("[]")
        return subtype?(actual[0..-3], expected[0..-3])
      end

      false
    end

    # Return true if +t+ belongs to the bigint type family.
    def self.bigint_family?(type_name)
      BIGINT_SUBTYPES.include?(type_name)
    end

    # Return true if +t+ belongs to the ByteString type family.
    def self.byte_family?(type_name)
      BYTESTRING_SUBTYPES.include?(type_name)
    end

    # Type-check a Runar AST. Returns the same AST plus any errors.
    #
    # @param contract [ContractNode]
    # @return [TypeCheckResult]
    def self.type_check(contract)
      checker = TypeChecker.new(contract)

      checker.check_constructor
      contract.methods.each { |method| checker.check_method(method) }

      TypeCheckResult.new(contract: contract, errors: checker.errors)
    end

    # -------------------------------------------------------------------
    # Type environment
    # -------------------------------------------------------------------

    # @api private
    class TypeEnv
      def initialize
        @scopes = [{}]
      end

      def push_scope
        @scopes.push({})
      end

      def pop_scope
        @scopes.pop unless @scopes.empty?
      end

      def define(name, type_name)
        @scopes.last[name] = type_name
      end

      # @return [Array(String, Boolean)] the type and whether it was found
      def lookup(name)
        @scopes.reverse_each do |scope|
          return [scope[name], true] if scope.key?(name)
        end
        ["", false]
      end
    end

    # -------------------------------------------------------------------
    # Affine types
    # -------------------------------------------------------------------

    AFFINE_TYPES = %w[Sig SigHashPreimage].to_set.freeze

    CONSUMING_FUNCTIONS = {
      "checkSig"      => [0],
      "checkMultiSig" => [0],
      "checkPreimage" => [0],
    }.freeze

    # -------------------------------------------------------------------
    # Type checker
    # -------------------------------------------------------------------

    # @api private
    class TypeChecker
      attr_reader :errors

      def initialize(contract)
        @contract = contract
        @errors = []
        @prop_types = {}
        @method_sigs = {}
        @consumed_values = {}
        @current_method_loc = nil
        @current_stmt_loc = nil

        contract.properties.each do |prop|
          @prop_types[prop.name] = type_node_to_string(prop.type)
        end

        # For StatefulSmartContract, add the implicit txPreimage property
        if contract.parent_class == "StatefulSmartContract"
          @prop_types["txPreimage"] = "SigHashPreimage"
        end

        contract.methods.each do |method|
          params = method.params.map { |p| type_node_to_string(p.type) }
          ret_type = "void"
          if method.visibility != "public"
            ret_type = TypeChecker.infer_method_return_type(method)
          end
          @method_sigs[method.name] = FuncSig.new(params: params, return_type: ret_type)
        end
      end

      def check_constructor
        ctor = @contract.constructor
        env = TypeEnv.new

        # Set current method location for diagnostics
        @current_method_loc = ctor.source_location

        # Reset affine tracking
        @consumed_values = {}

        ctor.params.each do |param|
          env.define(param.name, type_node_to_string(param.type))
        end
        @contract.properties.each do |prop|
          env.define(prop.name, type_node_to_string(prop.type))
        end

        check_statements(ctor.body, env)
      end

      def check_method(method)
        env = TypeEnv.new

        # Set current method location for diagnostics
        @current_method_loc = method.source_location

        # Reset affine tracking
        @consumed_values = {}

        method.params.each do |param|
          env.define(param.name, type_node_to_string(param.type))
        end

        check_statements(method.body, env)
      end

      # -------------------------------------------------------------------
      # Private method return type inference (class-level)
      # -------------------------------------------------------------------

      def self.infer_method_return_type(method)
        return_types = collect_return_types(method.body)
        return "void" if return_types.empty?

        first = return_types[0]
        return first if return_types.all? { |t| t == first }

        # Check if all are in the bigint family
        return "bigint" if return_types.all? { |t| BIGINT_SUBTYPES.include?(t) }

        # Check if all are in the ByteString family
        return "ByteString" if return_types.all? { |t| BYTESTRING_SUBTYPES.include?(t) }

        # Check if all are boolean
        return "boolean" if return_types.all? { |t| t == "boolean" }

        first
      end

      def self.collect_return_types(stmts)
        types = []
        stmts.each do |stmt|
          case stmt
          when ReturnStmt
            types << infer_expr_type_static(stmt.value) unless stmt.value.nil?
          when IfStmt
            types.concat(collect_return_types(stmt.then))
            types.concat(collect_return_types(stmt.else_)) unless stmt.else_.empty?
          when ForStmt
            types.concat(collect_return_types(stmt.body))
          end
        end
        types
      end

      def self.infer_expr_type_static(expr)
        return "<unknown>" if expr.nil?

        case expr
        when BigIntLiteral
          "bigint"
        when BoolLiteral
          "boolean"
        when ByteStringLiteral
          "ByteString"
        when Identifier
          return "boolean" if expr.name == "true" || expr.name == "false"
          "<unknown>"
        when BinaryExpr
          if %w[+ - * / % & | ^ << >>].include?(expr.op)
            "bigint"
          else
            # Comparison, equality, logical operators -> boolean
            "boolean"
          end
        when UnaryExpr
          expr.op == "!" ? "boolean" : "bigint"
        when CallExpr
          if expr.callee.is_a?(Identifier)
            sig = BUILTIN_FUNCTIONS[expr.callee.name]
            return sig.return_type unless sig.nil?
          end
          if expr.callee.is_a?(PropertyAccessExpr)
            sig = BUILTIN_FUNCTIONS[expr.callee.property]
            return sig.return_type unless sig.nil?
          end
          "<unknown>"
        when TernaryExpr
          cons_type = infer_expr_type_static(expr.consequent)
          return cons_type if cons_type != "<unknown>"
          infer_expr_type_static(expr.alternate)
        when IncrementExpr, DecrementExpr
          "bigint"
        else
          "<unknown>"
        end
      end

      private

      def add_error(msg)
        loc = @current_stmt_loc || @current_method_loc
        @errors << Diagnostic.new(message: msg, severity: Severity::ERROR, loc: loc)
      end

      def type_node_to_string(node)
        return "<unknown>" if node.nil?

        case node
        when PrimitiveType
          node.name
        when FixedArrayType
          "#{type_node_to_string(node.element)}[]"
        when CustomType
          node.name
        else
          "<unknown>"
        end
      end

      # -------------------------------------------------------------------
      # Statement checking
      # -------------------------------------------------------------------

      def check_statements(stmts, env)
        stmts.each { |stmt| check_statement(stmt, env) }
      end

      def check_statement(stmt, env)
        # Set statement-level source location for diagnostics
        prev_stmt_loc = @current_stmt_loc
        stmt_loc = stmt_source_location(stmt)
        @current_stmt_loc = stmt_loc unless stmt_loc.nil?

        case stmt
        when VariableDeclStmt
          init_type = infer_expr_type(stmt.init, env)
          if !stmt.type.nil?
            declared_type = type_node_to_string(stmt.type)
            unless Frontend.subtype?(init_type, declared_type)
              add_error("type '#{init_type}' is not assignable to type '#{declared_type}'")
            end
            env.define(stmt.name, declared_type)
          else
            env.define(stmt.name, init_type)
          end

        when AssignmentStmt
          target_type = infer_expr_type(stmt.target, env)
          value_type = infer_expr_type(stmt.value, env)
          unless Frontend.subtype?(value_type, target_type)
            add_error("type '#{value_type}' is not assignable to type '#{target_type}'")
          end

        when IfStmt
          cond_type = infer_expr_type(stmt.condition, env)
          if cond_type != "boolean"
            add_error("if condition must be boolean, got '#{cond_type}'")
          end
          env.push_scope
          check_statements(stmt.then, env)
          env.pop_scope
          unless stmt.else_.empty?
            env.push_scope
            check_statements(stmt.else_, env)
            env.pop_scope
          end

        when ForStmt
          env.push_scope
          check_statement(stmt.init, env)
          cond_type = infer_expr_type(stmt.condition, env)
          if cond_type != "boolean"
            add_error("for loop condition must be boolean, got '#{cond_type}'")
          end
          check_statements(stmt.body, env)
          env.pop_scope

        when ExpressionStmt
          infer_expr_type(stmt.expr, env)

        when ReturnStmt
          infer_expr_type(stmt.value, env) unless stmt.value.nil?
        end

        # Restore previous statement location
        @current_stmt_loc = prev_stmt_loc
      end

      def stmt_source_location(stmt)
        loc = stmt.respond_to?(:source_location) ? stmt.source_location : nil
        return nil if loc.nil?
        return loc if loc.file && !loc.file.empty?
        return loc if loc.line > 0

        nil
      end

      # -------------------------------------------------------------------
      # Type inference
      # -------------------------------------------------------------------

      def infer_expr_type(expr, env)
        return "<unknown>" if expr.nil?

        case expr
        when BigIntLiteral
          "bigint"
        when BoolLiteral
          "boolean"
        when ByteStringLiteral
          "ByteString"

        when Identifier
          return "<this>" if expr.name == "this"
          return "<super>" if expr.name == "super"

          type_name, found = env.lookup(expr.name)
          return type_name if found
          return "<builtin>" if BUILTIN_FUNCTIONS.key?(expr.name)

          "<unknown>"

        when PropertyAccessExpr
          return @prop_types[expr.property] if @prop_types.key?(expr.property)
          "<unknown>"

        when MemberExpr
          obj_type = infer_expr_type(expr.object, env)
          if obj_type == "<this>"
            return @prop_types[expr.property] if @prop_types.key?(expr.property)
            return "<method>" if @method_sigs.key?(expr.property)
            return "<method>" if expr.property == "getStateScript"
            return "<unknown>"
          end
          if expr.object.is_a?(Identifier) && expr.object.name == "SigHash"
            return "bigint"
          end
          "<unknown>"

        when BinaryExpr
          check_binary_expr(expr, env)

        when UnaryExpr
          check_unary_expr(expr, env)

        when CallExpr
          check_call_expr(expr, env)

        when TernaryExpr
          cond_type = infer_expr_type(expr.condition, env)
          if cond_type != "boolean"
            add_error("ternary condition must be boolean, got '#{cond_type}'")
          end
          cons_type = infer_expr_type(expr.consequent, env)
          alt_type = infer_expr_type(expr.alternate, env)
          if cons_type != alt_type
            return cons_type if Frontend.subtype?(alt_type, cons_type)
            return alt_type if Frontend.subtype?(cons_type, alt_type)
          end
          cons_type

        when IndexAccessExpr
          obj_type = infer_expr_type(expr.object, env)
          index_type = infer_expr_type(expr.index, env)
          unless Frontend.bigint_family?(index_type)
            add_error("array index must be bigint, got '#{index_type}'")
          end
          return obj_type[0..-3] if obj_type.end_with?("[]")
          "<unknown>"

        when IncrementExpr
          operand_type = infer_expr_type(expr.operand, env)
          unless Frontend.bigint_family?(operand_type)
            add_error("++ operator requires bigint, got '#{operand_type}'")
          end
          "bigint"

        when DecrementExpr
          operand_type = infer_expr_type(expr.operand, env)
          unless Frontend.bigint_family?(operand_type)
            add_error("-- operator requires bigint, got '#{operand_type}'")
          end
          "bigint"

        else
          "<unknown>"
        end
      end

      # -------------------------------------------------------------------
      # Binary expression type checking
      # -------------------------------------------------------------------

      def check_binary_expr(expr, env)
        left_type = infer_expr_type(expr.left, env)
        right_type = infer_expr_type(expr.right, env)

        # ByteString concatenation: ByteString + ByteString -> ByteString (via OP_CAT)
        if expr.op == "+" && Frontend.byte_family?(left_type) && Frontend.byte_family?(right_type)
          return "ByteString"
        end

        # Arithmetic: bigint x bigint -> bigint
        if %w[+ - * / %].include?(expr.op)
          unless Frontend.bigint_family?(left_type)
            add_error("left operand of '#{expr.op}' must be bigint, got '#{left_type}'")
          end
          unless Frontend.bigint_family?(right_type)
            add_error("right operand of '#{expr.op}' must be bigint, got '#{right_type}'")
          end
          return "bigint"
        end

        if %w[< <= > >=].include?(expr.op)
          unless Frontend.bigint_family?(left_type)
            add_error("left operand of '#{expr.op}' must be bigint, got '#{left_type}'")
          end
          unless Frontend.bigint_family?(right_type)
            add_error("right operand of '#{expr.op}' must be bigint, got '#{right_type}'")
          end
          return "boolean"
        end

        if expr.op == "===" || expr.op == "!=="
          compatible =
            Frontend.subtype?(left_type, right_type) ||
            Frontend.subtype?(right_type, left_type) ||
            (BYTESTRING_SUBTYPES.include?(left_type) && BYTESTRING_SUBTYPES.include?(right_type)) ||
            (BIGINT_SUBTYPES.include?(left_type) && BIGINT_SUBTYPES.include?(right_type))
          unless compatible
            if left_type != "<unknown>" && right_type != "<unknown>"
              add_error("cannot compare '#{left_type}' and '#{right_type}' with '#{expr.op}'")
            end
          end
          return "boolean"
        end

        if expr.op == "&&" || expr.op == "||"
          if left_type != "boolean" && left_type != "<unknown>"
            add_error("left operand of '#{expr.op}' must be boolean, got '#{left_type}'")
          end
          if right_type != "boolean" && right_type != "<unknown>"
            add_error("right operand of '#{expr.op}' must be boolean, got '#{right_type}'")
          end
          return "boolean"
        end

        if expr.op == "<<" || expr.op == ">>"
          unless Frontend.bigint_family?(left_type)
            add_error("left operand of '#{expr.op}' must be bigint, got '#{left_type}'")
          end
          unless Frontend.bigint_family?(right_type)
            add_error("right operand of '#{expr.op}' must be bigint, got '#{right_type}'")
          end
          return "bigint"
        end

        # Bitwise operators: bigint x bigint -> bigint, or ByteString x ByteString -> ByteString
        if %w[& | ^].include?(expr.op)
          if Frontend.byte_family?(left_type) && Frontend.byte_family?(right_type)
            return "ByteString"
          end
          unless Frontend.bigint_family?(left_type)
            add_error("left operand of '#{expr.op}' must be bigint or ByteString, got '#{left_type}'")
          end
          unless Frontend.bigint_family?(right_type)
            add_error("right operand of '#{expr.op}' must be bigint or ByteString, got '#{right_type}'")
          end
          return "bigint"
        end

        "<unknown>"
      end

      # -------------------------------------------------------------------
      # Unary expression type checking
      # -------------------------------------------------------------------

      def check_unary_expr(expr, env)
        operand_type = infer_expr_type(expr.operand, env)

        case expr.op
        when "!"
          if operand_type != "boolean" && operand_type != "<unknown>"
            add_error("operand of '!' must be boolean, got '#{operand_type}'")
          end
          "boolean"

        when "-"
          unless Frontend.bigint_family?(operand_type)
            add_error("operand of unary '-' must be bigint, got '#{operand_type}'")
          end
          "bigint"

        when "~"
          return "ByteString" if Frontend.byte_family?(operand_type)
          unless Frontend.bigint_family?(operand_type)
            add_error("operand of '~' must be bigint or ByteString, got '#{operand_type}'")
          end
          "bigint"

        else
          "<unknown>"
        end
      end

      # -------------------------------------------------------------------
      # Call expression type checking
      # -------------------------------------------------------------------

      def check_call_expr(expr, env)
        # super() call
        if expr.callee.is_a?(Identifier) && expr.callee.name == "super"
          expr.args.each { |arg| infer_expr_type(arg, env) }
          return "void"
        end

        # Direct builtin call
        if expr.callee.is_a?(Identifier)
          name = expr.callee.name
          if BUILTIN_FUNCTIONS.key?(name)
            return check_call_args(name, BUILTIN_FUNCTIONS[name], expr.args, env)
          end
          # Check if it's a known contract method
          if @method_sigs.key?(name)
            return check_call_args(name, @method_sigs[name], expr.args, env)
          end
          # Check if it's a local variable
          _, found = env.lookup(name)
          if found
            expr.args.each { |arg| infer_expr_type(arg, env) }
            return "<unknown>"
          end
          add_error(
            "unknown function '#{name}' -- only Runar built-in functions " \
            "and contract methods are allowed"
          )
          expr.args.each { |arg| infer_expr_type(arg, env) }
          return "<unknown>"
        end

        # this.method() via PropertyAccessExpr
        if expr.callee.is_a?(PropertyAccessExpr)
          prop = expr.callee.property
          if prop == "getStateScript"
            return "ByteString"
          end
          if prop == "addOutput"
            expr.args.each { |arg| infer_expr_type(arg, env) }
            return "void"
          end
          if prop == "addRawOutput"
            expr.args.each { |arg| infer_expr_type(arg, env) }
            return "void"
          end
          if @method_sigs.key?(prop)
            return check_call_args(prop, @method_sigs[prop], expr.args, env)
          end
          add_error(
            "unknown method 'this.#{prop}' -- only Runar built-in methods " \
            "and contract methods are allowed"
          )
          expr.args.each { |arg| infer_expr_type(arg, env) }
          return "<unknown>"
        end

        # this.method() via MemberExpr
        if expr.callee.is_a?(MemberExpr)
          obj_type = infer_expr_type(expr.callee.object, env)
          is_this = obj_type == "<this>" ||
            (expr.callee.object.is_a?(Identifier) && expr.callee.object.name == "this")
          if is_this
            if expr.callee.property == "getStateScript"
              return "ByteString"
            end
            if expr.callee.property == "addOutput"
              expr.args.each { |arg| infer_expr_type(arg, env) }
              return "void"
            end
            if expr.callee.property == "addRawOutput"
              expr.args.each { |arg| infer_expr_type(arg, env) }
              return "void"
            end
            if @method_sigs.key?(expr.callee.property)
              return check_call_args(
                expr.callee.property,
                @method_sigs[expr.callee.property],
                expr.args,
                env
              )
            end
          end
          # Not this.method -- reject (e.g. Math.floor)
          obj_name = "<expr>"
          if expr.callee.object.is_a?(Identifier)
            obj_name = expr.callee.object.name
          end
          add_error(
            "unknown function '#{obj_name}.#{expr.callee.property}' -- only Runar " \
            "built-in functions and contract methods are allowed"
          )
          expr.args.each { |arg| infer_expr_type(arg, env) }
          return "<unknown>"
        end

        # Fallback -- unknown callee shape
        add_error(
          "unsupported function call expression -- only Runar built-in " \
          "functions and contract methods are allowed"
        )
        infer_expr_type(expr.callee, env)
        expr.args.each { |arg| infer_expr_type(arg, env) }
        "<unknown>"
      end

      # -------------------------------------------------------------------
      # Argument checking
      # -------------------------------------------------------------------

      def check_call_args(func_name, sig, args, env)
        # assert special case
        if func_name == "assert"
          if args.length < 1 || args.length > 2
            add_error("assert() expects 1 or 2 arguments, got #{args.length}")
          end
          if args.length >= 1
            cond_type = infer_expr_type(args[0], env)
            if cond_type != "boolean" && cond_type != "<unknown>"
              add_error("assert() condition must be boolean, got '#{cond_type}'")
            end
          end
          infer_expr_type(args[1], env) if args.length >= 2
          return sig.return_type
        end

        # checkMultiSig special case
        if func_name == "checkMultiSig"
          args.each { |arg| infer_expr_type(arg, env) }
          check_affine_consumption(func_name, args, env)
          return sig.return_type
        end

        # Standard arg count check
        if args.length != sig.params.length
          add_error("#{func_name}() expects #{sig.params.length} argument(s), got #{args.length}")
        end

        count = [args.length, sig.params.length].min

        count.times do |i|
          arg_type = infer_expr_type(args[i], env)
          expected_type = sig.params[i]
          if !Frontend.subtype?(arg_type, expected_type) && arg_type != "<unknown>"
            add_error(
              "argument #{i + 1} of #{func_name}(): expected '#{expected_type}', " \
              "got '#{arg_type}'"
            )
          end
        end

        (count...args.length).each do |i|
          infer_expr_type(args[i], env)
        end

        # Affine type enforcement
        check_affine_consumption(func_name, args, env)

        sig.return_type
      end

      # -------------------------------------------------------------------
      # Affine consumption
      # -------------------------------------------------------------------

      def check_affine_consumption(func_name, args, env)
        consumed_indices = CONSUMING_FUNCTIONS[func_name]
        return if consumed_indices.nil?

        consumed_indices.each do |param_index|
          next if param_index >= args.length

          arg = args[param_index]
          next unless arg.is_a?(Identifier)

          arg_type, found = env.lookup(arg.name)
          next if !found || !AFFINE_TYPES.include?(arg_type)

          if @consumed_values[arg.name]
            add_error("affine value '#{arg.name}' has already been consumed")
          else
            @consumed_values[arg.name] = true
          end
        end
      end
    end
  end
end

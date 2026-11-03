# frozen_string_literal: true

require_relative "test_helper"

# Pull in the frontend modules directly so we can call validate() without
# going through the full compiler pipeline.
require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/validator"
require "runar_compiler/frontend/parser_ts"

class TestValidator < Minitest::Test
  include RunarCompiler::Frontend

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Parse TypeScript source and return the ContractNode. Fails the test on
  # parse errors.
  def parse_ts(source, file_name = "Test.runar.ts")
    result = RunarCompiler.send(:_parse_source, source, file_name)
    assert_empty result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil result.contract, "expected a contract from parsing"
    result.contract
  end

  # Build a minimal valid ContractNode manually. Override pieces as needed.
  def minimal_contract(
    name: "Test",
    parent_class: "SmartContract",
    properties: nil,
    constructor_body: nil,
    constructor_params: nil,
    methods: nil
  )
    props = properties || [
      PropertyNode.new(
        name: "x", type: PrimitiveType.new(name: "bigint"),
        readonly: (parent_class == "SmartContract"),
        source_location: SourceLocation.new(file: "test.runar.ts", line: 3)
      )
    ]

    ctor_params = constructor_params || [
      ParamNode.new(name: "x", type: PrimitiveType.new(name: "bigint"))
    ]

    ctor_body = constructor_body || [
      ExpressionStmt.new(
        expr: CallExpr.new(callee: Identifier.new(name: "super"), args: [Identifier.new(name: "x")])
      ),
      AssignmentStmt.new(
        target: PropertyAccessExpr.new(property: "x"),
        value: Identifier.new(name: "x")
      )
    ]

    meths = methods || [
      MethodNode.new(
        name: "check",
        visibility: "public",
        params: [ParamNode.new(name: "val", type: PrimitiveType.new(name: "bigint"))],
        body: [
          ExpressionStmt.new(
            expr: CallExpr.new(
              callee: Identifier.new(name: "assert"),
              args: [
                BinaryExpr.new(
                  op: "===",
                  left: Identifier.new(name: "val"),
                  right: PropertyAccessExpr.new(property: "x")
                )
              ]
            )
          )
        ],
        source_location: SourceLocation.new(file: "test.runar.ts", line: 10)
      )
    ]

    ContractNode.new(
      name: name,
      parent_class: parent_class,
      properties: props,
      constructor: ConstructorNode.new(
        params: ctor_params,
        body: ctor_body,
        source_location: SourceLocation.new(file: "test.runar.ts", line: 5)
      ),
      methods: meths,
      source_file: "test.runar.ts"
    )
  end

  # ---------------------------------------------------------------------------
  # 1. Valid minimal contract passes validation
  # ---------------------------------------------------------------------------

  def test_valid_minimal_contract_passes
    contract = minimal_contract
    result = RunarCompiler::Frontend.validate(contract)
    assert_empty result.errors.map(&:format_message), "minimal contract should validate cleanly"
  end

  # ---------------------------------------------------------------------------
  # 2. Valid P2PKH from source passes validation
  # ---------------------------------------------------------------------------

  def test_valid_p2pkh_from_source
    source = <<~TS
      import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

      class P2PKH extends SmartContract {
        readonly pubKeyHash: Addr;

        constructor(pubKeyHash: Addr) {
          super(pubKeyHash);
          this.pubKeyHash = pubKeyHash;
        }

        public unlock(sig: Sig, pubKey: PubKey): void {
          assert(hash160(pubKey) === this.pubKeyHash);
          assert(checkSig(sig, pubKey));
        }
      }
    TS

    contract = parse_ts(source, "P2PKH.runar.ts")
    result = RunarCompiler::Frontend.validate(contract)
    assert_empty result.errors.map(&:format_message), "P2PKH should validate without errors"
  end

  # ---------------------------------------------------------------------------
  # 3. Constructor must call super() as first statement
  # ---------------------------------------------------------------------------

  def test_constructor_missing_super_call
    contract = minimal_contract(
      constructor_body: [
        # Jump straight to assignment -- no super()
        AssignmentStmt.new(
          target: PropertyAccessExpr.new(property: "x"),
          value: Identifier.new(name: "x")
        )
      ]
    )
    result = RunarCompiler::Frontend.validate(contract)
    assert result.errors.any? { |e| e.message.downcase.include?("super") },
           "expected error about missing super() call, got: #{result.error_strings}"
  end

  # ---------------------------------------------------------------------------
  # 4. super() not as first statement
  # ---------------------------------------------------------------------------

  def test_super_not_first_statement
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          this.x = x;
          super(x);
        }

        public check(): void {
          assert(this.x > 0n);
        }
      }
    TS

    contract = parse_ts(source, "Bad.runar.ts")
    result = RunarCompiler::Frontend.validate(contract)
    assert result.errors.any? { |e| e.message.downcase.include?("super") },
           "expected error about super() not first, got: #{result.error_strings}"
  end

  # ---------------------------------------------------------------------------
  # 5. Public method must end with assert() (SmartContract)
  # ---------------------------------------------------------------------------

  def test_public_method_missing_final_assert
    contract = minimal_contract(
      methods: [
        MethodNode.new(
          name: "check",
          visibility: "public",
          params: [ParamNode.new(name: "val", type: PrimitiveType.new(name: "bigint"))],
          body: [
            # No assert -- just a bare expression
            ExpressionStmt.new(
              expr: BinaryExpr.new(
                op: "+",
                left: Identifier.new(name: "val"),
                right: BigIntLiteral.new(value: 1)
              )
            )
          ],
          source_location: SourceLocation.new(file: "test.runar.ts", line: 10)
        )
      ]
    )

    result = RunarCompiler::Frontend.validate(contract)
    assert result.errors.any? { |e| e.message.downcase.include?("assert") },
           "expected error about missing assert, got: #{result.error_strings}"
  end

  # ---------------------------------------------------------------------------
  # 6. Stateful contract public method does NOT need trailing assert
  # ---------------------------------------------------------------------------

  def test_stateful_no_final_assert_ok
    contract = minimal_contract(
      parent_class: "StatefulSmartContract",
      properties: [
        PropertyNode.new(
          name: "count", type: PrimitiveType.new(name: "bigint"),
          readonly: false,
          source_location: SourceLocation.new(file: "test.runar.ts", line: 3)
        )
      ],
      methods: [
        MethodNode.new(
          name: "increment",
          visibility: "public",
          params: [],
          body: [
            AssignmentStmt.new(
              target: PropertyAccessExpr.new(property: "count"),
              value: BinaryExpr.new(
                op: "+",
                left: PropertyAccessExpr.new(property: "count"),
                right: BigIntLiteral.new(value: 1)
              )
            )
          ],
          source_location: SourceLocation.new(file: "test.runar.ts", line: 10)
        )
      ]
    )

    result = RunarCompiler::Frontend.validate(contract)
    refute result.errors.any? { |e| e.message.include?("must end with an assert()") },
           "StatefulSmartContract public method should not require trailing assert"
  end

  # ---------------------------------------------------------------------------
  # 7. Direct recursion is detected
  # ---------------------------------------------------------------------------

  def test_direct_recursion
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Recursive extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(): void {
          this.check();
          assert(this.x > 0n);
        }
      }
    TS

    contract = parse_ts(source, "Recursive.runar.ts")
    result = RunarCompiler::Frontend.validate(contract)
    assert result.errors.any? { |e| e.message.downcase.include?("recurs") },
           "expected error about recursion, got: #{result.error_strings}"
  end

  # ---------------------------------------------------------------------------
  # 8. Indirect recursion (A -> B -> A) is detected
  # ---------------------------------------------------------------------------

  def test_indirect_recursion
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Indirect extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        private helper(): bigint {
          return this.check2();
        }

        private check2(): bigint {
          return this.helper();
        }

        public check(): void {
          const r = this.helper();
          assert(r > 0n);
        }
      }
    TS

    contract = parse_ts(source, "Indirect.runar.ts")
    result = RunarCompiler::Frontend.validate(contract)
    assert result.errors.any? { |e| e.message.downcase.include?("recurs") },
           "expected error about indirect recursion, got: #{result.error_strings}"
  end

  # ---------------------------------------------------------------------------
  # 9. Property not assigned in constructor
  # ---------------------------------------------------------------------------

  def test_property_not_assigned_in_constructor
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: bigint;
        readonly y: bigint;

        constructor(x: bigint, y: bigint) {
          super(x, y);
          this.y = y;
        }

        public check(): void {
          assert(this.y > 0n);
        }
      }
    TS

    contract = parse_ts(source, "Bad.runar.ts")
    result = RunarCompiler::Frontend.validate(contract)
    assert result.errors.any? { |e| e.message.include?("x") },
           "expected error about property 'x' not assigned, got: #{result.error_strings}"
  end

  # ---------------------------------------------------------------------------
  # 10. SmartContract with non-readonly property should fail
  # ---------------------------------------------------------------------------

  def test_smart_contract_nonreadonly_property
    contract = minimal_contract(
      properties: [
        PropertyNode.new(
          name: "x", type: PrimitiveType.new(name: "bigint"),
          readonly: false,
          source_location: SourceLocation.new(file: "test.runar.ts", line: 3)
        )
      ]
    )

    result = RunarCompiler::Frontend.validate(contract)
    assert result.errors.any? { |e| e.message.downcase.include?("readonly") },
           "expected error about non-readonly property on SmartContract, got: #{result.error_strings}"
  end

  # ---------------------------------------------------------------------------
  # 11. StatefulSmartContract with mutable property is allowed
  # ---------------------------------------------------------------------------

  def test_stateful_mutable_property_allowed
    contract = minimal_contract(
      parent_class: "StatefulSmartContract",
      properties: [
        PropertyNode.new(
          name: "count", type: PrimitiveType.new(name: "bigint"),
          readonly: false,
          source_location: SourceLocation.new(file: "test.runar.ts", line: 3)
        )
      ],
      methods: [
        MethodNode.new(
          name: "increment",
          visibility: "public",
          params: [],
          body: [
            AssignmentStmt.new(
              target: PropertyAccessExpr.new(property: "count"),
              value: BinaryExpr.new(
                op: "+",
                left: PropertyAccessExpr.new(property: "count"),
                right: BigIntLiteral.new(value: 1)
              )
            )
          ],
          source_location: SourceLocation.new(file: "test.runar.ts", line: 10)
        )
      ]
    )

    result = RunarCompiler::Frontend.validate(contract)
    refute result.errors.any? { |e| e.message.downcase.include?("readonly") },
           "expected no readonly errors for StatefulSmartContract mutable property"
  end

  # ---------------------------------------------------------------------------
  # 12. Void property type is rejected
  # ---------------------------------------------------------------------------

  def test_void_property_type_rejected
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Bad extends SmartContract {
        readonly x: void;

        constructor() {
          super();
        }

        public check(): void {
          assert(true);
        }
      }
    TS

    contract = parse_ts(source, "Bad.runar.ts")
    result = RunarCompiler::Frontend.validate(contract)
    assert result.errors.any? { |e| e.message.downcase.include?("void") },
           "expected error about void property type, got: #{result.error_strings}"
  end

  # ---------------------------------------------------------------------------
  # 13. Empty constructor body fails (no super)
  # ---------------------------------------------------------------------------

  def test_empty_constructor_body
    contract = minimal_contract(constructor_body: [])
    result = RunarCompiler::Frontend.validate(contract)
    assert result.errors.any? { |e| e.message.downcase.include?("super") },
           "expected error about super() with empty constructor, got: #{result.error_strings}"
  end

  # ---------------------------------------------------------------------------
  # 14. Multiple properties all assigned passes
  # ---------------------------------------------------------------------------

  def test_multiple_properties_all_assigned
    contract = minimal_contract(
      properties: [
        PropertyNode.new(name: "a", type: PrimitiveType.new(name: "bigint"), readonly: true,
                         source_location: SourceLocation.new(file: "test.runar.ts", line: 3)),
        PropertyNode.new(name: "b", type: PrimitiveType.new(name: "boolean"), readonly: true,
                         source_location: SourceLocation.new(file: "test.runar.ts", line: 4))
      ],
      constructor_params: [
        ParamNode.new(name: "a", type: PrimitiveType.new(name: "bigint")),
        ParamNode.new(name: "b", type: PrimitiveType.new(name: "boolean"))
      ],
      constructor_body: [
        ExpressionStmt.new(
          expr: CallExpr.new(callee: Identifier.new(name: "super"), args: [
            Identifier.new(name: "a"), Identifier.new(name: "b")
          ])
        ),
        AssignmentStmt.new(target: PropertyAccessExpr.new(property: "a"), value: Identifier.new(name: "a")),
        AssignmentStmt.new(target: PropertyAccessExpr.new(property: "b"), value: Identifier.new(name: "b"))
      ]
    )

    result = RunarCompiler::Frontend.validate(contract)
    assert_empty result.errors.map(&:format_message), "all properties assigned should pass"
  end

  # ---------------------------------------------------------------------------
  # 15. For loop with non-constant bound fails
  # ---------------------------------------------------------------------------

  def test_for_loop_nonconstant_bound
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class LoopBad extends SmartContract {
        readonly n: bigint;

        constructor(n: bigint) {
          super(n);
          this.n = n;
        }

        public check(): void {
          let total: bigint = 0n;
          for (let i: bigint = 0n; i < this.n; i++) { total += i; }
          assert(total > 0n);
        }
      }
    TS

    contract = parse_ts(source, "LoopBad.runar.ts")
    result = RunarCompiler::Frontend.validate(contract)
    assert result.errors.any? { |e| e.message.downcase.include?("constant") || e.message.downcase.include?("bound") },
           "expected error about non-constant loop bound, got: #{result.error_strings}"
  end

  # A bare identifier bound (`const N`) is likewise not unrollable and must be
  # rejected at the validator (never a panic/raise in anf-lower), matching the
  # reference TS compiler: only integer-literal loop bounds compile.
  def test_for_loop_identifier_bound_rejected
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      const N: bigint = 5n;

      class LoopIdent extends SmartContract {
        readonly target: bigint;

        constructor(target: bigint) {
          super(target);
          this.target = target;
        }

        public check(): void {
          let total: bigint = 0n;
          for (let i: bigint = 0n; i < N; i++) { total += i; }
          assert(total > 0n);
        }
      }
    TS

    contract = parse_ts(source, "LoopIdent.runar.ts")
    result = RunarCompiler::Frontend.validate(contract)
    assert result.errors.any? { |e| e.message.downcase.include?("constant") || e.message.downcase.include?("bound") },
           "expected identifier loop bound to be rejected, got: #{result.error_strings}"
  end

  # ---------------------------------------------------------------------------
  # 16. ByteString literal with odd-length hex fails
  # ---------------------------------------------------------------------------

  def test_bytestring_odd_length_hex
    contract = minimal_contract(
      methods: [
        MethodNode.new(
          name: "check",
          visibility: "public",
          params: [],
          body: [
            ExpressionStmt.new(
              expr: CallExpr.new(
                callee: Identifier.new(name: "assert"),
                args: [
                  BinaryExpr.new(
                    op: "===",
                    left: ByteStringLiteral.new(value: "abc"),
                    right: PropertyAccessExpr.new(property: "x")
                  )
                ]
              )
            )
          ],
          source_location: SourceLocation.new(file: "test.runar.ts", line: 10)
        )
      ]
    )

    result = RunarCompiler::Frontend.validate(contract)
    assert result.errors.any? { |e| e.message.downcase.include?("odd length") },
           "expected error about odd-length hex, got: #{result.error_strings}"
  end

  # ---------------------------------------------------------------------------
  # 17. ByteString literal with non-hex characters fails
  # ---------------------------------------------------------------------------

  def test_bytestring_nonhex_characters
    contract = minimal_contract(
      methods: [
        MethodNode.new(
          name: "check",
          visibility: "public",
          params: [],
          body: [
            ExpressionStmt.new(
              expr: CallExpr.new(
                callee: Identifier.new(name: "assert"),
                args: [
                  BinaryExpr.new(
                    op: "===",
                    left: ByteStringLiteral.new(value: "GGZZ"),
                    right: PropertyAccessExpr.new(property: "x")
                  )
                ]
              )
            )
          ],
          source_location: SourceLocation.new(file: "test.runar.ts", line: 10)
        )
      ]
    )

    result = RunarCompiler::Frontend.validate(contract)
    assert result.errors.any? { |e| e.message.downcase.include?("non-hex") },
           "expected error about non-hex characters, got: #{result.error_strings}"
  end

  # ---------------------------------------------------------------------------
  # 18. StatefulSmartContract warns on no mutable properties
  # ---------------------------------------------------------------------------

  def test_stateful_no_mutable_property_warns
    contract = minimal_contract(
      parent_class: "StatefulSmartContract",
      properties: [
        PropertyNode.new(
          name: "x", type: PrimitiveType.new(name: "bigint"),
          readonly: true,
          source_location: SourceLocation.new(file: "test.runar.ts", line: 3)
        )
      ],
      methods: [
        MethodNode.new(
          name: "check",
          visibility: "public",
          params: [],
          body: [],
          source_location: SourceLocation.new(file: "test.runar.ts", line: 10)
        )
      ]
    )

    result = RunarCompiler::Frontend.validate(contract)
    assert result.warnings.any? { |w| w.message.downcase.include?("mutable") },
           "expected warning about no mutable properties, got warnings: #{result.warning_strings}"
  end

  # ---------------------------------------------------------------------------
  # 19. Property initializer skips constructor assignment requirement
  # ---------------------------------------------------------------------------

  def test_property_initializer_no_constructor_assignment_needed
    contract = minimal_contract(
      properties: [
        PropertyNode.new(
          name: "x", type: PrimitiveType.new(name: "bigint"),
          readonly: true,
          initializer: BigIntLiteral.new(value: 42),
          source_location: SourceLocation.new(file: "test.runar.ts", line: 3)
        )
      ],
      constructor_params: [],
      constructor_body: [
        ExpressionStmt.new(
          expr: CallExpr.new(callee: Identifier.new(name: "super"), args: [])
        )
        # No assignment for 'x' -- it has an initializer
      ]
    )

    result = RunarCompiler::Frontend.validate(contract)
    refute result.errors.any? { |e| e.message.include?("x") && e.message.include?("assigned") },
           "property with initializer should not need constructor assignment"
  end

  # ---------------------------------------------------------------------------
  # 20. txPreimage declared in StatefulSmartContract fails
  # ---------------------------------------------------------------------------

  def test_stateful_txpreimage_declared_fails
    contract = minimal_contract(
      parent_class: "StatefulSmartContract",
      properties: [
        PropertyNode.new(
          name: "count", type: PrimitiveType.new(name: "bigint"),
          readonly: false,
          source_location: SourceLocation.new(file: "test.runar.ts", line: 3)
        ),
        PropertyNode.new(
          name: "txPreimage", type: PrimitiveType.new(name: "SigHashPreimage"),
          readonly: true,
          source_location: SourceLocation.new(file: "test.runar.ts", line: 4)
        )
      ],
      constructor_params: [
        ParamNode.new(name: "count", type: PrimitiveType.new(name: "bigint")),
        ParamNode.new(name: "txPreimage", type: PrimitiveType.new(name: "SigHashPreimage"))
      ],
      constructor_body: [
        ExpressionStmt.new(
          expr: CallExpr.new(callee: Identifier.new(name: "super"), args: [
            Identifier.new(name: "count"), Identifier.new(name: "txPreimage")
          ])
        ),
        AssignmentStmt.new(target: PropertyAccessExpr.new(property: "count"), value: Identifier.new(name: "count")),
        AssignmentStmt.new(target: PropertyAccessExpr.new(property: "txPreimage"), value: Identifier.new(name: "txPreimage"))
      ],
      methods: [
        MethodNode.new(
          name: "increment",
          visibility: "public",
          params: [],
          body: [
            AssignmentStmt.new(
              target: PropertyAccessExpr.new(property: "count"),
              value: BinaryExpr.new(
                op: "+",
                left: PropertyAccessExpr.new(property: "count"),
                right: BigIntLiteral.new(value: 1)
              )
            )
          ],
          source_location: SourceLocation.new(file: "test.runar.ts", line: 10)
        )
      ]
    )

    result = RunarCompiler::Frontend.validate(contract)
    assert result.errors.any? { |e| e.message.include?("txPreimage") },
           "expected error about txPreimage being implicit, got: #{result.error_strings}"
  end

  # ---------------------------------------------------------------------------
  # #126 -- contract must have at least one public method
  # ---------------------------------------------------------------------------

  def test_no_public_methods_reports_error
    source = <<~TS
      import { SmartContract, assert, PubKey, Sig, checkSig } from 'runar-lang';

      class Locked extends SmartContract {
        readonly pk: PubKey;

        constructor(pk: PubKey) {
          super(pk);
          this.pk = pk;
        }

        unlock(sig: Sig): void {
          assert(checkSig(sig, this.pk));
        }
      }
    TS

    contract = parse_ts(source, "Locked.runar.ts")
    result = RunarCompiler::Frontend.validate(contract)
    assert result.errors.any? { |e| e.message.include?("no public methods") },
           "expected error about no public methods, got: #{result.error_strings}"
  end

  def test_no_methods_at_all_reports_error
    contract = minimal_contract(methods: [])
    result = RunarCompiler::Frontend.validate(contract)
    assert result.errors.any? { |e| e.message.include?("no public methods") },
           "expected error about no public methods, got: #{result.error_strings}"
  end

  def test_at_least_one_public_method_passes
    contract = minimal_contract
    result = RunarCompiler::Frontend.validate(contract)
    refute result.errors.any? { |e| e.message.include?("no public methods") },
           "did not expect a no-public-methods error, got: #{result.error_strings}"
  end

  # ---------------------------------------------------------------------------
  # #121 -- accept non-zero-start and countdown for-loops
  # ---------------------------------------------------------------------------

  def test_for_loop_non_zero_start_accepted
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class C extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public m(): void {
          let sum: bigint = 0n;
          for (let i: bigint = 1n; i <= 3n; i++) {
            sum = sum + i;
          }
          assert(sum > 0n);
        }
      }
    TS

    contract = parse_ts(source, "C.runar.ts")
    result = RunarCompiler::Frontend.validate(contract)
    refute result.errors.any? { |e| e.message.include?("must start at 0") },
           "did not expect a non-zero start error (#121), got: #{result.error_strings}"
  end

  def test_for_loop_countdown_accepted
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class C extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public m(): void {
          let sum: bigint = 0n;
          for (let i: bigint = 3n; i > 0n; i--) {
            sum = sum + i;
          }
          assert(sum > 0n);
        }
      }
    TS

    contract = parse_ts(source, "C.runar.ts")
    result = RunarCompiler::Frontend.validate(contract)
    refute result.errors.any? { |e| e.message.include?("countdown") },
           "did not expect a countdown error (#121), got: #{result.error_strings}"
  end

  def test_for_loop_zero_start_counting_up_passes
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class C extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public m(): void {
          let sum: bigint = 0n;
          for (let i: bigint = 0n; i <= 3n; i++) {
            sum = sum + i;
          }
          assert(sum > 0n);
        }
      }
    TS

    contract = parse_ts(source, "C.runar.ts")
    result = RunarCompiler::Frontend.validate(contract)
    refute result.errors.any? { |e| e.message.include?("must start at 0") },
           "did not expect a non-zero start error, got: #{result.error_strings}"
    refute result.errors.any? { |e| e.message.include?("countdown") },
           "did not expect a countdown error, got: #{result.error_strings}"
  end

  # ---------------------------------------------------------------------------
  # F-063: array-literal elements are walked by every validator walker
  # ---------------------------------------------------------------------------
  #
  # ArrayLiteralExpr was missing from validate_expression, walk_expr,
  # collect_method_calls_in_expr and sub_expressions, so a construct written
  # inside `[...]` (the only place checkMultiSig's arguments can be written)
  # escaped the rule those walkers enforce. Pre-fix the recursion shape died
  # with SystemStackError in stack lowering instead of being refused.
  #
  # Proves: validate refuses each shape with the diagnostic the un-nested form
  # gets. Does not prove: CLI exit status or cross-tier parity
  # (conformance/negatives N99+).

  F063_HEADER = <<~TS
    class C extends SmartContract {
      readonly pk: PubKey;
      constructor(pk: PubKey) { super(pk); this.pk = pk; }
  TS

  def f063_errors(body, header = F063_HEADER)
    RunarCompiler::Frontend.validate(parse_ts(header + body + "\n}\n")).errors.map(&:message)
  end

  def test_f063_recursion_inside_array_literal_detected
    errs = f063_errors(<<~TS)
      private h(s: Sig): PubKey { assert(checkMultiSig([s], [this.h(s)])); return this.pk; }
      public unlock(s: Sig) { assert(checkMultiSig([s], [this.h(s)])); }
    TS
    assert errs.any? { |m| m.include?("recursion detected: method 'h'") }, errs.inspect
  end

  def test_f063_odd_length_hex_inside_array_literal_rejected
    errs = f063_errors("public unlock(s: Sig) { assert(checkMultiSig([s], [this.pk, toByteString('abc')])); }")
    assert errs.any? { |m| m.include?("ByteString literal 'abc' has odd length (3)") }, errs.inspect
  end

  def test_f063_non_hex_inside_array_literal_rejected
    errs = f063_errors("public unlock(s: Sig) { assert(checkMultiSig([s], [this.pk, toByteString('zz')])); }")
    assert errs.any? { |m| m.include?("ByteString literal 'zz' contains non-hex characters") }, errs.inspect
  end

  def test_f063_readonly_increment_inside_array_literal_rejected
    header = <<~TS
      class C extends SmartContract {
        readonly n: bigint;
        readonly pk: PubKey;
        constructor(n: bigint, pk: PubKey) { super(n, pk); this.n = n; this.pk = pk; }
    TS
    errs = f063_errors("public unlock(s: Sig) { const a = [this.n++]; assert(checkSig(s, this.pk)); }", header)
    assert errs.any? { |m| m.include?("cannot assign to readonly property 'n'") }, errs.inspect
  end

  def test_f063_output_intrinsic_inside_array_literal_in_loop_rejected
    header = <<~TS
      class C extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) { super(count); this.count = count; }
    TS
    errs = f063_errors(<<~TS, header)
      public step() {
        for (let i = 0n; i < 2n; i++) { const a = [this.addOutput(1000n, this.count)]; }
        assert(true);
      }
    TS
    assert errs.any? { |m| m.include?("Output intrinsic 'addOutput'") }, errs.inspect
  end
end

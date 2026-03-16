//! Pass 1: Parse
//!
//! Uses SWC to parse a TypeScript source file and extract the SmartContract
//! subclass into a Rúnar AST.

use swc_common::sync::Lrc;
use swc_common::{FileName, SourceMap};
use swc_ecma_ast as swc;
use swc_ecma_ast::{
    Accessibility, AssignExpr, AssignOp, AssignTarget, CallExpr, Callee, Class, ClassDecl,
    ClassMember, Decl, EsVersion, Expr, ForStmt, IfStmt, Lit, MemberExpr as SwcMemberExpr,
    MemberProp, ModuleDecl, ModuleItem, Param, ParamOrTsParamProp, Pat, PropName, ReturnStmt,
    SimpleAssignTarget, Stmt, SuperProp, TsEntityName, TsKeywordTypeKind, TsLit,
    TsParamPropParam, TsType, UnaryExpr as SwcUnaryExpr, UpdateExpr, UpdateOp, VarDecl,
    VarDeclKind, VarDeclOrExpr,
};
use swc_ecma_parser::{lexer::Lexer, Parser, StringInput, Syntax, TsSyntax};

use super::ast::{
    BinaryOp, ContractNode, Expression, MethodNode, ParamNode, PrimitiveTypeName,
    PropertyNode, SourceLocation, Statement, TypeNode, UnaryOp, Visibility,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Result of parsing a source file.
pub struct ParseResult {
    pub contract: Option<ContractNode>,
    pub errors: Vec<String>,
}

/// Parse a TypeScript source string and extract the Rúnar contract AST.
pub fn parse(source: &str, file_name: Option<&str>) -> ParseResult {
    let mut errors: Vec<String> = Vec::new();
    let file = file_name.unwrap_or("contract.ts");

    // Set up SWC parser
    let cm: Lrc<SourceMap> = Lrc::new(SourceMap::default());
    let fm = cm.new_source_file(Lrc::new(FileName::Custom(file.to_string())), source.to_string());
    let lexer = Lexer::new(
        Syntax::Typescript(TsSyntax {
            tsx: false,
            decorators: false,
            ..Default::default()
        }),
        EsVersion::Es2022,
        StringInput::from(&*fm),
        None,
    );
    let mut parser = Parser::new_from(lexer);

    let module = match parser.parse_module() {
        Ok(m) => m,
        Err(e) => {
            errors.push(format!("Parse error: {:?}", e));
            return ParseResult {
                contract: None,
                errors,
            };
        }
    };

    // Collect any parser errors
    for e in parser.take_errors() {
        errors.push(format!("Parse error: {:?}", e));
    }

    // Find the class that extends SmartContract or StatefulSmartContract
    let mut contract_class: Option<&ClassDecl> = None;
    let mut detected_parent_class: &str = "SmartContract";

    for item in &module.body {
        if let ModuleItem::Stmt(Stmt::Decl(Decl::Class(class_decl))) = item {
            if let Some(super_class) = &class_decl.class.super_class {
                if let Some(base_name) = get_base_class_name(super_class) {
                    if contract_class.is_some() {
                        errors.push(
                            "Only one SmartContract subclass is allowed per file".to_string(),
                        );
                    }
                    contract_class = Some(class_decl);
                    detected_parent_class = base_name;
                }
            }
        }
    }

    // Also check export declarations
    for item in &module.body {
        if let ModuleItem::ModuleDecl(ModuleDecl::ExportDecl(export_decl)) = item {
            if let Decl::Class(class_decl) = &export_decl.decl {
                if let Some(super_class) = &class_decl.class.super_class {
                    if let Some(base_name) = get_base_class_name(super_class) {
                        if contract_class.is_some() {
                            errors.push(
                                "Only one SmartContract subclass is allowed per file".to_string(),
                            );
                        }
                        contract_class = Some(class_decl);
                        detected_parent_class = base_name;
                    }
                }
            }
        }
    }

    let class_decl = match contract_class {
        Some(c) => c,
        None => {
            errors.push("No class extending SmartContract or StatefulSmartContract found".to_string());
            return ParseResult {
                contract: None,
                errors,
            };
        }
    };

    let contract_name = class_decl.ident.sym.to_string();
    let class = &class_decl.class;

    // Extract properties
    let properties = parse_properties(class, file, &mut errors);

    // Extract constructor
    let constructor_node = parse_constructor(class, file, &mut errors);

    // Extract methods
    let methods = parse_methods(class, file, &mut errors);

    let contract = ContractNode {
        name: contract_name,
        parent_class: detected_parent_class.to_string(),
        properties,
        constructor: constructor_node,
        methods,
        source_file: file.to_string(),
    };

    ParseResult {
        contract: Some(contract),
        errors,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn get_base_class_name(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Ident(ident) => {
            let name = ident.sym.as_ref();
            if name == "SmartContract" || name == "StatefulSmartContract" {
                Some(name)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn loc(file: &str, line: usize, column: usize) -> SourceLocation {
    SourceLocation {
        file: file.to_string(),
        line,
        column,
    }
}

fn default_loc(file: &str) -> SourceLocation {
    loc(file, 1, 0)
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

fn parse_properties(class: &Class, file: &str, errors: &mut Vec<String>) -> Vec<PropertyNode> {
    let mut result = Vec::new();

    for member in &class.body {
        if let ClassMember::ClassProp(prop) = member {
            let name = match &prop.key {
                PropName::Ident(ident) => ident.sym.to_string(),
                _ => {
                    errors.push("Property must have an identifier name".to_string());
                    continue;
                }
            };

            let readonly = prop.readonly;

            let prop_type = if let Some(ref ann) = prop.type_ann {
                parse_type_node(&ann.type_ann, file, errors)
            } else {
                errors.push(format!(
                    "Property '{}' must have an explicit type annotation",
                    name
                ));
                TypeNode::Custom("unknown".to_string())
            };

            // Parse initializer if present (SWC ClassProp.value)
            let initializer = prop.value.as_ref().map(|v| parse_expression(v, file, errors));

            result.push(PropertyNode {
                name,
                prop_type,
                readonly,
                initializer,
                source_location: default_loc(file),
            });
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

fn parse_constructor(class: &Class, file: &str, errors: &mut Vec<String>) -> MethodNode {
    for member in &class.body {
        if let ClassMember::Constructor(ctor) = member {
            let params = parse_constructor_params(&ctor.params, file, errors);
            let body = if let Some(ref block) = ctor.body {
                parse_block_stmts(&block.stmts, file, errors)
            } else {
                Vec::new()
            };

            return MethodNode {
                name: "constructor".to_string(),
                params,
                body,
                visibility: Visibility::Public,
                source_location: default_loc(file),
            };
        }
    }

    errors.push("Contract must have a constructor".to_string());
    MethodNode {
        name: "constructor".to_string(),
        params: Vec::new(),
        body: Vec::new(),
        visibility: Visibility::Public,
        source_location: default_loc(file),
    }
}

fn parse_constructor_params(
    params: &[ParamOrTsParamProp],
    file: &str,
    errors: &mut Vec<String>,
) -> Vec<ParamNode> {
    let mut result = Vec::new();

    for param in params {
        match param {
            ParamOrTsParamProp::Param(p) => {
                if let Some(ast_param) = parse_param_pat(&p.pat, file, errors) {
                    result.push(ast_param);
                }
            }
            ParamOrTsParamProp::TsParamProp(ts_param) => {
                match &ts_param.param {
                    TsParamPropParam::Ident(ident) => {
                        let name = ident.id.sym.to_string();
                        let param_type = if let Some(ref ann) = ident.type_ann {
                            parse_type_node(&ann.type_ann, file, errors)
                        } else {
                            errors.push(format!(
                                "Parameter '{}' must have an explicit type annotation",
                                name
                            ));
                            TypeNode::Custom("unknown".to_string())
                        };
                        result.push(ParamNode { name, param_type });
                    }
                    TsParamPropParam::Assign(_) => {
                        errors.push("Default parameter values are not supported".to_string());
                    }
                }
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

fn parse_methods(class: &Class, file: &str, errors: &mut Vec<String>) -> Vec<MethodNode> {
    let mut result = Vec::new();

    for member in &class.body {
        if let ClassMember::Method(method) = member {
            let name = match &method.key {
                PropName::Ident(ident) => ident.sym.to_string(),
                _ => {
                    errors.push("Method must have an identifier name".to_string());
                    continue;
                }
            };

            let params = parse_method_params(&method.function.params, file, errors);

            let visibility = if method.accessibility == Some(Accessibility::Public) {
                Visibility::Public
            } else {
                Visibility::Private
            };

            let body = if let Some(ref block) = method.function.body {
                parse_block_stmts(&block.stmts, file, errors)
            } else {
                Vec::new()
            };

            result.push(MethodNode {
                name,
                params,
                body,
                visibility,
                source_location: default_loc(file),
            });
        }
    }

    result
}

fn parse_method_params(
    params: &[Param],
    file: &str,
    errors: &mut Vec<String>,
) -> Vec<ParamNode> {
    let mut result = Vec::new();
    for param in params {
        if let Some(ast_param) = parse_param_pat(&param.pat, file, errors) {
            result.push(ast_param);
        }
    }
    result
}

fn parse_param_pat(
    pat: &Pat,
    file: &str,
    errors: &mut Vec<String>,
) -> Option<ParamNode> {
    match pat {
        Pat::Ident(ident) => {
            let name = ident.id.sym.to_string();
            let param_type = if let Some(ref ann) = ident.type_ann {
                parse_type_node(&ann.type_ann, file, errors)
            } else {
                errors.push(format!(
                    "Parameter '{}' must have an explicit type annotation",
                    name
                ));
                TypeNode::Custom("unknown".to_string())
            };
            Some(ParamNode { name, param_type })
        }
        _ => {
            errors.push("Unsupported parameter pattern".to_string());
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Type nodes
// ---------------------------------------------------------------------------

fn parse_type_node(ts_type: &TsType, file: &str, errors: &mut Vec<String>) -> TypeNode {
    match ts_type {
        // Keyword types
        TsType::TsKeywordType(kw) => match kw.kind {
            TsKeywordTypeKind::TsBigIntKeyword => TypeNode::Primitive(PrimitiveTypeName::Bigint),
            TsKeywordTypeKind::TsBooleanKeyword => {
                TypeNode::Primitive(PrimitiveTypeName::Boolean)
            }
            TsKeywordTypeKind::TsVoidKeyword => TypeNode::Primitive(PrimitiveTypeName::Void),
            TsKeywordTypeKind::TsNumberKeyword => {
                errors.push("'number' type is not allowed in Rúnar contracts; use 'bigint' instead".to_string());
                TypeNode::Primitive(PrimitiveTypeName::Bigint)
            }
            TsKeywordTypeKind::TsStringKeyword => {
                errors.push("'string' type is not allowed in Rúnar contracts; use 'ByteString' instead".to_string());
                TypeNode::Primitive(PrimitiveTypeName::ByteString)
            }
            _ => {
                errors.push(format!("Unsupported keyword type: {:?}", kw.kind));
                TypeNode::Custom("unknown".to_string())
            }
        },

        // Type references: Sha256, PubKey, FixedArray<T, N>, etc.
        TsType::TsTypeRef(type_ref) => {
            let type_name = ts_entity_name_to_string(&type_ref.type_name);

            // Check for FixedArray<T, N>
            if type_name == "FixedArray" {
                if let Some(ref type_params) = type_ref.type_params {
                    let params = &type_params.params;
                    if params.len() != 2 {
                        errors.push(
                            "FixedArray requires exactly 2 type arguments: FixedArray<T, N>"
                                .to_string(),
                        );
                        return TypeNode::Custom(type_name);
                    }

                    let element = parse_type_node(&params[0], file, errors);

                    // The second parameter should be a literal type for the length
                    let length = extract_type_literal_number(&params[1]);
                    if let Some(len) = length {
                        return TypeNode::FixedArray {
                            element: Box::new(element),
                            length: len,
                        };
                    } else {
                        errors.push(
                            "FixedArray size must be a non-negative integer literal".to_string(),
                        );
                        return TypeNode::Custom(type_name);
                    }
                } else {
                    errors.push("FixedArray requires type arguments".to_string());
                    return TypeNode::Custom(type_name);
                }
            }

            // Check for primitive types referenced by name
            if let Some(prim) = PrimitiveTypeName::from_str(&type_name) {
                return TypeNode::Primitive(prim);
            }

            // Unknown type reference
            TypeNode::Custom(type_name)
        }

        _ => {
            errors.push("Unsupported type annotation".to_string());
            TypeNode::Custom("unknown".to_string())
        }
    }
}

fn ts_entity_name_to_string(entity: &TsEntityName) -> String {
    match entity {
        TsEntityName::Ident(ident) => ident.sym.to_string(),
        TsEntityName::TsQualifiedName(qual) => {
            format!(
                "{}.{}",
                ts_entity_name_to_string(&qual.left),
                qual.right.sym
            )
        }
    }
}

/// Try to extract a literal number from a type node (e.g. `10` in `FixedArray<bigint, 10>`).
fn extract_type_literal_number(ts_type: &TsType) -> Option<usize> {
    match ts_type {
        TsType::TsLitType(lit) => match &lit.lit {
            TsLit::Number(n) => Some(n.value as usize),
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------

fn parse_block_stmts(stmts: &[Stmt], file: &str, errors: &mut Vec<String>) -> Vec<Statement> {
    let mut result = Vec::new();
    for stmt in stmts {
        if let Some(parsed) = parse_statement(stmt, file, errors) {
            result.push(parsed);
        }
    }
    result
}

fn parse_statement(stmt: &Stmt, file: &str, errors: &mut Vec<String>) -> Option<Statement> {
    match stmt {
        Stmt::Decl(Decl::Var(var_decl)) => parse_variable_statement(var_decl, file, errors),

        Stmt::Expr(expr_stmt) => parse_expression_statement(&expr_stmt.expr, file, errors),

        Stmt::If(if_stmt) => Some(parse_if_statement(if_stmt, file, errors)),

        Stmt::For(for_stmt) => Some(parse_for_statement(for_stmt, file, errors)),

        Stmt::Return(ret_stmt) => Some(parse_return_statement(ret_stmt, file, errors)),

        Stmt::Block(block) => {
            // Flatten block statements
            let stmts = parse_block_stmts(&block.stmts, file, errors);
            // Return as individual statements by wrapping in a block-like structure
            // For simplicity, we report an error -- blocks should be part of if/for
            if stmts.is_empty() {
                None
            } else {
                errors.push("Standalone block statements are not supported; use if/for".to_string());
                None
            }
        }

        _ => {
            errors.push(format!("Unsupported statement kind: {:?}", stmt));
            None
        }
    }
}

fn parse_variable_statement(
    var_decl: &VarDecl,
    file: &str,
    errors: &mut Vec<String>,
) -> Option<Statement> {
    if var_decl.decls.is_empty() {
        return None;
    }

    let decl = &var_decl.decls[0];
    let name = match &decl.name {
        Pat::Ident(ident) => ident.id.sym.to_string(),
        _ => {
            errors.push("Destructuring patterns are not supported in variable declarations".to_string());
            return None;
        }
    };

    let is_const = var_decl.kind == VarDeclKind::Const;

    let init = if let Some(ref init_expr) = decl.init {
        parse_expression(init_expr, file, errors)
    } else {
        errors.push(format!("Variable '{}' must have an initializer", name));
        Expression::BigIntLiteral { value: 0 }
    };

    let var_type = if let Pat::Ident(ident) = &decl.name {
        if let Some(ref ann) = ident.type_ann {
            Some(parse_type_node(&ann.type_ann, file, errors))
        } else {
            None
        }
    } else {
        None
    };

    Some(Statement::VariableDecl {
        name,
        var_type,
        mutable: !is_const,
        init,
        source_location: default_loc(file),
    })
}

fn parse_expression_statement(
    expr: &Expr,
    file: &str,
    errors: &mut Vec<String>,
) -> Option<Statement> {
    // Check if this is an assignment expression (a = b, this.x = b)
    if let Expr::Assign(assign) = expr {
        return Some(parse_assignment_expr(assign, file, errors));
    }

    let expression = parse_expression(expr, file, errors);
    Some(Statement::ExpressionStatement {
        expression,
        source_location: default_loc(file),
    })
}

fn parse_assignment_expr(
    assign: &AssignExpr,
    file: &str,
    errors: &mut Vec<String>,
) -> Statement {
    let target = parse_assign_target(&assign.left, file, errors);

    match assign.op {
        AssignOp::Assign => {
            let value = parse_expression(&assign.right, file, errors);
            Statement::Assignment {
                target,
                value,
                source_location: default_loc(file),
            }
        }
        // Compound assignments: +=, -=, *=, /=, %=
        op => {
            let bin_op = match op {
                AssignOp::AddAssign => Some(BinaryOp::Add),
                AssignOp::SubAssign => Some(BinaryOp::Sub),
                AssignOp::MulAssign => Some(BinaryOp::Mul),
                AssignOp::DivAssign => Some(BinaryOp::Div),
                AssignOp::ModAssign => Some(BinaryOp::Mod),
                _ => {
                    errors.push(format!("Unsupported compound assignment operator: {:?}", op));
                    None
                }
            };

            if let Some(bin_op) = bin_op {
                let right = parse_expression(&assign.right, file, errors);
                let target_for_rhs = parse_assign_target(&assign.left, file, errors);
                let value = Expression::BinaryExpr {
                    op: bin_op,
                    left: Box::new(target_for_rhs),
                    right: Box::new(right),
                };
                Statement::Assignment {
                    target,
                    value,
                    source_location: default_loc(file),
                }
            } else {
                let value = parse_expression(&assign.right, file, errors);
                Statement::Assignment {
                    target,
                    value,
                    source_location: default_loc(file),
                }
            }
        }
    }
}

fn parse_assign_target(
    target: &AssignTarget,
    file: &str,
    errors: &mut Vec<String>,
) -> Expression {
    match target {
        AssignTarget::Simple(simple) => match simple {
            SimpleAssignTarget::Ident(ident) => Expression::Identifier {
                name: ident.id.sym.to_string(),
            },
            SimpleAssignTarget::Member(member) => {
                parse_member_expression(member, file, errors)
            }
            _ => {
                errors.push("Unsupported assignment target".to_string());
                Expression::Identifier {
                    name: "_error".to_string(),
                }
            }
        },
        AssignTarget::Pat(_) => {
            errors.push("Destructuring assignment is not supported".to_string());
            Expression::Identifier {
                name: "_error".to_string(),
            }
        }
    }
}

fn parse_if_statement(if_stmt: &IfStmt, file: &str, errors: &mut Vec<String>) -> Statement {
    let condition = parse_expression(&if_stmt.test, file, errors);
    let then_branch = parse_stmt_or_block(&if_stmt.cons, file, errors);

    let else_branch = if_stmt
        .alt
        .as_ref()
        .map(|alt| parse_stmt_or_block(alt, file, errors));

    Statement::IfStatement {
        condition,
        then_branch,
        else_branch,
        source_location: default_loc(file),
    }
}

fn parse_stmt_or_block(
    stmt: &Stmt,
    file: &str,
    errors: &mut Vec<String>,
) -> Vec<Statement> {
    match stmt {
        Stmt::Block(block) => parse_block_stmts(&block.stmts, file, errors),
        _ => {
            if let Some(s) = parse_statement(stmt, file, errors) {
                vec![s]
            } else {
                Vec::new()
            }
        }
    }
}

fn parse_for_statement(for_stmt: &ForStmt, file: &str, errors: &mut Vec<String>) -> Statement {
    // Parse initializer
    let init = if let Some(ref init_expr) = for_stmt.init {
        match init_expr {
            VarDeclOrExpr::VarDecl(var_decl) => {
                if let Some(stmt) = parse_variable_statement(var_decl, file, errors) {
                    stmt
                } else {
                    make_default_for_init(file)
                }
            }
            VarDeclOrExpr::Expr(_) => {
                errors.push(
                    "For loop must have a variable declaration initializer".to_string(),
                );
                make_default_for_init(file)
            }
        }
    } else {
        errors.push("For loop must have an initializer".to_string());
        make_default_for_init(file)
    };

    // Parse condition
    let condition = if let Some(ref cond) = for_stmt.test {
        parse_expression(cond, file, errors)
    } else {
        errors.push("For loop must have a condition".to_string());
        Expression::BoolLiteral { value: false }
    };

    // Parse update
    let update = if let Some(ref upd) = for_stmt.update {
        parse_for_update(upd, file, errors)
    } else {
        errors.push("For loop must have an update expression".to_string());
        Statement::ExpressionStatement {
            expression: Expression::BigIntLiteral { value: 0 },
            source_location: default_loc(file),
        }
    };

    // Parse body
    let body = parse_stmt_or_block(&for_stmt.body, file, errors);

    Statement::ForStatement {
        init: Box::new(init),
        condition,
        update: Box::new(update),
        body,
        source_location: default_loc(file),
    }
}

fn parse_for_update(
    expr: &Expr,
    file: &str,
    errors: &mut Vec<String>,
) -> Statement {
    match expr {
        Expr::Update(update) => {
            let operand = parse_expression(&update.arg, file, errors);
            let is_increment = update.op == UpdateOp::PlusPlus;
            let expression = if is_increment {
                Expression::IncrementExpr {
                    operand: Box::new(operand),
                    prefix: update.prefix,
                }
            } else {
                Expression::DecrementExpr {
                    operand: Box::new(operand),
                    prefix: update.prefix,
                }
            };
            Statement::ExpressionStatement {
                expression,
                source_location: default_loc(file),
            }
        }
        _ => {
            let expression = parse_expression(expr, file, errors);
            Statement::ExpressionStatement {
                expression,
                source_location: default_loc(file),
            }
        }
    }
}

fn parse_return_statement(
    ret_stmt: &ReturnStmt,
    file: &str,
    errors: &mut Vec<String>,
) -> Statement {
    let value = ret_stmt
        .arg
        .as_ref()
        .map(|e| parse_expression(e, file, errors));

    Statement::ReturnStatement {
        value,
        source_location: default_loc(file),
    }
}

fn make_default_for_init(file: &str) -> Statement {
    Statement::VariableDecl {
        name: "_i".to_string(),
        var_type: None,
        mutable: true,
        init: Expression::BigIntLiteral { value: 0 },
        source_location: default_loc(file),
    }
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

fn parse_expression(expr: &Expr, file: &str, errors: &mut Vec<String>) -> Expression {
    match expr {
        Expr::Bin(bin) => parse_binary_expression(bin, file, errors),

        Expr::Unary(unary) => parse_unary_expression(unary, file, errors),

        Expr::Update(update) => parse_update_expression(update, file, errors),

        Expr::Call(call) => parse_call_expression(call, file, errors),

        Expr::Member(member) => parse_member_expression(member, file, errors),

        Expr::SuperProp(super_prop) => {
            // super.x -- unlikely in Rúnar but handle gracefully
            match &super_prop.prop {
                SuperProp::Ident(ident) => Expression::MemberExpr {
                    object: Box::new(Expression::Identifier {
                        name: "super".to_string(),
                    }),
                    property: ident.sym.to_string(),
                },
                SuperProp::Computed(comp) => {
                    let _ = parse_expression(&comp.expr, file, errors);
                    errors.push("Computed super property access not supported".to_string());
                    Expression::Identifier {
                        name: "super".to_string(),
                    }
                }
            }
        }

        Expr::Ident(ident) => Expression::Identifier {
            name: ident.sym.to_string(),
        },

        Expr::Lit(Lit::BigInt(bigint)) => {
            // Parse the BigInt value -- SWC gives the numeric part
            let val = bigint_to_i64(bigint);
            Expression::BigIntLiteral { value: val }
        }

        Expr::Lit(Lit::Num(num)) => {
            // Plain numeric literal -- treat as bigint for Rúnar
            Expression::BigIntLiteral {
                value: num.value as i64,
            }
        }

        Expr::Lit(Lit::Bool(b)) => Expression::BoolLiteral { value: b.value },

        Expr::Lit(Lit::Str(s)) => {
            // String literals are hex-encoded ByteString values
            Expression::ByteStringLiteral {
                value: s.value.to_string(),
            }
        }

        Expr::Tpl(tpl) => {
            // Template literal with no substitutions
            if tpl.exprs.is_empty() && tpl.quasis.len() == 1 {
                Expression::ByteStringLiteral {
                    value: tpl.quasis[0].raw.to_string(),
                }
            } else {
                errors.push("Template literals with expressions are not supported".to_string());
                Expression::ByteStringLiteral {
                    value: String::new(),
                }
            }
        }

        Expr::Cond(cond) => {
            let condition = parse_expression(&cond.test, file, errors);
            let consequent = parse_expression(&cond.cons, file, errors);
            let alternate = parse_expression(&cond.alt, file, errors);
            Expression::TernaryExpr {
                condition: Box::new(condition),
                consequent: Box::new(consequent),
                alternate: Box::new(alternate),
            }
        }

        Expr::Paren(paren) => parse_expression(&paren.expr, file, errors),

        Expr::This(_) => Expression::Identifier {
            name: "this".to_string(),
        },

        Expr::TsAs(as_expr) => {
            // Type assertions: ignore the type, parse the expression
            parse_expression(&as_expr.expr, file, errors)
        }

        Expr::TsNonNull(nn) => {
            // Non-null assertion: just parse the inner expression
            parse_expression(&nn.expr, file, errors)
        }

        Expr::Assign(assign) => {
            // Assignment expression in expression context -- should be handled
            // at statement level, but in case it appears in an expression context
            errors.push("Assignment expressions in expression context are not recommended".to_string());
            let value = parse_expression(&assign.right, file, errors);
            value
        }

        _ => {
            errors.push(format!("Unsupported expression: {:?}", expr));
            Expression::BigIntLiteral { value: 0 }
        }
    }
}

fn parse_binary_expression(
    bin: &swc::BinExpr,
    file: &str,
    errors: &mut Vec<String>,
) -> Expression {
    let left = parse_expression(&bin.left, file, errors);
    let right = parse_expression(&bin.right, file, errors);

    let op = match bin.op {
        swc::BinaryOp::Add => BinaryOp::Add,
        swc::BinaryOp::Sub => BinaryOp::Sub,
        swc::BinaryOp::Mul => BinaryOp::Mul,
        swc::BinaryOp::Div => BinaryOp::Div,
        swc::BinaryOp::Mod => BinaryOp::Mod,
        swc::BinaryOp::EqEqEq => BinaryOp::StrictEq,
        swc::BinaryOp::NotEqEq => BinaryOp::StrictNe,
        swc::BinaryOp::Lt => BinaryOp::Lt,
        swc::BinaryOp::LtEq => BinaryOp::Le,
        swc::BinaryOp::Gt => BinaryOp::Gt,
        swc::BinaryOp::GtEq => BinaryOp::Ge,
        swc::BinaryOp::LogicalAnd => BinaryOp::And,
        swc::BinaryOp::LogicalOr => BinaryOp::Or,
        swc::BinaryOp::BitAnd => BinaryOp::BitAnd,
        swc::BinaryOp::BitOr => BinaryOp::BitOr,
        swc::BinaryOp::BitXor => BinaryOp::BitXor,
        swc::BinaryOp::EqEq => {
            // Accept == and map to === (same as TS and Go parsers)
            BinaryOp::StrictEq
        }
        swc::BinaryOp::NotEq => {
            // Accept != and map to !== (same as TS and Go parsers)
            BinaryOp::StrictNe
        }
        _ => {
            errors.push(format!("Unsupported binary operator: {:?}", bin.op));
            BinaryOp::Add
        }
    };

    Expression::BinaryExpr {
        op,
        left: Box::new(left),
        right: Box::new(right),
    }
}

fn parse_unary_expression(
    unary: &SwcUnaryExpr,
    file: &str,
    errors: &mut Vec<String>,
) -> Expression {
    let operand = parse_expression(&unary.arg, file, errors);

    let op = match unary.op {
        swc::UnaryOp::Bang => UnaryOp::Not,
        swc::UnaryOp::Minus => UnaryOp::Neg,
        swc::UnaryOp::Tilde => UnaryOp::BitNot,
        _ => {
            errors.push(format!("Unsupported unary operator: {:?}", unary.op));
            UnaryOp::Neg
        }
    };

    Expression::UnaryExpr {
        op,
        operand: Box::new(operand),
    }
}

fn parse_update_expression(
    update: &UpdateExpr,
    file: &str,
    errors: &mut Vec<String>,
) -> Expression {
    let operand = parse_expression(&update.arg, file, errors);

    if update.op == UpdateOp::PlusPlus {
        Expression::IncrementExpr {
            operand: Box::new(operand),
            prefix: update.prefix,
        }
    } else {
        Expression::DecrementExpr {
            operand: Box::new(operand),
            prefix: update.prefix,
        }
    }
}

fn parse_call_expression(
    call: &CallExpr,
    file: &str,
    errors: &mut Vec<String>,
) -> Expression {
    let callee = match &call.callee {
        Callee::Expr(e) => parse_expression(e, file, errors),
        Callee::Super(_) => Expression::Identifier {
            name: "super".to_string(),
        },
        Callee::Import(_) => {
            errors.push("Dynamic import is not supported".to_string());
            Expression::Identifier {
                name: "_error".to_string(),
            }
        }
    };

    let args: Vec<Expression> = call
        .args
        .iter()
        .map(|arg| parse_expression(&arg.expr, file, errors))
        .collect();

    Expression::CallExpr {
        callee: Box::new(callee),
        args,
    }
}

fn parse_member_expression(
    member: &SwcMemberExpr,
    file: &str,
    errors: &mut Vec<String>,
) -> Expression {
    let prop_name = match &member.prop {
        MemberProp::Ident(ident) => ident.sym.to_string(),
        MemberProp::Computed(comp) => {
            // Computed member access: obj[expr]
            let object = parse_expression(&member.obj, file, errors);
            let index = parse_expression(&comp.expr, file, errors);
            return Expression::IndexAccess {
                object: Box::new(object),
                index: Box::new(index),
            };
        }
        MemberProp::PrivateName(_priv_name) => {
            errors.push("Private field access (#field) is not supported".to_string());
            "_private".to_string()
        }
    };

    // this.x -> PropertyAccess
    if let Expr::This(_) = &*member.obj {
        return Expression::PropertyAccess {
            property: prop_name,
        };
    }

    // General member access: obj.method
    let object = parse_expression(&member.obj, file, errors);
    Expression::MemberExpr {
        object: Box::new(object),
        property: prop_name,
    }
}

// ---------------------------------------------------------------------------
// BigInt helpers
// ---------------------------------------------------------------------------

/// Convert SWC BigInt to i64. SWC represents BigInt as a boxed `num_bigint::BigInt`.
fn bigint_to_i64(bigint_lit: &swc::BigInt) -> i64 {
    // SWC BigInt has a `value` field of type `Box<num_bigint::BigInt>`.
    // We convert via string representation to i64.
    use std::str::FromStr;
    let s = bigint_lit.value.to_string();
    i64::from_str(&s).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Multi-format dispatch
// ---------------------------------------------------------------------------

/// Parse a source string, automatically selecting the parser based on file extension.
///
/// Supported extensions:
/// - `.runar.sol` -> Solidity-like parser
/// - `.runar.move` -> Move-style parser
/// - `.runar.rs` -> Rust DSL parser
/// - `.runar.py` -> Python parser
/// - anything else (including `.runar.ts`) -> TypeScript parser (default)
pub fn parse_source(source: &str, file_name: Option<&str>) -> ParseResult {
    let name = file_name.unwrap_or("contract.ts");
    if name.ends_with(".runar.sol") {
        return super::parser_sol::parse_solidity(source, file_name);
    }
    if name.ends_with(".runar.move") {
        return super::parser_move::parse_move(source, file_name);
    }
    if name.ends_with(".runar.rs") {
        return super::parser_rustmacro::parse_rust_dsl(source, file_name);
    }
    if name.ends_with(".runar.py") {
        return super::parser_python::parse_python(source, file_name);
    }
    if name.ends_with(".runar.go") {
        return super::parser_gocontract::parse_go_contract(source, file_name);
    }
    if name.ends_with(".runar.rb") {
        return super::parser_ruby::parse_ruby(source, file_name);
    }
    // Default: TypeScript parser
    parse(source, file_name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Basic P2PKH contract
    // -----------------------------------------------------------------------

    const P2PKH_SOURCE: &str = r#"
        import { SmartContract, assert, Sig, PubKey, Ripemd160, hash160 } from 'runar-lang';

        class P2PKH extends SmartContract {
            readonly pubKeyHash: Ripemd160;

            constructor(pubKeyHash: Ripemd160) {
                super(pubKeyHash);
            }

            public unlock(sig: Sig, pubKey: PubKey) {
                assert(hash160(pubKey) === this.pubKeyHash);
                assert(checkSig(sig, pubKey));
            }
        }
    "#;

    #[test]
    fn test_parse_p2pkh_contract_name() {
        let result = parse(P2PKH_SOURCE, Some("P2PKH.runar.ts"));
        assert!(result.errors.is_empty(), "unexpected errors: {:?}", result.errors);
        let contract = result.contract.expect("should produce a contract");
        assert_eq!(contract.name, "P2PKH");
    }

    #[test]
    fn test_parse_p2pkh_parent_class() {
        let result = parse(P2PKH_SOURCE, Some("P2PKH.runar.ts"));
        let contract = result.contract.unwrap();
        assert_eq!(contract.parent_class, "SmartContract");
    }

    #[test]
    fn test_parse_p2pkh_properties() {
        let result = parse(P2PKH_SOURCE, Some("P2PKH.runar.ts"));
        let contract = result.contract.unwrap();
        assert_eq!(contract.properties.len(), 1);
        assert_eq!(contract.properties[0].name, "pubKeyHash");
        assert!(contract.properties[0].readonly);
        assert!(matches!(
            &contract.properties[0].prop_type,
            TypeNode::Primitive(PrimitiveTypeName::Ripemd160)
        ));
    }

    #[test]
    fn test_parse_p2pkh_constructor() {
        let result = parse(P2PKH_SOURCE, Some("P2PKH.runar.ts"));
        let contract = result.contract.unwrap();
        assert_eq!(contract.constructor.name, "constructor");
        assert_eq!(contract.constructor.params.len(), 1);
        assert_eq!(contract.constructor.params[0].name, "pubKeyHash");
    }

    #[test]
    fn test_parse_p2pkh_methods() {
        let result = parse(P2PKH_SOURCE, Some("P2PKH.runar.ts"));
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods.len(), 1);
        assert_eq!(contract.methods[0].name, "unlock");
        assert_eq!(contract.methods[0].visibility, Visibility::Public);
        assert_eq!(contract.methods[0].params.len(), 2);
        assert_eq!(contract.methods[0].params[0].name, "sig");
        assert_eq!(contract.methods[0].params[1].name, "pubKey");
    }

    // -----------------------------------------------------------------------
    // Stateful Counter contract
    // -----------------------------------------------------------------------

    const COUNTER_SOURCE: &str = r#"
        import { StatefulSmartContract, assert } from 'runar-lang';

        class Counter extends StatefulSmartContract {
            count: bigint;

            constructor(count: bigint) {
                super(count);
            }

            public increment() {
                this.count++;
                assert(this.count > 0n);
            }
        }
    "#;

    #[test]
    fn test_parse_counter_stateful() {
        let result = parse(COUNTER_SOURCE, Some("Counter.runar.ts"));
        assert!(result.errors.is_empty(), "unexpected errors: {:?}", result.errors);
        let contract = result.contract.expect("should produce a contract");
        assert_eq!(contract.name, "Counter");
        assert_eq!(contract.parent_class, "StatefulSmartContract");
    }

    #[test]
    fn test_parse_counter_mutable_property() {
        let result = parse(COUNTER_SOURCE, Some("Counter.runar.ts"));
        let contract = result.contract.unwrap();
        assert_eq!(contract.properties.len(), 1);
        assert_eq!(contract.properties[0].name, "count");
        assert!(!contract.properties[0].readonly, "count should be mutable");
        assert!(matches!(
            &contract.properties[0].prop_type,
            TypeNode::Primitive(PrimitiveTypeName::Bigint)
        ));
    }

    #[test]
    fn test_parse_counter_increment_method() {
        let result = parse(COUNTER_SOURCE, Some("Counter.runar.ts"));
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods.len(), 1);
        assert_eq!(contract.methods[0].name, "increment");
        assert_eq!(contract.methods[0].visibility, Visibility::Public);
        assert!(contract.methods[0].params.is_empty());
        assert!(!contract.methods[0].body.is_empty(), "increment body should not be empty");
    }

    // -----------------------------------------------------------------------
    // Multiple methods
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_multiple_methods() {
        let source = r#"
            import { SmartContract, assert } from 'runar-lang';

            class Multi extends SmartContract {
                readonly x: bigint;

                constructor(x: bigint) {
                    super(x);
                }

                public methodA(a: bigint) {
                    assert(a > 0n);
                }

                public methodB(b: bigint) {
                    assert(b > 0n);
                }

                private helper(v: bigint) {
                    assert(v > 0n);
                }
            }
        "#;
        let result = parse(source, Some("Multi.runar.ts"));
        assert!(result.errors.is_empty(), "unexpected errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods.len(), 3);
        assert_eq!(contract.methods[0].name, "methodA");
        assert_eq!(contract.methods[0].visibility, Visibility::Public);
        assert_eq!(contract.methods[1].name, "methodB");
        assert_eq!(contract.methods[1].visibility, Visibility::Public);
        assert_eq!(contract.methods[2].name, "helper");
        assert_eq!(contract.methods[2].visibility, Visibility::Private);
    }

    // -----------------------------------------------------------------------
    // Property with initializer
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_property_with_initializer() {
        let source = r#"
            import { StatefulSmartContract, assert } from 'runar-lang';

            class WithInit extends StatefulSmartContract {
                count: bigint = 0n;

                constructor() {
                    super();
                }

                public check() {
                    assert(this.count === 0n);
                }
            }
        "#;
        let result = parse(source, Some("WithInit.runar.ts"));
        assert!(result.errors.is_empty(), "unexpected errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.properties.len(), 1);
        assert!(
            contract.properties[0].initializer.is_some(),
            "property should have an initializer"
        );
    }

    // -----------------------------------------------------------------------
    // Error handling
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_no_contract_class_error() {
        let source = r#"
            class NotAContract {
                doSomething() {}
            }
        "#;
        let result = parse(source, Some("bad.runar.ts"));
        assert!(result.contract.is_none(), "should not produce a contract");
        assert!(
            result.errors.iter().any(|e| e.contains("No class extending SmartContract")),
            "should report missing SmartContract error, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_parse_syntax_error() {
        let source = "class { this is not valid }}}}}";
        let result = parse(source, Some("bad.runar.ts"));
        assert!(
            !result.errors.is_empty(),
            "should report parse errors for invalid syntax"
        );
    }

    #[test]
    fn test_parse_empty_source_error() {
        let source = "";
        let result = parse(source, Some("empty.runar.ts"));
        assert!(result.contract.is_none());
        assert!(
            result.errors.iter().any(|e| e.contains("No class extending SmartContract")),
            "empty source should report no contract found, got: {:?}",
            result.errors
        );
    }

    // -----------------------------------------------------------------------
    // Expressions: binary, unary, ternary, member access
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_binary_expressions() {
        let source = r#"
            import { SmartContract, assert } from 'runar-lang';

            class BinOps extends SmartContract {
                readonly x: bigint;

                constructor(x: bigint) {
                    super(x);
                }

                public check(a: bigint, b: bigint) {
                    const sum = a + b;
                    const diff = a - b;
                    const prod = a * b;
                    assert(sum > 0n);
                }
            }
        "#;
        let result = parse(source, Some("BinOps.runar.ts"));
        assert!(result.errors.is_empty(), "unexpected errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;
        // Should have at least 3 variable declarations and 1 assert
        assert!(body.len() >= 4, "expected at least 4 statements, got {}", body.len());
    }

    #[test]
    fn test_parse_ternary_expression() {
        let source = r#"
            import { SmartContract, assert } from 'runar-lang';

            class Ternary extends SmartContract {
                readonly x: bigint;

                constructor(x: bigint) {
                    super(x);
                }

                public check(a: bigint) {
                    const result = a > 0n ? 1n : 0n;
                    assert(result === 1n);
                }
            }
        "#;
        let result = parse(source, Some("Ternary.runar.ts"));
        assert!(result.errors.is_empty(), "unexpected errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        // Find the ternary in the first variable declaration
        if let Statement::VariableDecl { init, .. } = &contract.methods[0].body[0] {
            assert!(
                matches!(init, Expression::TernaryExpr { .. }),
                "expected ternary expression, got {:?}",
                init
            );
        } else {
            panic!("expected VariableDecl as first statement");
        }
    }

    // -----------------------------------------------------------------------
    // parse_source dispatch
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_source_ts_dispatch() {
        // parse_source with .runar.ts should use the TS parser
        let result = parse_source(P2PKH_SOURCE, Some("P2PKH.runar.ts"));
        assert!(result.errors.is_empty(), "unexpected errors: {:?}", result.errors);
        let contract = result.contract.expect("should produce a contract via TS parser");
        assert_eq!(contract.name, "P2PKH");
    }

    #[test]
    fn test_parse_source_default_dispatch() {
        // parse_source with no extension hint should default to TS parser
        let result = parse_source(P2PKH_SOURCE, None);
        assert!(result.errors.is_empty(), "unexpected errors: {:?}", result.errors);
        assert!(result.contract.is_some());
    }

    // -----------------------------------------------------------------------
    // For loop
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_for_loop() {
        let source = r#"
            import { SmartContract, assert } from 'runar-lang';

            class Loop extends SmartContract {
                readonly x: bigint;

                constructor(x: bigint) {
                    super(x);
                }

                public check() {
                    let sum = 0n;
                    for (let i = 0n; i < 10n; i++) {
                        sum += i;
                    }
                    assert(sum === 45n);
                }
            }
        "#;
        let result = parse(source, Some("Loop.runar.ts"));
        assert!(result.errors.is_empty(), "unexpected errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;
        // Should contain a ForStatement
        let has_for = body.iter().any(|s| matches!(s, Statement::ForStatement { .. }));
        assert!(has_for, "should contain a ForStatement, got: {:?}", body);
    }

    // -----------------------------------------------------------------------
    // If-else
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_if_else() {
        let source = r#"
            import { SmartContract, assert } from 'runar-lang';

            class IfElse extends SmartContract {
                readonly x: bigint;

                constructor(x: bigint) {
                    super(x);
                }

                public check(a: bigint) {
                    if (a > 0n) {
                        assert(a > 0n);
                    } else {
                        assert(a === 0n);
                    }
                }
            }
        "#;
        let result = parse(source, Some("IfElse.runar.ts"));
        assert!(result.errors.is_empty(), "unexpected errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;
        let has_if = body.iter().any(|s| matches!(s, Statement::IfStatement { .. }));
        assert!(has_if, "should contain an IfStatement");
    }

    // -----------------------------------------------------------------------
    // Exported contract class
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_exported_contract() {
        let source = r#"
            import { SmartContract, assert } from 'runar-lang';

            export class Exported extends SmartContract {
                readonly val: bigint;

                constructor(val: bigint) {
                    super(val);
                }

                public check() {
                    assert(this.val > 0n);
                }
            }
        "#;
        let result = parse(source, Some("Exported.runar.ts"));
        assert!(result.errors.is_empty(), "unexpected errors: {:?}", result.errors);
        let contract = result.contract.expect("exported class should be found");
        assert_eq!(contract.name, "Exported");
    }

    // -----------------------------------------------------------------------
    // Type parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_various_param_types() {
        let source = r#"
            import { SmartContract, assert, PubKey, Sig, ByteString, Sha256 } from 'runar-lang';

            class TypeTest extends SmartContract {
                readonly h: Sha256;

                constructor(h: Sha256) {
                    super(h);
                }

                public check(sig: Sig, pubKey: PubKey, data: ByteString, flag: boolean) {
                    assert(flag);
                }
            }
        "#;
        let result = parse(source, Some("TypeTest.runar.ts"));
        assert!(result.errors.is_empty(), "unexpected errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let params = &contract.methods[0].params;
        assert_eq!(params.len(), 4);
        assert!(matches!(&params[0].param_type, TypeNode::Primitive(PrimitiveTypeName::Sig)));
        assert!(matches!(&params[1].param_type, TypeNode::Primitive(PrimitiveTypeName::PubKey)));
        assert!(matches!(&params[2].param_type, TypeNode::Primitive(PrimitiveTypeName::ByteString)));
        assert!(matches!(&params[3].param_type, TypeNode::Primitive(PrimitiveTypeName::Boolean)));
    }
}

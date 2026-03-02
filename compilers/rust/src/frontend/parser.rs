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
    self, BinaryOp, ContractNode, Expression, MethodNode, ParamNode, PrimitiveTypeName,
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

            result.push(PropertyNode {
                name,
                prop_type,
                readonly,
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
            errors.push("Use === instead of == for equality comparison".to_string());
            BinaryOp::StrictEq
        }
        swc::BinaryOp::NotEq => {
            errors.push("Use !== instead of != for inequality comparison".to_string());
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
    // Default: TypeScript parser
    parse(source, file_name)
}

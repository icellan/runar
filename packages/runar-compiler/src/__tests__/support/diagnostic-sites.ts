import { Project, SyntaxKind, VariableDeclarationKind, type Node, type SourceFile } from 'ts-morph';
import { resolve } from 'node:path';

/**
 * Static inventory of every diagnostic the TypeScript validate + typecheck
 * passes can emit (R-101).
 *
 * The reviewer's complaint was that rejection behaviour — which INVALID
 * programs a compiler refuses — is the half of the equivalence claim nobody
 * measures, and that a corpus of a dozen hand-picked fixtures against 100+
 * diagnostic sites is not proportionate. Counting sites by hand rots the day
 * someone adds one, so the inventory is DERIVED from the sources: every
 * `makeDiagnostic(...)` call in the two passes, keyed by its message template.
 *
 * A template is turned into a matcher by escaping the literal chunks and
 * letting each `${...}` hole match anything, so the runtime message produced
 * by a real compile can be traced back to the call site that produced it.
 */

export interface DiagnosticSite {
  /** Repo-relative source file holding the `makeDiagnostic` call. */
  file: string;
  /** 1-based line of the call. */
  line: number;
  /** Message template with `${...}` holes replaced by HOLE. */
  template: string;
  /** Matches a runtime message emitted by this site. */
  matcher: RegExp;
  /** Stable identity: `<basename>:<template>`. Survives line moves. */
  id: string;
}

/** Placeholder standing in for a `${...}` interpolation: a control character
 *  no diagnostic message can contain, so splitting a template on it can never
 *  split a literal chunk. */
export const HOLE = '\u0001';

export const DIAGNOSTIC_PASS_FILES = [
  'packages/runar-compiler/src/passes/02-validate.ts',
  'packages/runar-compiler/src/passes/03-typecheck.ts',
] as const;

/**
 * Flatten a message argument into literal chunks and holes.
 *
 * Five shapes appear in the passes, and all must be handled or the
 * inventory silently under-counts (the failure mode this whole gate exists to
 * prevent): a plain string, a template literal, a `+` chain of either, an
 * identifier naming a top-level const initialized to one of the above, and a
 * call to a top-level function whose body is a single `return <...>;` of one
 * of the above (e.g. `rabinKeyWriteMessage(w.prop)` — N-205's message is a
 * shared helper because it is also thrown from IR validation, not just
 * pushed as a diagnostic). Template spans are already holes regardless of
 * what expression they interpolate (see the TemplateExpression case below),
 * so the call's argument value never needs to be resolved — only the
 * function's own template shape does. This does NOT handle a helper whose
 * body builds the string with a `+` chain over a parameter identifier
 * (there is no such helper today); that shape would still be reported as
 * unextractable.
 */
export function flatten(node: Node, sourceFile?: SourceFile): string | null {
  switch (node.getKind()) {
    case SyntaxKind.StringLiteral:
    case SyntaxKind.NoSubstitutionTemplateLiteral:
      return (node as unknown as { getLiteralText(): string }).getLiteralText();

    case SyntaxKind.TemplateExpression: {
      const te = node.asKindOrThrow(SyntaxKind.TemplateExpression);
      const parts: string[] = [te.getHead().getLiteralText()];
      for (const span of te.getTemplateSpans()) {
        parts.push(HOLE, span.getLiteral().getLiteralText());
      }
      return parts.join('');
    }

    case SyntaxKind.BinaryExpression: {
      const be = node.asKindOrThrow(SyntaxKind.BinaryExpression);
      if (be.getOperatorToken().getKind() !== SyntaxKind.PlusToken) return null;
      const left = flatten(be.getLeft(), sourceFile);
      const right = flatten(be.getRight(), sourceFile);
      if (left === null || right === null) return null;
      return left + right;
    }

    case SyntaxKind.ParenthesizedExpression:
      return flatten(node.asKindOrThrow(SyntaxKind.ParenthesizedExpression).getExpression(), sourceFile);

    case SyntaxKind.CallExpression: {
      if (!sourceFile) return null;
      const call = node.asKindOrThrow(SyntaxKind.CallExpression);
      const callee = call.getExpression();
      if (callee.getKind() !== SyntaxKind.Identifier) return null;
      const fn = sourceFile.getFunction(callee.getText());
      if (!fn) return null;
      const statements = fn.getStatements();
      if (statements.length !== 1 || statements[0]!.getKind() !== SyntaxKind.ReturnStatement) return null;
      const ret = statements[0]!.asKindOrThrow(SyntaxKind.ReturnStatement);
      const expr = ret.getExpression();
      if (!expr) return null;
      return flatten(expr, sourceFile);
    }

    case SyntaxKind.Identifier: {
      if (!sourceFile) return null;
      const id = node.asKindOrThrow(SyntaxKind.Identifier).getText();
      // Look for a top-level const declaration with this name
      for (const stmt of sourceFile.getVariableStatements()) {
        // Only consider const declarations, not let/var
        if (stmt.getDeclarationKind() !== VariableDeclarationKind.Const) continue;
        for (const decl of stmt.getDeclarations()) {
          if (decl.getName() === id) {
            const init = decl.getInitializer();
            if (init) {
              return flatten(init, sourceFile);
            }
          }
        }
      }
      return null;
    }

    default:
      return null;
  }
}

function toMatcher(template: string): RegExp {
  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // `[^]*?` (not `.*?`) so a hole spans newlines — several messages are
  // multi-line and interpolate lists.
  return new RegExp('^' + template.split(HOLE).map(esc).join('[^]*?') + '$');
}

/**
 * Every diagnostic site in the validate + typecheck passes.
 *
 * Throws when a `makeDiagnostic` message argument cannot be reduced to a
 * template. That is deliberate: an un-extractable site would otherwise be
 * dropped from the denominator, quietly improving the coverage number by
 * hiding a diagnostic — exactly the accounting this gate is supposed to stop.
 */
export function collectDiagnosticSites(repoRoot: string): DiagnosticSite[] {
  const project = new Project({ skipAddingFilesFromTsConfig: true });
  const sites: DiagnosticSite[] = [];
  const unextractable: string[] = [];

  for (const file of DIAGNOSTIC_PASS_FILES) {
    const sf = project.addSourceFileAtPath(resolve(repoRoot, file));
    for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (call.getExpression().getText() !== 'makeDiagnostic') continue;
      const arg = call.getArguments()[0];
      const line = call.getStartLineNumber();
      if (!arg) {
        unextractable.push(`${file}:${line} (no message argument)`);
        continue;
      }
      const template = flatten(arg, sf);
      if (template === null) {
        unextractable.push(`${file}:${line} ${arg.getText().slice(0, 80).replace(/\s+/g, ' ')}`);
        continue;
      }
      const base = file.slice(file.lastIndexOf('/') + 1);
      sites.push({
        file,
        line,
        template,
        matcher: toMatcher(template),
        id: `${base}:${template}`,
      });
    }
  }

  if (unextractable.length > 0) {
    throw new Error(
      `[diagnostic-sites] ${unextractable.length} makeDiagnostic call(s) have a message this ` +
      `extractor cannot reduce to a template, so they would vanish from the coverage ` +
      `denominator:\n  ${unextractable.join('\n  ')}\n` +
      `Either build the message from string/template literals joined by \`+\`, or teach ` +
      `flatten() the new shape.`,
    );
  }

  return sites;
}

/** Index of the sites a runtime diagnostic message can be attributed to. */
export function attribute(sites: DiagnosticSite[], message: string): number[] {
  const hits: number[] = [];
  sites.forEach((s, i) => {
    if (s.matcher.test(message)) hits.push(i);
  });
  return hits;
}

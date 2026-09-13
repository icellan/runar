import { Project, SyntaxKind, type Node } from 'ts-morph';
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
 * Three shapes appear in the passes, and all three must be handled or the
 * inventory silently under-counts (the failure mode this whole gate exists to
 * prevent): a plain string, a template literal, and — for the long messages —
 * a `+` chain of either.
 */
function flatten(node: Node): string | null {
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
      const left = flatten(be.getLeft());
      const right = flatten(be.getRight());
      if (left === null || right === null) return null;
      return left + right;
    }

    case SyntaxKind.ParenthesizedExpression:
      return flatten(node.asKindOrThrow(SyntaxKind.ParenthesizedExpression).getExpression());

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
      const template = flatten(arg);
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

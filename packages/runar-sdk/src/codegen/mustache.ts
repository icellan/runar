// ---------------------------------------------------------------------------
// codegen/mustache.ts — Minimal Mustache template renderer for code generation
// ---------------------------------------------------------------------------
// Supports: {{var}}, {{#section}}...{{/section}}, {{^section}}...{{/section}}, {{.}}
// No HTML escaping, no partials, no lambdas.

type Context = Record<string, unknown>;

/**
 * Render a Mustache template with the given context.
 */
export function renderMustache(template: string, context: Context): string {
  return renderSection(template, context);
}

function renderSection(template: string, context: Context): string {
  // Process sections: {{#key}}...{{/key}} and {{^key}}...{{/key}}
  let result = template;

  // Repeatedly process sections from innermost out
  let changed = true;
  while (changed) {
    changed = false;
    result = result.replace(
      /\{\{([#^])(\w+(?:\.\w+)*)\}\}([\s\S]*?)\{\{\/\2\}\}/g,
      (_match, type: string, key: string, body: string) => {
        changed = true;
        const value = resolve(context, key);

        if (type === '^') {
          // Inverted section: render if falsy/empty
          if (!value || (Array.isArray(value) && value.length === 0)) {
            return renderSection(body, context);
          }
          return '';
        }

        // Normal section
        if (Array.isArray(value)) {
          return value
            .map((item) => {
              if (typeof item === 'object' && item !== null) {
                return renderSection(body, { ...context, ...item });
              }
              // Primitive array item: {{.}} resolves to the item
              return renderSection(body, { ...context, '.': item });
            })
            .join('');
        }

        if (value && typeof value === 'object') {
          return renderSection(body, { ...context, ...(value as Context) });
        }

        if (value) {
          return renderSection(body, context);
        }

        return '';
      },
    );
  }

  // Replace variables: {{key}} or {{key.subkey}}
  result = result.replace(/\{\{(\w+(?:\.\w+)*|\.)}\}/g, (_match, key: string) => {
    const value = resolve(context, key);
    if (value === undefined || value === null) return '';
    return String(value);
  });

  return result;
}

function resolve(context: Context, key: string): unknown {
  if (key === '.') return context['.'];
  const parts = key.split('.');
  let current: unknown = context;
  for (const part of parts) {
    if (current === null || current === undefined) return undefined;
    current = (current as Context)[part];
  }
  return current;
}

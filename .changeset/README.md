# Changesets — scaffolding only, NOT the release flow

**Nothing in this repository consumes these files.** `@changesets/cli` is a
devDependency and no script, workflow or hook ever invokes it. Writing a
changeset here does not bump a version, does not produce a changelog entry, and
does not affect a release in any way.

This is R-283 (CL-GAP-071), recorded here rather than fixed by deleting the
directory, because one real changeset already lives in it
(`anys-oppushtx-binding.md`, written 2026-09-01) and it is a good description of
a real change that is worth keeping.

## What actually releases

    scripts/bump-version.sh     rewrites versions across the workspace (sed-based)
    scripts/bump-version.sh --check   the consistency gate CI runs
    scripts/release.sh          tags and drives the release
    scripts/publish-all.sh      publishes npm / crates / gems / PyPI / Maven

If you want your change to appear in a release, use those. If you want to record
a human-readable summary of a change, a file here is a reasonable place for it —
just do not expect it to do anything on its own.

## If changesets is ever adopted for real

Wire `changeset version` and `changeset publish` into the scripts above, and
then rewrite this README — `tests/r283-changeset-scaffolding.test.ts` requires
this file to keep saying "NOT the release flow" for exactly as long as no script
invokes the CLI, and will fail once one does.

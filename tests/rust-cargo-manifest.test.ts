import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { resolve } from 'node:path';

/**
 * F-384: Validate that published Rust crates declare an MSRV consistent with
 * their dependency graph.
 *
 * The compilers/rust crate is published to crates.io as a library/binary.
 * Declaring a Minimum Supported Rust Version (MSRV) lets users know what
 * versions they need. An MSRV lower than the maximum rust_version declared by
 * any dependency is a lie — that dependency will not compile.
 *
 * This test:
 * 1. Asserts compilers/rust/Cargo.toml declares a rust-version key
 * 2. Spawns `cargo metadata` to find the maximum rust_version of all dependencies
 * 3. Asserts the declared MSRV >= the maximum from the dependency graph
 *
 * The test FAILS hard if cargo is unavailable (no skip fallback).
 *
 * Note: the dependency version constraint issue (>=0.2.89, <0.3 being open) is
 * already resolved at HEAD by commit 79dd98dc, which raised the floor to 0.2.89.
 * A caret constraint like ^0.2.89 is equivalent to >=0.2.89, <0.3 in Cargo, so
 * that half of F-384 is satisfied. This test addresses the MSRV half only.
 */

const REPO = resolve(__dirname, '..');
const RUST_COMPILER_CARGO = resolve(REPO, 'compilers/rust/Cargo.toml');
const RUST_COMPILER_DIR = resolve(REPO, 'compilers/rust');

function parseVersion(v: string): [number, number, number] {
  const parts = v.split('.');
  return [parseInt(parts[0]!) || 0, parseInt(parts[1]!) || 0, parseInt(parts[2]!) || 0];
}

function versionToNumber(v: [number, number, number]): number {
  return v[0]! * 1_000_000 + v[1]! * 1000 + v[2]!;
}

describe('F-384: rust-cargo-manifest MSRV', () => {
  const cargoContent = readFileSync(RUST_COMPILER_CARGO, 'utf-8');

  it('rust-version is declared in [package]', () => {
    expect(cargoContent).toMatch(/rust-version\s*=\s*"[\d.]+"/i);
  });

  it('declared rust-version is >= max rust_version from cargo metadata', () => {
    // Extract declared rust-version
    const match = cargoContent.match(/rust-version\s*=\s*"([\d.]+)"/i);
    expect(match, 'rust-version should be defined').toBeTruthy();
    const declaredRustVersion = match![1]!;

    // Spawn cargo metadata and extract max rust_version
    let metadata: any;
    try {
      const output = execSync('cargo metadata --format-version 1 --locked', {
        cwd: RUST_COMPILER_DIR,
        encoding: 'utf-8',
      });
      metadata = JSON.parse(output);
    } catch (e) {
      throw new Error(`cargo metadata failed (cargo must be available): ${e}`);
    }

    const rustVersions = metadata.packages
      .map((pkg: any) => pkg.rust_version)
      .filter((v: any) => v != null && v.length > 0);

    expect(rustVersions.length, 'cargo metadata should find packages with rust_version').toBeGreaterThan(0);

    // Find max
    const maxVersion = rustVersions.reduce((acc: string, v: string) => {
      const accNum = versionToNumber(parseVersion(acc));
      const vNum = versionToNumber(parseVersion(v));
      return vNum > accNum ? v : acc;
    });

    // Get the top 3 packages for the error message
    const packageVersions = metadata.packages
      .filter((pkg: any) => pkg.rust_version != null && pkg.rust_version.length > 0)
      .map((pkg: any) => ({ name: pkg.name, version: pkg.rust_version }))
      .sort((a: any, b: any) => {
        const aNum = versionToNumber(parseVersion(a.version));
        const bNum = versionToNumber(parseVersion(b.version));
        return bNum - aNum;
      })
      .slice(0, 3);

    const declaredNum = versionToNumber(parseVersion(declaredRustVersion));
    const maxNum = versionToNumber(parseVersion(maxVersion));

    expect(
      declaredNum >= maxNum,
      `Declared rust-version ${declaredRustVersion} must be >= max from dependencies ${maxVersion}. Top packages: ${packageVersions.map((p: any) => `${p.name}:${p.version}`).join(', ')}`,
    ).toBe(true);
  });
});

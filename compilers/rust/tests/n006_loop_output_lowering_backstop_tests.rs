//! N-006 / CL-BUG-186 — the pass-4 backstop behind R-127.
//!
//! R-127 is a syntactic search in the validator. `lower_to_anf` is public, so a
//! caller can go `parse_source` -> `lower_to_anf` having run no validator at
//! all, and `lower_for_statement` used to drop the body sub-context's
//! `add_output_refs` / `add_data_output_refs` without a word: the loop's
//! outputs were built but left out of the continuation hash, so a spender
//! could drop them (proven on @bsv/sdk Spend for the TS and Go tiers in
//! packages/runar-testing/src/__tests__/f005-go-loop-output-continuation.test.ts).
//!
//! What this proves: this tier's pass 4 refuses a loop whose body registered
//! an output ref, with R-127's shared diagnostic, whatever let the contract
//! past passes 1-3; a loop with no output in it still lowers.
//! What it does not prove: anything about emitted bytes.

use runar_compiler_rust::frontend::anf_lower::lower_to_anf;
use runar_compiler_rust::frontend::parser::parse_source;

const HEAD: &str = "import { StatefulSmartContract, ByteString, assert, num2bin } from 'runar-lang';

class Fan extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }
";

fn lower_unvalidated(method: &str) -> Option<String> {
    let src = format!("{HEAD}{method}\n}}\n");
    let parsed = parse_source(&src, Some("Fan.runar.ts"));
    assert!(parsed.errors.is_empty(), "parse: {:?}", parsed.errors);
    let contract = parsed.contract.expect("contract");
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(|| lower_to_anf(&contract));
    std::panic::set_hook(prev);
    match r {
        Ok(_) => None,
        Err(p) => Some(
            p.downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default(),
        ),
    }
}

#[test]
fn n006_array_literal_raw_output_in_loop_is_refused_at_lowering() {
    let refusal = lower_unvalidated(
        "  public fan(n: bigint) {
    this.addOutput(1000n, this.count + 1n);
    for (let i = 0n; i < 2n; i++) {
      const xs = [this.addRawOutput(n, num2bin(i, 4n))];
    }
  }",
    )
    .expect("lower_to_anf accepted an output intrinsic inside a loop body");
    assert!(
        refusal.contains("Output intrinsic 'addRawOutput' cannot be called inside a loop body."),
        "not the R-127 diagnostic: {refusal}"
    );
}

#[test]
fn n006_add_output_and_data_output_in_loop_are_refused_at_lowering() {
    let out = lower_unvalidated(
        "  public fan(n: bigint) {
    this.addOutput(1000n, this.count);
    for (let i = 0n; i < 2n; i++) {
      this.addOutput(1000n, this.count + i);
    }
    assert(n > 0n);
  }",
    )
    .expect("addOutput in a loop lowered");
    assert!(out.contains("Output intrinsic 'addOutput' cannot be called inside a loop body."), "{out}");

    let data = lower_unvalidated(
        "  public fan(n: bigint) {
    for (let i = 0n; i < 2n; i++) {
      if (i < n) {
        this.addDataOutput(0n, num2bin(i, 4n));
      }
    }
    this.count = this.count + 1n;
  }",
    )
    .expect("addDataOutput in a loop lowered");
    assert!(
        data.contains("Output intrinsic 'addDataOutput' cannot be called inside a loop body."),
        "{data}"
    );
}

#[test]
fn n006_control_loop_without_outputs_still_lowers() {
    assert_eq!(
        lower_unvalidated(
            "  public fan(n: bigint) {
    let acc: bigint = 0n;
    for (let i = 0n; i < 2n; i++) {
      acc = acc + n;
    }
    this.addOutput(1000n, this.count + acc);
  }",
        ),
        None
    );
}

import Lake
open Lake DSL

package «runar-verification» where
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩,
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib RunarVerification where
  roots := #[`RunarVerification]

lean_exe goldenLoad where
  root := `tests.GoldenLoad
  supportInterpreter := true

lean_exe roundtrip where
  root := `tests.Roundtrip
  supportInterpreter := true

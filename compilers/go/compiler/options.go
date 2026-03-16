package compiler

// CompileOptions controls optional compiler behavior.
type CompileOptions struct {
	// DisableConstantFolding skips the ANF constant folding pass.
	// Default (false) enables constant folding.
	DisableConstantFolding bool
}

func mergeOptions(opts []CompileOptions) CompileOptions {
	if len(opts) == 0 {
		return CompileOptions{}
	}
	return opts[0]
}

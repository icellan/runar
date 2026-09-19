package frontend

import "testing"

func TestExtractBindingVariant_HonoursAll(t *testing.T) {
	r, ok := extractBindingVariantDirective("/** @bindingVariant all */")
	if !ok || !r.ok() || r.value != "all" {
		t.Fatalf("got %+v ok=%v, want all", r, ok)
	}
}

func TestExtractBindingVariant_ProseIsError(t *testing.T) {
	r, ok := extractBindingVariantDirective("/** Do NOT use @bindingVariant all */")
	if !ok || r.ok() {
		t.Fatalf("prose must error, got %+v ok=%v", r, ok)
	}
}

func TestExtractBindingVariant_TypeIdentIsAbsent(t *testing.T) {
	_, ok := extractBindingVariantDirective("/** @bindingVariantType foo */")
	if ok {
		t.Fatal("identifier continuation must not be a directive")
	}
}

package runar

import (
	"reflect"
	"testing"
)

// TestFixedArray_FlatSerializeRoundTrip verifies that a 1D FixedArray
// state field round-trips through SerializeState → DeserializeState
// as a flat Go slice of ints.
func TestFixedArray_FlatSerializeRoundTrip(t *testing.T) {
	fields := []StateField{
		{
			Name:  "board",
			Type:  "FixedArray<bigint, 3>",
			Index: 0,
			FixedArray: &ABIFixedArray{
				ElementType:    "bigint",
				Length:         3,
				SyntheticNames: []string{"board__0", "board__1", "board__2"},
			},
		},
	}
	values := map[string]interface{}{
		"board": []interface{}{int64(1), int64(2), int64(3)},
	}
	hex := SerializeState(fields, values)
	// Each bigint encodes as 8 raw bytes (NUM2BIN 8) = 16 hex chars; 3 fields = 48 chars.
	if len(hex) != 48 {
		t.Errorf("serialized hex length = %d, want 48", len(hex))
	}
	out := DeserializeState(fields, hex)
	got, ok := out["board"].([]interface{})
	if !ok {
		t.Fatalf("deserialized board is %T, want []interface{}", out["board"])
	}
	if len(got) != 3 {
		t.Fatalf("len(board) = %d, want 3", len(got))
	}
	for i, want := range []int64{1, 2, 3} {
		if got[i] != want {
			t.Errorf("board[%d] = %v, want %d", i, got[i], want)
		}
	}
}

// TestFixedArray_NestedSerializeRoundTrip verifies that a 2D nested
// FixedArray state field round-trips as a nested Go slice.
func TestFixedArray_NestedSerializeRoundTrip(t *testing.T) {
	fields := []StateField{
		{
			Name:  "grid",
			Type:  "FixedArray<FixedArray<bigint, 2>, 2>",
			Index: 0,
			FixedArray: &ABIFixedArray{
				ElementType:    "FixedArray<bigint, 2>",
				Length:         2,
				SyntheticNames: []string{"grid__0__0", "grid__0__1", "grid__1__0", "grid__1__1"},
			},
		},
	}
	values := map[string]interface{}{
		"grid": []interface{}{
			[]interface{}{int64(10), int64(20)},
			[]interface{}{int64(30), int64(40)},
		},
	}
	hex := SerializeState(fields, values)
	// 4 bigints * 16 hex chars each = 64.
	if len(hex) != 64 {
		t.Errorf("serialized hex length = %d, want 64", len(hex))
	}
	out := DeserializeState(fields, hex)
	got, ok := out["grid"].([]interface{})
	if !ok {
		t.Fatalf("grid is %T, want []interface{}", out["grid"])
	}
	want := []interface{}{
		[]interface{}{int64(10), int64(20)},
		[]interface{}{int64(30), int64(40)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("grid = %v, want %v", got, want)
	}
}

// TestFixedArray_ParseDims sanity-checks parseFixedArrayDims on flat,
// 2D, and 3D FixedArray type strings.
func TestFixedArray_ParseDims(t *testing.T) {
	cases := []struct {
		typ  string
		want []int
	}{
		{"bigint", []int(nil)},
		{"FixedArray<bigint, 9>", []int{9}},
		{"FixedArray<FixedArray<bigint, 2>, 3>", []int{3, 2}},
		{"FixedArray<FixedArray<FixedArray<bigint, 2>, 3>, 4>", []int{4, 3, 2}},
	}
	for _, c := range cases {
		got := parseFixedArrayDims(c.typ)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseFixedArrayDims(%q) = %v, want %v", c.typ, got, c.want)
		}
	}
}

// TestFixedArray_UnwrapLeaf sanity-checks unwrapFixedArrayLeaf on
// flat, 2D, and 3D FixedArray type strings.
func TestFixedArray_UnwrapLeaf(t *testing.T) {
	cases := []struct {
		typ, want string
	}{
		{"bigint", "bigint"},
		{"FixedArray<bigint, 9>", "bigint"},
		{"FixedArray<FixedArray<bigint, 2>, 3>", "bigint"},
		{"FixedArray<FixedArray<Point, 2>, 3>", "Point"},
	}
	for _, c := range cases {
		got := unwrapFixedArrayLeaf(c.typ)
		if got != c.want {
			t.Errorf("unwrapFixedArrayLeaf(%q) = %q, want %q", c.typ, got, c.want)
		}
	}
}

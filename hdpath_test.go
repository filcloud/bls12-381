package bls12_381

import (
	"reflect"
	"testing"
)

func TestHDPathParsing(t *testing.T) {
	base := DerivationPath{12381, 60, 0, 0}
	tests := []struct {
		input  string
		base   *DerivationPath
		output DerivationPath
	}{
		// Plain absolute derivation paths
		{"m/12381/60/0/0", nil, DerivationPath{12381, 60, 0, 0}},
		{"m/12381/60/0/128", nil, DerivationPath{12381, 60, 0, 128}},
		{"m/12381/60/0/0", nil, DerivationPath{12381, 60, 0, 0}},
		{"m/12381/60/0/128", nil, DerivationPath{12381, 60, 0, 128}},

		// Plain relative derivation paths
		{"0", &base, DerivationPath{12381, 60, 0, 0, 0}},
		{"128", &base, DerivationPath{12381, 60, 0, 0, 128}},

		// Hexadecimal absolute derivation paths
		{"m/0x305D/0x3C/0x00/0x00", nil, DerivationPath{12381, 60, 0, 0}},
		{"m/0x305D/0x3C/0x00/0x80", nil, DerivationPath{12381, 60, 0, 128}},

		// Hexadecimal relative derivation paths
		{"0x00", &base, DerivationPath{12381, 60, 0, 0, 0}},
		{"0x80", &base, DerivationPath{12381, 60, 0, 0, 128}},

		// Weird inputs just to ensure they work
		{"	m  /   12381		\n/\n   60	\n\n\t   /\n0  /\t\t	0", nil, DerivationPath{12381, 60, 0, 0}},

		// Invaid derivation paths
		{"", nil, nil},              // Empty relative derivation path
		{"m", nil, nil},             // Empty absolute derivation path
		{"m/", nil, nil},            // Missing last derivation component
		{"/12381/60/0/0", nil, nil}, // Absolute path without m prefix, might be user error
		{"m/4294967296", nil, nil},  // Overflows 32 bit integer
		{"m/-1", nil, nil},          // Cannot contain negative number
	}
	for i, tt := range tests {
		var base []DerivationPath
		if tt.base != nil {
			base = append(base, *tt.base)
		}
		path, err := ParseDerivationPath(tt.input, base...)
		if !reflect.DeepEqual(path, tt.output) {
			t.Errorf("test %d: parse mismatch: have %v (%v), want %v", i, path, err, tt.output)
		} else if path == nil && err == nil {
			t.Errorf("test %d: nil path and error: %v", i, err)
		}
	}
}

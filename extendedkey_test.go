package bls12_381

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"testing"
)

func TestExtendedKey(t *testing.T) {
	indices := generateIndices(10)

	for i, c := range testCases {
		s, ok := big.NewInt(0).SetString(c.seed, 0)
		if !ok {
			t.Errorf("test case %d, big.Int SetString failed", i)
		}
		seed := toBytes(s, (len(c.seed)-2)/2)
		m, err := NewMaster(seed)
		if err != nil {
			t.Errorf("test case %d, %s", i, err)
		}

		d1, err := deriveDescendant(m, indices)
		if err != nil {
			t.Errorf("test case %d, %s", i, err)
		}
		d2, err := deriveDescendant(m, indices)
		if err != nil {
			t.Errorf("test case %d, %s", i, err)
		}
		if bytes.Compare(d1.privateKey[:], d2.privateKey[:]) != 0 {
			t.Errorf("test case %d, inconsistent derived child", i)
		}
		fmt.Printf("child address: %s\n", d1.Address())

		str := d1.String()
		k, err := NewKeyFromString(str)
		if err != nil {
			t.Errorf("test case %d, %s", i, err)
		}
		if k.String() != str {
			t.Errorf("test case %d, inconsistent base58 string", i)
		}
	}
}

func generateIndices(n int) []uint32 {
	indices := make([]uint32, n)
	for i := 0; i < n; i++ {
		indices[i] = rand.Uint32()
	}
	return indices
}

func deriveDescendant(k *ExtendedKey, indices []uint32) (*ExtendedKey, error) {
	var err error
	for _, i := range indices {
		k, err = k.Child(i)
		if err != nil {
			return nil, err
		}
	}
	return k, nil
}

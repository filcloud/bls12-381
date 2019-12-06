package bls12_381

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2334.md

const DefaultPurpose = 12381

type DerivationPath []uint32

// ParseDerivationPath converts a user specified derivation path string to the
// internal binary representation.
//
// Full derivation paths need to start with the `m/` prefix, relative derivation
// paths (which will get appended to the provided base path) must not have prefixes
// in front of the first element. Whitespace is ignored.
// Modified copy from https://github.com/ethereum/go-ethereum/blob/master/accounts/hd.go
func ParseDerivationPath(path string, base ...DerivationPath) (DerivationPath, error) {
	var result DerivationPath

	// Handle absolute or relative paths
	components := strings.Split(path, "/")
	switch {
	case len(components) == 0:
		return nil, errors.New("empty derivation path")

	case strings.TrimSpace(components[0]) == "":
		return nil, errors.New("ambiguous path: use 'm/' prefix for absolute paths, or no leading '/' for relative ones")

	case strings.TrimSpace(components[0]) == "m": // 'm/' prefix
		components = components[1:]

	default: // relative path, no '/' prefix
		if len(base) > 0 {
			result = append(result, base[0]...)
		} else {
			return nil, errors.New("base path must be provided for relative path")
		}
	}

	if len(components) == 0 {
		return nil, errors.New("empty derivation path") // Empty relative paths
	}

	// All remaining components are relative, append one by one
	for _, component := range components {
		// Ignore any user added whitespace
		component = strings.TrimSpace(component)

		value, ok := new(big.Int).SetString(component, 0)
		if !ok {
			return nil, fmt.Errorf("invalid component: %s", component)
		}
		max := math.MaxUint32
		if value.Sign() < 0 || value.Cmp(big.NewInt(int64(max))) > 0 {
			return nil, fmt.Errorf("component %v out of allowed range [0, %d]", value, max)
		}

		// Append and repeat
		result = append(result, uint32(value.Uint64()))
	}
	return result, nil
}

// String implements the stringer interface, converting a binary derivation path
// to its canonical representation.
func (path DerivationPath) String() string {
	result := "m"
	for _, component := range path {
		result = fmt.Sprintf("%s/%d", result, component)
	}
	return result
}

func DeriveKey(master *ExtendedKey, path DerivationPath) (*ExtendedKey, error) {
	key := master
	var err error
	for _, val := range path {
		key, err = key.Child(val)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

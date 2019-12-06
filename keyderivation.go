package bls12_381

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2333.md

//noinspection GoSnakeCaseUsage
var curveOrder, _ = big.NewInt(0).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 0)

// ceil((1.5 * ceil(log2(r))) / 8)
// https://www.wolframalpha.com/input/?i=ceil%28%281.5+*+ceil%28log2%2852435875175126190479447740508185965837690552500527637822603658699938581184513%29%29%29+%2F+8%29
//noinspection GoSnakeCaseUsage
const hkdf_mod_r_L = 48

var maxUint256 = big.NewInt(0).Sub(big.NewInt(0).Exp(big.NewInt(2), big.NewInt(256), nil), big.NewInt(1))

//noinspection ALL
func ikm_to_lamport_SK(IKM, salt []byte) ([][]byte, error) {
	lamport_SK := make([][]byte, 255)
	r := hkdf.New(sha256.New, IKM, salt, nil)
	for i := range lamport_SK {
		sk := make([]byte, sha256.Size)
		n, err := r.Read(sk)
		if err != nil {
			return nil, err
		}
		if n != sha256.Size {
			return nil, errors.New("hkdf: entropy limit reached")
		}
		lamport_SK[i] = sk
	}
	return lamport_SK, nil
}

//noinspection ALL
func parent_SK_to_lamport_PK(parent_SK *big.Int, index uint32) ([]byte, error) {
	salt := make([]byte, 4)
	binary.BigEndian.PutUint32(salt, index)

	IKM := toBytes(parent_SK, 32)
	lamport_0, err := ikm_to_lamport_SK(IKM, salt)
	if err != nil {
		return nil, err
	}
	// fmt.Printf("lamport_0: %x\n", lamport_0)

	not_IKM := big.NewInt(0).Xor(parent_SK, maxUint256) // flip bits
	lamport_1, err := ikm_to_lamport_SK(toBytes(not_IKM, 32), salt)
	if err != nil {
		return nil, err
	}
	// fmt.Printf("lamport_1: %x\n", lamport_1)

	lamport_SKs := append(lamport_0, lamport_1...)
	lamport_PK := make([]byte, 0, sha256.Size*len(lamport_SKs))
	for _, sk := range lamport_SKs {
		h := sha256.Sum256(sk)
		lamport_PK = append(lamport_PK, h[:]...)
	}

	compressed_PK := sha256.Sum256(lamport_PK)
	// fmt.Printf("compressed_PK: %x\n", compressed_PK)
	return compressed_PK[:], nil
}

//noinspection ALL
func hkdf_mod_r(IKM []byte) (*big.Int, error) {
	okm := make([]byte, hkdf_mod_r_L)
	r := hkdf.New(sha256.New, IKM, []byte("BLS-SIG-KEYGEN-SALT-"), nil)
	n, err := r.Read(okm)
	if err != nil {
		return nil, err
	}
	if n != hkdf_mod_r_L {
		return nil, errors.New("hkdf: entropy limit reached")
	}
	bi := big.NewInt(0).SetBytes(okm)
	return big.NewInt(0).Mod(bi, curveOrder), nil
}

//noinspection ALL
func DeriveChildSK(parent_SK *big.Int, index uint32) (*big.Int, error) {
	lamport_PK, err := parent_SK_to_lamport_PK(parent_SK, index)
	if err != nil {
		return nil, err
	}
	return hkdf_mod_r(lamport_PK)
}

//noinspection ALL
func DeriveMasterSK(seed []byte) (*big.Int, error) {
	if len(seed) < 16 {
		return nil, errors.New("seed must be >= 128 bits")
	}
	return hkdf_mod_r(seed)
}

func toBytes(b *big.Int, length int) []byte {
	result := make([]byte, length)
	bytes := b.Bytes()
	copy(result[length-len(bytes):], bytes)
	return result
}

func reverseBytes(a []byte) []byte {
	b := make([]byte, len(a))
	for i := len(a)/2 - 1; i >= 0; i-- {
		opp := len(a) - 1 - i
		b[i], b[opp] = a[opp], a[i]
	}
	return b
}

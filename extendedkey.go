package bls12_381

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil/base58"
	ffi "github.com/filecoin-project/filecoin-ffi"
	"github.com/filecoin-project/lotus/chain/address"
)

const (
	RecommendedSeedLen = 32 // 256 bits
	MinSeedBytes       = 16 // 128 bits
	MaxSeedBytes       = 64 // 512 bits

	serializedKeyLen = 1 + 4 + 4 + 32
)

var (
	ErrInvalidSeedLen = fmt.Errorf("seed length must be between %d and %d bits",
		MinSeedBytes*8, MaxSeedBytes*8)
	ErrDeriveBeyondMaxDepth = errors.New("cannot derive a key with more than 255 indices in its path")
	ErrInvalidKeyLen        = errors.New("the provided serialized extended key length is invalid")
	ErrBadChecksum          = errors.New("bad extended key checksum")
)

type ExtendedKey struct {
	key        *big.Int
	privateKey ffi.PrivateKey
	publicKey  *ffi.PublicKey
	depth      uint8
	parentFP   []byte
	childNum   uint32
}

func NewMaster(seed []byte) (*ExtendedKey, error) {
	key, err := DeriveMasterSK(seed)
	if err != nil {
		return nil, err
	}
	privateKey := reverseBytes(toBytes(key, 32))
	parentFP := []byte{0x00, 0x00, 0x00, 0x00}
	k := &ExtendedKey{
		key:      key,
		parentFP: parentFP,
	}
	copy(k.privateKey[:], privateKey)
	return k, nil
}

func NewExtendedKey(privateKey, parentFP []byte, depth uint8,
	childNum uint32) *ExtendedKey {
	if len(privateKey) != 32 {
		panic("private key must be 32 bytes")
	}
	key := big.NewInt(0).SetBytes(reverseBytes(privateKey))
	k := &ExtendedKey{
		key:      key,
		depth:    depth,
		parentFP: parentFP,
		childNum: childNum,
	}
	copy(k.privateKey[:], privateKey)
	return k
}

func (k *ExtendedKey) Child(i uint32) (*ExtendedKey, error) {
	if k.depth == math.MaxUint8 {
		return nil, ErrDeriveBeyondMaxDepth
	}

	key, err := DeriveChildSK(k.key, i)
	if err != nil {
		return nil, err
	}

	publicKey := k.PublicKey()
	h := sha256.Sum256(publicKey[:])
	parentFP := h[:4]

	return NewExtendedKey(reverseBytes(toBytes(key, 32)), parentFP, k.depth+1, i), nil
}

func (k *ExtendedKey) PrivateKey() ffi.PrivateKey {
	return k.privateKey
}

func (k *ExtendedKey) PublicKey() ffi.PublicKey {
	if k.publicKey == nil {
		publicKey := ffi.PrivateKeyPublicKey(k.privateKey)
		k.publicKey = &publicKey
	}
	return *k.publicKey
}

func (k *ExtendedKey) Depth() uint8 {
	return k.depth
}

func (k *ExtendedKey) ParentFingerprint() uint32 {
	return binary.BigEndian.Uint32(k.parentFP)
}

func zero(b []byte) {
	lenb := len(b)
	for i := 0; i < lenb; i++ {
		b[i] = 0
	}
}

func (k *ExtendedKey) Zero() {
	k.key = nil
	zero(k.privateKey[:])
	zero(k.publicKey[:])
	zero(k.parentFP)
	k.depth = 0
	k.childNum = 0
}

// String returns the extended key as a human-readable base58-encoded string.
func (k *ExtendedKey) String() string {
	if k.key == nil {
		return "zeroed extended key"
	}

	var childNumBytes [4]byte
	binary.BigEndian.PutUint32(childNumBytes[:], k.childNum)

	// The serialized format is:
	// depth (1) || parent fingerprint (4)) ||
	// child num (4) || key data (32) || checksum (4)
	serializedBytes := make([]byte, 0, serializedKeyLen+4)
	serializedBytes = append(serializedBytes, k.depth)
	serializedBytes = append(serializedBytes, k.parentFP...)
	serializedBytes = append(serializedBytes, childNumBytes[:]...)
	serializedBytes = append(serializedBytes, reverseBytes(toBytes(k.key, 32))...)

	checkSum := chainhash.DoubleHashB(serializedBytes)[:4]
	serializedBytes = append(serializedBytes, checkSum...)
	return base58.Encode(serializedBytes)
}

func (k *ExtendedKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

func (k *ExtendedKey) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	key, err := NewKeyFromString(s)
	if err != nil {
		return err
	}
	*k = *key
	return nil
}

// NewKeyFromString returns a new extended key instance from a base58-encoded
// extended key.
func NewKeyFromString(key string) (*ExtendedKey, error) {
	decoded := base58.Decode(key)
	if len(decoded) != serializedKeyLen+4 {
		return nil, ErrInvalidKeyLen
	}

	payload := decoded[:len(decoded)-4]
	checkSum := decoded[len(decoded)-4:]
	expectedCheckSum := chainhash.DoubleHashB(payload)[:4]
	if !bytes.Equal(checkSum, expectedCheckSum) {
		return nil, ErrBadChecksum
	}

	depth := payload[0]
	parentFP := payload[1:5]
	childNum := binary.BigEndian.Uint32(payload[5:9])
	privateKey := payload[9:41]

	return NewExtendedKey(privateKey, parentFP, depth, childNum), nil
}

func (k *ExtendedKey) Address() address.Address {
	k.PublicKey()
	addr, err := address.NewBLSAddress(k.publicKey[:])
	if err != nil {
		panic("invalid public key") // should never happen
	}
	return addr
}

func GenerateSeed(length uint8) ([]byte, error) {
	if length < MinSeedBytes || length > MaxSeedBytes {
		return nil, ErrInvalidSeedLen
	}

	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

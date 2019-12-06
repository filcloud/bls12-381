package bls12_381

import (
	"fmt"
	"math/big"
	"testing"
)

//noinspection ALL
type testCase struct {
	seed        string
	master_SK   string
	child_index uint32
	child_SK    string
}

var testCases = []testCase{
	{
		"0xc55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
		"12513733877922233913083619867448865075222526338446857121953625441395088009793",
		0,
		"7419543105316279183937430842449358701327973165530407166294956473095303972104",
	},
	{
		"0x3141592653589793238462643383279502884197169399375105820974944592",
		"46029459550803682895343812821003080589696405386150182061394330539196052371668",
		3141592653,
		"43469287647733616183478983885105537266268532274998688773496918571876759327260",
	},
	{
		"0x0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
		"45379166311535261329029945990467475187325618028073620882733843918126031931161",
		4294967295,
		"46475244006136701976831062271444482037125148379128114617927607151318277762946",
	},
	{
		"0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
		"31740500954810567003972734830331791822878290325762596213711963944729383643688",
		42,
		"51041472511529980987749393477251359993058329222191894694692317000136653813011",
	},
}

//noinspection ALL
func TestKeyDerivation(t *testing.T) {
	for i, c := range testCases {
		seed, ok := big.NewInt(0).SetString(c.seed, 0)
		if !ok {
			t.Errorf("test case %d, big.Int SetString failed", i)
		}

		master_SK, ok := big.NewInt(0).SetString(c.master_SK, 0)
		if !ok {
			t.Errorf("test case %d, big.Int SetString failed", i)
		}
		derived_master_SK, err := DeriveMasterSK(toBytes(seed, (len(c.seed)-2)/2))
		if err != nil {
			t.Errorf("test case %d, %s", i, err)
		}
		if derived_master_SK.Cmp(master_SK) != 0 {
			t.Errorf("test case %d, got %s; want %s", i, derived_master_SK, master_SK)
		}

		child_SK, ok := big.NewInt(0).SetString(c.child_SK, 0)
		if !ok {
			t.Errorf("test case %d, big.Int SetString failed", i)
		}
		derived_child_SK, err := DeriveChildSK(derived_master_SK, c.child_index)
		if err != nil {
			t.Errorf("test case %d, %s", i, err)
		}
		if derived_child_SK.Cmp(child_SK) != 0 {
			t.Errorf("test case %d, got %s; want %s", i, derived_child_SK, child_SK)
		}
		fmt.Printf("master len: %d, child len: %d\n", len(master_SK.Bytes()), len(child_SK.Bytes()))
	}
}

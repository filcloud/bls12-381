module github.com/filcloud/bls12-381

go 1.13

require (
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/btcsuite/btcutil v1.0.1
	github.com/filecoin-project/filecoin-ffi v0.0.0-20200226231125-fc253ccb5294
	github.com/filecoin-project/go-address v0.0.2-0.20200218010043-eb9bb40ed5be
	github.com/filecoin-project/specs-actors v0.0.0-20200302223606-0eaf97b10aaf // indirect
	github.com/ipfs/go-ipld-format v0.0.2 // indirect
	github.com/whyrusleeping/cbor-gen v0.0.0-20200223203819-95cdfde1438f // indirect
	golang.org/x/crypto v0.0.0-20200302210943-78000ba7a073
	golang.org/x/sys v0.0.0-20200302150141-5c8b2ff67527 // indirect
)

replace github.com/filecoin-project/filecoin-ffi => github.com/filcloud/filecoin-ffi v0.0.0-20200305084630-1217aa92d64a

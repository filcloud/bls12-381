module github.com/filcloud/bls12-381

go 1.13

require (
	github.com/btcsuite/btcd v0.0.0-20190824003749-130ea5bddde3
	github.com/btcsuite/btcutil v0.0.0-20190425235716-9e5f4b9a998d
	github.com/filecoin-project/filecoin-ffi v0.0.0-20191205025532-6d9e80001bfa
	github.com/filecoin-project/lotus v0.0.0-20191205112143-3673a9110fc4
	golang.org/x/crypto v0.0.0-20191202143827-86a70503ff7e
)

replace github.com/filecoin-project/lotus => ../../../../standalone/lotus

replace github.com/filecoin-project/filecoin-ffi => ../../../../standalone/lotus/extern/filecoin-ffi

package midnightverifier

import (
	"math/big"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/crypto"
	"github.com/ava-labs/subnet-evm/precompile/contract"
)

// Blobs (the verifier params and each verifying key) live in the precompile's own storage:
//
//	slot H(tag, id)       = len(blob) + 1   (0 = absent)
//	slot H(tag, id) + 1+i = 32-byte chunk i (last chunk right-padded with zeros)
//
// H is keccak256 over the tag and id, so the regions of different blobs never meet.
var (
	paramsTag = []byte("dpo2u.l1.midnight-verifier.params.v1")
	vkTag     = []byte("dpo2u.l1.midnight-verifier.vk.v1")
)

func blobBase(tag []byte, id common.Hash) common.Hash {
	return crypto.Keccak256Hash(tag, id[:])
}

func slotAt(base common.Hash, i int) common.Hash {
	n := new(big.Int).SetBytes(base[:])
	n.Add(n, big.NewInt(int64(i)))
	n.Mod(n, new(big.Int).Lsh(big.NewInt(1), 256))
	return common.BigToHash(n)
}

func words(n int) int { return (n + 31) / 32 }

// blobLen returns the stored length and whether the blob exists. One slot read.
func blobLen(state contract.StateReader, tag []byte, id common.Hash) (int, bool) {
	h := state.GetState(ContractAddress, blobBase(tag, id))
	v := new(big.Int).SetBytes(h[:])
	if v.Sign() == 0 {
		return 0, false
	}
	return int(v.Int64() - 1), true
}

func readBlob(state contract.StateReader, tag []byte, id common.Hash, n int) []byte {
	base := blobBase(tag, id)
	out := make([]byte, words(n)*32)
	for i := 0; i < words(n); i++ {
		w := state.GetState(ContractAddress, slotAt(base, 1+i))
		copy(out[i*32:], w[:])
	}
	return out[:n]
}

func writeBlob(state contract.StateDB, tag []byte, id common.Hash, data []byte) {
	base := blobBase(tag, id)
	state.SetState(ContractAddress, base, common.BigToHash(big.NewInt(int64(len(data))+1)))
	for i := 0; i < words(len(data)); i++ {
		var w common.Hash
		copy(w[:], data[i*32:min(len(data), (i+1)*32)])
		state.SetState(ContractAddress, slotAt(base, 1+i), w)
	}
}

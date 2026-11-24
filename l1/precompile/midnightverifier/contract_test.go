package midnightverifier

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/vm"
	"github.com/ava-labs/subnet-evm/core/extstate"
	"github.com/ava-labs/subnet-evm/precompile/precompiletest"
	"github.com/ava-labs/subnet-evm/utils"
	"github.com/stretchr/testify/require"
)

// vector is the k=12 membership proof from ../testdata, made with Midnight's own prover
// (midnight-zk, pinned rev) over an INSECURE test SRS.
type vector struct {
	params, vk, proof []byte
	publicInputs      []*big.Int
}

func loadVector(t testing.TB) vector { return loadVectorFrom(t, "membership-k12") }

func loadVectorFrom(t testing.TB, name string) vector {
	t.Helper()
	dir := filepath.Join("..", "testdata", name)
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		return b
	}
	var meta struct {
		PublicInputs []string `json:"publicInputs"`
	}
	require.NoError(t, json.Unmarshal(read("vector.json"), &meta))
	v := vector{params: read("params.bin"), vk: read("vk.bin"), proof: read("proof.bin")}
	for _, s := range meta.PublicInputs {
		x, ok := new(big.Int).SetString(s[2:], 16)
		require.True(t, ok)
		v.publicInputs = append(v.publicInputs, x)
	}
	return v
}

func cloneInts(xs []*big.Int) []*big.Int {
	out := make([]*big.Int, len(xs))
	for i, x := range xs {
		out[i] = new(big.Int).Set(x)
	}
	return out
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// BLS12-381 scalar field modulus r.
var blsR, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

func TestMidnightVerifierRun(t *testing.T) {
	v := loadVector(t)
	vkHash := VerifyingKeyHash(v.vk)
	cfg := NewConfig(utils.NewUint64(0), v.params)
	withKey := func(t testing.TB, state *extstate.StateDB) { writeBlob(state, vkTag, vkHash, v.vk) }
	verifyGas := func(nPI, proofLen int) uint64 {
		return VerifyGasCost + VerifyInputGas(len(v.vk), len(v.params), nPI, proofLen)
	}
	verifyInput := func(t testing.TB, proof []byte, pis []*big.Int) []byte {
		return must(PackVerify(VerifyInput{VkHash: vkHash, Proof: proof, PublicInputs: pis}))
	}
	tampered := append([]byte{}, v.proof...)
	tampered[len(tampered)/2] ^= 1
	changedPI := cloneInts(v.publicInputs)
	changedPI[1].SetUint64(0x80) // claim membership in other sets
	nonCanonical := cloneInts(v.publicInputs)
	nonCanonical[0].Add(nonCanonical[0], blsR) // same value mod r: must be refused, not reduced

	tests := []precompiletest.PrecompileTest{
		{
			Name:        "registerVerifyingKey stores the key and returns its keccak",
			Caller:      common.Address{1},
			Config:      cfg,
			InputFn:     func(t testing.TB) []byte { return must(PackRegisterVerifyingKey(v.vk)) },
			SuppliedGas: RegisterVerifyingKeyGasCost + RegisterStoreGas(len(v.vk)),
			ExpectedRes: must(PackRegisterVerifyingKeyOutput(vkHash)),
			AfterHook: func(t testing.TB, state *extstate.StateDB) {
				n, ok := blobLen(state, vkTag, vkHash)
				require.True(t, ok)
				require.Equal(t, v.vk, readBlob(state, vkTag, vkHash, n))
				logs := state.Logs()
				require.Len(t, logs, 1)
				require.Equal(t, vkHash, logs[0].Topics[1])
			},
		},
		{
			Name:        "registering the same key again only pays the base cost",
			Caller:      common.Address{2},
			Config:      cfg,
			BeforeHook:  withKey,
			InputFn:     func(t testing.TB) []byte { return must(PackRegisterVerifyingKey(v.vk)) },
			SuppliedGas: RegisterVerifyingKeyGasCost,
			ExpectedRes: must(PackRegisterVerifyingKeyOutput(vkHash)),
		},
		{
			Name:        "a key that does not parse is refused",
			Caller:      common.Address{1},
			Config:      cfg,
			InputFn:     func(t testing.TB) []byte { return must(PackRegisterVerifyingKey(v.vk[:len(v.vk)-1])) },
			SuppliedGas: RegisterVerifyingKeyGasCost,
			ExpectedErr: "invalid verifying key",
		},
		{
			Name:        "readOnly registerVerifyingKey should fail",
			Caller:      common.Address{1},
			InputFn:     func(t testing.TB) []byte { return must(PackRegisterVerifyingKey(v.vk)) },
			SuppliedGas: RegisterVerifyingKeyGasCost,
			ReadOnly:    true,
			ExpectedErr: vm.ErrWriteProtection.Error(),
		},
		{
			Name:        "insufficient gas for registerVerifyingKey should fail",
			Caller:      common.Address{1},
			InputFn:     func(t testing.TB) []byte { return must(PackRegisterVerifyingKey(v.vk)) },
			SuppliedGas: RegisterVerifyingKeyGasCost - 1,
			ExpectedErr: vm.ErrOutOfGas.Error(),
		},
		{
			Name:        "insufficient gas to store a new key should fail",
			Caller:      common.Address{1},
			Config:      cfg,
			InputFn:     func(t testing.TB) []byte { return must(PackRegisterVerifyingKey(v.vk)) },
			SuppliedGas: RegisterVerifyingKeyGasCost + RegisterStoreGas(len(v.vk)) - 1,
			ExpectedErr: vm.ErrOutOfGas.Error(),
		},
		{
			Name:        "isRegistered is true for a stored key",
			Caller:      common.Address{1},
			Config:      cfg,
			BeforeHook:  withKey,
			InputFn:     func(t testing.TB) []byte { return must(PackIsRegistered(vkHash)) },
			SuppliedGas: IsRegisteredGasCost,
			ReadOnly:    true,
			ExpectedRes: must(PackIsRegisteredOutput(true)),
		},
		{
			Name:        "isRegistered is false for an unknown key",
			Caller:      common.Address{1},
			InputFn:     func(t testing.TB) []byte { return must(PackIsRegistered([32]byte{9})) },
			SuppliedGas: IsRegisteredGasCost,
			ReadOnly:    true,
			ExpectedRes: must(PackIsRegisteredOutput(false)),
		},
		{
			Name:        "insufficient gas for isRegistered should fail",
			Caller:      common.Address{1},
			InputFn:     func(t testing.TB) []byte { return must(PackIsRegistered(vkHash)) },
			SuppliedGas: IsRegisteredGasCost - 1,
			ExpectedErr: vm.ErrOutOfGas.Error(),
		},
		{
			Name:        "verify accepts the Midnight proof",
			Caller:      common.Address{1},
			Config:      cfg,
			BeforeHook:  withKey,
			InputFn:     func(t testing.TB) []byte { return verifyInput(t, v.proof, v.publicInputs) },
			SuppliedGas: verifyGas(len(v.publicInputs), len(v.proof)),
			ReadOnly:    true,
			ExpectedRes: must(PackVerifyOutput(true)),
		},
		{
			Name:        "verify rejects a tampered proof",
			Caller:      common.Address{1},
			Config:      cfg,
			BeforeHook:  withKey,
			InputFn:     func(t testing.TB) []byte { return verifyInput(t, tampered, v.publicInputs) },
			SuppliedGas: verifyGas(len(v.publicInputs), len(tampered)),
			ReadOnly:    true,
			ExpectedRes: must(PackVerifyOutput(false)),
		},
		{
			Name:        "verify rejects a changed public input",
			Caller:      common.Address{1},
			Config:      cfg,
			BeforeHook:  withKey,
			InputFn:     func(t testing.TB) []byte { return verifyInput(t, v.proof, changedPI) },
			SuppliedGas: verifyGas(len(changedPI), len(v.proof)),
			ReadOnly:    true,
			ExpectedRes: must(PackVerifyOutput(false)),
		},
		{
			Name:        "verify rejects a truncated proof",
			Caller:      common.Address{1},
			Config:      cfg,
			BeforeHook:  withKey,
			InputFn:     func(t testing.TB) []byte { return verifyInput(t, v.proof[:100], v.publicInputs) },
			SuppliedGas: verifyGas(len(v.publicInputs), 100),
			ReadOnly:    true,
			ExpectedRes: must(PackVerifyOutput(false)),
		},
		{
			Name:        "verify refuses a non-canonical public input",
			Caller:      common.Address{1},
			Config:      cfg,
			BeforeHook:  withKey,
			InputFn:     func(t testing.TB) []byte { return verifyInput(t, v.proof, nonCanonical) },
			SuppliedGas: verifyGas(len(nonCanonical), len(v.proof)),
			ReadOnly:    true,
			ExpectedErr: "not a canonical",
		},
		{
			Name:        "verify refuses the wrong number of public inputs",
			Caller:      common.Address{1},
			Config:      cfg,
			BeforeHook:  withKey,
			InputFn:     func(t testing.TB) []byte { return verifyInput(t, v.proof, v.publicInputs[:1]) },
			SuppliedGas: verifyGas(1, len(v.proof)),
			ReadOnly:    true,
			ExpectedErr: "wrong number of public inputs",
		},
		{
			Name:        "verify refuses an unregistered key",
			Caller:      common.Address{1},
			Config:      cfg,
			InputFn:     func(t testing.TB) []byte { return verifyInput(t, v.proof, v.publicInputs) },
			SuppliedGas: VerifyGasCost,
			ReadOnly:    true,
			ExpectedErr: ErrUnknownVerifyingKey.Error(),
		},
		{
			Name:        "verify refuses without configured params",
			Caller:      common.Address{1},
			BeforeHook:  withKey,
			InputFn:     func(t testing.TB) []byte { return verifyInput(t, v.proof, v.publicInputs) },
			SuppliedGas: VerifyGasCost,
			ReadOnly:    true,
			ExpectedErr: ErrNoParams.Error(),
		},
		{
			Name:        "verify with other params rejects the proof",
			Caller:      common.Address{1},
			Config:      NewConfig(utils.NewUint64(0), otherParams(t, v.params)),
			BeforeHook:  withKey,
			InputFn:     func(t testing.TB) []byte { return verifyInput(t, v.proof, v.publicInputs) },
			SuppliedGas: verifyGas(len(v.publicInputs), len(v.proof)),
			ReadOnly:    true,
			ExpectedRes: must(PackVerifyOutput(false)),
		},
		{
			Name:        "insufficient gas for verify should fail",
			Caller:      common.Address{1},
			Config:      cfg,
			BeforeHook:  withKey,
			InputFn:     func(t testing.TB) []byte { return verifyInput(t, v.proof, v.publicInputs) },
			SuppliedGas: verifyGas(len(v.publicInputs), len(v.proof)) - 1,
			ReadOnly:    true,
			ExpectedErr: vm.ErrOutOfGas.Error(),
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) { test.Run(t, Module) })
	}
}

// otherParams returns valid verifier params of another SRS: the generator of G2 (tau = 1), taken
// from the Rust crate's test helper so that it is a real point. Falls back to skipping.
func otherParams(t testing.TB, params []byte) []byte {
	b, err := os.ReadFile(filepath.Join("..", "testdata", "membership-k12", "other-params.bin"))
	if err != nil {
		t.Skip("testdata/membership-k12/other-params.bin missing")
	}
	require.NotEqual(t, params, b)
	return b
}

// TestStellarFixtureProof: the proofs the Soroban verifier was built against (Stellar
// thread, Midnight SRS bls_midnight_2p14 = the real [tau]_2) is accepted through the precompile too.
func TestStellarFixtureProof(t *testing.T) {
	// poseidon: zk-stdlib relation; zkir-hash and escrow-context: Compact circuits (ZKIR v2) proved
	// by the Midnight ledger's own prover, key taken from the ledger's VerifierKey.
	for _, name := range []string{"poseidon-k6-midnight", "zkir-hash", "escrow-context"} {
		t.Run(name, func(t *testing.T) { stellarFixture(t, name) })
	}
}

func stellarFixture(t *testing.T, name string) {
	v := loadVectorFrom(t, name)
	vkHash := VerifyingKeyHash(v.vk)
	bad := cloneInts(v.publicInputs)
	bad[0].Xor(bad[0], big.NewInt(1))
	for _, c := range []struct {
		name string
		pis  []*big.Int
		want bool
	}{{"accepts", v.publicInputs, true}, {"rejects another statement", bad, false}} {
		test := precompiletest.PrecompileTest{
			Name:        c.name,
			Caller:      common.Address{1},
			Config:      NewConfig(utils.NewUint64(0), v.params),
			BeforeHook:  func(t testing.TB, state *extstate.StateDB) { writeBlob(state, vkTag, vkHash, v.vk) },
			Input:       must(PackVerify(VerifyInput{VkHash: vkHash, Proof: v.proof, PublicInputs: c.pis})),
			SuppliedGas: VerifyGasCost + VerifyInputGas(len(v.vk), len(v.params), len(c.pis), len(v.proof)),
			ReadOnly:    true,
			ExpectedRes: must(PackVerifyOutput(c.want)),
		}
		t.Run(c.name, func(t *testing.T) { test.Run(t, Module) })
	}
}

// TestVerifyGasCalibration checks that the base verify cost stays above what native verification
// takes at a conservative 20 Mgas/s, the rate geth-style pricing targets.
func TestVerifyGasCalibration(t *testing.T) {
	v := loadVector(t)
	pi := make([]byte, 0, 64)
	for _, x := range v.publicInputs {
		w := common.BigToHash(x)
		pi = append(pi, w[:]...)
	}
	const runs = 20
	start := time.Now()
	for i := 0; i < runs; i++ {
		ok, err := nativeVerify(v.params, v.vk, pi, v.proof)
		require.NoError(t, err)
		require.True(t, ok)
	}
	perCall := time.Since(start) / runs
	gasAt20M := uint64(perCall.Seconds() * 20_000_000)
	t.Logf("native verify %v per call, about %d gas at 20 Mgas/s (base cost %d)", perCall, gasAt20M, VerifyGasCost)
	require.Less(t, gasAt20M, VerifyGasCost)
}

func TestPackUnpackVerifyingKeyRegisteredEventData(t *testing.T) {
	dataInput := VerifyingKeyRegisteredEventData{Size: big.NewInt(1276)}
	_, data, err := PackVerifyingKeyRegisteredEvent([32]byte{1}, dataInput)
	require.NoError(t, err)
	unpacked, err := UnpackVerifyingKeyRegisteredEventData(data)
	require.NoError(t, err)
	require.Equal(t, dataInput, unpacked)
}

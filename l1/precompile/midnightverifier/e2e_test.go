package midnightverifier_test

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	ethereum "github.com/ava-labs/libevm"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"
	"github.com/ava-labs/subnet-evm/eth/ethconfig"
	"github.com/ava-labs/subnet-evm/ethclient/simulated"
	"github.com/ava-labs/subnet-evm/node"
	"github.com/ava-labs/subnet-evm/params"
	"github.com/ava-labs/subnet-evm/utils"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/subnet-evm/plugin/evm"

	mv "github.com/fredericosanntana/dpo2u-avalanche/l1/precompile/midnightverifier"
)

// TestMain registers Subnet-EVM's libevm extras, as the VM's main does.
func TestMain(m *testing.M) {
	evm.RegisterAllLibEVMExtras()
	os.Exit(m.Run())
}

// TestEndToEndOnSubnetEVM runs the precompile inside a real Subnet-EVM chain (simulated backend):
// enabled from genesis with Midnight's Filecoin [tau]_2, a key registered by a signed transaction,
// and the Stellar fixture proof verified through eth_call.
func TestEndToEndOnSubnetEVM(t *testing.T) {
	dir := filepath.Join("..", "testdata", "poseidon-k6-filecoin")
	read := func(n string) []byte { b, err := os.ReadFile(filepath.Join(dir, n)); require.NoError(t, err); return b }
	verifierParams, vk, proof := read("params.bin"), read("vk.bin"), read("proof.bin")
	var meta struct{ PublicInputs []string }
	require.NoError(t, json.Unmarshal(read("vector.json"), &meta))
	pi, _ := new(big.Int).SetString(meta.PublicInputs[0][2:], 16)

	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	from := crypto.PubkeyToAddress(key.PublicKey)
	funds := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	sim := simulated.NewBackend(types.GenesisAlloc{from: {Balance: funds}}, func(_ *node.Config, c *ethconfig.Config) {
		params.GetExtra(c.Genesis.Config).GenesisPrecompiles[mv.ConfigKey] = mv.NewConfig(utils.NewUint64(0), verifierParams)
	})
	defer sim.Close()
	client := sim.Client()
	ctx := context.Background()

	// Register the key with a signed transaction.
	data, err := mv.PackRegisterVerifyingKey(vk)
	require.NoError(t, err)
	chainID, err := client.ChainID(ctx)
	require.NoError(t, err)
	gasPrice, err := client.SuggestGasPrice(ctx)
	require.NoError(t, err)
	to := mv.ContractAddress
	gas, err := client.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &to, Data: data})
	require.NoError(t, err)
	tx := types.NewTx(&types.LegacyTx{Nonce: 0, To: &to, Gas: gas, GasPrice: gasPrice, Data: data})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), key)
	require.NoError(t, err)
	require.NoError(t, client.SendTransaction(ctx, signed))
	sim.Commit(true)
	receipt, err := client.TransactionReceipt(ctx, signed.Hash())
	require.NoError(t, err)
	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)
	require.Len(t, receipt.Logs, 1)
	vkHash := mv.VerifyingKeyHash(vk)
	require.Equal(t, vkHash, receipt.Logs[0].Topics[1])
	t.Logf("registerVerifyingKey: %d gas for a %d-byte key", receipt.GasUsed, len(vk))

	call := func(pis []*big.Int) (bool, uint64) {
		in, err := mv.PackVerify(mv.VerifyInput{VkHash: vkHash, Proof: proof, PublicInputs: pis})
		require.NoError(t, err)
		msg := ethereum.CallMsg{From: from, To: &to, Data: in}
		out, err := client.CallContract(ctx, msg, nil)
		require.NoError(t, err)
		ok, err := mv.UnpackVerifyOutput(out)
		require.NoError(t, err)
		g, err := client.EstimateGas(ctx, msg)
		require.NoError(t, err)
		return ok, g
	}
	ok, g := call([]*big.Int{pi})
	require.True(t, ok, "the Midnight proof verifies on chain")
	t.Logf("verify: %d gas (estimate, incl. 21k intrinsic and calldata)", g)
	ok, _ = call([]*big.Int{new(big.Int).Add(pi, big.NewInt(1))})
	require.False(t, ok, "another statement is rejected")
}

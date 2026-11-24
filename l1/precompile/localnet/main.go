// Command localnet starts a local Avalanche network (tmpnet, AvalancheGo v1.14.0) with the DPO2U
// L1: the genesis from l1/genesis with test addresses filled in, run by the DPO2U VM build
// (l1/precompile, Subnet-EVM + MidnightVerifier precompile). Test only: the keys below are the
// well-known Hardhat development keys.
//
//	AVALANCHEGO_PATH=/path/to/avalanchego go run ./localnet start   # prints the L1 RPC URL
//	go run ./localnet stop
//	go run ./localnet vmid                                          # plugin file name
//	DPO2U_RELAYER_KEY=0x.. go run ./localnet relay <src rpc> <dst rpc> <tx> <teleporter>  # ICM delivery
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ava-labs/avalanchego/config"
	"github.com/ava-labs/avalanchego/tests/fixture/tmpnet"
	"github.com/ava-labs/avalanchego/utils/logging"
	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/ethclient"
	"github.com/ava-labs/subnet-evm/plugin/evm"
)

// Hardhat development accounts #0..#2 (public test keys, never use outside a local network).
const (
	deployer   = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	safe       = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" // stands in for the L1 Safe 2-of-3
	icmRelayer = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
	chainID    = 432_100 // local only
)

// Funded with 100 AVAX each on the local C-Chain: deployer #0, relayer #2, Teleporter deployer #5.
var cchainFunded = []string{deployer, icmRelayer, "0x9965507D1a55bcC2695C58bA16FB37d819B0A4dc"}

func genesis(templatePath string) ([]byte, error) {
	b, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, err
	}
	s := string(b)
	r := strings.NewReplacer(
		`"__CHAIN_ID__"`, fmt.Sprint(chainID),
		"__SAFE__", safe,
		"__DEPLOYER_NO_0X__", strings.TrimPrefix(deployer, "0x"),
		"__ICM_RELAYER_NO_0X__", strings.TrimPrefix(icmRelayer, "0x"),
		"__DEPLOYER__", deployer,
		"__ICM_RELAYER__", icmRelayer,
		`"__WARP_ACTIVATION_UNIX__"`, fmt.Sprint(time.Now().Unix()),
	)
	s = r.Replace(s)
	var g map[string]any
	if err := json.Unmarshal([]byte(s), &g); err != nil {
		return nil, err
	}
	delete(g, "_comment")
	// The Safe needs gas to call setManager on the AllowList.
	g["alloc"].(map[string]any)[strings.TrimPrefix(safe, "0x")] = map[string]any{"balance": "0x3635C9ADC5DEA00000"}
	return json.Marshal(g)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: localnet start|stop")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	log := logging.NewLogger("localnet", logging.NewWrappedCore(logging.Info, os.Stderr, logging.Colors.ConsoleEncoder()))
	here, _ := os.Getwd()
	root := filepath.Join(here, "build", "localnet-state")
	stateFile := filepath.Join(root, "network-dir")

	switch os.Args[1] {
	case "vmid":
		fmt.Println(evm.ID)
	case "start":
		g, err := genesis(filepath.Join(here, "..", "genesis", "dpo2u-l1.genesis.template.json"))
		must(err)
		// The plugin dir must hold the DPO2U VM binary under the Subnet-EVM VM ID (see vmid).
		pluginDir := filepath.Join(here, "build", "plugins")
		nodes := tmpnet.NewNodesOrPanic(2)
		subnet := &tmpnet.Subnet{
			Name: "dpo2u",
			Chains: []*tmpnet.Chain{{
				VMID:    evm.ID,
				Genesis: g,
				Config:  `{"log-level":"info","warp-api-enabled":true}`,
			}},
			ValidatorIDs: tmpnet.NodesToIDs(nodes...),
		}
		network := &tmpnet.Network{
			Owner:   "dpo2u-l1-localnet",
			Nodes:   nodes,
			Subnets: []*tmpnet.Subnet{subnet},
			DefaultFlags: tmpnet.FlagsMap{
				config.ProposerVMUseCurrentHeightKey: "true",
				config.FdLimitKey:                    "16384",
				// Two nodes, not one: tmpnet turns sybil protection off on a one-node network, and then
				// every chain sees an EMPTY validator set, so Warp (ICM) cannot verify anything. With
				// two validators sybil protection stays on; k = 1 keeps consensus quick.
				config.SnowSampleSizeKey:           "1",
				config.SnowPreferenceQuorumSizeKey: "1",
				config.SnowConfidenceQuorumSizeKey: "1",
				config.SnowCommitThresholdKey:      "1",
				config.SnowConcurrentRepollsKey:    "1",
			},
			DefaultRuntimeConfig: tmpnet.NodeRuntimeConfig{Process: &tmpnet.ProcessRuntimeConfig{
				AvalancheGoPath: os.Getenv("AVALANCHEGO_PATH"),
				PluginDir:       pluginDir,
			}},
		}
		must(os.MkdirAll(root, 0o755))
		must(tmpnet.BootstrapNewNetwork(ctx, log, network, root))
		must(os.WriteFile(stateFile, []byte(network.Dir), 0o644))
		uri := network.Nodes[0].URI
		rpc := fmt.Sprintf("%s/ext/bc/%s/rpc", uri, network.Subnets[0].Chains[0].ChainID)
		must(os.WriteFile(filepath.Join(root, "rpc-url"), []byte(rpc), 0o644))
		// Local C-Chain (primary network): fund the Hardhat dev accounts used by the A4 ICM demo
		// from tmpnet's pre-funded key.
		cRPC := uri + "/ext/bc/C/rpc"
		c, err := ethclient.DialContext(ctx, cRPC)
		must(err)
		funder := network.PreFundedKeys[0].ToECDSA()
		hundred := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
		for _, a := range cchainFunded {
			to := common.HexToAddress(a)
			_, err := send(ctx, c, funder, &to, hundred, nil, nil)
			must(err)
		}
		must(os.WriteFile(filepath.Join(root, "cchain-rpc-url"), []byte(cRPC), 0o644))
		fmt.Println(rpc)
	case "relay":
		if len(os.Args) != 6 {
			fmt.Fprintln(os.Stderr, "usage: localnet relay <src rpc> <dst rpc> <tx hash> <teleporter>  (key in DPO2U_RELAYER_KEY)")
			os.Exit(2)
		}
		must(relay(ctx, os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Getenv("DPO2U_RELAYER_KEY")))
	case "stop":
		dir, err := os.ReadFile(stateFile)
		must(err)
		must(tmpnet.StopNetwork(ctx, log, string(dir)))
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "localnet:", err)
		os.Exit(1)
	}
}

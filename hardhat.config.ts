import { HardhatUserConfig, subtask } from "hardhat/config";
import { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD } from "hardhat/builtin-tasks/task-names";
import "@nomicfoundation/hardhat-toolbox";
import "dotenv/config";
import path from "node:path";

const SOLC_VERSION = "0.8.20"; // pinned: the vendored SP1 Groth16Verifier requires exactly 0.8.20

// Use the solcjs build shipped in the `solc` npm package instead of downloading a
// compiler at build time (reproducible, works behind restrictive proxies).
subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, async (args: { solcVersion: string }, _hre, runSuper) => {
  if (args.solcVersion === SOLC_VERSION) {
    const compilerPath = path.join(__dirname, "node_modules", "solc", "soljson.js");
    return { compilerPath, isSolcJs: true, version: args.solcVersion, longVersion: "0.8.20+commit.a1b79de6" };
  }
  return runSuper();
});

const accounts = process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [];

const config: HardhatUserConfig = {
  solidity: { version: SOLC_VERSION, settings: { optimizer: { enabled: true, runs: 200 } } },
  networks: {
    // Local DPO2U L1 started by l1/precompile/localnet (tmpnet). Hardhat's public development
    // keys #0..#3 (deployer, stand-in Safe, ICM relayer, subject): local network only.
    dpo2uLocal: {
      url: process.env.DPO2U_L1_RPC || "http://127.0.0.1:9650/ext/bc/dpo2u/rpc",
      chainId: 432100,
      accounts: [
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
        "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
      ],
    },
    fuji: {
      url: process.env.FUJI_RPC_URL || "https://api.avax-test.network/ext/bc/C/rpc",
      chainId: 43113,
      accounts,
    },
    avalanche: {
      url: process.env.AVALANCHE_RPC_URL || "https://api.avax.network/ext/bc/C/rpc",
      chainId: 43114,
      accounts,
    },
  },
  etherscan: {
    // Snowtrace (Routescan) verification for Fuji and C-Chain; Routescan needs no paid key.
    apiKey: { fuji: "snowtrace", avalanche: "snowtrace" },
    customChains: [
      {
        network: "fuji",
        chainId: 43113,
        urls: {
          apiURL: "https://api.routescan.io/v2/network/testnet/evm/43113/etherscan",
          browserURL: "https://testnet.snowtrace.io",
        },
      },
      {
        network: "avalanche",
        chainId: 43114,
        urls: {
          apiURL: "https://api.routescan.io/v2/network/mainnet/evm/43114/etherscan",
          browserURL: "https://snowtrace.io",
        },
      },
    ],
  },
  sourcify: { enabled: false },
};

export default config;

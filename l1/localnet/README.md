# DPO2U L1 on a local network (phase A3)

`a3-local-e2e.ts` runs the whole admission path on a real AvalancheGo v1.14.0 node, running the DPO2U VM
(Subnet-EVM v0.8.0 plus the MidnightVerifier precompile):

1. The Transaction AllowList blocks an unknown wallet.
2. The verifying key of a Midnight circuit is registered in the precompile.
3. The ComplianceGate (A1) is deployed and the Safe makes it Manager of the AllowList.
4. A relayer submits a Midnight proof. The precompile verifies it on chain and the gate enables the
   wallet. A tampered proof (`InvalidProof`), a replayed nonce (`NonceUsed`) and a proof bound to
   another chain (`WrongChain`) are refused.
5. The admitted wallet can now transact.
6. The Safe revokes it, and the VM blocks it again.

## Run it

```sh
# AvalancheGo v1.14.0 binary: https://github.com/ava-labs/avalanchego/releases/tag/v1.14.0
cd l1/precompile
./build-ffi.sh
(cd midnight-verifier-ffi && cargo build --release --bin prove-gate-v0)
mkdir -p build/plugins && go build -o build/plugins/$(go run ./localnet vmid) ./plugin
AVALANCHEGO_PATH=/path/to/avalanchego go run ./localnet start   # prints the L1 RPC URL
cd ../..
DPO2U_L1_RPC=$(cat l1/precompile/build/localnet-state/rpc-url) \
MIDNIGHT_SRS=<midnight-transient-crypto-3.1.0>/static/bls_midnight_2p14 \
  npx hardhat run l1/localnet/a3-local-e2e.ts --network dpo2uLocal
(cd l1/precompile && go run ./localnet stop)
```

`localnet` fills the genesis template with Hardhat's public development keys:

| Key | Role |
|---|---|
| #0 | deployer |
| #1 | stand-in for the Safe |
| #2 | ICM relayer |
| #3 | subject |

It sets chain id 432100 and uses the current time as the Warp activation. These keys and this
chain are for local use only.

## Result (2026-11-24)

| Step | Gas |
|---|---|
| `registerVerifyingKey` (1,229 B key) | 1,033,177 |
| `admit` (gate + precompile verify + AllowList) | ~987,800 |

Both fit in the 15M block gas limit.

## What the proof is, and is not

`prove-gate-v0` is a **test circuit**. It has the gate's 15 public inputs (layout v0) and only
constrains `pass == 1`. It is a genuine Midnight proof (zk-stdlib 2.4.0, Midnight SRS), so this run
exercises the real verifier, precompile, gate and AllowList. It proves nothing about Travel Rule
compliance: **never pin its key in a real policy.** The next step replaces it with the TravelRuleGate
`evaluateTransfer` proof (k=17) and maps that statement onto the gate's layout.

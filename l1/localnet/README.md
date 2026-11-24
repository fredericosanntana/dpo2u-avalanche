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
7. The **real TravelRuleGate v12 `evaluateTransfer` proof** from a Midnight preview capture goes
   through the gate's Midnight statement lane. The precompile verifies it, and
   `checkMidnight(policy, capture transfer_id, proof, statement)` returns true. A FAIL verdict
   (`PinMismatch`), a statement changed outside the pins (`InvalidProof`) and an admission for a
   wallet the capture was not made for (`ContextMismatch`) are refused.

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
| #3 | subject (seller in the DvP run) |
| #4 | buyer in the DvP run |

It sets chain id 432100 and uses the current time as the Warp activation. These keys and this
chain are for local use only.

## Result (2026-11-24)

| Step | Gas |
|---|---|
| `registerVerifyingKey` (1,229 B key) | 1,033,177 |
| `admit` (gate + precompile verify + AllowList) | ~987,800 |
| `registerVerifyingKey` (real `evaluateTransfer` key, 2,285 B) | 1,718,449 |
| `checkMidnight`, real proof, 417 statement values (estimate, incl. calldata) | 2,099,001 |

Both fit in the 15M block gas limit.

## The Midnight statement lane

`admitMidnight(policyId, subject, nonce, proof, statement)` takes the circuit's real statement,
following the same model as the Stellar escrow gate. The Safe pins the following per policy, and
any other change is caught by the proof:

- the statement length;
- the values at fixed positions:
  - verdict `status = 1` (PASS) and `fail_reason = 0`;
  - policy hash;
  - sanctions list root;
  - pepper commitment;
  - provider;
- the list's `issued_at` (checked against `minIssuedAt`, the stale-list fix) and `valid_until`
  (which caps the admission).

Positions are 0-based. A Compact `Bytes<32>` is two values, `[byte 31, bytes 0..30 LE]`.
Statement map for v12:

| Value | Position |
|---|---|
| `transfer_id` | 202 |
| `status` | 208 |
| `fail_reason` | 228 |
| policy hash | 290 |
| list root | 311 |
| pepper commitment | 373 |
| provider | 114 |
| `valid_until` | 353 |
| `issued_at` | 394 |

The wallet is bound through `transfer_id`. The VASP evaluates on Midnight with
`transfer_id = gate.admissionContext(subject, nonce)`, which is
`keccak256(domain, chain id, gate, subject, nonce)`. The capture used here was made with another
`transfer_id`, so it can be checked but cannot admit a wallet. Admitting one with a real proof
needs a new evaluate on Midnight preview with that context.

## What the layout-v0 proof is, and is not

`prove-gate-v0` is a **test circuit**. It has the gate's 15 public inputs (layout v0) and only
constrains `pass == 1`. It is a genuine Midnight proof (zk-stdlib 2.4.0, Midnight SRS), so this run
exercises the real verifier, precompile, gate and AllowList. It proves nothing about Travel Rule
compliance: **never pin its key in a real policy.** The next step replaces it with the TravelRuleGate
`evaluateTransfer` proof (k=17) and maps that statement onto the gate's layout.

## CVM test token with delivery vs payment (`a3-cvm-dvp-local-e2e.ts`)

Same network, same run steps, other script. Contracts in `contracts/l1/cvm/`:

- `DPO2UL1SecurityToken`: a TEST security token (not an offer, no legal effect). Every mint and
  transfer requires the receiver, and the sender, to hold a gate admission right now. That adds to
  the AllowList: it also blocks receiving, and it blocks an admission that expired but was not yet
  removed. The issuer can pause, redeem, and make a logged `controllerTransfer` (court order) to an
  admitted wallet.
- `DPO2UL1TestCash`: test BRL (2 decimals).
- `DPO2UL1DvP`: the seller proposes, the named buyer settles. Both legs move in one transaction or
  neither does. The contract holds no tokens.

Run (2026-11-24): two wallets admitted by Midnight proof; mint and transfer to a non-admitted
wallet refused (`NotAdmitted`); trade of 10 units for R$ 250.00 settled in one tx (144,225 gas);
after the gate froze the buyer, a second trade could not settle and nothing moved.

Data protection (LGPD/GDPR): on chain there are only wallets, amounts and hashes (terms, trade
confirmation, court-order reference). The person behind a wallet, the KYC file and the Travel
Rule data stay with the VASP and the issuer.

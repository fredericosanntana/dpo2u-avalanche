# DPO2U on Avalanche

English · [Português](README.pt-BR.md)

Compliance-as-code seal for institutions, banks and VASPs on Avalanche C-Chain (Fuji testnet first). Part of the DPO2U stack already running on Midnight, Solana and Stellar.

What is here (phase 0 and the core of phase 1):

| Piece | File | What it does |
|---|---|---|
| Interface spec | `contracts/interfaces/IDPO2UAttestation.sol`, `docs/SPEC.md` | chain-neutral attestation model: PASS/FAIL/REVIEW, verdict origin, pack hash, mandatory expiry |
| Registry | `contracts/DPO2UComplianceRegistry.sol` | the seal. Use cases, authorized submitters, revocation, `isValid` / `isSubjectCompliant` oracle |
| ZK attestor | `contracts/DPO2UZkThresholdAttestor.sol` | verifies the DPO2U SP1 v6.1.0 Groth16 proof of `score ≥ threshold` (the same proof verified on Solana) and seals a MACHINE-origin PASS. The score never touches the chain |
| Passport oracle | `contracts/DPO2UPassportOracle.sol` | PSAV conformity passport per subject and pack (tier, status, mandatory expiry), issued only on top of a usable registry seal. Any contract asks `isValid` / `isAccountValid` before dealing with a counterparty. Example: `contracts/examples/PassportGatedSettlement.sol` |
| SP1 verifier | `contracts/vendor/sp1/` | vendored, unmodified, from [succinctlabs/sp1-contracts](https://github.com/succinctlabs/sp1-contracts) tag `v6.1.0` (MIT) |
| SDK | `src/` | `AvalancheChainAnchor`, shape-compatible with the DPO2U control-plane `ChainAnchorPort`; Avalanche networks in CAIP-2 |

## Run

```bash
npm install
npm test          # 41 tests, including the real SP1 proof
npm run gas
```

The compiler is the `solc@0.8.20` npm package (solcjs), so nothing is downloaded at build time. 0.8.20 is pinned because the vendored SP1 Groth16 verifier requires it.

Measured gas on the local network: `registerAttestation` about 194k, `submitProof` (Groth16 verify + seal) about 412k.

## Deploy to Fuji

```bash
cp .env.example .env   # PRIVATE_KEY of a funded Fuji account
npm run deploy:fuji    # writes deployments/fuji.json
```

The deployer becomes the admin. The passport oracle goes on top of an existing registry with `npm run deploy:passport:fuji` (reads and updates `deployments/fuji.json`; `PASSPORT_ISSUER` authorizes an issuer). Set `ADMIN_ADDRESS` to start a two-step transfer to a multisig, which must then call `acceptAdmin()`.

## Invariants

REVIEW and FAIL are never valid. Every seal expires. A seal is written once. The ZK attestor's verifier and program key are immutable. Without a signer or RPC, the anchor throws instead of faking a receipt, so the control plane records REVIEW. Details in `docs/SPEC.md`.

## Fixture

`test/fixtures/` holds the proof from `dpo2u-solana/zk-circuits/proofs` (commit `e8c09e7`): threshold 70, subject commitment of `did:test:company:acme`, program vkey `0x00a79ec5…b414`.

## License

MIT

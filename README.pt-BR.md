# DPO2U na Avalanche

[English](README.md) · Português

Selo de compliance-as-code para instituições, bancos e PSAVs na Avalanche C-Chain (Fuji primeiro). Faz parte da stack DPO2U que já roda em Midnight, Solana e Stellar.

## O que tem aqui

| Peça | Arquivo | O que faz |
|---|---|---|
| Especificação da interface | `contracts/interfaces/IDPO2UAttestation.sol`, `docs/SPEC.pt-BR.md` | modelo de atestação neutro de rede: PASS/FAIL/REVIEW, origem do veredito, hash do pack e validade obrigatória |
| Registry | `contracts/DPO2UComplianceRegistry.sol` | o selo. Use cases, submitters autorizados, revogação e o oráculo `isValid` / `isSubjectCompliant` |
| Atestador ZK | `contracts/DPO2UZkThresholdAttestor.sol` | verifica a prova SP1 v6.1.0 Groth16 da DPO2U de `score ≥ threshold` (a mesma prova verificada no Solana) e sela um PASS de origem MACHINE. O score nunca vai para a chain |
| Oráculo de passaporte | `contracts/DPO2UPassportOracle.sol` | passaporte de conformidade PSAV por sujeito e pack (tier, status, validade obrigatória), emitido só em cima de um selo utilizável do registry (PASS, ou REVIEW para tier1-machine-only). Qualquer contrato pergunta `isValid` / `isAccountValid` antes de negociar com uma contraparte. Exemplo: `contracts/examples/PassportGatedSettlement.sol` |
| Verificador SP1 | `contracts/vendor/sp1/` | cópia sem modificação de [succinctlabs/sp1-contracts](https://github.com/succinctlabs/sp1-contracts), tag `v6.1.0` (MIT) |
| SDK | `src/` | `AvalancheChainAnchor`, no mesmo formato do `ChainAnchorPort` do control plane da DPO2U; redes Avalanche em CAIP-2 |

## Na Fuji (09/11/2026)

Todos os contratos estão verificados no [Snowtrace](https://testnet.snowtrace.io). Endereços e transações em `deployments/fuji.json`.

| Contrato | Endereço |
|---|---|
| SP1Verifier | `0xA9EF51126b02DDb8C284C424EfC4C54893d5979E` |
| DPO2UComplianceRegistry | `0xc997C83FbF40c70867b9A969a2AC2ee2Ae87C4cE` |
| DPO2UZkThresholdAttestor | `0x0a48471953bEFaEDE2f75E0D9A54f0EAFe68B9B7` |
| DPO2UPassportOracle | `0x27bb394d3fFdD7DDc5bb67F8C8Ee64073BeDF2b2` |

No registry, os use cases PSAV `psav_partner_br_v1` e `vasp_por_br_v1` estão ativos com o packHash do control plane. O gateway da DPO2U (`0xA6203d148a66Bf1fd39eC0Ea48d65F7945B67d4F`) está autorizado a selar no registry e a emitir passaportes no oráculo.

## Rodar

```bash
npm install
npm test          # 41 testes, incluindo a prova SP1 real
npm run gas
```

O compilador é o pacote npm `solc@0.8.20` (solcjs), então nada é baixado no build. A versão 0.8.20 está fixada porque o verificador SP1 Groth16 exige.

Gas medido na rede local: `registerAttestation` cerca de 194k, `submitProof` (verificação Groth16 + selo) cerca de 412k.

## Deploy na Fuji

```bash
cp .env.example .env          # PRIVATE_KEY de uma conta com AVAX de testnet
npm run deploy:fuji           # grava deployments/fuji.json
npm run deploy:passport:fuji  # oráculo de passaporte em cima do registry existente
```

Quem faz o deploy vira o admin. `PASSPORT_ISSUER` autoriza um emissor no oráculo. `ADMIN_ADDRESS` inicia a transferência de admin em dois passos para um multisig, que depois chama `acceptAdmin()`.

## Invariantes

REVIEW e FAIL nunca são válidos. Todo selo e todo passaporte expiram ("silêncio = não conformidade"). Um selo é escrito uma vez só. O verificador e a chave do programa do atestador ZK são imutáveis. Sem signer ou RPC, o anchor lança erro em vez de forjar recibo, e o control plane registra REVIEW. Detalhes em `docs/SPEC.pt-BR.md`.

## Fixture

`test/fixtures/` guarda a prova de `dpo2u-solana/zk-circuits/proofs` (commit `e8c09e7`): threshold 70, compromisso do sujeito `did:test:company:acme`, vkey do programa `0x00a79ec5…b414`.

## Licença

MIT

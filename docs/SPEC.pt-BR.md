# Interface de atestação DPO2U — spec v0.1 (neutra de rede)

[English](SPEC.md) · Português

Status: rascunho, escrito na fase 0 do plano da Avalanche. A Avalanche (`contracts/interfaces/IDPO2UAttestation.sol`) é a primeira implementação completa. Stellar (`anticorruption-attestation`) e Midnight (`ComplianceRegistry.compact`) já usam o mesmo modelo central e podem ser alinhados a esta spec depois.

## Modelo de dados

Uma atestação tem como chave `(useCaseId, evidenceHash)` e é escrita uma vez só.

| Campo | Tipo | Significado |
|---|---|---|
| `useCaseId` | bytes32 | keccak256 do identificador do use case, por exemplo `psav_partner_br_v1` |
| `evidenceHash` | bytes32 | sha256 da evidência off-chain ou do compromisso do run. A evidência nunca vai para a chain |
| `subject` | bytes32 | hash da conta CAIP-10, do DID ou do identificador de registro. Nunca a identidade em claro |
| `verdict` | enum | `NONE`, `PASS`, `FAIL`, `REVIEW` |
| `origin` | enum | `MACHINE`, `HUMAN_REVIEWED`, `THIRD_PARTY` (spec PSAV §6.2) |
| `issuedAt`, `expiresAt` | uint64 | a validade é obrigatória e limitada por `maxValidity` |
| `metadataHash` | bytes32 | hash do resumo do run (regras, vereditos, revisores) |
| `packHash`, `packVersion` | bytes32, uint32 | o pack de regras contra o qual o veredito foi avaliado, copiado do use case no momento da escrita |
| `revoked` | bool | suspensão ou revogação, visível para sempre |

## Invariantes (toda implementação passa nos mesmos testes)

1. Só `PASS` pode ser válido. `REVIEW` e `FAIL` nunca são válidos.
2. Toda atestação expira. Expirada = não válida ("silêncio = não conformidade").
3. `(useCaseId, evidenceHash)` é escrito uma vez só (anti-replay).
4. Só submitters autorizados escrevem; só o admin configura use cases e submitters.
5. A revogação é feita pelo admin ou pelo submitter original, e continua visível.
6. Uma atestação com base em ZK fixa o verificador e a chave do programa no deploy. Nenhuma função aceita uma chave de verificação vinda de quem chama.
7. Um adaptador de rede fora do ar nunca gera PASS: o control plane registra REVIEW.

## Códigos de erro

`NotAuthorized` (1), `UseCaseInactive` (2), `AttestationExists` (3), `AttestationNotFound` (4), `AdminOnly` (5) mantêm a numeração do contrato Soroban, para que os SDKs mapeiem do mesmo jeito.

## Superfície de leitura (oráculo)

- `isValid(useCaseId, evidenceHash)`: PASS, não revogado, não expirado.
- `isSubjectCompliant(useCaseId, subject)`: a atestação mais recente do sujeito é válida. Um FAIL mais novo se sobrepõe a um PASS mais antigo.

## Oráculo de passaporte (`DPO2UPassportOracle`)

Espelho EVM do Passport do control plane (spec PSAV §3.4). Para cada `(subject, packId)` existe um passaporte atual: `passportId`, `packHash`, `tier`, `status`, `issuedAt`, `expiresAt`, `issuer` e o selo em que ele se apoia (`sealUseCaseId`, `sealEvidenceHash`).

- A ordem dos tiers segue o `TIER_RANK` do control plane: `NONE < TIER1_MACHINE_ONLY < TIER1 < TIER2 < TIER3`. `NONE` significa "sem passaporte" e é recusado como `minTier`.
- `issuePassport` (só emissores autorizados) exige um selo que exista no registry, não esteja revogado, não seja FAIL, não tenha expirado e tenha o mesmo `subject` e `packHash` do passaporte (senão, `SealMismatch`). Um selo REVIEW só sustenta passaporte `TIER1_MACHINE_ONLY`. A validade é limitada por `maxValidity` e, para tier2 e tier3, também por 31 dias (`TIER_WINDOW_DAYS` do control plane). Cada `passportId` é usado uma vez só. Um passaporte novo substitui o atual daquele pack.
- `suspendPassport` / `revokePassport` (admin ou o emissor que emitiu) valem no mesmo bloco e não têm volta. O caminho de volta é emitir um passaporte novo (`passportId` novo), apoiado num selo que continue utilizável.
- Leitura: `isValid(subject, packId, minTier)`, `isAccountValid(address, packId, minTier)`, `isValidAll(subject, packIds[], minTier)` e `subjectOf(address)` = keccak256 do CAIP-10 em minúsculas (`eip155:<chainId>:0x…`), o mesmo subject que o gateway grava.
- Silêncio = não conformidade: um passaporte expirado, suspenso, revogado ou inexistente simplesmente não é válido.

Consumidor de exemplo: `contracts/examples/PassportGatedSettlement.sol` só move AVAX quando pagador e recebedor têm passaporte válido para o pack e o tier fixados.

## Próximas interfaces (fases seguintes)

`Solvency` (prova de reservas ≥ passivo), `LegalSource` (citação → hash da norma), `TravelRuleGate` (transferência só com hash de payload IVMS-101 atestado e passaportes válidos nas duas pontas; porta do padrão Soroban `defindex-rebalance-gate`).

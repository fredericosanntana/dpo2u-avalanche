// Deploys DPO2UTravelRuleGate on top of the existing registry, with the example target
// TravelRuleTransferLog, ATTESTATION LANE ONLY: no Groth16 verifiers yet (the proof lane
// reverts VerifierNotSet until real verifiers exist; a mock is never deployed).
//   npx hardhat run scripts/deploy-travel-rule-gate.ts --network fuji
// Writes travelRuleGate { gate, target, useCase, ... } to deployments/<network>.json.
// Env: PRIVATE_KEY (deployer = gate admin), TRG_USE_CASE (default travel_rule_v1, the gateway set id; must be
//      configured and active in the registry by its admin before `execute` can pass),
//      TRG_PARTY_USE_CASE (optional: require both parties compliant under this use case),
//      TRG_OPERATOR (optional operator to authorize), ADMIN_ADDRESS (optional two-step transfer).
import { ethers, network } from "hardhat";
import fs from "node:fs";
import path from "node:path";

const id = (s: string) => ethers.keccak256(ethers.toUtf8Bytes(s));

async function main() {
  const [deployer] = await ethers.getSigners();
  const file = path.join(__dirname, "..", "deployments", `${network.name}.json`);
  const dep = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!dep.registry) throw new Error(`no registry in ${file}`);
  const useCase = process.env.TRG_USE_CASE || "travel_rule_v1";
  const partyUseCase = process.env.TRG_PARTY_USE_CASE || "";
  console.log(`network=${network.name} deployer=${deployer.address} registry=${dep.registry} useCase=${useCase} partyUseCase=${partyUseCase || "(off)"}`);

  const target = await (await ethers.getContractFactory("TravelRuleTransferLog")).deploy();
  await target.waitForDeployment();
  const gate = await (await ethers.getContractFactory("DPO2UTravelRuleGate")).deploy(
    deployer.address,
    dep.registry,
    await target.getAddress(),
    id(useCase),
    partyUseCase ? id(partyUseCase) : ethers.ZeroHash,
    ethers.ZeroAddress,
    ethers.ZeroAddress,
  );
  await gate.waitForDeployment();
  const bindTx = await target.bindGate(await gate.getAddress());
  await bindTx.wait();

  const out: Record<string, unknown> = {
    gate: await gate.getAddress(),
    gateDeployTx: gate.deploymentTransaction()?.hash,
    target: await target.getAddress(),
    targetDeployTx: target.deploymentTransaction()?.hash,
    bindGateTx: bindTx.hash,
    useCase,
    useCaseId: id(useCase),
    partyUseCase: partyUseCase || null,
    lanes: "attestation only (no Groth16 verifiers)",
    deployedAt: new Date().toISOString(),
  };
  if (process.env.TRG_OPERATOR) {
    const tx = await gate.authorizeOperator(process.env.TRG_OPERATOR, true);
    await tx.wait();
    out.operator = process.env.TRG_OPERATOR;
    out.operatorAuthTx = tx.hash;
  }
  if (process.env.ADMIN_ADDRESS) await (await gate.transferAdmin(process.env.ADMIN_ADDRESS)).wait();
  dep.travelRuleGate = out;
  fs.writeFileSync(file, JSON.stringify(dep, null, 2) + "\n");
  console.log(out);
}

main().catch((e) => { console.error(e); process.exit(1); });

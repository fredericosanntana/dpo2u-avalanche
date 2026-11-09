// Deploys the DPO2USolvencyRegistry (private proof of reserves, grant M4) on top of the
// existing registry and SP1 v6.1.0 verifier, configures its use case and authorizes it as
// a submitter.
//   SOLVENCY_VKEY=0x… npx hardhat run scripts/deploy-solvency.ts --network fuji
// Env:
//   PRIVATE_KEY            deployer = registry admin
//   SOLVENCY_VKEY          bytes32 vkey of the SP1 program (zk/solvency), pinned for good
//   SOLVENCY_USE_CASE      use case string (default solvency_por_br_v1)
//   SOLVENCY_VALIDITY_DAYS seal validity counted from the snapshot (default 2)
//   SOLVENCY_MAX_AGE_HOURS max snapshot age at submission (default 24)
// Use case pack: packHash = sha256(vkey bytes), packVersion = 10000 (1.0.0). The program IS the
// policy here, so the pack is pinned to the exact program that produced the proof.
import { ethers, network } from "hardhat";
import fs from "node:fs";
import path from "node:path";

async function main() {
  const vkey = process.env.SOLVENCY_VKEY || "";
  if (!/^0x[0-9a-fA-F]{64}$/.test(vkey)) throw new Error("SOLVENCY_VKEY must be a bytes32 hex");
  const useCase = process.env.SOLVENCY_USE_CASE || "solvency_por_br_v1";
  const validity = Number(process.env.SOLVENCY_VALIDITY_DAYS || 2) * 86_400;
  const maxAge = Number(process.env.SOLVENCY_MAX_AGE_HOURS || 24) * 3_600;

  const [deployer] = await ethers.getSigners();
  const file = path.join(__dirname, "..", "deployments", `${network.name}.json`);
  const dep = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!dep.registry || !dep.sp1Verifier) throw new Error(`registry/sp1Verifier missing in ${file}`);

  const useCaseId = ethers.keccak256(ethers.toUtf8Bytes(useCase));
  const packHash = ethers.sha256(vkey);
  const packVersion = 10000;
  console.log(`network=${network.name} deployer=${deployer.address} registry=${dep.registry} verifier=${dep.sp1Verifier}`);
  console.log(`useCase=${useCase} validity=${validity}s maxSnapshotAge=${maxAge}s vkey=${vkey}`);

  const solv = await (await ethers.getContractFactory("DPO2USolvencyRegistry")).deploy(
    dep.sp1Verifier, vkey, dep.registry, useCaseId, validity, maxAge,
  );
  await solv.waitForDeployment();
  const deployTx = solv.deploymentTransaction()?.hash;
  const address = await solv.getAddress();

  const registry = await ethers.getContractAt("DPO2UComplianceRegistry", dep.registry);
  const ucTx = await registry.configureUseCase(useCaseId, true, packHash, packVersion);
  await ucTx.wait();
  const authTx = await registry.authorizeSubmitter(address, true);
  await authTx.wait();

  dep.solvencyRegistry = {
    address,
    deployTx,
    deployedAt: new Date().toISOString(),
    programVKey: vkey,
    useCase,
    useCaseId,
    packHash,
    packVersion,
    validitySeconds: validity,
    maxSnapshotAgeSeconds: maxAge,
    configureUseCaseTx: ucTx.hash,
    authorizeSubmitterTx: authTx.hash,
  };
  fs.writeFileSync(file, JSON.stringify(dep, null, 2) + "\n");
  console.log(JSON.stringify(dep.solvencyRegistry, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });

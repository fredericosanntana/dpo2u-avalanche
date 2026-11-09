// Seals a solvency proof on the DPO2USolvencyRegistry (permissionless), then reads it back.
//   SOLVENCY_PROOF_DIR=<dir with proof.bin + public_values.bin> npx hardhat run scripts/seal-solvency.ts --network fuji
import { ethers, network } from "hardhat";
import fs from "node:fs";
import path from "node:path";

async function main() {
  const dir = process.env.SOLVENCY_PROOF_DIR || "";
  const pv = fs.readFileSync(path.join(dir, "public_values.bin"));
  const proof = fs.readFileSync(path.join(dir, "proof.bin"));
  const dep = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "deployments", `${network.name}.json`), "utf8"));
  const solv = await ethers.getContractAt("DPO2USolvencyRegistry", dep.solvencyRegistry.address);
  const reg = await ethers.getContractAt("DPO2UComplianceRegistry", dep.registry);
  const decoded = await solv.decodePublicValues(pv);
  const tx = await solv.sealSolvency(pv, proof);
  const rc = await tx.wait();
  const evidenceHash = ethers.sha256(pv);
  const a = await reg.getAttestation(dep.solvencyRegistry.useCaseId, evidenceHash);
  console.log(JSON.stringify({
    tx: tx.hash, status: rc?.status, gasUsed: rc?.gasUsed.toString(),
    entityId: decoded.entityId, snapshotAt: Number(decoded.snapshotAt), solvent: decoded.solvent, evidenceHash,
    isSolvent: await solv.isSolvent(decoded.entityId),
    registry: { verdict: Number(a.verdict), origin: Number(a.origin), submitter: a.submitter, expiresAt: Number(a.expiresAt), packHash: a.packHash },
  }));
}
main().catch((e) => { console.error(e); process.exit(1); });

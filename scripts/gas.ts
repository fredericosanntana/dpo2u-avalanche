// Prints gas for the main paths on the local Hardhat network.
import { ethers } from "hardhat";
import fs from "node:fs";
import path from "node:path";
async function main() {
  const [admin] = await ethers.getSigners();
  const fx = path.join(__dirname, "..", "test", "fixtures");
  const id = (s: string) => ethers.keccak256(ethers.toUtf8Bytes(s));
  const v = await (await ethers.getContractFactory("SP1Verifier")).deploy();
  const r = await (await ethers.getContractFactory("DPO2UComplianceRegistry")).deploy(admin.address, 365 * 86400);
  const a = await (await ethers.getContractFactory("DPO2UZkThresholdAttestor")).deploy(await v.getAddress(), fs.readFileSync(path.join(fx, "vkey.hex"), "utf8").trim(), await r.getAddress(), id("zk"), 70, 86400 * 90);
  await r.configureUseCase(id("zk"), true, ethers.ZeroHash, 1);
  await r.configureUseCase(id("uc"), true, ethers.ZeroHash, 1);
  await r.authorizeSubmitter(await a.getAddress(), true);
  await r.authorizeSubmitter(admin.address, true);
  const t1 = await (await r.registerAttestation(id("uc"), id("e"), id("s"), 1, 1, id("m"), Math.floor(Date.now() / 1000) + 86400 * 30)).wait();
  const t2 = await (await a.submitProof(fs.readFileSync(path.join(fx, "public_values.bin")), fs.readFileSync(path.join(fx, "proof.bin")))).wait();
  console.log(`registerAttestation gas=${t1!.gasUsed}`);
  console.log(`submitProof (SP1 Groth16 verify + seal) gas=${t2!.gasUsed}`);
}
main().catch((e) => { console.error(e); process.exit(1); });

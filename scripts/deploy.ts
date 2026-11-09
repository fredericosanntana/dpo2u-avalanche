// Deploys the DPO2U Avalanche stack: SP1 v6.1.0 Groth16 verifier, registry and the
// ZK threshold attestor; configures use cases and authorizes submitters.
//   npx hardhat run scripts/deploy.ts --network fuji
// Env: PRIVATE_KEY (deployer = initial admin), GATEWAY_ADDRESS (optional submitter),
//      ADMIN_ADDRESS (optional: starts a two-step admin transfer to a multisig).
import { ethers, network } from "hardhat";
import fs from "node:fs";
import path from "node:path";

const DAY = 86_400;
const id = (s: string) => ethers.keccak256(ethers.toUtf8Bytes(s));

const PSAV_USE_CASES = [
  { useCaseId: "psav_partner_br_v1", pack: "psav-partner-br@1.0.0", packHash: "0x5098e1806e2a918da1aa7f1db39c0b4e41e022d2d7bad6abcdc511b6ddddab86", packVersion: 10000 },
  { useCaseId: "vasp_por_br_v1", pack: "psav-safeguard-br@1.1.0", packHash: "0xda7e8b23363947d80dff87be55be565b74dcf991daf10060d7b0cf1eeb5ea713", packVersion: 10100 },
] as const;

async function main() {
  const [deployer] = await ethers.getSigners();
  const vkey = fs.readFileSync(path.join(__dirname, "..", "test", "fixtures", "vkey.hex"), "utf8").trim();
  console.log(`network=${network.name} chainId=${network.config.chainId} deployer=${deployer.address}`);

  const verifier = await (await ethers.getContractFactory("SP1Verifier")).deploy();
  await verifier.waitForDeployment();
  const registry = await (await ethers.getContractFactory("DPO2UComplianceRegistry")).deploy(deployer.address, 365 * DAY);
  await registry.waitForDeployment();

  const zkUseCase = id("zk-threshold@1");
  const attestor = await (await ethers.getContractFactory("DPO2UZkThresholdAttestor")).deploy(
    await verifier.getAddress(), vkey, await registry.getAddress(), zkUseCase, 70, 90 * DAY,
  );
  await attestor.waitForDeployment();

  await (await registry.configureUseCase(zkUseCase, true, ethers.ZeroHash, 1)).wait();
  await (await registry.configureUseCase(id("dpo2u/control-plane/attestation/v1"), true, ethers.ZeroHash, 1)).wait();
  // PSAV use cases of the DPO2U gateway: id = keccak256(use_case_id), packHash = the control
  // plane's packHash (sha256 of the canonical pack), packVersion = major*10000+minor*100+patch.
  for (const uc of PSAV_USE_CASES) {
    await (await registry.configureUseCase(id(uc.useCaseId), true, uc.packHash, uc.packVersion)).wait();
  }
  await (await registry.authorizeSubmitter(await attestor.getAddress(), true)).wait();
  if (process.env.GATEWAY_ADDRESS) await (await registry.authorizeSubmitter(process.env.GATEWAY_ADDRESS, true)).wait();
  if (process.env.ADMIN_ADDRESS) await (await registry.transferAdmin(process.env.ADMIN_ADDRESS)).wait();

  const out = {
    network: network.name,
    chainId: network.config.chainId,
    deployedAt: new Date().toISOString(),
    sp1Verifier: await verifier.getAddress(),
    registry: await registry.getAddress(),
    zkThresholdAttestor: await attestor.getAddress(),
    programVKey: vkey,
  };
  fs.mkdirSync(path.join(__dirname, "..", "deployments"), { recursive: true });
  fs.writeFileSync(path.join(__dirname, "..", "deployments", `${network.name}.json`), JSON.stringify(out, null, 2) + "\n");
  console.log(out);
}

main().catch((e) => { console.error(e); process.exit(1); });

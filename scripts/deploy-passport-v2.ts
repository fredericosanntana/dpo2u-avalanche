// Deploys the upgradeable PassportOracle (v2: implementation + ERC-1967 UUPS proxy) on top of
// an existing registry. Consumers use the PROXY address; upgrades go through the admin.
//   npx hardhat run scripts/deploy-passport-v2.ts --network fuji
// Writes passportOracleV2 { proxy, implementation, ... } to deployments/<network>.json and keeps
// the v1 entry (passportOracle) untouched.
// Env: PRIVATE_KEY (deployer = initial admin), PASSPORT_ISSUER (optional issuer to authorize),
//      PASSPORT_MAX_VALIDITY_DAYS (default 365),
//      ADMIN_ADDRESS (the Safe: starts the two-step admin transfer; the Safe must call acceptAdmin).
import { ethers, network } from "hardhat";
import fs from "node:fs";
import path from "node:path";

async function main() {
  const [deployer] = await ethers.getSigners();
  const file = path.join(__dirname, "..", "deployments", `${network.name}.json`);
  const dep = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!dep.registry) throw new Error(`no registry in ${file}`);
  const days = Number(process.env.PASSPORT_MAX_VALIDITY_DAYS || 365);
  console.log(`network=${network.name} deployer=${deployer.address} registry=${dep.registry} maxValidity=${days}d`);

  const impl = await (await ethers.getContractFactory("DPO2UPassportOracleV2")).deploy();
  await impl.waitForDeployment();
  const init = impl.interface.encodeFunctionData("initialize", [deployer.address, dep.registry, days * 86_400]);
  const proxy = await (await ethers.getContractFactory("ERC1967Proxy")).deploy(await impl.getAddress(), init);
  await proxy.waitForDeployment();
  const oracle = await ethers.getContractAt("DPO2UPassportOracleV2", await proxy.getAddress());

  const out: Record<string, unknown> = {
    proxy: await proxy.getAddress(),
    implementation: await impl.getAddress(),
    deployTx: proxy.deploymentTransaction()?.hash,
    deployedAt: new Date().toISOString(),
  };
  if (process.env.PASSPORT_ISSUER) {
    const tx = await oracle.authorizeIssuer(process.env.PASSPORT_ISSUER, true);
    await tx.wait();
    out.issuer = process.env.PASSPORT_ISSUER;
    out.issuerAuthTx = tx.hash;
  }
  if (process.env.ADMIN_ADDRESS) {
    const tx = await oracle.transferAdmin(process.env.ADMIN_ADDRESS);
    await tx.wait();
    out.pendingAdmin = process.env.ADMIN_ADDRESS;
    out.adminTransferTx = tx.hash;
  }
  dep.passportOracleV2 = out;
  fs.writeFileSync(file, JSON.stringify(dep, null, 2) + "\n");
  console.log(out);
}

main().catch((e) => { console.error(e); process.exit(1); });

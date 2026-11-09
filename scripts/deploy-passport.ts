// Deploys the DPO2U PassportOracle on top of an existing registry (phase 2 / grant M3).
//   npx hardhat run scripts/deploy-passport.ts --network fuji
// Reads the registry from deployments/<network>.json and writes `passportOracle` back.
// Env: PRIVATE_KEY (deployer = initial admin), PASSPORT_ISSUER (optional issuer to authorize),
//      PASSPORT_MAX_VALIDITY_DAYS (default 365, the control-plane tier1 window),
//      ADMIN_ADDRESS (optional: starts a two-step admin transfer to a multisig).
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

  const oracle = await (await ethers.getContractFactory("DPO2UPassportOracle")).deploy(deployer.address, dep.registry, days * 86_400);
  await oracle.waitForDeployment();
  // Issuer metadata belongs to the oracle it was written for: a redeploy clears it.
  delete dep.passportIssuer;
  delete dep.passportIssuerAuthTx;
  if (process.env.PASSPORT_ISSUER) {
    const tx = await oracle.authorizeIssuer(process.env.PASSPORT_ISSUER, true);
    await tx.wait();
    dep.passportIssuer = process.env.PASSPORT_ISSUER;
    dep.passportIssuerAuthTx = tx.hash;
  }
  if (process.env.ADMIN_ADDRESS) await (await oracle.transferAdmin(process.env.ADMIN_ADDRESS)).wait();

  dep.passportOracle = await oracle.getAddress();
  dep.passportOracleDeployedAt = new Date().toISOString();
  fs.writeFileSync(file, JSON.stringify(dep, null, 2) + "\n");
  console.log({ passportOracle: dep.passportOracle });
}

main().catch((e) => { console.error(e); process.exit(1); });

// Deploys DPO2UMidnightRelay on top of the existing registry, adds relayer #1, sets routes for
// use cases that exist on BOTH networks, and authorizes the relay as a registry submitter.
//   RELAYER_ADDRESS=0x… npx hardhat run scripts/deploy-midnight-relay.ts --network fuji
// Env:
//   PRIVATE_KEY        deployer = relay admin = registry admin
//   RELAYER_ADDRESS    relayer #1 (its own key and its own Midnight indexer; never the deployer)
//   RELAY_THRESHOLD    default 1 (TESTNET with a single relayer; the consortium raises it with
//                      setRelayer + setThreshold as each operator brings its own key and node)
//   RELAY_ROUTES       comma list of use cases present on both networks (default psav_partner_br_v1)
//   RELAY_VALIDITY_DAYS validity of a relayed seal on the C-Chain (default 90)
// Midnight stores use_case_id as the UTF-8 string right-padded to 32 bytes; the C-Chain registry
// keys use cases by keccak256(string). The route maps one to the other.
import { ethers, network } from "hardhat";
import fs from "node:fs";
import path from "node:path";

const padded = (s: string) => {
  const b = Buffer.alloc(32);
  Buffer.from(s, "utf8").copy(b, 0, 0, Math.min(Buffer.byteLength(s), 32));
  return "0x" + b.toString("hex");
};

async function main() {
  const relayer = process.env.RELAYER_ADDRESS || "";
  if (!ethers.isAddress(relayer)) throw new Error("RELAYER_ADDRESS required");
  const threshold = Number(process.env.RELAY_THRESHOLD || 1);
  const routes = (process.env.RELAY_ROUTES || "psav_partner_br_v1").split(",").map((s) => s.trim()).filter(Boolean);
  const validity = Number(process.env.RELAY_VALIDITY_DAYS || 90) * 86_400;

  const [deployer] = await ethers.getSigners();
  if (relayer.toLowerCase() === deployer.address.toLowerCase()) throw new Error("relayer must not be the deployer");
  const file = path.join(__dirname, "..", "deployments", `${network.name}.json`);
  const dep = JSON.parse(fs.readFileSync(file, "utf8"));
  const registry = await ethers.getContractAt("DPO2UComplianceRegistry", dep.registry);

  const relay = await (await ethers.getContractFactory("DPO2UMidnightRelay")).deploy(deployer.address, dep.registry, threshold);
  await relay.waitForDeployment();
  const address = await relay.getAddress();
  const txs: Record<string, string> = { deploy: relay.deploymentTransaction()!.hash };

  txs.setRelayer = (await (await relay.setRelayer(relayer, true)).wait())!.hash;
  const routeOut: unknown[] = [];
  for (const uc of routes) {
    const useCaseId = ethers.keccak256(ethers.toUtf8Bytes(uc));
    const u = await registry.getUseCase(useCaseId);
    if (!u.active) throw new Error(`use case ${uc} is not active on the C-Chain registry`);
    const tx = await (await relay.setRoute(padded(uc), useCaseId, validity)).wait();
    routeOut.push({ useCase: uc, midnightUseCaseId: padded(uc), useCaseId, validitySeconds: validity, tx: tx!.hash });
  }
  txs.authorizeSubmitter = (await (await registry.authorizeSubmitter(address, true)).wait())!.hash;

  dep.midnightRelay = {
    address, admin: deployer.address, threshold, relayers: [relayer], routes: routeOut, txs,
    note: "TESTNET, single relayer (1-of-1). Each operator adds its own key and Midnight node; threshold rises with them.",
    deployedAt: new Date().toISOString(),
  };
  fs.writeFileSync(file, JSON.stringify(dep, null, 2) + "\n");
  console.log(JSON.stringify(dep.midnightRelay, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });

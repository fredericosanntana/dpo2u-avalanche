// Deploys DPO2UTravelRuleVerdictMirror: Midnight TravelRuleGate verdicts (format v1) on the C-Chain.
//   MIRROR_SOURCE_CONTRACT=<hex> MIRROR_POLICIES=<hex32,...> RELAYER_ADDRESS=0x… \
//   npx hardhat run scripts/deploy-verdict-mirror.ts --network fuji
// Env:
//   PRIVATE_KEY             deployer = mirror admin
//   MIRROR_SOURCE_CHAIN     default midnight:preview on fuji, midnight:mainnet on avalanche
//   MIRROR_SOURCE_CONTRACT  TravelRuleGate address on Midnight (hex, no 0x); comma list for several gates
//   MIRROR_POLICIES         policy_hash values the Midnight gate records (hex32, comma list)
//   RELAYER_ADDRESS         relayer #1 (comma list for more); each with its own key and Midnight indexer
//   MIRROR_THRESHOLD        default 1
//   ADMIN_ADDRESS           optional two-step admin transfer (e.g. the Safe); the Safe must call acceptAdmin
// TRUST MODEL: operator trust, not a proof (docs/TRAVEL-RULE-VERDICT-MIRROR.md).
import { ethers, network } from "hardhat";
import fs from "node:fs";
import path from "node:path";

const list = (s?: string) => (s || "").split(",").map((x) => x.trim().replace(/^0x/, "")).filter(Boolean);

async function main() {
  const sourceChain = process.env.MIRROR_SOURCE_CHAIN || (network.name === "avalanche" ? "midnight:mainnet" : "midnight:preview");
  if (network.name === "avalanche" && sourceChain !== "midnight:mainnet") throw new Error("on avalanche the source must be midnight:mainnet");
  const sources = list(process.env.MIRROR_SOURCE_CONTRACT);
  const policies = list(process.env.MIRROR_POLICIES);
  const relayers = (process.env.RELAYER_ADDRESS || "").split(",").map((s) => s.trim()).filter(Boolean);
  const threshold = Number(process.env.MIRROR_THRESHOLD || 1);
  if (!sources.length || sources.some((s) => !/^[0-9a-f]{2,128}$/i.test(s) || s.length % 2)) throw new Error("MIRROR_SOURCE_CONTRACT: hex address(es) of the Midnight gate");
  if (!policies.length || policies.some((p) => !/^[0-9a-f]{64}$/i.test(p) || /^0+$/.test(p))) throw new Error("MIRROR_POLICIES: non-zero hex32 value(s)");
  if (!relayers.length || relayers.some((r) => !ethers.isAddress(r))) throw new Error("RELAYER_ADDRESS: address(es)");
  if (threshold < 1 || threshold > relayers.length) throw new Error("MIRROR_THRESHOLD must be 1..number of relayers");

  const [deployer] = await ethers.getSigners();
  if (relayers.some((r) => r.toLowerCase() === deployer.address.toLowerCase())) throw new Error("a relayer must not be the deployer/admin");
  console.log(`network=${network.name} deployer=${deployer.address} source=${sourceChain} gates=${sources.join(",")} threshold=${threshold}/${relayers.length}`);

  const m = await (await ethers.getContractFactory("DPO2UTravelRuleVerdictMirror")).deploy(deployer.address, threshold);
  await m.waitForDeployment();
  const txs: Record<string, string> = {};
  for (const s of sources) txs[`source:${s.slice(0, 8)}`] = (await (await m.setSource(sourceChain, "0x" + s.toLowerCase(), true)).wait())!.hash;
  for (const p of policies) txs[`policy:${p.slice(0, 8)}`] = (await (await m.setPolicy("0x" + p.toLowerCase(), true)).wait())!.hash;
  for (const r of relayers) txs[`relayer:${r.slice(0, 8)}`] = (await (await m.setRelayer(r, true)).wait())!.hash;
  if (process.env.ADMIN_ADDRESS) txs.transferAdmin = (await (await m.transferAdmin(process.env.ADMIN_ADDRESS)).wait())!.hash;

  const file = path.join(__dirname, "..", "deployments", `${network.name}.json`);
  const dep = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : { network: network.name };
  dep.travelRuleVerdictMirror = {
    address: await m.getAddress(),
    deployTx: m.deploymentTransaction()?.hash,
    admin: deployer.address,
    pendingAdmin: process.env.ADMIN_ADDRESS || null,
    threshold,
    relayers,
    source: { chain: sourceChain, contracts: sources.map((s) => s.toLowerCase()) },
    policies: policies.map((p) => p.toLowerCase()),
    format: "dpo2u.travel-rule-verdict/1",
    trustModel: "operator (no Midnight light client; M-of-N relayers)",
    txs,
    deployedAt: new Date().toISOString(),
  };
  fs.writeFileSync(file, JSON.stringify(dep, null, 2) + "\n");
  console.log(dep.travelRuleVerdictMirror);
}

main().catch((e) => { console.error(e); process.exit(1); });

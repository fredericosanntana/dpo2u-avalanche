// Relays one Midnight TravelRuleGate verdict to DPO2UTravelRuleVerdictMirror on the C-Chain.
//   VERDICT_IN=export.json npx hardhat run scripts/relay-travel-rule-verdict.ts --network fuji
//   MIDNIGHT_REPO=/path/dpo2u-midnight TRANSFER=<id> MIDNIGHT_TX=<tx> npx hardhat run ... --network fuji
// VERDICT_IN is the output of dpo2u-midnight scripts/export-verdict.ts ({ verdict, digest }); without
// it the script runs export-verdict.ts itself (read-only, indexer only; MIDNIGHT_NETWORK defaults to
// preview, mainnet on avalanche). PRIVATE_KEY must be a relayer allowlisted in the mirror.
// PLAN=1 prints what would be sent and sends nothing. Writes an evidence record to
// deployments/evidence/<network>/. TRUST MODEL: operator trust, not a proof.
import { ethers, network } from "hardhat";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { checkVerdict, checkForMirror, verdictDigest, toSolidityVerdict, evidenceRecord, canonicalJson } from "../src/travel-rule-verdict";

function readExport(): { verdict: any; digest: string } {
  if (process.env.VERDICT_IN) return JSON.parse(fs.readFileSync(process.env.VERDICT_IN, "utf8"));
  const repo = process.env.MIDNIGHT_REPO;
  if (!repo || !process.env.TRANSFER || !process.env.MIDNIGHT_TX) throw new Error("set VERDICT_IN, or MIDNIGHT_REPO + TRANSFER + MIDNIGHT_TX");
  const args = ["tsx", "scripts/export-verdict.ts", "--transfer", process.env.TRANSFER, "--tx", process.env.MIDNIGHT_TX];
  if (process.env.MIDNIGHT_GATE) args.push("--contract", process.env.MIDNIGHT_GATE);
  const net = process.env.MIDNIGHT_NETWORK || (network.name === "avalanche" ? "mainnet" : "preview");
  const out = execFileSync("npx", args, { cwd: repo, encoding: "utf8", env: { ...process.env, MIDNIGHT_NETWORK: net } });
  return JSON.parse(out.slice(out.indexOf("{")));
}

async function main() {
  const { verdict, digest } = readExport();
  const problems = [...checkVerdict(verdict), ...checkForMirror(verdict)];
  if (problems.length) throw new Error("refused: " + problems.join("; "));
  if (verdictDigest(verdict) !== digest) throw new Error(`refused: export digest ${digest} != sha256(canonical) ${verdictDigest(verdict)}`);
  if (network.name === "avalanche" && verdict.source_chain !== "midnight:mainnet") throw new Error("refused: only midnight:mainnet verdicts go to the C-Chain mainnet");

  const file = path.join(__dirname, "..", "deployments", `${network.name}.json`);
  const addr = process.env.MIRROR_ADDRESS || JSON.parse(fs.readFileSync(file, "utf8")).travelRuleVerdictMirror?.address;
  if (!addr) throw new Error(`no travelRuleVerdictMirror in ${file}; set MIRROR_ADDRESS`);
  const m = await ethers.getContractAt("DPO2UTravelRuleVerdictMirror", addr);
  const v = toSolidityVerdict(verdict);
  const onchain = await m.digest(v);
  if (onchain !== "0x" + digest) throw new Error(`refused: mirror computes ${onchain}, Midnight export says ${digest}`);

  if (process.env.PLAN === "1") {
    console.log(JSON.stringify({ plan: { network: network.name, mirror: addr, digest, canonical: canonicalJson(verdict), call: "submit(verdict)" } }, null, 2));
    return;
  }
  const relayer = (await ethers.getSigners())[Number(process.env.SIGNER_INDEX || 0)];
  const tx = await m.connect(relayer).submit(v);
  const rc = await tx.wait();
  const rec = await m.getRecord(v.transferId);
  const recorded = rec.digest === "0x" + digest;
  const confirmed = rc!.logs.map((l) => { try { return m.interface.parseLog(l); } catch { return null; } }).find((e) => e?.name === "VerdictConfirmed");
  const ev = evidenceRecord({ verdict, digest, relayedAt: new Date().toISOString(), chain: {
    network: network.name, chainId: Number((await ethers.provider.getNetwork()).chainId), mirror: addr, relayer: relayer.address,
    tx: tx.hash, block: rc!.blockNumber, confirmations: confirmed ? Number(confirmed.args.confirmations) : null, recorded,
  } });
  const dir = path.join(__dirname, "..", "deployments", "evidence", network.name);
  fs.mkdirSync(dir, { recursive: true });
  const out = path.join(dir, `${verdict.transfer_id.slice(0, 16)}-${digest.slice(0, 8)}.json`);
  fs.writeFileSync(out, JSON.stringify(ev, null, 2) + "\n");
  console.log(JSON.stringify({ digest, tx: tx.hash, recorded, evidence: path.relative(process.cwd(), out) }));
}

main().catch((e) => { console.error(e?.message ?? e); process.exit(1); });

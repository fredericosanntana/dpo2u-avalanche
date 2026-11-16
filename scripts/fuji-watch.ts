// fuji-watch.ts — watches the Midnight -> C-Chain bridge on Fuji and raises alerts.
//
//   npx ts-node --transpile-only scripts/fuji-watch.ts            one pass, posts alerts
//   DRY_RUN=1 npx ts-node --transpile-only scripts/fuji-watch.ts  one pass, prints only
//
// Checks (each one yields an alert or nothing):
//   RelayerDown        critical  relayer systemd unit not active
//   RelayerStalled     critical  no relayer pass logged for STALL_MIN minutes
//   RelayerErrors      warning   >= ERR_MIN of the last 5 passes errored or had a failed seal
//   RelayDivergence    critical  a SealRelayed on the Fuji relay has no matching FINAL Midnight seal
//   RelayLag           warning   a mapped Midnight seal is still not relayed on two consecutive passes
//   MirrorDivergence   critical  a VerdictRecorded on the mirror differs from the verdict re-exported from Midnight
//   MirrorUnverifiable warning   a mirror verdict could not be re-exported from Midnight (indexer down, etc.)
//   WatchError         warning   the watch pass itself failed (so silence is never mistaken for health)
//
// Alerts go to the local Alertmanager (ALERTMANAGER_URL, default http://127.0.0.1:9093), which already
// routes critical/warning to Telegram. Each alert carries endsAt = now + 3 intervals: when a check stops
// firing the alert resolves by itself. No token is read here.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { Contract, JsonRpcProvider } from "ethers";
import { GraphQLIndexerTransport, IndexerSealSource } from "../src/midnight-indexer-source";
import { loadComplianceRegistryDecoder } from "../src/midnight-decoder";
import { MIDNIGHT_RELAY_ABI } from "../src/midnight-relayer";

const env = (k: string, d: string) => (process.env[k] === undefined || process.env[k] === "" ? d : (process.env[k] as string));
const DRY = process.env.DRY_RUN === "1";
const UNIT = env("RELAYER_UNIT", "dpo2u-midnight-relayer1");
const LOG = env("RELAYER_LOG", "/var/log/dpo2u-midnight-relayer1.log");
const STALL_MIN = Number(env("STALL_MIN", "15"));
const ERR_MIN = Number(env("ERR_MIN", "3"));
const INTERVAL_MIN = Number(env("WATCH_INTERVAL_MIN", "10"));
const STATE = env("WATCH_STATE_FILE", "/var/lib/dpo2u-fuji-watch/state.json");
const AM = env("ALERTMANAGER_URL", "http://127.0.0.1:9093");
const RPC = env("FUJI_RPC_URL", "https://api.avax-test.network/ext/bc/C/rpc");
const LOGS_API = env("LOGS_API", "https://api.routescan.io/v2/network/testnet/evm/43113/etherscan/api");
const TOOLING = env("MIDNIGHT_TOOLING_DIR", "/root/dpo2u-midnight-relayer-tooling");
const MIDNIGHT_REPO = env("MIDNIGHT_REPO", "/root/dpo2u-midnight-self-funding");
const INDEXER_HTTP = env("MIDNIGHT_INDEXER_HTTP", "https://indexer.preview.midnight.network/api/v4/graphql");
const INDEXER_WS = env("MIDNIGHT_INDEXER_WS", "wss://indexer.preview.midnight.network/api/v4/graphql/ws");
const MIRROR_RECHECK_H = Number(env("MIRROR_RECHECK_H", "6"));

type Alert = { name: string; severity: "critical" | "warning"; summary: string; key?: string };
type State = { lag: Record<string, number>; mirrorChecked: Record<string, number> };

const MIRROR_ABI = [
  "event VerdictRecorded(bytes32 indexed transferId, bytes32 indexed digest, bool pass, bool released, uint8 reasonCode)",
  "function getRecord(bytes32 transferId) view returns (tuple(bytes32 digest, bool pass, bool released, uint8 reasonCode, bytes32 stableHash, uint64 sourceBlock, bytes sourceTx, uint64 recordedAt, address[] relayedBy))",
];
const T_SEAL_RELAYED = "0xb7ef9a45fdfbca1746dc238da6a6fe2f235c255f06c01c28e9479add91c9a83d";
const T_VERDICT_RECORDED = "0xf2458bd8589cdf6a282ae2da216b7db24008cd95b861adb8e189f91b2e3f69f7";

function loadState(): State {
  try { return JSON.parse(fs.readFileSync(STATE, "utf8")); } catch { return { lag: {}, mirrorChecked: {} }; }
}

async function logs(address: string, topic0: string): Promise<{ topics: string[]; data: string; blockNumber: string; transactionHash: string }[]> {
  const u = `${LOGS_API}?module=logs&action=getLogs&address=${address}&topic0=${topic0}&fromBlock=0&toBlock=latest`;
  const r = await fetch(u);
  if (!r.ok) throw new Error(`logs API HTTP ${r.status}`);
  const j: any = await r.json();
  if (j.status === "1") return j.result;
  if (j.message === "No records found" || (Array.isArray(j.result) && j.result.length === 0)) return [];
  throw new Error(`logs API: ${j.message}`);
}

function checkRelayer(out: Alert[]) {
  let active = "unknown";
  try { active = execFileSync("systemctl", ["is-active", UNIT], { encoding: "utf8" }).trim(); } catch (e: any) { active = String(e.stdout || "inactive").trim(); }
  if (active !== "active") out.push({ name: "RelayerDown", severity: "critical", summary: `${UNIT} está ${active}` });

  const lines = fs.existsSync(LOG) ? fs.readFileSync(LOG, "utf8").trim().split("\n").slice(-200) : [];
  const events = lines.map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter((e) => e && (e.event === "pass" || e.event === "error"));
  const last = events[events.length - 1];
  const ageMin = last ? (Date.now() - Date.parse(last.at)) / 60000 : Infinity;
  if (ageMin > STALL_MIN) out.push({ name: "RelayerStalled", severity: "critical", summary: `${UNIT}: última passada há ${Number.isFinite(ageMin) ? Math.round(ageMin) + " min" : "nunca"} (limite ${STALL_MIN} min)` });
  const recent = events.slice(-5);
  const bad = recent.filter((e) => e.event === "error" || (e.results || []).some((r: any) => r.outcome === "failed"));
  if (bad.length >= ERR_MIN) {
    const msg = String(bad[bad.length - 1].error || (bad[bad.length - 1].results || []).find((r: any) => r.outcome === "failed")?.error || "").slice(0, 160);
    out.push({ name: "RelayerErrors", severity: "warning", summary: `${UNIT}: ${bad.length} das últimas ${recent.length} passadas com erro. Último: ${msg}` });
  }
}

async function checkRelay(out: Alert[], fuji: any, provider: JsonRpcProvider, st: State) {
  const relayAddr: string = fuji.midnightRelay.address;
  const relay = new Contract(relayAddr, MIDNIGHT_RELAY_ABI, provider);
  const cur = JSON.parse(fs.readFileSync(path.join(TOOLING, "deployment-preview-v9.json"), "utf8")).contracts.find((c: any) => c.name === "ComplianceRegistry");
  // Registries the relayer read before a repoint ("hex@ISO-cutoff,..."). Their state is not decodable with the
  // current build, so a seal from them is accepted only if it was relayed before the repoint; anything later is
  // a divergence (the relayer no longer reads them).
  const previous = env("PREVIOUS_REGISTRIES", "817dc7481a314991c57c49ea354315bc3366cff213343faf93dc195ca422c135@2026-11-16T03:10:00Z")
    .split(",").filter(Boolean).map((p) => { const [a, t] = p.split("@"); return { key: "0x" + a.toLowerCase(), cutoff: Date.parse(t) / 1000 }; });
  const curKey = "0x" + String(cur.contractAddress).toLowerCase().replace(/^0x/, "");
  const { seals } = await new IndexerSealSource({
    transport: new GraphQLIndexerTransport({ httpUrl: INDEXER_HTTP, wsUrl: INDEXER_WS }),
    contractAddress: cur.contractAddress, decode: await loadComplianceRegistryDecoder(TOOLING), deployHeight: cur.blockHeight, finalityLag: 5,
  }).sealsSince(undefined); // every FINAL seal of the current registry since its deploy
  const midDigests = new Map<string, any>();
  for (const s of seals) midDigests.set(String(await relay.sealDigest(s)).toLowerCase(), s);

  for (const l of await logs(relayAddr, T_SEAL_RELAYED) as any[]) {
    const d = l.topics[1].toLowerCase();
    const midContract = "0x" + l.data.slice(2, 66).toLowerCase();
    const where = `selo ${d.slice(0, 18)}… (tx ${l.transactionHash.slice(0, 18)}…)`;
    if (midContract === curKey) {
      if (!midDigests.has(d)) out.push({ name: "RelayDivergence", severity: "critical", key: d, summary: `Relay Fuji registrou o ${where} sem selo FINAL correspondente no ComplianceRegistry Midnight ${curKey.slice(0, 14)}…` });
      continue;
    }
    const prev = previous.find((p) => p.key === midContract);
    if (!prev) out.push({ name: "RelayDivergence", severity: "critical", key: d, summary: `Relay Fuji registrou o ${where} de um contrato Midnight desconhecido ${midContract.slice(0, 14)}…` });
    else if (parseInt(l.timeStamp, 16) > prev.cutoff) out.push({ name: "RelayDivergence", severity: "critical", key: d, summary: `Relay Fuji registrou o ${where} do registry antigo ${midContract.slice(0, 14)}… depois da troca de fonte` });
  }

  const nextLag: Record<string, number> = {};
  for (const [d, s] of midDigests) {
    const route = await relay.routes(s.midnightUseCaseId);
    if (route.useCaseId === "0x" + "0".repeat(64)) continue;
    if (await relay.relayed(d)) continue;
    nextLag[d] = (st.lag[d] || 0) + 1;
    if (nextLag[d] >= 2) out.push({ name: "RelayLag", severity: "warning", key: d, summary: `Selo Midnight ${s.evidenceHash.slice(0, 18)}… com rota mapeada ainda não relayado na Fuji (${nextLag[d]} passadas do vigia)` });
  }
  st.lag = nextLag;
}

async function checkMirror(out: Alert[], fuji: any, provider: JsonRpcProvider, st: State) {
  const m = fuji.travelRuleVerdictMirror;
  if (!m?.address) return;
  const mirror = new Contract(m.address, MIRROR_ABI, provider);
  const contracts: string[] = m.source?.contracts || [];
  const net = String(m.source?.chain || "midnight:preview").split(":")[1];
  for (const l of await logs(m.address, T_VERDICT_RECORDED)) {
    const transferId = l.topics[1].toLowerCase();
    const eventDigest = l.topics[2].toLowerCase();
    const rec = await mirror.getRecord(transferId);
    const recDigest = String(rec.digest).toLowerCase();
    const key = `${transferId}:${recDigest}`;
    if (recDigest !== eventDigest && !rec.released) {
      // A release re-records with a new digest; an un-released record whose digest moved is odd.
      out.push({ name: "MirrorDivergence", severity: "critical", key: transferId, summary: `Espelho: registro de ${transferId.slice(0, 18)}… mudou de digest sem release` });
    }
    if (Date.now() - (st.mirrorChecked[key] || 0) < MIRROR_RECHECK_H * 3600_000) continue;
    const tx = String(rec.sourceTx).slice(2); // raw Midnight tx id bytes (see toSolidityVerdict anchor.tx)
    let exported: string | undefined;
    let lastErr = "";
    for (const c of contracts) {
      try {
        const o = execFileSync("npx", ["tsx", "scripts/export-verdict.ts", "--transfer", transferId.slice(2), "--tx", tx, "--contract", c],
          { cwd: MIDNIGHT_REPO, encoding: "utf8", timeout: 240_000, env: { ...process.env, MIDNIGHT_NETWORK: net }, stdio: ["ignore", "pipe", "pipe"] });
        exported = String(JSON.parse(o.slice(o.indexOf("{"))).digest).toLowerCase().replace(/^0x/, "");
        break;
      } catch (e: any) { lastErr = String(e.stderr || e.message || e).split("\n").filter(Boolean).slice(-1)[0]?.slice(0, 160) || "?"; }
    }
    if (exported === undefined) {
      out.push({ name: "MirrorUnverifiable", severity: "warning", key: transferId, summary: `Espelho: não consegui reexportar da Midnight o veredito ${transferId.slice(0, 18)}… (${lastErr})` });
      continue;
    }
    if ("0x" + exported !== recDigest) {
      out.push({ name: "MirrorDivergence", severity: "critical", key: transferId,
        summary: `Espelho Fuji tem digest ${recDigest.slice(0, 18)}… para ${transferId.slice(0, 18)}…, a Midnight reexporta ${exported.slice(0, 16)}…` });
      continue;
    }
    st.mirrorChecked[key] = Date.now();
  }
}

async function post(alerts: Alert[]) {
  const endsAt = new Date(Date.now() + 3 * INTERVAL_MIN * 60_000).toISOString();
  const body = alerts.map((a) => ({
    labels: { alertname: `DPO2UFuji${a.name}`, severity: a.severity, service: "dpo2u-fuji-bridge", ...(a.key ? { key: a.key.slice(0, 18) } : {}) },
    annotations: { summary: a.summary, description: a.summary },
    endsAt,
  }));
  if (DRY || !body.length) return;
  const r = await fetch(`${AM}/api/v2/alerts`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`alertmanager HTTP ${r.status}: ${(await r.text()).slice(0, 200)}`);
}

async function main() {
  const fuji = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "deployments", "fuji.json"), "utf8"));
  const provider = new JsonRpcProvider(RPC, 43113, { staticNetwork: true });
  const st = loadState();
  const alerts: Alert[] = [];
  const steps: [string, () => Promise<void> | void][] = [
    ["relayer", () => checkRelayer(alerts)],
    ["relay", () => checkRelay(alerts, fuji, provider, st)],
    ["mirror", () => checkMirror(alerts, fuji, provider, st)],
  ];
  const errors: string[] = [];
  for (const [n, f] of steps) {
    try { await f(); } catch (e) { errors.push(`${n}: ${(e instanceof Error ? e.message : String(e)).slice(0, 160)}`); }
  }
  if (errors.length) alerts.push({ name: "WatchError", severity: "warning", summary: `Vigia da Fuji não completou: ${errors.join(" | ")}` });
  await post(alerts);
  fs.mkdirSync(path.dirname(STATE), { recursive: true });
  fs.writeFileSync(STATE, JSON.stringify(st));
  console.log(JSON.stringify({ at: new Date().toISOString(), event: "watch", dry: DRY, alerts: alerts.map((a) => ({ severity: a.severity, name: a.name, summary: a.summary })), errors }));
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });

// midnight-relayer-daemon.ts — one relayer of the DPO2UMidnightRelay consortium.
//
//   npx ts-node scripts/midnight-relayer-daemon.ts [--once]
// Env:
//   RELAYER_KEY_FILE       mode-600 file with this relayer's private key (never printed)
//   MIDNIGHT_TOOLING_DIR   dpo2u-midnight checkout on ledger-v9 (compiled contract + runtime)
//   MIDNIGHT_INDEXER_HTTP / MIDNIGHT_INDEXER_WS   this relayer's own indexer (defaults: public preview,
//                          a PROVISIONAL bridge until the relayer's own node and indexer are synced)
//   FUJI_RPC_URL           default public Fuji RPC
//   RELAY_CURSOR_FILE      default /var/lib/dpo2u-midnight-relayer/cursor
//   RELAY_INTERVAL_SEC     default 120
//   RELAY_FINALITY_LAG     default 5 blocks
// Logs one JSON line per pass. The relay and the registry decide; this process only confirms seals.
import fs from "node:fs";
import path from "node:path";
import { JsonRpcProvider, Wallet } from "ethers";
import { relayOnce } from "../src/midnight-relayer";
import { GraphQLIndexerTransport, IndexerSealSource } from "../src/midnight-indexer-source";
import { loadComplianceRegistryDecoder } from "../src/midnight-decoder";

const env = (k: string, d?: string) => {
  const v = process.env[k] ?? d;
  if (v === undefined || v === "") throw new Error(`${k} is required`);
  return v;
};

async function main() {
  const once = process.argv.includes("--once");
  const tooling = env("MIDNIGHT_TOOLING_DIR");
  const key = fs.readFileSync(env("RELAYER_KEY_FILE"), "utf8").trim();
  const provider = new JsonRpcProvider(env("FUJI_RPC_URL", "https://api.avax-test.network/ext/bc/C/rpc"), 43113, { staticNetwork: true });
  const signer = new Wallet(key, provider);
  const fuji = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "deployments", "fuji.json"), "utf8"));
  const relayAddress: string = fuji.midnightRelay.address;
  const mid = JSON.parse(fs.readFileSync(path.join(tooling, "deployment-preview-v9.json"), "utf8")).contracts.find((c: any) => c.name === "ComplianceRegistry");
  const httpUrl = env("MIDNIGHT_INDEXER_HTTP", "https://indexer.preview.midnight.network/api/v4/graphql");
  const wsUrl = env("MIDNIGHT_INDEXER_WS", "wss://indexer.preview.midnight.network/api/v4/graphql/ws");
  const source = new IndexerSealSource({
    transport: new GraphQLIndexerTransport({ httpUrl, wsUrl }),
    contractAddress: mid.contractAddress,
    decode: await loadComplianceRegistryDecoder(tooling),
    deployHeight: mid.blockHeight,
    finalityLag: Number(env("RELAY_FINALITY_LAG", "5")),
  });
  const cursorFile = env("RELAY_CURSOR_FILE", "/var/lib/dpo2u-midnight-relayer/cursor");
  fs.mkdirSync(path.dirname(cursorFile), { recursive: true });
  const interval = Number(env("RELAY_INTERVAL_SEC", "120")) * 1000;
  console.log(JSON.stringify({ at: new Date().toISOString(), event: "start", relayer: signer.address, relay: relayAddress, midnightContract: mid.contractAddress, indexer: httpUrl }));

  for (;;) {
    const cursor = fs.existsSync(cursorFile) ? fs.readFileSync(cursorFile, "utf8").trim() || undefined : undefined;
    try {
      const report = await relayOnce({ source, relayAddress, signer, cursor });
      if (report.cursor !== undefined && report.cursor !== cursor) fs.writeFileSync(cursorFile, report.cursor + "\n");
      console.log(JSON.stringify({ at: new Date().toISOString(), event: "pass", cursorIn: cursor ?? null, cursorOut: report.cursor ?? null, results: report.results }));
    } catch (e) {
      console.log(JSON.stringify({ at: new Date().toISOString(), event: "error", cursor: cursor ?? null, error: e instanceof Error ? e.message : String(e) }));
      if (once) process.exit(1);
    }
    if (once) break;
    await new Promise((r) => setTimeout(r, interval));
  }
}

main().catch((e) => { console.error(e); process.exit(1); });

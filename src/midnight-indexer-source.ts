// midnight-indexer-source.ts — MidnightSealSource backed by a Midnight indexer (GraphQL v4).
//
// Reads the `attestUseCase` seals of one Midnight ComplianceRegistry. The indexer serves each
// contract action with the contract state after it; the state is decoded by an injected
// `StateDecoder` (built where the Midnight tooling runs, from the compiled contract's `ledger()`),
// so this module carries no Midnight dependency. A seal is attributed to the `attestUseCase` call
// whose state first contains its evidence hash, which gives the Midnight transaction hash.
//
// Cursor: the highest block height already scanned, as a decimal string. Each pass scans actions
// up to `tip - finalityLag`, so a seal is only ever reported from a block at least `finalityLag`
// blocks deep. Passes are idempotent (relayOnce skips relayed/confirmed seals), so a pass may
// re-read earlier actions safely.
import type { MidnightSeal, MidnightSealSource } from "./midnight-relayer";

export interface DecodedSeal {
  evidenceHash: string; // 0x + 64 hex
  midnightUseCaseId: string; // 0x + 64 hex (UTF-8 use case id right-padded to 32 bytes)
  verdict: 0 | 1 | 2;
  metadataHash: string; // 0x + 64 hex
}

/** Decodes the hex contract state served by the indexer into the seals it holds. */
export type StateDecoder = (stateHex: string) => DecodedSeal[];

export interface ContractActionRow {
  kind: "ContractDeploy" | "ContractCall" | "ContractUpdate" | string;
  entryPoint?: string;
  stateHex: string;
  txHash: string;
  blockHeight: number;
}

export interface IndexerTransport {
  tipHeight(): Promise<number>;
  /** Every action of `address` from `fromHeight` on, in chain order. */
  actionsFrom(address: string, fromHeight: number): Promise<ContractActionRow[]>;
}

const hex32 = (h: string) => "0x" + h.replace(/^0x/, "").toLowerCase().padStart(64, "0");

/** GraphQL v4 transport: `block` for the tip, the `contractActions` subscription for history. */
export class GraphQLIndexerTransport implements IndexerTransport {
  constructor(private opts: { httpUrl: string; wsUrl: string; quietMs?: number; timeoutMs?: number; WebSocketImpl?: any }) {}

  async tipHeight(): Promise<number> {
    const r = await fetch(this.opts.httpUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ query: "{ block { height } }" }),
    });
    const j: any = await r.json();
    const h = j?.data?.block?.height;
    if (typeof h !== "number") throw new Error(`indexer tip: unexpected response ${JSON.stringify(j).slice(0, 200)}`);
    return h;
  }

  actionsFrom(address: string, fromHeight: number): Promise<ContractActionRow[]> {
    const WS = this.opts.WebSocketImpl ?? (globalThis as any).WebSocket;
    if (!WS) throw new Error("no WebSocket implementation available");
    const quietMs = this.opts.quietMs ?? 4000;
    const timeoutMs = this.opts.timeoutMs ?? 60_000;
    const query = `subscription($a: HexEncoded!, $h: Int!) {
      contractActions(address: $a, offset: { height: $h }) {
        __typename
        ... on ContractCall { entryPoint }
        state
        transaction { hash block { height } }
      }
    }`;
    return new Promise((resolve, reject) => {
      const rows: ContractActionRow[] = [];
      const ws = new WS(this.opts.wsUrl, "graphql-transport-ws");
      let quiet: any;
      const done = (err?: unknown) => {
        clearTimeout(quiet);
        clearTimeout(hard);
        try { ws.close(); } catch { /* closing */ }
        if (err) reject(err); else resolve(rows);
      };
      const arm = () => { clearTimeout(quiet); quiet = setTimeout(() => done(), quietMs); };
      const hard = setTimeout(() => done(new Error("indexer subscription timed out")), timeoutMs);
      ws.onopen = () => ws.send(JSON.stringify({ type: "connection_init" }));
      ws.onerror = (e: any) => done(new Error(`indexer websocket error: ${e?.message ?? e}`));
      ws.onmessage = (ev: any) => {
        const msg = JSON.parse(typeof ev.data === "string" ? ev.data : Buffer.from(ev.data).toString());
        if (msg.type === "connection_ack") {
          ws.send(JSON.stringify({ id: "1", type: "subscribe", payload: { query, variables: { a: address.replace(/^0x/, ""), h: fromHeight } } }));
          arm();
        } else if (msg.type === "next") {
          if (msg.payload?.errors) return done(new Error(`indexer: ${JSON.stringify(msg.payload.errors).slice(0, 300)}`));
          const a = msg.payload?.data?.contractActions;
          if (a) rows.push({ kind: a.__typename, entryPoint: a.entryPoint, stateHex: a.state, txHash: a.transaction.hash, blockHeight: a.transaction.block.height });
          arm();
        } else if (msg.type === "error") {
          done(new Error(`indexer: ${JSON.stringify(msg.payload).slice(0, 300)}`));
        } else if (msg.type === "complete") {
          done();
        }
      };
    });
  }
}

export class IndexerSealSource implements MidnightSealSource {
  constructor(
    private opts: {
      transport: IndexerTransport;
      contractAddress: string; // Midnight ComplianceRegistry address (hex, 32 bytes)
      decode: StateDecoder;
      /** Block height of the contract deploy: history is replayed from here to attribute seals. */
      deployHeight: number;
      /** Blocks to stay behind the tip before reporting a seal (default 5). */
      finalityLag?: number;
    },
  ) {}

  async sealsSince(cursor: string | undefined): Promise<{ seals: MidnightSeal[]; cursor: string | undefined }> {
    const lag = this.opts.finalityLag ?? 5;
    const safe = (await this.opts.transport.tipHeight()) - lag;
    const after = cursor === undefined ? this.opts.deployHeight - 1 : Number(cursor);
    if (!Number.isFinite(after)) throw new Error(`bad cursor ${cursor}`);
    if (safe <= after) return { seals: [], cursor };

    const actions = (await this.opts.transport.actionsFrom(this.opts.contractAddress, this.opts.deployHeight))
      .filter((a) => a.blockHeight <= safe)
      .sort((x, y) => x.blockHeight - y.blockHeight);

    const seen = new Set<string>();
    const seals: MidnightSeal[] = [];
    for (const a of actions) {
      const decoded = this.opts.decode(a.stateHex);
      for (const d of decoded) {
        const key = d.evidenceHash.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        // Attribute only to an attestUseCase call; a deploy or maintenance update never writes seals.
        if (a.kind !== "ContractCall" || a.entryPoint !== "attestUseCase") continue;
        if (a.blockHeight <= after) continue; // already reported in an earlier pass
        seals.push({
          midnightContract: hex32(this.opts.contractAddress),
          midnightTx: hex32(a.txHash),
          midnightUseCaseId: hex32(d.midnightUseCaseId),
          midnightVerdict: d.verdict,
          evidenceHash: hex32(d.evidenceHash),
          metadataHash: hex32(d.metadataHash),
        });
      }
    }
    return { seals, cursor: String(safe) };
  }
}

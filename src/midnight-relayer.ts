// midnight-relayer.ts — one relayer of the DPO2UMidnightRelay consortium.
//
// Reads FINAL `attestUseCase` seals from Midnight through a `MidnightSealSource` (the indexer
// adapter lives where the Midnight tooling runs: the DPO2U chairman daemon) and confirms each one
// on the C-Chain relay. The relay registers a seal only when `threshold` independent relayers
// confirmed the identical seal, so a single compromised relayer cannot write a verdict.
//
// Idempotent: seals already relayed, already confirmed by this relayer, or on unmapped use cases
// are skipped, so the loop can be re-run over the same window.
import { Contract, type ContractRunner } from "ethers";

export interface MidnightSeal {
  midnightContract: string; // bytes32
  midnightTx: string; // bytes32
  midnightUseCaseId: string; // bytes32, as stored on Midnight
  midnightVerdict: 0 | 1 | 2; // 0 FAIL, 1 PASS, 2 REVIEW
  evidenceHash: string; // bytes32
  metadataHash: string; // bytes32
}

/** Source of FINAL Midnight seals (never unconfirmed/mempool ones). */
export interface MidnightSealSource {
  sealsSince(cursor: string | undefined): Promise<{ seals: MidnightSeal[]; cursor: string | undefined }>;
}

export const MIDNIGHT_RELAY_ABI = [
  "function sealDigest((bytes32 midnightContract, bytes32 midnightTx, bytes32 midnightUseCaseId, uint8 midnightVerdict, bytes32 evidenceHash, bytes32 metadataHash) s) view returns (bytes32)",
  "function confirm((bytes32 midnightContract, bytes32 midnightTx, bytes32 midnightUseCaseId, uint8 midnightVerdict, bytes32 evidenceHash, bytes32 metadataHash) s) returns (bool)",
  "function relayed(bytes32) view returns (bool)",
  "function confirmedBy(bytes32, address) view returns (bool)",
  "function routes(bytes32) view returns (bytes32 useCaseId, uint64 validity)",
];

export type RelayOutcome = "confirmed" | "registered" | "skipped:relayed" | "skipped:confirmed" | "skipped:unmapped" | "failed";

export interface RelayReport {
  /** Cursor to persist: the source's new cursor, or the input cursor when any seal failed. */
  cursor: string | undefined;
  results: { evidenceHash: string; outcome: RelayOutcome; txHash?: string; error?: string }[];
}

/** One pass: read seals after `cursor` and confirm each on the relay as `signer`. */
export async function relayOnce(args: {
  source: MidnightSealSource;
  relayAddress: string;
  signer: ContractRunner & { getAddress(): Promise<string> };
  cursor?: string;
}): Promise<RelayReport> {
  const relay = new Contract(args.relayAddress, MIDNIGHT_RELAY_ABI, args.signer);
  const me = await args.signer.getAddress();
  const { seals, cursor } = await args.source.sealsSince(args.cursor);
  const results: RelayReport["results"] = [];
  for (const s of seals) {
    try {
      const route = await relay.routes(s.midnightUseCaseId);
      if (route.useCaseId === "0x" + "0".repeat(64)) {
        results.push({ evidenceHash: s.evidenceHash, outcome: "skipped:unmapped" });
        continue;
      }
      const digest: string = await relay.sealDigest(s);
      if (await relay.relayed(digest)) {
        results.push({ evidenceHash: s.evidenceHash, outcome: "skipped:relayed" });
        continue;
      }
      if (await relay.confirmedBy(digest, me)) {
        results.push({ evidenceHash: s.evidenceHash, outcome: "skipped:confirmed" });
        continue;
      }
      const tx = await relay.confirm(s);
      const receipt = await tx.wait();
      const registered = await relay.relayed(digest);
      results.push({ evidenceHash: s.evidenceHash, outcome: registered ? "registered" : "confirmed", txHash: receipt?.hash ?? tx.hash });
    } catch (err) {
      results.push({ evidenceHash: s.evidenceHash, outcome: "failed", error: err instanceof Error ? err.message : String(err) });
    }
  }
  // A failed seal (RPC error, reverted tx) must be retried: never advance past it. Re-reading the
  // same window is safe because every other outcome above is idempotent.
  const anyFailed = results.some((r) => r.outcome === "failed");
  return { cursor: anyFailed ? args.cursor : cursor, results };
}

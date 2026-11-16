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
  // relay errors
  "error NotRelayer()",
  "error ZeroValue()",
  "error InvalidVerdict()",
  "error UnmappedUseCase()",
  "error AlreadyConfirmed()",
  "error AlreadyRelayed()",
  // registry errors, bubbled up from registerAttestation
  "error NotAuthorized()",
  "error UseCaseInactive()",
  "error AttestationExists()",
  "error ZeroEvidenceHash()",
  "error InvalidExpiry()",
  "error ValidityTooLong()",
];

/**
 * Reverts caused by the seal itself: retrying can never succeed, so the seal is skipped (logged)
 * and the cursor advances. Every other error (RPC, nonce, gas, and reverts caused by
 * configuration that an admin can fix: NotRelayer, NotAuthorized, UseCaseInactive, ...) is
 * retried on the next pass.
 */
export const SKIP_ON_REVERT = new Set(["AttestationExists", "InvalidVerdict", "ZeroValue", "ZeroEvidenceHash"]);

/** Name of the custom error a simulated call reverted with, or undefined if it is not a revert. */
function revertName(relay: Contract, err: any): string | undefined {
  // In-process Hardhat network: the error is not an ethers CALL_EXCEPTION, only a message.
  const m = /reverted with custom error '(\w+)\(/.exec(String(err?.message ?? ""));
  if (m) return m[1];
  if (err?.code !== "CALL_EXCEPTION") return undefined;
  if (err.revert?.name) return err.revert.name;
  const data = err.data ?? err.info?.error?.data;
  if (typeof data === "string" && data.length >= 10) {
    try {
      return relay.interface.parseError(data)?.name ?? `0x${data.slice(2, 10)}`;
    } catch {
      return `0x${data.slice(2, 10)}`;
    }
  }
  return "revert";
}

export type RelayOutcome = "confirmed" | "registered" | "skipped:relayed" | "skipped:confirmed" | "skipped:unmapped" | "skipped:reverted" | "failed";

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
      // Simulate first: a deterministic revert (e.g. the registry already holds this evidence
      // under the use case: AttestationExists) would otherwise block the cursor forever.
      try {
        await relay.confirm.staticCall(s);
      } catch (err) {
        const name = revertName(relay, err);
        if (name && SKIP_ON_REVERT.has(name)) {
          results.push({ evidenceHash: s.evidenceHash, outcome: "skipped:reverted", error: name });
          continue;
        }
        throw err;
      }
      const tx = await relay.confirm(s);
      const receipt = await tx.wait();
      const registered = await relay.relayed(digest);
      results.push({ evidenceHash: s.evidenceHash, outcome: registered ? "registered" : "confirmed", txHash: receipt?.hash ?? tx.hash });
    } catch (err) {
      results.push({ evidenceHash: s.evidenceHash, outcome: "failed", error: err instanceof Error ? err.message : String(err) });
    }
  }
  // A failed seal (RPC error, reverted tx, fixable configuration) must be retried: never advance
  // past it. Re-reading the same window is safe because every other outcome above is idempotent.
  // Seals that can never be confirmed (SKIP_ON_REVERT) are reported as skipped:reverted instead.
  const anyFailed = results.some((r) => r.outcome === "failed");
  return { cursor: anyFailed ? args.cursor : cursor, results };
}

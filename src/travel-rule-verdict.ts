// Common Travel Rule verdict format v1 (dpo2u-midnight docs/VERDICT-FORMAT.md), C-Chain relayer side.
// canonicalJson / checkVerdict mirror dpo2u-midnight scripts/lib/verdict.ts; the shared vectors
// (test/fixtures/verdict-v1-crosschain.json) pin this file, the Solidity library and the Midnight
// and Soroban implementations to the same digests.
import { createHash } from "node:crypto";

export const VERDICT_FORMAT = "dpo2u.travel-rule-verdict/1";
export const EVIDENCE_FORMAT = "dpo2u.travel-rule-relay-evidence/1";

export const REASON_LABELS: Record<number, string> = {
  0: "none",
  1: "missing_party_info",
  2: "missing_originator_document_above_threshold",
  3: "counterparty_vasp_not_attested",
  4: "sanctions_hit",
};

export const TRUST_STATEMENT =
  "Operator trust, not a proof. The C-Chain mirror checks the verdict's form (format rules, pinned " +
  "Midnight gate, allowed policy, digest, M-of-N authorized relayers) but has no Midnight light " +
  "client or state proof: it cannot check that Midnight produced this verdict. Audit it by " +
  "re-exporting the verdict from Midnight at the anchored tx and comparing the digest.";

export type Verdict = {
  format: string;
  transfer_id: string;
  verdict: "PASS" | "FAIL";
  released: boolean;
  reason: { code: number; label: string };
  policy_hash: string;
  originator_root: string;
  beneficiary_root: string;
  source_chain: string;
  source_contract: string;
  block: { height: number; hash: string } | null;
  tx: string | null;
  sanctions?: { list_root: string; provider_id: string; valid_until: number };
};

const HEX32 = /^[0-9a-f]{64}$/;

export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  if (v && typeof v === "object")
    return "{" + Object.keys(v as object).sort().filter((k) => (v as any)[k] !== undefined).map((k) => JSON.stringify(k) + ":" + canonicalJson((v as any)[k])).join(",") + "}";
  return JSON.stringify(v);
}

export const verdictDigest = (v: Verdict) => createHash("sha256").update(canonicalJson(v)).digest("hex");

export function checkVerdict(v: any): string[] {
  const e: string[] = [];
  if (v?.format !== VERDICT_FORMAT) e.push(`format must be ${VERDICT_FORMAT}`);
  for (const k of ["transfer_id", "policy_hash", "originator_root", "beneficiary_root"]) if (!HEX32.test(String(v?.[k]))) e.push(`${k} must be 32 bytes lowercase hex`);
  if (!["PASS", "FAIL"].includes(v?.verdict)) e.push("verdict must be PASS or FAIL");
  if (typeof v?.released !== "boolean") e.push("released must be a boolean");
  if (v?.released && v?.verdict !== "PASS") e.push("only a PASS can be released");
  if (!Number.isInteger(v?.reason?.code) || REASON_LABELS[v.reason.code] !== v?.reason?.label) e.push("reason must be { code 0..4, label } with the matching label");
  if ((v?.verdict === "PASS") !== (v?.reason?.code === 0)) e.push("PASS has reason 0 and FAIL a non-zero reason");
  if (typeof v?.source_chain !== "string" || !/^[a-z0-9-]+:[a-z0-9-]+$/.test(v.source_chain)) e.push('source_chain must be "<chain>:<network>"');
  if (!/^[0-9a-f]+$/.test(String(v?.source_contract))) e.push("source_contract must be hex");
  if (v?.block !== null && !(Number.isInteger(v?.block?.height) && /^[0-9a-f]+$/.test(String(v?.block?.hash)))) e.push("block must be null or { height, hash }");
  if (v?.tx !== null && !/^[0-9a-f]+$/.test(String(v?.tx))) e.push("tx must be null or hex");
  if ((v?.block === null) !== (v?.tx === null)) e.push("block and tx are both set or both null");
  if (v?.sanctions !== undefined && !(HEX32.test(String(v.sanctions.list_root)) && HEX32.test(String(v.sanctions.provider_id)) && Number.isInteger(v.sanctions.valid_until))) e.push("sanctions must be { list_root, provider_id, valid_until }");
  return e;
}

/** What the mirror contract refuses on top of the format rules. */
export function checkForMirror(v: Verdict): string[] {
  const e: string[] = [];
  if (v.policy_hash === "0".repeat(64)) e.push("policy_hash is zero (pre-v10 gate); the mirror refuses it");
  if (v.block === null) e.push("verdict is not anchored: export it with --tx <evaluateTransfer|releaseTransfer tx>");
  const evenHex = (s: unknown) => typeof s === "string" && s.length > 0 && s.length % 2 === 0 && s.length <= 128;
  if (!evenHex(v.source_contract)) e.push("source_contract must be 1..64 bytes of hex");
  if (v.block && (!evenHex(v.block.hash) || !evenHex(v.tx))) e.push("block hash and tx must be 1..64 bytes of hex");
  if (v.source_chain.length > 64) e.push("source_chain longer than 64");
  return e;
}

const hx = (s: string) => "0x" + s;
const ZERO32 = "0x" + "00".repeat(32);

/** Format v1 object -> TravelRuleVerdictV1.Verdict tuple (ethers object form). */
export function toSolidityVerdict(v: Verdict) {
  return {
    transferId: hx(v.transfer_id),
    pass: v.verdict === "PASS",
    released: v.released,
    reasonCode: v.reason.code,
    policyHash: hx(v.policy_hash),
    originatorRoot: hx(v.originator_root),
    beneficiaryRoot: hx(v.beneficiary_root),
    sourceChain: v.source_chain,
    sourceContract: hx(v.source_contract),
    anchored: v.block !== null,
    anchor: v.block === null ? { height: 0, hash: "0x", tx: "0x" } : { height: v.block.height, hash: hx(v.block.hash), tx: hx(v.tx as string) },
    hasSanctions: v.sanctions !== undefined,
    sanctions: v.sanctions === undefined
      ? { listRoot: ZERO32, providerId: ZERO32, validUntil: 0 }
      : { listRoot: hx(v.sanctions.list_root), providerId: hx(v.sanctions.provider_id), validUntil: v.sanctions.valid_until },
  };
}

export function evidenceRecord(a: { verdict: Verdict; digest: string; chain: Record<string, unknown>; relayedAt: string }) {
  const v = a.verdict;
  return {
    format: EVIDENCE_FORMAT,
    trust_model: "operator",
    trust_statement: TRUST_STATEMENT,
    midnight: {
      verdict: v,
      digest: a.digest,
      reproduce: `MIDNIGHT_NETWORK=${v.source_chain.split(":")[1]} npx tsx scripts/export-verdict.ts --transfer ${v.transfer_id} --tx ${v.tx} --contract ${v.source_contract}`,
    },
    avalanche: a.chain,
    relayed_at: a.relayedAt,
  };
}

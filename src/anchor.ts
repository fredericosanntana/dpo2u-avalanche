// AvalancheChainAnchor — shape-compatible with the DPO2U control-plane ChainAnchorPort
// (DPO2U/packages/control-plane/src/ports/index.ts): `target`, `anchor(req)`, `verify(commitment)`.
// It is structurally typed on purpose, so this package does not import the monorepo.
//
// Failure policy (PSAV spec §5): this adapter never fabricates a receipt. With no signer
// or RPC it throws, and the control plane turns the rule into REVIEW, never PASS.
import { createHash } from "node:crypto";
import { Contract, JsonRpcProvider, Wallet, type ContractRunner, id as selectorOf, isHexString, keccak256, toUtf8Bytes } from "ethers";
import { resolveAvalancheNetwork, type AvalancheNetwork } from "./chains";

export const REGISTRY_ABI = [
  "function registerAttestation(bytes32 useCaseId, bytes32 evidenceHash, bytes32 subject, uint8 verdict, uint8 origin, bytes32 metadataHash, uint64 expiresAt)",
  "function revokeAttestation(bytes32 useCaseId, bytes32 evidenceHash, bytes32 reasonHash)",
  "function isValid(bytes32 useCaseId, bytes32 evidenceHash) view returns (bool)",
  "function isSubjectCompliant(bytes32 useCaseId, bytes32 subject) view returns (bool)",
  "function getAttestation(bytes32 useCaseId, bytes32 evidenceHash) view returns (tuple(uint8 verdict, uint8 origin, bool revoked, uint64 issuedAt, uint64 expiresAt, address submitter, bytes32 subject, bytes32 metadataHash, bytes32 packHash, uint32 packVersion))",
] as const;

const NOT_FOUND_SELECTOR = selectorOf("AttestationNotFound()").slice(0, 10).toLowerCase();

export const Verdict = { PASS: 1, FAIL: 2, REVIEW: 3 } as const;
export const Origin = { MACHINE: 0, HUMAN_REVIEWED: 1, THIRD_PARTY: 2 } as const;

/** Same shapes as the control-plane port (copied, not imported). */
export interface AnchorRequest {
  subject: string;
  /** sha256 hex commitment (with or without 0x). */
  commitment: string;
  schema: string;
  storageUri?: string;
}
export interface AnchorResult {
  target: "avalanche";
  txSig?: string;
  slot?: number;
  explorerUrl?: string;
  local?: boolean;
}
export interface AnchorVerification {
  found: boolean;
  revoked?: boolean;
}

export interface AvalancheAnchorOptions {
  network?: string; // fuji | avalanche | eip155:43113 | eip155:43114
  rpcUrl?: string;
  registryAddress: string;
  privateKey?: string;
  /** Inject a runner (signer or provider) instead of rpcUrl/privateKey — tests, HSM, multisig relayers. */
  runner?: ContractRunner;
  /** Use-case id string; hashed with keccak256 to bytes32. Default: dpo2u/control-plane/attestation/v1 */
  useCase?: string;
  /** Seconds of validity for each seal (silence = non-compliance). Default 90 days. */
  validitySeconds?: number;
  origin?: number;
}

export function toBytes32Hex(hex: string): string {
  const h = hex.startsWith("0x") ? hex : `0x${hex}`;
  if (!isHexString(h, 32)) throw new Error(`expected 32-byte hex, got ${hex}`);
  return h.toLowerCase();
}

/** Subject identifiers never go on-chain in clear: keccak256 of the string. */
export function subjectHash(subject: string): string {
  return keccak256(toUtf8Bytes(subject));
}

/** metadataHash = sha256(schema | storageUri) — binds the seal to its run record. */
export function metadataHash(req: AnchorRequest): string {
  return "0x" + createHash("sha256").update(`${req.schema}|${req.storageUri ?? ""}`).digest("hex");
}

export class AvalancheChainAnchor {
  readonly target = "avalanche" as const;
  readonly network: AvalancheNetwork;
  private readonly registry: Contract;
  private readonly useCaseId: string;
  private readonly validitySeconds: number;
  private readonly origin: number;
  private queue: Promise<unknown> = Promise.resolve(); // serialize nonces

  constructor(opts: AvalancheAnchorOptions) {
    this.network = resolveAvalancheNetwork(opts.network ?? "fuji");
    let runner: ContractRunner;
    if (opts.runner) runner = opts.runner;
    else {
      const provider = new JsonRpcProvider(opts.rpcUrl ?? this.network.defaultRpc, this.network.chainId);
      runner = opts.privateKey ? new Wallet(opts.privateKey, provider) : provider;
    }
    this.registry = new Contract(opts.registryAddress, REGISTRY_ABI, runner);
    this.useCaseId = keccak256(toUtf8Bytes(opts.useCase ?? "dpo2u/control-plane/attestation/v1"));
    this.validitySeconds = opts.validitySeconds ?? 90 * 86_400;
    this.origin = opts.origin ?? Origin.HUMAN_REVIEWED;
  }

  async anchor(req: AnchorRequest): Promise<AnchorResult> {
    const run = async (): Promise<AnchorResult> => {
      if (typeof this.registry.runner?.sendTransaction !== "function") {
        throw new Error("avalanche anchor: no signer configured (fail-closed; the rule must go to REVIEW)");
      }
      const expiresAt = Math.floor(Date.now() / 1000) + this.validitySeconds;
      const tx = await this.registry.registerAttestation(
        this.useCaseId,
        toBytes32Hex(req.commitment),
        subjectHash(req.subject),
        Verdict.PASS,
        this.origin,
        metadataHash(req),
        expiresAt,
      );
      const receipt = await tx.wait();
      return {
        target: "avalanche",
        txSig: tx.hash,
        slot: receipt?.blockNumber,
        explorerUrl: `${this.network.explorer}/tx/${tx.hash}`,
        local: false,
      };
    };
    const p = this.queue.then(run, run);
    this.queue = p.catch(() => undefined);
    return p;
  }

  async verify(commitment: string): Promise<AnchorVerification> {
    try {
      const a = await this.registry.getAttestation(this.useCaseId, toBytes32Hex(commitment));
      return { found: true, revoked: Boolean(a.revoked) };
    } catch (err: unknown) {
      // Only the contract's AttestationNotFound() maps to found:false. Any transport or
      // RPC error propagates, so the control plane records REVIEW instead of a verdict.
      const data = (err as { data?: unknown }).data;
      if (typeof data === "string" && data.toLowerCase().startsWith(NOT_FOUND_SELECTOR)) return { found: false };
      throw err;
    }
  }

  /** Oracle read used by /verify: PASS, not revoked, not expired. */
  async isValid(commitment: string): Promise<boolean> {
    return this.registry.isValid(this.useCaseId, toBytes32Hex(commitment));
  }

  get useCaseIdHex(): string {
    return this.useCaseId;
  }
}

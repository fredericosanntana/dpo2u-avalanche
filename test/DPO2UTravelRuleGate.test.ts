import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

const PASS = 1, FAIL = 2, REVIEW = 3;
const MACHINE = 0;
const DAY = 86_400;
const id = (s: string) => ethers.keccak256(ethers.toUtf8Bytes(s));
const ZERO = ethers.ZeroHash;
const MASK = (1n << 248n) - 1n;

describe("DPO2UTravelRuleGate", () => {
  const UC = id("travel-rule-adjacent@1");
  const PARTY_UC = id("psav-passport@1");
  const ORIG = id("eip155:43113:0x00000000000000000000000000000000000000A1");
  const BENE = id("eip155:43113:0x00000000000000000000000000000000000000B2");
  const SCOPE = id("rebalance");
  const META = id("run-summary");
  const PAYLOAD = ethers.AbiCoder.defaultAbiCoder().encode(["string", "uint256"], ["unwind", 1000n]);
  const parties = { originator: ORIG, beneficiary: BENE };
  const REC = BigInt(id("eip155:43113:0x00000000000000000000000000000000000000B2")) & MASK;
  const proof = { a: [1n, 2n], b: [[3n, 4n], [5n, 6n]], c: [7n, 8n] };

  async function deploy(opts: { partyUc?: string; noVerifiers?: boolean } = {}) {
    const [admin, submitter, operator, other, newAdmin] = await ethers.getSigners();
    const reg = await (await ethers.getContractFactory("DPO2UComplianceRegistry")).deploy(admin.address, 365 * DAY);
    await reg.configureUseCase(UC, true, id("pack:tr"), 1);
    await reg.configureUseCase(PARTY_UC, true, id("pack:passport"), 1);
    await reg.authorizeSubmitter(submitter.address, true);

    const policyV = await (await ethers.getContractFactory("MockPolicyVerifier")).deploy();
    const memberV = await (await ethers.getContractFactory("MockMembershipVerifier")).deploy();
    const target = await (await ethers.getContractFactory("MockGatedTarget")).deploy();
    const provider = await (await ethers.getContractFactory("MockRootProvider")).deploy();

    const gate = await (await ethers.getContractFactory("DPO2UTravelRuleGate")).deploy(
      admin.address,
      await reg.getAddress(),
      await target.getAddress(),
      UC,
      opts.partyUc ?? ZERO,
      opts.noVerifiers ? ethers.ZeroAddress : await policyV.getAddress(),
      opts.noVerifiers ? ethers.ZeroAddress : await memberV.getAddress(),
    );
    await target.setGate(await gate.getAddress());
    await gate.authorizeOperator(operator.address, true);
    return { reg, gate, target, policyV, memberV, provider, admin, submitter, operator, other, newAdmin };
  }

  async function intent(gate: any, operator: any, nonce = 1n, days = 1, p = parties, payload = PAYLOAD) {
    const expiresAt = BigInt((await time.latest()) + days * DAY);
    const ev = await gate.deriveEvidenceHash(operator.address, SCOPE, nonce, expiresAt, p, payload);
    return { nonce, expiresAt, ev, p, payload };
  }

  async function seal(reg: any, submitter: any, uc: string, ev: string, verdict = PASS, subject = ORIG, days = 30) {
    await reg
      .connect(submitter)
      .registerAttestation(uc, ev, subject, verdict, MACHINE, META, BigInt((await time.latest()) + days * DAY));
  }

  const run = (gate: any, op: any, i: any) =>
    gate.connect(op).execute(SCOPE, i.nonce, i.expiresAt, i.ev, i.p, i.payload);
  const runZk = (gate: any, op: any, i: any, signals: bigint[]) =>
    gate.connect(op).executeWithProof(SCOPE, i.nonce, i.expiresAt, i.ev, i.p, i.payload, proof, signals);

  // ── Attestation lane ──────────────────────────────────────────────────────

  it("PASS executes the target once and emits GatedExecution", async () => {
    const { reg, gate, target, submitter, operator } = await deploy();
    const i = await intent(gate, operator);
    await seal(reg, submitter, UC, i.ev);
    await expect(run(gate, operator, i)).to.emit(gate, "GatedExecution");
    expect(await target.calls()).to.equal(1);
    expect(await target.lastOperator()).to.equal(operator.address);
    expect(await target.lastEvidence()).to.equal(i.ev);
    expect(await target.lastPayload()).to.equal(PAYLOAD);
    expect(await gate.consumedEvidence(i.ev)).to.equal(true);
  });

  it("rejects a non-operator", async () => {
    const { reg, gate, submitter, operator, other } = await deploy();
    const i = await intent(gate, operator);
    await seal(reg, submitter, UC, i.ev);
    await expect(run(gate, other, i)).to.be.revertedWithCustomError(gate, "Unauthorized");
  });

  it("rejects a revoked operator", async () => {
    const { reg, gate, submitter, operator } = await deploy();
    const i = await intent(gate, operator);
    await seal(reg, submitter, UC, i.ev);
    await gate.authorizeOperator(operator.address, false);
    await expect(run(gate, operator, i)).to.be.revertedWithCustomError(gate, "Unauthorized");
  });

  it("rejects an expired intent", async () => {
    const { reg, gate, submitter, operator } = await deploy();
    const i = await intent(gate, operator);
    await seal(reg, submitter, UC, i.ev);
    await time.increase(2 * DAY);
    await expect(run(gate, operator, i)).to.be.revertedWithCustomError(gate, "EvidenceExpired");
  });

  it("anti-replay: the same evidence cannot run twice", async () => {
    const { reg, gate, submitter, operator } = await deploy();
    const i = await intent(gate, operator);
    await seal(reg, submitter, UC, i.ev);
    await run(gate, operator, i);
    await expect(run(gate, operator, i)).to.be.revertedWithCustomError(gate, "EvidenceReplay");
  });

  it("binding: a payload that differs from the sealed one is rejected", async () => {
    const { reg, gate, submitter, operator } = await deploy();
    const i = await intent(gate, operator);
    await seal(reg, submitter, UC, i.ev);
    const tampered = { ...i, payload: ethers.AbiCoder.defaultAbiCoder().encode(["string", "uint256"], ["unwind", 9999n]) };
    await expect(run(gate, operator, tampered)).to.be.revertedWithCustomError(gate, "EvidenceHashMismatch");
  });

  it("binding: swapping the beneficiary is rejected", async () => {
    const { reg, gate, submitter, operator } = await deploy();
    const i = await intent(gate, operator);
    await seal(reg, submitter, UC, i.ev);
    const swapped = { ...i, p: { originator: ORIG, beneficiary: id("attacker") } };
    await expect(run(gate, operator, swapped)).to.be.revertedWithCustomError(gate, "EvidenceHashMismatch");
  });

  it("binding: another operator cannot use someone else's sealed intent", async () => {
    const { reg, gate, submitter, operator, other } = await deploy();
    await gate.authorizeOperator(other.address, true);
    const i = await intent(gate, operator);
    await seal(reg, submitter, UC, i.ev);
    await expect(run(gate, other, i)).to.be.revertedWithCustomError(gate, "EvidenceHashMismatch");
  });

  it("missing attestation is rejected", async () => {
    const { gate, operator } = await deploy();
    const i = await intent(gate, operator);
    await expect(run(gate, operator, i)).to.be.revertedWithCustomError(gate, "AttestationMissing");
  });

  it("FAIL and REVIEW are rejected", async () => {
    for (const v of [FAIL, REVIEW]) {
      const { reg, gate, submitter, operator } = await deploy();
      const i = await intent(gate, operator);
      await seal(reg, submitter, UC, i.ev, v);
      await expect(run(gate, operator, i)).to.be.revertedWithCustomError(gate, "AttestationNotPass");
    }
  });

  it("a PASS sealed under another use case does not count", async () => {
    const { reg, gate, submitter, operator } = await deploy();
    const i = await intent(gate, operator);
    await seal(reg, submitter, PARTY_UC, i.ev);
    await expect(run(gate, operator, i)).to.be.revertedWithCustomError(gate, "AttestationMissing");
  });

  it("a revoked PASS is rejected", async () => {
    const { reg, gate, submitter, operator } = await deploy();
    const i = await intent(gate, operator);
    await seal(reg, submitter, UC, i.ev);
    await reg.revokeAttestation(UC, i.ev, id("reason"));
    await expect(run(gate, operator, i)).to.be.revertedWithCustomError(gate, "AttestationNotValid");
  });

  it("a PASS that expired in the registry is rejected even if the intent is still live", async () => {
    const { reg, gate, submitter, operator } = await deploy();
    const i = await intent(gate, operator, 1n, 10);
    await seal(reg, submitter, UC, i.ev, PASS, ORIG, 1);
    await time.increase(2 * DAY);
    await expect(run(gate, operator, i)).to.be.revertedWithCustomError(gate, "AttestationNotValid");
  });

  // ── Parties (Travel Rule originator / beneficiary) ────────────────────────

  it("with partyUseCaseId set, both parties must be compliant", async () => {
    const { reg, gate, target, submitter, operator } = await deploy({ partyUc: PARTY_UC });
    const i = await intent(gate, operator);
    await seal(reg, submitter, UC, i.ev);
    await expect(run(gate, operator, i)).to.be.revertedWithCustomError(gate, "PartyNotCompliant");

    await seal(reg, submitter, PARTY_UC, id("passport-orig"), PASS, ORIG);
    await expect(run(gate, operator, i)).to.be.revertedWithCustomError(gate, "PartyNotCompliant");

    await seal(reg, submitter, PARTY_UC, id("passport-bene"), PASS, BENE);
    await run(gate, operator, i);
    expect(await target.calls()).to.equal(1);
  });

  it("a newer FAIL on a party blocks the transfer", async () => {
    const { reg, gate, submitter, operator } = await deploy({ partyUc: PARTY_UC });
    const i = await intent(gate, operator);
    await seal(reg, submitter, UC, i.ev);
    await seal(reg, submitter, PARTY_UC, id("passport-orig"), PASS, ORIG);
    await seal(reg, submitter, PARTY_UC, id("passport-bene"), PASS, BENE);
    await seal(reg, submitter, PARTY_UC, id("passport-bene-2"), FAIL, BENE);
    await expect(run(gate, operator, i)).to.be.revertedWithCustomError(gate, "PartyNotCompliant");
  });

  // ── Proof lane: policy circuit (3 signals) ────────────────────────────────

  it("policy proof: PASS signal + right context executes", async () => {
    const { gate, target, operator } = await deploy();
    const i = await intent(gate, operator);
    const ctx = await gate.deriveZkContext(i.ev);
    expect(ctx >> 248n).to.equal(0n);
    await expect(runZk(gate, operator, i, [1n, 42n, ctx])).to.emit(gate, "GatedExecution");
    expect(await target.calls()).to.equal(1);
    await expect(runZk(gate, operator, i, [1n, 42n, ctx])).to.be.revertedWithCustomError(gate, "EvidenceReplay");
  });

  it("policy proof: pass != 1, wrong context, bad verify, bad signal count", async () => {
    const { gate, policyV, operator } = await deploy();
    const i = await intent(gate, operator);
    const ctx = await gate.deriveZkContext(i.ev);
    await expect(runZk(gate, operator, i, [0n, 42n, ctx])).to.be.revertedWithCustomError(gate, "ProofNotPass");
    await expect(runZk(gate, operator, i, [1n, 42n, ctx + 1n])).to.be.revertedWithCustomError(gate, "BadProofContext");
    await expect(runZk(gate, operator, i, [1n, 42n])).to.be.revertedWithCustomError(gate, "BadProofSignals");
    await policyV.setResult(false);
    await expect(runZk(gate, operator, i, [1n, 42n, ctx])).to.be.revertedWithCustomError(gate, "ZkVerifyFailed");
  });

  it("a lane without a verifier is disabled", async () => {
    const { gate, operator } = await deploy({ noVerifiers: true });
    const i = await intent(gate, operator);
    const ctx = await gate.deriveZkContext(i.ev);
    await expect(runZk(gate, operator, i, [1n, 42n, ctx])).to.be.revertedWithCustomError(gate, "VerifierNotSet");
  });

  // ── Proof lane: membership circuit (4 signals) ────────────────────────────

  it("membership proof: needs a root, matches it, burns the nullifier", async () => {
    const { gate, target, operator } = await deploy();
    const root = id("admitted-set-root");
    const nul = BigInt(id("nullifier-1"));
    const i1 = await intent(gate, operator, 1n);
    const ctx1 = await gate.deriveZkContext(i1.ev);

    await expect(runZk(gate, operator, i1, [BigInt(root), nul, REC, ctx1])).to.be.revertedWithCustomError(
      gate,
      "AdmittedRootNotSet",
    );
    await gate.setAdmittedRoot(root);
    await expect(runZk(gate, operator, i1, [BigInt(id("other-root")), nul, REC, ctx1])).to.be.revertedWithCustomError(
      gate,
      "NonMemberRoot",
    );
    await runZk(gate, operator, i1, [BigInt(root), nul, REC, ctx1]);
    expect(await gate.consumedNullifier(ethers.toBeHex(nul, 32))).to.equal(true);
    expect(await target.calls()).to.equal(1);

    // fresh intent, same credential → nullifier replay
    const i2 = await intent(gate, operator, 2n);
    const ctx2 = await gate.deriveZkContext(i2.ev);
    await expect(runZk(gate, operator, i2, [BigInt(root), nul, REC, ctx2])).to.be.revertedWithCustomError(
      gate,
      "NullifierReplay",
    );
  });

  it("membership proof: a failed verify does not burn the nullifier", async () => {
    const { gate, memberV, operator } = await deploy();
    const root = id("admitted-set-root");
    await gate.setAdmittedRoot(root);
    const nul = BigInt(id("nullifier-x"));
    const i = await intent(gate, operator);
    const ctx = await gate.deriveZkContext(i.ev);
    await memberV.setResult(false);
    await expect(runZk(gate, operator, i, [BigInt(root), nul, REC, ctx])).to.be.revertedWithCustomError(
      gate,
      "ZkVerifyFailed",
    );
    expect(await gate.consumedNullifier(ethers.toBeHex(nul, 32))).to.equal(false);
    await memberV.setResult(true);
    await runZk(gate, operator, i, [BigInt(root), nul, REC, ctx]);
  });

  it("membership proof: the live root provider overrides the pinned root", async () => {
    const { gate, provider, operator } = await deploy();
    await gate.setAdmittedRoot(id("pinned"));
    await provider.setRoot(id("live"));
    await gate.setRootProvider(await provider.getAddress());
    const i = await intent(gate, operator);
    const ctx = await gate.deriveZkContext(i.ev);
    await expect(runZk(gate, operator, i, [BigInt(id("pinned")), 1n, REC, ctx])).to.be.revertedWithCustomError(
      gate,
      "NonMemberRoot",
    );
    await runZk(gate, operator, i, [BigInt(id("live")), 1n, REC, ctx]);
    await gate.setRootProvider(ethers.ZeroAddress);
    expect(await gate.resolveAdmittedRoot()).to.equal(id("pinned"));
  });

  it("membership proof: a proof for another recipient is rejected", async () => {
    const { gate, operator } = await deploy();
    const root = id("admitted-set-root");
    await gate.setAdmittedRoot(root);
    const i = await intent(gate, operator);
    const ctx = await gate.deriveZkContext(i.ev);
    expect(await gate.deriveRecipientSignal(BENE)).to.equal(REC);
    const otherRec = BigInt(id("someone-else")) & MASK;
    await expect(runZk(gate, operator, i, [BigInt(root), 7n, otherRec, ctx])).to.be.revertedWithCustomError(
      gate,
      "BadProofRecipient",
    );
  });

  // ── Admin / safety ────────────────────────────────────────────────────────

  it("admin-only setters and two-step admin transfer", async () => {
    const { gate, other, newAdmin } = await deploy();
    await expect(gate.connect(other).authorizeOperator(other.address, true)).to.be.revertedWithCustomError(gate, "AdminOnly");
    await expect(gate.connect(other).setAdmittedRoot(id("x"))).to.be.revertedWithCustomError(gate, "AdminOnly");
    await expect(gate.connect(other).setRootProvider(other.address)).to.be.revertedWithCustomError(gate, "AdminOnly");
    await expect(gate.connect(other).setTarget(other.address)).to.be.revertedWithCustomError(gate, "AdminOnly");
    await expect(gate.connect(other).setUseCases(UC, ZERO)).to.be.revertedWithCustomError(gate, "AdminOnly");
    await gate.transferAdmin(newAdmin.address);
    await expect(gate.connect(other).acceptAdmin()).to.be.revertedWithCustomError(gate, "AdminOnly");
    await gate.connect(newAdmin).acceptAdmin();
    expect(await gate.admin()).to.equal(newAdmin.address);
  });

  it("changing the target invalidates intents sealed for the old target", async () => {
    const { reg, gate, submitter, operator, other } = await deploy();
    const i = await intent(gate, operator);
    await seal(reg, submitter, UC, i.ev);
    await gate.setTarget(other.address);
    await expect(run(gate, operator, i)).to.be.revertedWithCustomError(gate, "EvidenceHashMismatch");
  });

  it("the target cannot re-enter the gate", async () => {
    const { reg, gate, target, submitter, operator } = await deploy();
    await gate.authorizeOperator(await target.getAddress(), true);
    const i = await intent(gate, operator);
    await seal(reg, submitter, UC, i.ev);
    const reenter = gate.interface.encodeFunctionData("execute", [SCOPE, i.nonce, i.expiresAt, i.ev, i.p, i.payload]);
    await target.setReenter(reenter);
    await expect(run(gate, operator, i)).to.be.revertedWithCustomError(gate, "Reentrancy");
  });
});

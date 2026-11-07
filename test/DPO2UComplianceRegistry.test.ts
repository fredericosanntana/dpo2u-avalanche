import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

const PASS = 1, FAIL = 2, REVIEW = 3;
const MACHINE = 0, HUMAN_REVIEWED = 1;
const DAY = 86_400;
const id = (s: string) => ethers.keccak256(ethers.toUtf8Bytes(s));

describe("DPO2UComplianceRegistry", () => {
  const UC = id("psav-partner-br@1");
  const PACK = id("pack:psav-partner-br@1");
  const SUBJECT = id("eip155:43113:0x000000000000000000000000000000000000dEaD");
  const META = id("run-summary");

  async function deploy() {
    const [admin, submitter, other, newAdmin] = await ethers.getSigners();
    const Registry = await ethers.getContractFactory("DPO2UComplianceRegistry");
    const reg = await Registry.deploy(admin.address, 365 * DAY);
    await reg.configureUseCase(UC, true, PACK, 1);
    await reg.authorizeSubmitter(submitter.address, true);
    return { reg, admin, submitter, other, newAdmin };
  }

  async function exp(days = 30) {
    return BigInt((await time.latest()) + days * DAY);
  }

  it("registers a PASS that is valid and carries the pack hash/version", async () => {
    const { reg, submitter } = await deploy();
    const ev = id("evidence-1");
    await expect(reg.connect(submitter).registerAttestation(UC, ev, SUBJECT, PASS, HUMAN_REVIEWED, META, await exp()))
      .to.emit(reg, "AttestationRegistered");
    expect(await reg.isValid(UC, ev)).to.equal(true);
    expect(await reg.isSubjectCompliant(UC, SUBJECT)).to.equal(true);
    const a = await reg.getAttestation(UC, ev);
    expect(a.packHash).to.equal(PACK);
    expect(a.packVersion).to.equal(1);
    expect(a.origin).to.equal(HUMAN_REVIEWED);
    expect(await reg.attestationCount()).to.equal(1);
  });

  it("invariant: REVIEW is never valid", async () => {
    const { reg, submitter } = await deploy();
    const ev = id("evidence-review");
    await reg.connect(submitter).registerAttestation(UC, ev, SUBJECT, REVIEW, MACHINE, META, await exp());
    expect(await reg.isValid(UC, ev)).to.equal(false);
    expect(await reg.isSubjectCompliant(UC, SUBJECT)).to.equal(false);
  });

  it("invariant: FAIL is never valid", async () => {
    const { reg, submitter } = await deploy();
    const ev = id("evidence-fail");
    await reg.connect(submitter).registerAttestation(UC, ev, SUBJECT, FAIL, MACHINE, META, await exp());
    expect(await reg.isValid(UC, ev)).to.equal(false);
  });

  it("invariant: silence = non-compliance (a PASS expires on its own)", async () => {
    const { reg, submitter } = await deploy();
    const ev = id("evidence-expiring");
    await reg.connect(submitter).registerAttestation(UC, ev, SUBJECT, PASS, MACHINE, META, await exp(10));
    expect(await reg.isValid(UC, ev)).to.equal(true);
    await time.increase(11 * DAY);
    expect(await reg.isValid(UC, ev)).to.equal(false);
    expect(await reg.isSubjectCompliant(UC, SUBJECT)).to.equal(false);
  });

  it("the latest attestation decides: a newer FAIL overrides an older PASS", async () => {
    const { reg, submitter } = await deploy();
    await reg.connect(submitter).registerAttestation(UC, id("e-old"), SUBJECT, PASS, MACHINE, META, await exp());
    await reg.connect(submitter).registerAttestation(UC, id("e-new"), SUBJECT, FAIL, MACHINE, META, await exp());
    expect(await reg.isSubjectCompliant(UC, SUBJECT)).to.equal(false);
    expect(await reg.latestEvidenceOf(UC, SUBJECT)).to.equal(id("e-new"));
  });

  it("rejects missing or unbounded expiry", async () => {
    const { reg, submitter } = await deploy();
    const now = BigInt(await time.latest());
    await expect(reg.connect(submitter).registerAttestation(UC, id("e"), SUBJECT, PASS, MACHINE, META, 0))
      .to.be.revertedWithCustomError(reg, "InvalidExpiry");
    await expect(reg.connect(submitter).registerAttestation(UC, id("e"), SUBJECT, PASS, MACHINE, META, now))
      .to.be.revertedWithCustomError(reg, "InvalidExpiry");
    await expect(reg.connect(submitter).registerAttestation(UC, id("e"), SUBJECT, PASS, MACHINE, META, await exp(400)))
      .to.be.revertedWithCustomError(reg, "ValidityTooLong");
  });

  it("rejects a zero evidence hash (it is the no-record sentinel)", async () => {
    const { reg, submitter } = await deploy();
    await expect(reg.connect(submitter).registerAttestation(UC, ethers.ZeroHash, SUBJECT, PASS, MACHINE, META, await exp()))
      .to.be.revertedWithCustomError(reg, "ZeroEvidenceHash");
  });

  it("rejects verdict NONE", async () => {
    const { reg, submitter } = await deploy();
    await expect(reg.connect(submitter).registerAttestation(UC, id("e"), SUBJECT, 0, MACHINE, META, await exp()))
      .to.be.revertedWithCustomError(reg, "InvalidVerdict");
  });

  it("anti-replay: the same (useCase, evidence) cannot be written twice", async () => {
    const { reg, submitter } = await deploy();
    const ev = id("evidence-dup");
    await reg.connect(submitter).registerAttestation(UC, ev, SUBJECT, PASS, MACHINE, META, await exp());
    await expect(reg.connect(submitter).registerAttestation(UC, ev, SUBJECT, FAIL, MACHINE, META, await exp()))
      .to.be.revertedWithCustomError(reg, "AttestationExists");
  });

  it("blocks unauthorized submitters and inactive or unknown use cases", async () => {
    const { reg, submitter, other } = await deploy();
    await expect(reg.connect(other).registerAttestation(UC, id("e"), SUBJECT, PASS, MACHINE, META, await exp()))
      .to.be.revertedWithCustomError(reg, "NotAuthorized");
    await expect(reg.connect(submitter).registerAttestation(id("unknown"), id("e"), SUBJECT, PASS, MACHINE, META, await exp()))
      .to.be.revertedWithCustomError(reg, "UseCaseInactive");
    await reg.configureUseCase(UC, false, PACK, 1);
    await expect(reg.connect(submitter).registerAttestation(UC, id("e"), SUBJECT, PASS, MACHINE, META, await exp()))
      .to.be.revertedWithCustomError(reg, "UseCaseInactive");
  });

  it("a removed submitter can no longer write", async () => {
    const { reg, submitter } = await deploy();
    await reg.authorizeSubmitter(submitter.address, false);
    await expect(reg.connect(submitter).registerAttestation(UC, id("e"), SUBJECT, PASS, MACHINE, META, await exp()))
      .to.be.revertedWithCustomError(reg, "NotAuthorized");
  });

  it("revocation: admin or original submitter only, stays visible, once", async () => {
    const { reg, submitter, other } = await deploy();
    const ev = id("evidence-revoke");
    await reg.connect(submitter).registerAttestation(UC, ev, SUBJECT, PASS, MACHINE, META, await exp());
    await expect(reg.connect(other).revokeAttestation(UC, ev, id("reason")))
      .to.be.revertedWithCustomError(reg, "NotAuthorized");
    await expect(reg.connect(submitter).revokeAttestation(UC, ev, id("reason")))
      .to.emit(reg, "AttestationRevoked");
    expect(await reg.isValid(UC, ev)).to.equal(false);
    expect((await reg.getAttestation(UC, ev)).revoked).to.equal(true);
    await expect(reg.revokeAttestation(UC, ev, id("again"))).to.be.revertedWithCustomError(reg, "AlreadyRevoked");
    await expect(reg.revokeAttestation(UC, id("missing"), id("r"))).to.be.revertedWithCustomError(reg, "AttestationNotFound");
  });

  it("admin-only configuration and two-step admin transfer", async () => {
    const { reg, other, newAdmin } = await deploy();
    await expect(reg.connect(other).configureUseCase(UC, true, PACK, 2)).to.be.revertedWithCustomError(reg, "AdminOnly");
    await expect(reg.connect(other).authorizeSubmitter(other.address, true)).to.be.revertedWithCustomError(reg, "AdminOnly");
    await reg.transferAdmin(newAdmin.address);
    await expect(reg.connect(other).acceptAdmin()).to.be.revertedWithCustomError(reg, "NotAuthorized");
    await reg.connect(newAdmin).acceptAdmin();
    expect(await reg.admin()).to.equal(newAdmin.address);
  });

  it("unknown subject is not compliant and unknown evidence is not valid", async () => {
    const { reg } = await deploy();
    expect(await reg.isSubjectCompliant(UC, id("nobody"))).to.equal(false);
    expect(await reg.isValid(UC, id("nothing"))).to.equal(false);
  });
});

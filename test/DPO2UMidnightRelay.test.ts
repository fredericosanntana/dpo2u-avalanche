import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

const DAY = 86_400;
const id = (s: string) => ethers.keccak256(ethers.toUtf8Bytes(s));
const b32 = (s: string) => ethers.zeroPadBytes(ethers.toUtf8Bytes(s), 32) as string; // Midnight Bytes<32> string
const UC = id("psav_partner_br_v1");
const MID_UC = b32("psav_partner_br_v1");

function seal(over: Partial<Record<string, unknown>> = {}) {
  return {
    midnightContract: id("midnight:ComplianceRegistry"),
    midnightTx: id("midnight:tx:1"),
    midnightUseCaseId: MID_UC,
    midnightVerdict: 1,
    evidenceHash: id("evidence-1"),
    metadataHash: id("meta-1"),
    ...over,
  };
}

describe("DPO2UMidnightRelay", () => {
  async function deploy(threshold = 2) {
    const [admin, r1, r2, r3, other] = await ethers.getSigners();
    const reg = await (await ethers.getContractFactory("DPO2UComplianceRegistry")).deploy(admin.address, 365 * DAY);
    await reg.configureUseCase(UC, true, id("pack"), 1);
    const relay = await (await ethers.getContractFactory("DPO2UMidnightRelay")).deploy(admin.address, await reg.getAddress(), threshold);
    await reg.authorizeSubmitter(await relay.getAddress(), true);
    for (const r of [r1, r2, r3]) await relay.setRelayer(r.address, true);
    await relay.setRoute(MID_UC, UC, 90 * DAY);
    return { reg, relay, admin, r1, r2, r3, other };
  }

  it("registers only when the threshold of relayers confirm the same seal", async () => {
    const { reg, relay, r1, r2 } = await deploy(2);
    const s = seal();
    const d = await relay.sealDigest(s);
    await expect(relay.connect(r1).confirm(s)).to.emit(relay, "SealConfirmed").withArgs(d, r1.address, 1);
    expect(await reg.isValid(UC, s.evidenceHash)).to.equal(false);
    await expect(relay.connect(r2).confirm(s)).to.emit(relay, "SealRelayed");
    expect(await reg.isValid(UC, s.evidenceHash)).to.equal(true);
    const a = await reg.getAttestation(UC, s.evidenceHash);
    expect(a.subject).to.equal(await relay.subjectOf(s.evidenceHash));
    expect(a.metadataHash).to.equal(
      ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32", "bytes32"], [s.metadataHash, s.midnightContract, s.midnightTx])),
    );
    expect(a.expiresAt).to.equal(BigInt(await time.latest()) + BigInt(90 * DAY));
  });

  it("translates Midnight verdicts (0 FAIL, 1 PASS, 2 REVIEW) and rejects anything else", async () => {
    const { reg, relay, r1, r2 } = await deploy(2);
    const fail = seal({ midnightVerdict: 0, evidenceHash: id("e-fail") });
    const review = seal({ midnightVerdict: 2, evidenceHash: id("e-review") });
    for (const s of [fail, review]) {
      await relay.connect(r1).confirm(s);
      await relay.connect(r2).confirm(s);
    }
    expect((await reg.getAttestation(UC, fail.evidenceHash)).verdict).to.equal(2); // FAIL
    expect((await reg.getAttestation(UC, review.evidenceHash)).verdict).to.equal(3); // REVIEW
    expect(await reg.isValid(UC, fail.evidenceHash)).to.equal(false);
    await expect(relay.connect(r1).confirm(seal({ midnightVerdict: 3 }))).to.be.revertedWithCustomError(relay, "InvalidVerdict");
  });

  it("one relayer cannot reach the threshold alone, nor vote twice; non-relayers cannot vote", async () => {
    const { relay, r1, other } = await deploy(2);
    await relay.connect(r1).confirm(seal());
    await expect(relay.connect(r1).confirm(seal())).to.be.revertedWithCustomError(relay, "AlreadyConfirmed");
    await expect(relay.connect(other).confirm(seal())).to.be.revertedWithCustomError(relay, "NotRelayer");
  });

  it("conflicting seals for the same evidence: only the first to reach the threshold is registered", async () => {
    const { reg, relay, r1, r2, r3 } = await deploy(2);
    const honest = seal();
    const forged = seal({ midnightVerdict: 0, midnightTx: id("midnight:tx:forged") });
    await relay.connect(r1).confirm(honest);
    await relay.connect(r3).confirm(forged);
    await relay.connect(r2).confirm(honest); // honest reaches 2 first
    expect(await reg.isValid(UC, honest.evidenceHash)).to.equal(true);
    await expect(relay.connect(r1).confirm(forged)).to.be.revertedWithCustomError(reg, "AttestationExists");
    await expect(relay.connect(r3).confirm(honest)).to.be.revertedWithCustomError(relay, "AlreadyRelayed");
  });

  it("unmapped Midnight use cases and zero fields are refused; unmapping stops relaying", async () => {
    const { relay, r1 } = await deploy(1);
    await expect(relay.connect(r1).confirm(seal({ midnightUseCaseId: b32("other_v1") }))).to.be.revertedWithCustomError(relay, "UnmappedUseCase");
    await expect(relay.connect(r1).confirm(seal({ midnightTx: ethers.ZeroHash }))).to.be.revertedWithCustomError(relay, "ZeroValue");
    await expect(relay.connect(r1).confirm(seal({ evidenceHash: ethers.ZeroHash }))).to.be.revertedWithCustomError(relay, "ZeroValue");
    await relay.setRoute(MID_UC, ethers.ZeroHash, 0);
    await expect(relay.connect(r1).confirm(seal())).to.be.revertedWithCustomError(relay, "UnmappedUseCase");
  });

  it("relayed seals expire (silence = non-compliance)", async () => {
    const { reg, relay, r1, r2 } = await deploy(2);
    const s = seal();
    await relay.connect(r1).confirm(s);
    await relay.connect(r2).confirm(s);
    await time.increase(90 * DAY + 1);
    expect(await reg.isValid(UC, s.evidenceHash)).to.equal(false);
  });

  it("admin: relayer set with count, threshold, routes, two-step transfer", async () => {
    const { relay, admin, r1, other } = await deploy(2);
    expect(await relay.relayerCount()).to.equal(3);
    await relay.setRelayer(r1.address, false);
    await relay.setRelayer(r1.address, false); // idempotent
    expect(await relay.relayerCount()).to.equal(2);
    await expect(relay.setThreshold(0)).to.be.revertedWithCustomError(relay, "InvalidThreshold");
    await expect(relay.connect(other).setThreshold(1)).to.be.revertedWithCustomError(relay, "AdminOnly");
    await expect(relay.setRoute(MID_UC, UC, 0)).to.be.revertedWithCustomError(relay, "ZeroValue");
    await relay.transferAdmin(other.address);
    await relay.connect(other).acceptAdmin();
    expect(await relay.admin()).to.equal(other.address);
    await expect(relay.connect(admin).setRelayer(r1.address, true)).to.be.revertedWithCustomError(relay, "AdminOnly");
  });
});

describe("midnight-relayer (off-chain loop) against the relay", () => {
  it("two relayers running the loop register the seal once; re-runs are idempotent", async () => {
    const { relayOnce } = await import("../src/midnight-relayer");
    const [admin, r1, r2] = await ethers.getSigners();
    const reg = await (await ethers.getContractFactory("DPO2UComplianceRegistry")).deploy(admin.address, 365 * DAY);
    await reg.configureUseCase(UC, true, id("pack"), 1);
    const relay = await (await ethers.getContractFactory("DPO2UMidnightRelay")).deploy(admin.address, await reg.getAddress(), 2);
    await reg.authorizeSubmitter(await relay.getAddress(), true);
    await relay.setRelayer(r1.address, true);
    await relay.setRelayer(r2.address, true);
    await relay.setRoute(MID_UC, UC, 90 * DAY);

    const s = seal() as any;
    const unmapped = seal({ midnightUseCaseId: b32("other_v1"), evidenceHash: id("e-2") }) as any;
    const source = { sealsSince: async () => ({ seals: [s, unmapped], cursor: "c1" }) };
    const addr = await relay.getAddress();

    const a = await relayOnce({ source, relayAddress: addr, signer: r1 });
    expect(a.results.map((r) => r.outcome)).to.deep.equal(["confirmed", "skipped:unmapped"]);
    expect((await relayOnce({ source, relayAddress: addr, signer: r1 })).results[0].outcome).to.equal("skipped:confirmed");
    expect((await relayOnce({ source, relayAddress: addr, signer: r2 })).results[0].outcome).to.equal("registered");
    expect(await reg.isValid(UC, s.evidenceHash)).to.equal(true);
    expect((await relayOnce({ source, relayAddress: addr, signer: r2 })).results[0].outcome).to.equal("skipped:relayed");
  });
});

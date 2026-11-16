import { expect } from "chai";
import { ethers } from "hardhat";
import fs from "node:fs";
import path from "node:path";
import { toSolidityVerdict, checkForMirror, verdictDigest, evidenceRecord } from "../src/travel-rule-verdict";

// Same shared vectors as TravelRuleVerdictV1.test.ts, dpo2u-midnight and the Soroban gate.
const { vectors } = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "verdict-v1-crosschain.json"), "utf8"));
const by = (n: string) => structuredClone(vectors.find((x: any) => x.name === n).verdict);
const sol = (n: string) => toSolidityVerdict(by(n));

describe("DPO2UTravelRuleVerdictMirror", () => {
  async function deploy(threshold = 1) {
    const [admin, r1, r2, other] = await ethers.getSigners();
    const m = await (await ethers.getContractFactory("DPO2UTravelRuleVerdictMirror")).deploy(admin.address, threshold);
    await m.setRelayer(r1.address, true);
    await m.setRelayer(r2.address, true);
    const v = sol("pass-released-anchored");
    await m.setSource(v.sourceChain, v.sourceContract, true);
    await m.setPolicy(v.policyHash, true);
    return { m, admin, r1, r2, other };
  }

  it("digest on-chain = the shared vector digest", async () => {
    const { m } = await deploy();
    for (const x of vectors) expect(await m.digest(toSolidityVerdict(x.verdict)), x.name).to.equal("0x" + x.digest);
  });

  it("one relayer records a PASS; requirePass returns the digest", async () => {
    const { m, r1 } = await deploy();
    const v = sol("pass-released-anchored");
    expect(await m.isPass(v.transferId)).to.equal(false);
    await expect(m.requirePass(v.transferId)).to.be.revertedWithCustomError(m, "NotCleared");
    await expect(m.connect(r1).submit(v)).to.emit(m, "VerdictRecorded");
    const rec = await m.getRecord(v.transferId);
    expect(rec.digest).to.equal("0x" + verdictDigest(by("pass-released-anchored")));
    expect(rec.relayedBy).to.deep.equal([r1.address]);
    expect(rec.sourceBlock).to.equal(v.anchor.height);
    expect(rec.sourceTx).to.equal(v.anchor.tx);
    expect(await m.isPass(v.transferId)).to.equal(true);
    expect(await m.isReleased(v.transferId)).to.equal(true);
    expect(await m.requirePass(v.transferId)).to.equal(rec.digest);
  });

  it("2-of-2: records only at the second distinct relayer", async () => {
    const { m, r1, r2 } = await deploy(2);
    const v = sol("pass-released-anchored");
    await m.connect(r1).submit(v);
    expect(await m.isPass(v.transferId)).to.equal(false);
    const d = await m.digest(v);
    expect(await m.pendingConfirmations(d)).to.deep.equal([r1.address]);
    await expect(m.connect(r1).submit(v)).to.be.revertedWithCustomError(m, "AlreadyConfirmed");
    await m.connect(r2).submit(v);
    expect(await m.isPass(v.transferId)).to.equal(true);
    expect((await m.getRecord(v.transferId)).relayedBy).to.deep.equal([r1.address, r2.address]);
    expect(await m.pendingConfirmations(d)).to.deep.equal([]);
  });

  it("a removed relayer's confirmation stops counting", async () => {
    const { m, r1, r2 } = await deploy(2);
    const v = sol("pass-released-anchored");
    await m.connect(r1).submit(v);
    await m.setRelayer(r1.address, false);
    await m.connect(r2).submit(v);
    expect(await m.isPass(v.transferId)).to.equal(false);
  });

  it("FAIL is recorded, is final and does not clear", async () => {
    const { m, r1 } = await deploy();
    const v = sol("fail-4-sanctions-hit-anchored");
    await m.connect(r1).submit(v);
    expect((await m.getRecord(v.transferId)).reasonCode).to.equal(4);
    expect(await m.isPass(v.transferId)).to.equal(false);
    await expect(m.requirePass(v.transferId)).to.be.revertedWithCustomError(m, "NotCleared");
    const asPass = { ...v, pass: true, reasonCode: 0, released: false };
    await expect(m.connect(r1).submit(asPass)).to.be.revertedWithCustomError(m, "Conflict");
  });

  it("PASS not released -> PASS released with a new anchor; nothing else", async () => {
    const { m, r1, r2 } = await deploy();
    const v = sol("pass-not-released-anchored");
    await m.connect(r1).submit(v);
    expect(await m.isReleased(v.transferId)).to.equal(false);
    await expect(m.connect(r1).submit(v)).to.be.revertedWithCustomError(m, "AlreadyRecorded");

    const changedRoot = { ...v, released: true, originatorRoot: ethers.hexlify(new Uint8Array(32).fill(7)) };
    await expect(m.connect(r1).submit(changedRoot)).to.be.revertedWithCustomError(m, "Conflict");

    const rel = { ...v, released: true, anchor: { height: 81_010, hash: "0x" + "ab".repeat(32), tx: "0x" + "cd".repeat(32) } };
    await m.connect(r1).submit(rel);
    expect(await m.isReleased(v.transferId)).to.equal(true);
    await expect(m.connect(r2).submit({ ...rel, released: false })).to.be.revertedWithCustomError(m, "Conflict");
  });

  it("fail-closed: relayer, anchor, source, policy", async () => {
    const { m, r1, other } = await deploy();
    const v = sol("pass-released-anchored");
    await expect(m.connect(other).submit(v)).to.be.revertedWithCustomError(m, "NotRelayer");
    await expect(m.connect(r1).submit(sol("pass-released"))).to.be.revertedWithCustomError(m, "Unanchored");
    await expect(m.connect(r1).submit({ ...v, sourceContract: "0xff" })).to.be.revertedWithCustomError(m, "SourceNotPinned");
    await expect(m.connect(r1).submit({ ...v, sourceChain: "midnight:mainnet" })).to.be.revertedWithCustomError(m, "SourceNotPinned");
    await expect(m.connect(r1).submit({ ...v, policyHash: "0x" + "01".repeat(32) })).to.be.revertedWithCustomError(m, "PolicyNotAllowed");
    await expect(m.connect(r1).submit({ ...v, policyHash: ethers.ZeroHash })).to.be.revertedWithCustomError(m, "ZeroPolicy");
    await expect(m.connect(r1).submit({ ...v, reasonCode: 2 })).to.be.reverted; // format rule (library)
  });

  it("admin-only configuration and two-step admin transfer", async () => {
    const { m, other } = await deploy();
    await expect(m.connect(other).setRelayer(other.address, true)).to.be.revertedWithCustomError(m, "AdminOnly");
    await expect(m.connect(other).setPolicy(ethers.ZeroHash, true)).to.be.revertedWithCustomError(m, "AdminOnly");
    await expect(m.setThreshold(0)).to.be.revertedWithCustomError(m, "InvalidThreshold");
    await m.transferAdmin(other.address);
    await m.connect(other).acceptAdmin();
    expect(await m.admin()).to.equal(other.address);
  });

  it("relayer helpers: refuse what the mirror refuses, evidence states the trust model", () => {
    expect(checkForMirror(by("pass-released-anchored"))).to.deep.equal([]);
    expect(checkForMirror(by("pass-released")).join()).to.match(/not anchored/);
    const v = by("pass-released-anchored");
    const ev = evidenceRecord({ verdict: v, digest: verdictDigest(v), chain: { network: "fuji" }, relayedAt: "2026-11-16T00:00:00Z" });
    expect(ev.trust_model).to.equal("operator");
    expect(ev.trust_statement).to.match(/not a proof/);
    expect(ev.midnight.reproduce).to.contain(`--tx ${v.tx}`);
  });
});

describe("DPO2UTravelRuleVerdictMirror, real preview verdict", () => {
  it("the verdict relayed to Stellar on 2026-11-16 has the same digest on the C-Chain", async () => {
    const real = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "verdict-preview-961b2b2e.json"), "utf8"));
    expect(verdictDigest(real.verdict)).to.equal(real.digest);
    const [admin, r1] = await ethers.getSigners();
    const m = await (await ethers.getContractFactory("DPO2UTravelRuleVerdictMirror")).deploy(admin.address, 1);
    const v = toSolidityVerdict(real.verdict);
    expect(await m.digest(v)).to.equal("0x" + real.digest);
    await m.setRelayer(r1.address, true);
    await m.setSource(v.sourceChain, v.sourceContract, true);
    await m.setPolicy(v.policyHash, true);
    await m.connect(r1).submit(v);
    expect(await m.requirePass(v.transferId)).to.equal("0x" + real.digest);
  });
});

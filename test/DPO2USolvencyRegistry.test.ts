import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

const DAY = 86_400;
const UC = ethers.keccak256(ethers.toUtf8Bytes("solvency_por_br_v1"));
const VKEY = ethers.keccak256(ethers.toUtf8Bytes("solvency-program-vkey"));
const coder = ethers.AbiCoder.defaultAbiCoder();

const ENTITY = ethers.keccak256(ethers.toUtf8Bytes("cnpj:00.000.000/0001-00"));
const REPORT = ethers.keccak256(ethers.toUtf8Bytes("ipfs://por-report-20261109"));
const SOURCES = ethers.keccak256(ethers.toUtf8Bytes("custodian-key|ledger-key"));

function ctx(entity: string, snapshotAt: number, nonce = 1) {
  return ethers.keccak256(coder.encode(["bytes32", "uint64", "uint256"], [entity, snapshotAt, nonce]));
}

let NOW = 0; // set per test from the latest block
const HOUR = 3_600;

function pv(o: { entity?: string; report?: string; context?: string; sources?: string; at?: number; solvent?: boolean } = {}) {
  const at = o.at ?? NOW - HOUR;
  const entity = o.entity ?? ENTITY;
  return coder.encode(
    ["bytes32", "bytes32", "bytes32", "bytes32", "uint64", "bool"],
    [entity, o.report ?? REPORT, o.context ?? ctx(entity, at), o.sources ?? SOURCES, at, o.solvent ?? true],
  );
}

// MockSP1Verifier accepts proof == abi.encode(keccak256(abi.encode(vkey, publicValues))).
function proofFor(publicValues: string, vkey = VKEY) {
  return coder.encode(["bytes32"], [ethers.keccak256(coder.encode(["bytes32", "bytes"], [vkey, publicValues]))]);
}

describe("DPO2USolvencyRegistry", () => {
  async function deploy(opts: { vkey?: string } = {}) {
    const [admin, anyone] = await ethers.getSigners();
    const verifier = await (await ethers.getContractFactory("MockSP1Verifier")).deploy();
    const reg = await (await ethers.getContractFactory("DPO2UComplianceRegistry")).deploy(admin.address, 365 * DAY);
    await reg.configureUseCase(UC, true, ethers.ZeroHash, 1);
    const sr = await (await ethers.getContractFactory("DPO2USolvencyRegistry")).deploy(
      await verifier.getAddress(),
      opts.vkey ?? VKEY,
      await reg.getAddress(),
      UC,
      2 * DAY,
      DAY,
    );
    await reg.authorizeSubmitter(await sr.getAddress(), true);
    NOW = await time.latest();
    return { reg, sr, admin, anyone };
  }

  it("seals a solvent proof permissionlessly and writes a MACHINE PASS to the registry", async () => {
    const { reg, sr, anyone } = await deploy();
    const p = pv();
    const evidence = ethers.sha256(p);
    await expect(sr.connect(anyone).sealSolvency(p, proofFor(p)))
      .to.emit(sr, "SolvencySealed")
      .withArgs(ENTITY, evidence, NOW - HOUR, REPORT, SOURCES);
    expect(await sr.isSolvent(ENTITY)).to.equal(true);
    expect(await sr.solvencyCount()).to.equal(1);
    const a = await reg.getAttestation(UC, evidence);
    expect(a.origin).to.equal(0); // MACHINE
    expect(a.subject).to.equal(ENTITY);
    expect(a.metadataHash).to.equal(ethers.keccak256(coder.encode(["bytes32", "bytes32"], [VKEY, evidence])));
    const r = await sr.getSolvencyRecord(ENTITY);
    expect(r.snapshotAt).to.equal(NOW - HOUR);
    expect(a.expiresAt).to.equal(NOW - HOUR + 2 * DAY); // expiry follows the snapshot
    expect(r.reportCommitment).to.equal(REPORT);
    expect(r.sourcesHash).to.equal(SOURCES);
    expect(r.evidenceHash).to.equal(evidence);
  });

  it("has no getter that leaks reserves or liabilities", async () => {
    const { sr } = await deploy();
    const names = sr.interface.fragments.filter((f) => f.type === "function").map((f: any) => f.name.toLowerCase());
    expect(names.some((n: string) => n.includes("reserve") || n.includes("liabilit"))).to.equal(false);
  });

  it("rejects solvent = false", async () => {
    const { sr } = await deploy();
    const p = pv({ solvent: false });
    await expect(sr.sealSolvency(p, proofFor(p))).to.be.revertedWithCustomError(sr, "Insolvent");
  });

  it("rejects an invalid proof and tampered public values", async () => {
    const { sr } = await deploy();
    const p = pv();
    await expect(sr.sealSolvency(p, proofFor(pv({ at: NOW - 2 * HOUR })))).to.be.reverted;
    const bad = pv({ report: ethers.ZeroHash });
    await expect(sr.sealSolvency(bad, proofFor(p))).to.be.reverted;
  });

  it("canonical VK pinning: a registry pinned to another program rejects the proof", async () => {
    const { sr } = await deploy({ vkey: ethers.keccak256(ethers.toUtf8Bytes("other-program")) });
    const p = pv();
    await expect(sr.sealSolvency(p, proofFor(p))).to.be.reverted;
  });

  it("rejects malformed public values and a zero entity", async () => {
    const { sr } = await deploy();
    const short = coder.encode(["bytes32", "bool"], [ENTITY, true]);
    await expect(sr.sealSolvency(short, proofFor(short))).to.be.revertedWithCustomError(sr, "BadPublicValues");
    const z = pv({ entity: ethers.ZeroHash });
    await expect(sr.sealSolvency(z, proofFor(z))).to.be.revertedWithCustomError(sr, "ZeroEntity");
  });

  it("anti-replay: a context can be sealed only once, even with another report", async () => {
    const { sr } = await deploy();
    const c = ctx(ENTITY, NOW - 2 * HOUR);
    const p1 = pv({ context: c, at: NOW - 2 * HOUR });
    await sr.sealSolvency(p1, proofFor(p1));
    const p2 = pv({ context: c, at: NOW - HOUR, report: ethers.keccak256(ethers.toUtf8Bytes("other")) });
    await expect(sr.sealSolvency(p2, proofFor(p2))).to.be.revertedWithCustomError(sr, "ContextUsed");
  });

  it("snapshots only move forward: an older or same-time snapshot cannot replace the latest", async () => {
    const { sr } = await deploy();
    const p1 = pv({ at: NOW - 2 * HOUR });
    await sr.sealSolvency(p1, proofFor(p1));
    const older = pv({ at: NOW - 3 * HOUR });
    await expect(sr.sealSolvency(older, proofFor(older))).to.be.revertedWithCustomError(sr, "StaleSnapshot");
    const same = pv({ at: NOW - 2 * HOUR, context: ctx(ENTITY, NOW - 2 * HOUR, 2) });
    await expect(sr.sealSolvency(same, proofFor(same))).to.be.revertedWithCustomError(sr, "StaleSnapshot");
    const next = pv({ at: NOW - HOUR });
    await sr.sealSolvency(next, proofFor(next));
    expect((await sr.getSolvencyRecord(ENTITY)).snapshotAt).to.equal(NOW - HOUR);
  });

  it("freshness: rejects a first seal from an old snapshot and a snapshot from the future", async () => {
    const { sr } = await deploy();
    const old = pv({ at: NOW - DAY - HOUR }); // older than maxSnapshotAge (1 day)
    await expect(sr.sealSolvency(old, proofFor(old))).to.be.revertedWithCustomError(sr, "StaleSnapshot");
    const future = pv({ at: NOW + DAY });
    await expect(sr.sealSolvency(future, proofFor(future))).to.be.revertedWithCustomError(sr, "FutureSnapshot");
  });

  it("rejects a config where snapshots could outlive their validity", async () => {
    const f = await ethers.getContractFactory("DPO2USolvencyRegistry");
    await expect(f.deploy(ethers.ZeroAddress, VKEY, ethers.ZeroAddress, UC, DAY, DAY)).to.be.revertedWithCustomError(f, "BadConfig");
  });

  it("entities are independent", async () => {
    const { sr } = await deploy();
    const other = ethers.keccak256(ethers.toUtf8Bytes("cnpj:11.111.111/0001-11"));
    const p1 = pv({ at: NOW - HOUR });
    await sr.sealSolvency(p1, proofFor(p1));
    const p2 = pv({ entity: other, at: NOW - 2 * HOUR });
    await sr.sealSolvency(p2, proofFor(p2));
    expect(await sr.isSolvent(ENTITY)).to.equal(true);
    expect(await sr.isSolvent(other)).to.equal(true);
  });

  it("silence counts as non-compliance: the seal expires without a new daily proof", async () => {
    const { sr } = await deploy();
    expect(await sr.isSolvent(ENTITY)).to.equal(false);
    const p = pv();
    await sr.sealSolvency(p, proofFor(p));
    await time.increase(2 * DAY - HOUR + 1); // validity counts from the snapshot (1h old)
    expect(await sr.isSolvent(ENTITY)).to.equal(false);
  });

  it("revocation in the registry turns isSolvent off", async () => {
    const { reg, sr } = await deploy();
    const p = pv();
    await sr.sealSolvency(p, proofFor(p));
    await reg.revokeAttestation(UC, ethers.sha256(p), ethers.keccak256(ethers.toUtf8Bytes("source key compromised")));
    expect(await sr.isSolvent(ENTITY)).to.equal(false);
  });

  it("deactivating the use case turns existing seals off and blocks new ones", async () => {
    const { reg, sr } = await deploy();
    const p0 = pv({ at: NOW - 2 * HOUR });
    await sr.sealSolvency(p0, proofFor(p0));
    await reg.configureUseCase(UC, false, ethers.ZeroHash, 1);
    expect(await sr.isSolvent(ENTITY)).to.equal(false);
    const p = pv();
    await expect(sr.sealSolvency(p, proofFor(p))).to.be.revertedWithCustomError(reg, "UseCaseInactive");
  });
});

import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

const PASS = 1, FAIL = 2, REVIEW = 3;
const MACHINE = 0;
const T = { NONE: 0, TIER1_MACHINE_ONLY: 1, TIER1: 2, TIER2: 3, TIER3: 4 };
const DAY = 86_400;
const id = (s: string) => ethers.keccak256(ethers.toUtf8Bytes(s));

const UC = id("psav_partner_br_v1");
const PACK_ID = id("psav-partner-br@1.0.0");
const PACK_HASH = "0x5098e1806e2a918da1aa7f1db39c0b4e41e022d2d7bad6abcdc511b6ddddab86";
const SUBJECT = id("eip155:43113:0x000000000000000000000000000000000000dead");

describe("DPO2UPassportOracle", () => {
  async function deploy() {
    const [admin, gateway, issuer, other, alice, bob] = await ethers.getSigners();
    const reg = await (await ethers.getContractFactory("DPO2UComplianceRegistry")).deploy(admin.address, 365 * DAY);
    await reg.configureUseCase(UC, true, PACK_HASH, 10000);
    await reg.authorizeSubmitter(gateway.address, true);
    const oracle = await (await ethers.getContractFactory("DPO2UPassportOracle")).deploy(admin.address, await reg.getAddress(), 366 * DAY);
    await oracle.authorizeIssuer(issuer.address, true);
    return { reg, oracle, admin, gateway, issuer, other, alice, bob };
  }

  async function seal(reg: any, gateway: any, ev: string, verdict = PASS, days = 90) {
    await reg.connect(gateway).registerAttestation(UC, id(ev), SUBJECT, verdict, MACHINE, id("meta"), BigInt((await time.latest()) + days * DAY));
    return id(ev);
  }

  async function exp(days: number) {
    return BigInt((await time.latest()) + days * DAY);
  }

  async function issue(oracle: any, issuer: any, opts: { subject?: string; tier?: number; days?: number; pid?: string; ev: string }) {
    return oracle
      .connect(issuer)
      .issuePassport(opts.subject ?? SUBJECT, PACK_ID, PACK_HASH, opts.tier ?? T.TIER1, await exp(opts.days ?? 365), id(opts.pid ?? "pp-1"), UC, opts.ev);
  }

  it("issues on top of a sealed run and answers by tier", async () => {
    const { reg, oracle, gateway, issuer } = await deploy();
    const ev = await seal(reg, gateway, "run-1");
    await expect(issue(oracle, issuer, { ev, tier: T.TIER2, days: 31 })).to.emit(oracle, "PassportIssued");
    expect(await oracle.isValid(SUBJECT, PACK_ID, T.TIER1_MACHINE_ONLY)).to.equal(true);
    expect(await oracle.isValid(SUBJECT, PACK_ID, T.TIER2)).to.equal(true);
    expect(await oracle.isValid(SUBJECT, PACK_ID, T.TIER3)).to.equal(false);
    const p = await oracle.getPassport(SUBJECT, PACK_ID);
    expect(p.packHash).to.equal(PACK_HASH);
    expect(p.sealEvidenceHash).to.equal(ev);
    expect(p.sealUseCaseId).to.equal(UC);
  });

  it("invariant: silence = non-compliance (expires on its own)", async () => {
    const { reg, oracle, gateway, issuer } = await deploy();
    const ev = await seal(reg, gateway, "run-1");
    await issue(oracle, issuer, { ev, days: 31 });
    expect(await oracle.isValid(SUBJECT, PACK_ID, T.TIER1)).to.equal(true);
    await time.increase(32 * DAY);
    expect(await oracle.isValid(SUBJECT, PACK_ID, T.TIER1)).to.equal(false);
  });

  it("requires a seal that exists, is not revoked, not expired and not FAIL (REVIEW allowed: tier1-machine-only)", async () => {
    const { reg, oracle, gateway, issuer } = await deploy();
    await expect(issue(oracle, issuer, { ev: id("never-sealed") })).to.be.revertedWithCustomError(oracle, "SealNotFound");
    const fail = await seal(reg, gateway, "run-fail", FAIL);
    await expect(issue(oracle, issuer, { ev: fail, pid: "pp-f" })).to.be.revertedWithCustomError(oracle, "SealNotUsable");
    const revoked = await seal(reg, gateway, "run-rev");
    await reg.connect(gateway).revokeAttestation(UC, revoked, id("r"));
    await expect(issue(oracle, issuer, { ev: revoked, pid: "pp-r" })).to.be.revertedWithCustomError(oracle, "SealNotUsable");
    const old = await seal(reg, gateway, "run-old", PASS, 1);
    await time.increase(2 * DAY);
    await expect(issue(oracle, issuer, { ev: old, pid: "pp-o" })).to.be.revertedWithCustomError(oracle, "SealNotUsable");
    const review = await seal(reg, gateway, "run-review", REVIEW);
    await expect(issue(oracle, issuer, { ev: review, pid: "pp-v1", tier: T.TIER1 })).to.be.revertedWithCustomError(oracle, "SealNotUsable");
    await expect(issue(oracle, issuer, { ev: review, pid: "pp-v3", tier: T.TIER3, days: 30 })).to.be.revertedWithCustomError(oracle, "SealNotUsable");
    await expect(issue(oracle, issuer, { ev: review, pid: "pp-v", tier: T.TIER1_MACHINE_ONLY })).to.emit(oracle, "PassportIssued");
  });

  it("binds the passport to the seal's subject and pack hash", async () => {
    const { reg, oracle, gateway, issuer } = await deploy();
    const ev = await seal(reg, gateway, "run-1");
    await expect(issue(oracle, issuer, { ev, subject: id("someone-else") })).to.be.revertedWithCustomError(oracle, "SealMismatch");
    await expect(
      oracle.connect(issuer).issuePassport(SUBJECT, PACK_ID, id("other-pack"), T.TIER1, await exp(30), id("pp-p"), UC, ev),
    ).to.be.revertedWithCustomError(oracle, "SealMismatch");
    await expect(issue(oracle, issuer, { ev })).to.emit(oracle, "PassportIssued");
  });

  it("tier2/tier3 are capped at 31 days even when maxValidity is longer", async () => {
    const { reg, oracle, gateway, issuer } = await deploy();
    const ev = await seal(reg, gateway, "run-1");
    await expect(issue(oracle, issuer, { ev, tier: T.TIER2, days: 60 })).to.be.revertedWithCustomError(oracle, "ValidityTooLong");
    await expect(issue(oracle, issuer, { ev, tier: T.TIER3, days: 32 })).to.be.revertedWithCustomError(oracle, "ValidityTooLong");
    await expect(issue(oracle, issuer, { ev, tier: T.TIER1, days: 365 })).to.emit(oracle, "PassportIssued");
  });

  it("suspension takes effect at once and is not undone; revocation stays terminal", async () => {
    const { reg, oracle, gateway, issuer } = await deploy();
    const ev = await seal(reg, gateway, "run-1");
    await issue(oracle, issuer, { ev });
    await expect(oracle.connect(issuer).suspendPassport(SUBJECT, PACK_ID, id("late 5710"))).to.emit(oracle, "PassportSuspended");
    expect(await oracle.isValid(SUBJECT, PACK_ID, T.TIER1_MACHINE_ONLY)).to.equal(false);
    await expect(oracle.connect(issuer).suspendPassport(SUBJECT, PACK_ID, id("again"))).to.be.revertedWithCustomError(oracle, "PassportNotValid");
    await expect(oracle.connect(issuer).revokePassport(SUBJECT, PACK_ID, id("fraud"))).to.emit(oracle, "PassportRevoked");
    await expect(oracle.connect(issuer).revokePassport(SUBJECT, PACK_ID, id("again"))).to.be.revertedWithCustomError(oracle, "PassportNotValid");
    expect((await oracle.getPassport(SUBJECT, PACK_ID)).status).to.equal(3); // REVOKED, still visible
  });

  it("a new passport (new id, new seal) supersedes the old one; a passport id is used once", async () => {
    const { reg, oracle, gateway, issuer } = await deploy();
    const ev1 = await seal(reg, gateway, "run-1");
    await issue(oracle, issuer, { ev: ev1 });
    await oracle.connect(issuer).suspendPassport(SUBJECT, PACK_ID, id("r"));
    await expect(issue(oracle, issuer, { ev: ev1 })).to.be.revertedWithCustomError(oracle, "PassportIdUsed");
    const ev2 = await seal(reg, gateway, "run-2");
    await issue(oracle, issuer, { ev: ev2, pid: "pp-2", tier: T.TIER3, days: 31 });
    expect(await oracle.isValid(SUBJECT, PACK_ID, T.TIER3)).to.equal(true);
    expect((await oracle.getPassport(SUBJECT, PACK_ID)).passportId).to.equal(id("pp-2"));
  });

  it("only issuers issue; only the admin or the issuing issuer suspends/revokes", async () => {
    const { reg, oracle, gateway, issuer, other } = await deploy();
    const ev = await seal(reg, gateway, "run-1");
    await expect(issue(oracle, other, { ev })).to.be.revertedWithCustomError(oracle, "NotAuthorized");
    await issue(oracle, issuer, { ev });
    await expect(oracle.connect(other).suspendPassport(SUBJECT, PACK_ID, id("r"))).to.be.revertedWithCustomError(oracle, "NotAuthorized");
    await expect(oracle.suspendPassport(SUBJECT, PACK_ID, id("admin"))).to.emit(oracle, "PassportSuspended");
    await expect(oracle.connect(other).authorizeIssuer(other.address, true)).to.be.revertedWithCustomError(oracle, "AdminOnly");
  });

  it("rejects bad input: tier NONE, zero fields, missing or unbounded expiry, minTier NONE", async () => {
    const { reg, oracle, gateway, issuer } = await deploy();
    const ev = await seal(reg, gateway, "run-1");
    await expect(issue(oracle, issuer, { ev, tier: T.NONE })).to.be.revertedWithCustomError(oracle, "InvalidTier");
    await expect(issue(oracle, issuer, { ev, days: 400 })).to.be.revertedWithCustomError(oracle, "ValidityTooLong");
    await expect(
      oracle.connect(issuer).issuePassport(SUBJECT, PACK_ID, PACK_HASH, T.TIER1, BigInt(await time.latest()), id("pp-x"), UC, ev),
    ).to.be.revertedWithCustomError(oracle, "InvalidExpiry");
    await expect(
      oracle.connect(issuer).issuePassport(ethers.ZeroHash, PACK_ID, PACK_HASH, T.TIER1, await exp(30), id("pp-z"), UC, ev),
    ).to.be.revertedWithCustomError(oracle, "ZeroValue");
    await expect(oracle.isValid(SUBJECT, PACK_ID, T.NONE)).to.be.revertedWithCustomError(oracle, "InvalidTier");
    expect(await oracle.isValid(id("nobody"), PACK_ID, T.TIER1)).to.equal(false);
  });

  it("isValidAll: every required pack must hold", async () => {
    const { reg, oracle, gateway, issuer } = await deploy();
    const ev = await seal(reg, gateway, "run-1");
    await issue(oracle, issuer, { ev });
    expect(await oracle.isValidAll(SUBJECT, [PACK_ID], T.TIER1)).to.equal(true);
    expect(await oracle.isValidAll(SUBJECT, [PACK_ID, id("psav-safeguard-br@1.1.0")], T.TIER1)).to.equal(false);
  });

  it("subjectOf matches the gateway's CAIP-10 subject (keccak of eip155:<chainid>:<lowercase address>)", async () => {
    const { oracle, alice } = await deploy();
    const { chainId } = await ethers.provider.getNetwork();
    expect(await oracle.subjectOf(alice.address)).to.equal(id(`eip155:${chainId}:${alice.address.toLowerCase()}`));
  });

  it("two-step admin transfer", async () => {
    const { oracle, other } = await deploy();
    await oracle.transferAdmin(other.address);
    await oracle.connect(other).acceptAdmin();
    expect(await oracle.admin()).to.equal(other.address);
  });
});

describe("PassportGatedSettlement (example consumer)", () => {
  it("settles only when both sides hold a valid passport, and refuses after suspension or expiry", async () => {
    const [admin, gateway, issuer, alice, bob, carol] = await ethers.getSigners();
    const reg = await (await ethers.getContractFactory("DPO2UComplianceRegistry")).deploy(admin.address, 365 * DAY);
    await reg.configureUseCase(UC, true, PACK_HASH, 10000);
    await reg.authorizeSubmitter(gateway.address, true);
    const oracle = await (await ethers.getContractFactory("DPO2UPassportOracle")).deploy(admin.address, await reg.getAddress(), 366 * DAY);
    await oracle.authorizeIssuer(issuer.address, true);
    const desk = await (await ethers.getContractFactory("PassportGatedSettlement")).deploy(await oracle.getAddress(), PACK_ID, T.TIER1);

    const passFor = async (who: string, tag: string, days = 365) => {
      const subject = await oracle.subjectOf(who);
      await reg.connect(gateway).registerAttestation(UC, id(`run-${tag}`), subject, PASS, MACHINE, id("m"), BigInt((await time.latest()) + 90 * DAY));
      await oracle.connect(issuer).issuePassport(subject, PACK_ID, PACK_HASH, T.TIER1, BigInt((await time.latest()) + days * DAY), id(`pp-${tag}`), UC, id(`run-${tag}`));
    };
    await passFor(alice.address, "alice");
    await passFor(bob.address, "bob", 31);

    const one = ethers.parseEther("1");
    await expect(desk.connect(alice).settle(bob.address, { value: one })).to.changeEtherBalances([alice, bob], [-one, one]);
    await expect(desk.connect(alice).settle(carol.address, { value: one })).to.be.revertedWithCustomError(desk, "PayeeNotCompliant");
    await expect(desk.connect(carol).settle(bob.address, { value: one })).to.be.revertedWithCustomError(desk, "PayerNotCompliant");

    await oracle.connect(issuer).suspendPassport(await oracle.subjectOf(alice.address), PACK_ID, id("r"));
    await expect(desk.connect(alice).settle(bob.address, { value: one })).to.be.revertedWithCustomError(desk, "PayerNotCompliant");

    await passFor(alice.address, "alice-2");
    await time.increase(32 * DAY); // bob's 31-day passport lapses
    await expect(desk.connect(alice).settle(bob.address, { value: one })).to.be.revertedWithCustomError(desk, "PayeeNotCompliant");
  });
});

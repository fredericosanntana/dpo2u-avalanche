import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

const PASS = 1;
const MACHINE = 0;
const T = { NONE: 0, TIER1_MACHINE_ONLY: 1, TIER1: 2, TIER2: 3, TIER3: 4 };
const S = { NONE: 0, PROPOSED: 1, ACTIVE: 2, CONSENT_REVOKED: 3, ENDED: 4 };
const DAY = 86_400;
const id = (s: string) => ethers.keccak256(ethers.toUtf8Bytes(s));

const UC = id("psav_partner_br_v1");
const PACK_ID = id("psav-partner-br@1.0.0");
const PACK_HASH = "0x5098e1806e2a918da1aa7f1db39c0b4e41e022d2d7bad6abcdc511b6ddddab86";
const DIRECTOR = id("director:cpf-hash");

describe("DPO2USponsorshipRegistry", () => {
  async function deploy() {
    const [admin, gateway, issuer, spsav, partner, other] = await ethers.getSigners();
    const reg = await (await ethers.getContractFactory("DPO2UComplianceRegistry")).deploy(admin.address, 365 * DAY);
    await reg.configureUseCase(UC, true, PACK_HASH, 10000);
    await reg.authorizeSubmitter(gateway.address, true);
    const oracle = await (await ethers.getContractFactory("DPO2UPassportOracle")).deploy(admin.address, await reg.getAddress(), 365 * DAY);
    await oracle.authorizeIssuer(issuer.address, true);
    const sp = await (await ethers.getContractFactory("DPO2USponsorshipRegistry")).deploy(admin.address, await oracle.getAddress());
    await sp.setLicensedSponsor(spsav.address, true);
    return { reg, oracle, sp, admin, gateway, issuer, spsav, partner, other };
  }

  // Seal + passport for `who`, the way the gateway would (subject = oracle.subjectOf).
  async function passport(f: any, who: string, tier = T.TIER2, days = 31, tag = "1") {
    const subject = await f.oracle.subjectOf(who);
    const ev = id(`run-${who}-${tag}`);
    const now = await time.latest();
    await f.reg.connect(f.gateway).registerAttestation(UC, ev, subject, PASS, MACHINE, id("meta"), BigInt(now + 90 * DAY));
    await f.oracle.connect(f.issuer).issuePassport(subject, PACK_ID, PACK_HASH, tier, BigInt(now + days * DAY), id(`pp-${who}-${tag}`), UC, ev);
    return subject;
  }

  async function propose(f: any, minTier = T.TIER1) {
    await f.sp.connect(f.spsav).propose(f.partner.address, [PACK_ID], minTier, DIRECTOR);
    return 1n;
  }

  it("licensed SPSAV proposes; partner consents with a qualifying passport → active", async () => {
    const f = await deploy();
    await expect(f.sp.connect(f.spsav).propose(f.partner.address, [PACK_ID], T.TIER1, DIRECTOR))
      .to.emit(f.sp, "SponsorshipProposed")
      .withArgs(1, f.spsav.address, f.partner.address, [PACK_ID], T.TIER1, DIRECTOR);
    expect(await f.sp.isActive(1)).to.equal(false);
    await passport(f, f.partner.address);
    await expect(f.sp.connect(f.partner).grantConsent(1)).to.emit(f.sp, "ConsentGranted").withArgs(1, f.partner.address);
    expect(await f.sp.isActive(1)).to.equal(true);
    const s = await f.sp.getSponsorship(1);
    expect(s.status).to.equal(S.ACTIVE);
    expect(s.accountableDirectorHash).to.equal(DIRECTOR);
    expect(s.requiredPackIds).to.deep.equal([PACK_ID]);
  });

  it("consent needs a passport for every required pack at minTier", async () => {
    const f = await deploy();
    await propose(f, T.TIER3);
    await expect(f.sp.connect(f.partner).grantConsent(1)).to.be.revertedWithCustomError(f.sp, "PassportNotQualifying");
    await passport(f, f.partner.address, T.TIER2);
    await expect(f.sp.connect(f.partner).grantConsent(1)).to.be.revertedWithCustomError(f.sp, "PassportNotQualifying");
    await f.sp.connect(f.spsav).propose(f.partner.address, [PACK_ID, id("psav-safeguard-br@1.1.0")], T.TIER1, DIRECTOR);
    await expect(f.sp.connect(f.partner).grantConsent(2)).to.be.revertedWithCustomError(f.sp, "PassportNotQualifying");
  });

  it("only the partner consents or revokes; consent can be granted again after revoking", async () => {
    const f = await deploy();
    await propose(f);
    await passport(f, f.partner.address);
    await expect(f.sp.connect(f.spsav).grantConsent(1)).to.be.revertedWithCustomError(f.sp, "NotAuthorized");
    await f.sp.connect(f.partner).grantConsent(1);
    await expect(f.sp.connect(f.spsav).revokeConsent(1)).to.be.revertedWithCustomError(f.sp, "NotAuthorized");
    await expect(f.sp.connect(f.partner).revokeConsent(1)).to.emit(f.sp, "ConsentRevoked");
    expect(await f.sp.isActive(1)).to.equal(false);
    await f.sp.connect(f.partner).grantConsent(1);
    expect(await f.sp.isActive(1)).to.equal(true);
    await expect(f.sp.connect(f.partner).grantConsent(1)).to.be.revertedWithCustomError(f.sp, "InvalidState");
  });

  it("passport suspension or expiry turns the sponsorship off in the same block (no relayer)", async () => {
    const f = await deploy();
    await propose(f);
    const subject = await passport(f, f.partner.address, T.TIER2, 31);
    await f.sp.connect(f.partner).grantConsent(1);
    expect(await f.sp.isActive(1)).to.equal(true);
    await f.oracle.connect(f.issuer).suspendPassport(subject, PACK_ID, id("kyb finding"));
    expect(await f.sp.isActive(1)).to.equal(false);

    const g = await deploy();
    await propose(g);
    await passport(g, g.partner.address, T.TIER2, 31);
    await g.sp.connect(g.partner).grantConsent(1);
    await time.increase(32 * DAY);
    expect(await g.sp.isActive(1)).to.equal(false);
  });

  it("delicensing the SPSAV turns its sponsorships off; unlicensed cannot propose", async () => {
    const f = await deploy();
    await propose(f);
    await passport(f, f.partner.address);
    await f.sp.connect(f.partner).grantConsent(1);
    await f.sp.setLicensedSponsor(f.spsav.address, false);
    expect(await f.sp.isActive(1)).to.equal(false);
    await expect(f.sp.connect(f.other).propose(f.partner.address, [PACK_ID], T.TIER1, DIRECTOR)).to.be.revertedWithCustomError(f.sp, "NotLicensedSponsor");
  });

  it("end is terminal and limited to sponsor, partner or admin", async () => {
    const f = await deploy();
    await propose(f);
    await expect(f.sp.connect(f.other).end(1, id("x"))).to.be.revertedWithCustomError(f.sp, "NotAuthorized");
    await expect(f.sp.connect(f.spsav).end(1, id("contract terminated"))).to.emit(f.sp, "SponsorshipEnded");
    await passport(f, f.partner.address);
    await expect(f.sp.connect(f.partner).grantConsent(1)).to.be.revertedWithCustomError(f.sp, "InvalidState");
    await expect(f.sp.end(1, id("y"))).to.be.revertedWithCustomError(f.sp, "InvalidState");
  });

  it("rejects bad proposals: self-sponsorship, zero partner, no packs, zero pack, no director, tier NONE", async () => {
    const f = await deploy();
    const p = f.sp.connect(f.spsav);
    await expect(p.propose(f.spsav.address, [PACK_ID], T.TIER1, DIRECTOR)).to.be.revertedWithCustomError(f.sp, "SelfSponsorship");
    await expect(p.propose(ethers.ZeroAddress, [PACK_ID], T.TIER1, DIRECTOR)).to.be.revertedWithCustomError(f.sp, "ZeroAddress");
    await expect(p.propose(f.partner.address, [], T.TIER1, DIRECTOR)).to.be.revertedWithCustomError(f.sp, "ZeroValue");
    await expect(p.propose(f.partner.address, [ethers.ZeroHash], T.TIER1, DIRECTOR)).to.be.revertedWithCustomError(f.sp, "ZeroValue");
    await expect(p.propose(f.partner.address, [PACK_ID], T.TIER1, ethers.ZeroHash)).to.be.revertedWithCustomError(f.sp, "ZeroValue");
    await expect(p.propose(f.partner.address, [PACK_ID], T.NONE, DIRECTOR)).to.be.revertedWithCustomError(f.sp, "InvalidTier");
    await expect(f.sp.getSponsorship(99)).to.be.revertedWithCustomError(f.sp, "UnknownSponsorship");
    expect(await f.sp.isActive(99)).to.equal(false);
  });

  it("two-step admin transfer", async () => {
    const f = await deploy();
    await f.sp.transferAdmin(f.other.address);
    await expect(f.sp.connect(f.spsav).acceptAdmin()).to.be.revertedWithCustomError(f.sp, "NotAuthorized");
    await f.sp.connect(f.other).acceptAdmin();
    expect(await f.sp.admin()).to.equal(f.other.address);
    await expect(f.sp.setLicensedSponsor(f.spsav.address, false)).to.be.revertedWithCustomError(f.sp, "AdminOnly");
  });
});

import { expect } from "chai";
import { ethers } from "hardhat";

const j = (code: string) => ethers.zeroPadBytes(ethers.toUtf8Bytes(code), 16) as string; // Solana-style 16-byte seed
const h = (s: string) => ethers.keccak256(ethers.toUtf8Bytes(s));
const BR = j("BR-LGPD");
const T0 = 1_600_000_000;

describe("DPO2ULegalSourceManifest", () => {
  async function deploy() {
    const [admin, curator, anyone, next] = await ethers.getSigners();
    const m = await (await ethers.getContractFactory("DPO2ULegalSourceManifest")).deploy(admin.address);
    await m.setCurator(curator.address, true);
    return { m, admin, curator, anyone, next };
  }

  it("publishes append-only manifest versions; old versions stay readable", async () => {
    const { m, curator } = await deploy();
    await expect(m.connect(curator).publishManifest(BR, h("corpus-v1"), T0, "ipfs://v1"))
      .to.emit(m, "ManifestPublished")
      .withArgs(BR, 1, h("corpus-v1"), T0, "ipfs://v1");
    await m.connect(curator).publishManifest(BR, h("corpus-v2"), T0 + 100, "ipfs://v2");
    expect(await m.latestVersion(BR)).to.equal(2);
    expect((await m.getManifest(BR, 1)).contentHash).to.equal(h("corpus-v1"));
    const [v, latest] = await m.getLatestManifest(BR);
    expect(v).to.equal(2);
    expect(latest.sourceUri).to.equal("ipfs://v2");
    expect(latest.curator).to.equal(curator.address);
  });

  it("rejects effective dates that go backwards, zero hash and empty jurisdiction", async () => {
    const { m, curator } = await deploy();
    await m.connect(curator).publishManifest(BR, h("v1"), T0, "u");
    await expect(m.connect(curator).publishManifest(BR, h("v2"), T0 - 1, "u")).to.be.revertedWithCustomError(m, "EffectiveDateBackwards");
    await expect(m.connect(curator).publishManifest(BR, ethers.ZeroHash, T0, "u")).to.be.revertedWithCustomError(m, "ZeroHash");
    await expect(m.connect(curator).publishManifest(j(""), h("v"), T0, "u")).to.be.revertedWithCustomError(m, "EmptyJurisdiction");
  });

  it("anchors citations write-once against an existing manifest version", async () => {
    const { m, curator } = await deploy();
    const cid = await m.citationIdOf("LGPD", "Art.18");
    expect(cid).to.equal(h("LGPD|Art.18"));
    await expect(m.connect(curator).anchorCitation(cid, h("art18-text"), BR, 1)).to.be.revertedWithCustomError(m, "UnknownManifest");
    await m.connect(curator).publishManifest(BR, h("v1"), T0, "u");
    await expect(m.connect(curator).anchorCitation(cid, h("art18-text"), BR, 1))
      .to.emit(m, "CitationAnchored")
      .withArgs(cid, BR, h("art18-text"), 1);
    await expect(m.connect(curator).anchorCitation(cid, h("other"), BR, 1)).to.be.revertedWithCustomError(m, "CitationExists");
    const c = await m.getCitation(cid);
    expect(c.manifestVersion).to.equal(1);
    expect(c.jurisdiction).to.equal(BR);
    expect(await m.citationCount()).to.equal(1);
  });

  it("verifySource / verifySources: match, mismatch, unknown citation and length mismatch", async () => {
    const { m, curator } = await deploy();
    await m.connect(curator).publishManifest(BR, h("v1"), T0, "u");
    const a = h("LGPD|Art.18");
    const b = h("LGPD|Art.46");
    await m.connect(curator).anchorCitation(a, h("t18"), BR, 1);
    await m.connect(curator).anchorCitation(b, h("t46"), BR, 1);
    expect(await m.verifySource(a, h("t18"))).to.equal(true);
    expect(await m.verifySource(a, h("tampered"))).to.equal(false);
    expect(await m.verifySources([a, b], [h("t18"), h("t46")])).to.equal(true);
    expect(await m.verifySources([a, b], [h("t18"), h("x")])).to.equal(false);
    await expect(m.verifySource(h("LGPD|Art.99"), h("t"))).to.be.revertedWithCustomError(m, "UnknownCitation");
    await expect(m.verifySources([a], [])).to.be.revertedWithCustomError(m, "LengthMismatch");
  });

  it("only curators curate; only the admin sets curators; two-step admin transfer", async () => {
    const { m, admin, curator, anyone, next } = await deploy();
    await expect(m.connect(anyone).publishManifest(BR, h("v"), T0, "u")).to.be.revertedWithCustomError(m, "NotCurator");
    await expect(m.connect(anyone).setCurator(anyone.address, true)).to.be.revertedWithCustomError(m, "AdminOnly");
    await m.setCurator(curator.address, false);
    await expect(m.connect(curator).publishManifest(BR, h("v"), T0, "u")).to.be.revertedWithCustomError(m, "NotCurator");
    await m.transferAdmin(next.address);
    expect(await m.admin()).to.equal(admin.address);
    await expect(m.connect(anyone).acceptAdmin()).to.be.revertedWithCustomError(m, "NotAuthorized");
    await m.connect(next).acceptAdmin();
    expect(await m.admin()).to.equal(next.address);
    await expect(m.setCurator(anyone.address, true)).to.be.revertedWithCustomError(m, "AdminOnly");
  });
});

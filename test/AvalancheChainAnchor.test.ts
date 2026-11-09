import { expect } from "chai";
import { ethers } from "hardhat";
import { AvalancheChainAnchor, Origin, subjectHash } from "../src";

const DAY = 86_400;

describe("AvalancheChainAnchor (control-plane ChainAnchorPort shape)", () => {
  async function setup() {
    const [admin, gateway] = await ethers.getSigners();
    const reg = await (await ethers.getContractFactory("DPO2UComplianceRegistry")).deploy(admin.address, 365 * DAY);
    const anchor = new AvalancheChainAnchor({
      network: "fuji",
      registryAddress: await reg.getAddress(),
      runner: gateway,
      useCase: "psav-partner-br@1",
    });
    await reg.configureUseCase(anchor.useCaseIdHex, true, ethers.ZeroHash, 1);
    await reg.authorizeSubmitter(gateway.address, true);
    return { reg, anchor, admin };
  }

  const commitment = "ab".repeat(32); // sha256 hex without 0x, as the control plane sends it

  it("anchors a commitment and verifies it", async () => {
    const { reg, anchor } = await setup();
    const res = await anchor.anchor({ subject: "tenant:acme", commitment, schema: "dpo2u/run/v1" });
    expect(res.target).to.equal("avalanche");
    expect(res.local).to.equal(false);
    expect(res.explorerUrl).to.match(/^https:\/\/testnet\.snowtrace\.io\/tx\/0x/);
    expect(await anchor.verify(commitment)).to.deep.equal({ found: true, revoked: false });
    expect(await anchor.isValid(commitment)).to.equal(true);
    const a = await reg.getAttestation(anchor.useCaseIdHex, "0x" + commitment);
    expect(a.subject).to.equal(subjectHash("tenant:acme"));
    expect(a.origin).to.equal(Origin.HUMAN_REVIEWED);
  });

  it("unknown commitment → found:false", async () => {
    const { anchor } = await setup();
    expect(await anchor.verify("cd".repeat(32))).to.deep.equal({ found: false });
  });

  it("reports revocation", async () => {
    const { reg, anchor } = await setup();
    await anchor.anchor({ subject: "tenant:acme", commitment, schema: "dpo2u/run/v1" });
    await reg.revokeAttestation(anchor.useCaseIdHex, "0x" + commitment, ethers.ZeroHash);
    expect(await anchor.verify(commitment)).to.deep.equal({ found: true, revoked: true });
  });

  it("serializes concurrent anchors (no nonce collisions)", async () => {
    const { anchor } = await setup();
    const reqs = ["01", "02", "03"].map((b) => anchor.anchor({ subject: "t", commitment: b.repeat(32), schema: "s" }));
    const res = await Promise.all(reqs);
    expect(new Set(res.map((r) => r.txSig)).size).to.equal(3);
  });

  it("fail-closed: without a signer it throws instead of faking a receipt", async () => {
    const { reg } = await setup();
    const ro = new AvalancheChainAnchor({ registryAddress: await reg.getAddress(), runner: ethers.provider });
    let threw = false;
    try { await ro.anchor({ subject: "t", commitment, schema: "s" }); } catch { threw = true; }
    expect(threw).to.equal(true);
  });

  it("transport errors propagate from verify (→ REVIEW upstream)", async () => {
    const dead = new AvalancheChainAnchor({ registryAddress: ethers.ZeroAddress, rpcUrl: "http://127.0.0.1:9", network: "fuji" });
    let threw = false;
    try { await dead.verify(commitment); } catch { threw = true; }
    expect(threw).to.equal(true);
  });
});

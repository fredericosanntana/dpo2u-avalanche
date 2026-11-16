import { expect } from "chai";
import { ethers } from "hardhat";
import fs from "node:fs";
import path from "node:path";

// Shared vectors of the common verdict format v1, copied verbatim from dpo2u-midnight
// test/vectors/verdict-v1-crosschain.json (the first six come from the compiled Compact
// TravelRuleGate in the simulator). The Soroban gate in dpo2u-stellar tests the same file.
const { format, vectors } = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "verdict-v1-crosschain.json"), "utf8"));
const hx = (s: string) => "0x" + s;
const by = (n: string) => vectors.find((x: any) => x.name === n).verdict;

function toSol(j: any) {
  return {
    transferId: hx(j.transfer_id),
    pass: j.verdict === "PASS",
    released: j.released,
    reasonCode: j.reason.code,
    policyHash: hx(j.policy_hash),
    originatorRoot: hx(j.originator_root),
    beneficiaryRoot: hx(j.beneficiary_root),
    sourceChain: j.source_chain,
    sourceContract: hx(j.source_contract),
    anchored: j.block !== null,
    anchor: j.block === null ? { height: 0, hash: "0x", tx: "0x" } : { height: j.block.height, hash: hx(j.block.hash), tx: hx(j.tx) },
    hasSanctions: j.sanctions !== undefined,
    sanctions: j.sanctions === undefined
      ? { listRoot: ethers.ZeroHash, providerId: ethers.ZeroHash, validUntil: 0 }
      : { listRoot: hx(j.sanctions.list_root), providerId: hx(j.sanctions.provider_id), validUntil: j.sanctions.valid_until },
  };
}

describe("TravelRuleVerdictV1 (common verdict format)", () => {
  async function harness() {
    return (await ethers.getContractFactory("TravelRuleVerdictHarness")).deploy();
  }

  it("canonical JSON and SHA-256 digest match every shared vector", async () => {
    expect(format).to.equal("dpo2u.travel-rule-verdict/1");
    expect(vectors.length).to.equal(11);
    const h = await harness();
    for (const x of vectors) {
      const v = toSol(x.verdict);
      expect(ethers.toUtf8String(await h.canonical(v)), x.name).to.equal(x.canonical);
      expect(await h.digest(v), x.name).to.equal(hx(x.digest));
    }
  });

  it("rejects verdicts that break the format rules", async () => {
    const h = await harness();
    const base = toSol(by("pass-released-anchored"));
    await expect(h.digest({ ...base, reasonCode: 3 })).to.be.reverted; // PASS with a reason
    await expect(h.digest({ ...base, pass: false, released: false })).to.be.reverted; // FAIL with reason 0
    await expect(h.digest({ ...base, pass: false, reasonCode: 2 })).to.be.reverted; // released FAIL
    await expect(h.digest({ ...base, pass: false, released: false, reasonCode: 9 })).to.be.reverted;
    await expect(h.digest({ ...base, sourceChain: "midnight" })).to.be.reverted;
    await expect(h.digest({ ...base, sourceChain: "Midnight:preview" })).to.be.reverted;
    await expect(h.digest({ ...base, sourceChain: 'midnight:pre"view' })).to.be.reverted;
    await expect(h.digest({ ...base, sourceContract: "0x" })).to.be.reverted;
    await expect(h.digest({ ...base, sourceContract: "0x" + "ab".repeat(65) })).to.be.reverted;
    await expect(h.digest({ ...base, anchor: { ...base.anchor, tx: "0x" } })).to.be.reverted;
    // Max lengths are fine.
    expect(await h.digest({ ...base, sourceContract: "0x" + "ab".repeat(64) })).to.match(/^0x[0-9a-f]{64}$/);
  });
});

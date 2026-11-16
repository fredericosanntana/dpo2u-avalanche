import { expect } from "chai";
import { ethers } from "hardhat";
import fs from "node:fs";
import path from "node:path";

// Real membership proof (dpo2u-stellar membership_withdraw.circom, DEV setup) against the
// snarkjs-exported verifier used by the gate's membership lane. The proof is a fixture because
// the zkey (131 MB) is not in git; the gate-side checks of that lane (root, nullifier, recipient,
// context) are covered with the mock verifier in DPO2UTravelRuleGate.test.ts.
const fx = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "membership-proof-dev.json"), "utf8"));

describe("DPO2UMembershipGroth16Verifier (real Groth16, dev setup)", () => {
  it("verifies the real proof and rejects any changed public signal", async () => {
    const v = await (await ethers.getContractFactory("DPO2UMembershipGroth16Verifier")).deploy();
    expect(await v.verifyProof(fx.a, fx.b, fx.c, fx.publicSignals)).to.equal(true);
    for (let i = 0; i < 4; i++) {
      const s = [...fx.publicSignals];
      s[i] = (BigInt(s[i]) + 1n).toString();
      expect(await v.verifyProof(fx.a, fx.b, fx.c, s), `signal ${i}`).to.equal(false);
    }
    const badC = [fx.c[0], (BigInt(fx.c[1]) + 1n).toString()];
    expect(await v.verifyProof(fx.a, fx.b, badC, fx.publicSignals)).to.equal(false);
  });

  it("the gate deploys with both real verifiers", async () => {
    const [admin] = await ethers.getSigners();
    const reg = await (await ethers.getContractFactory("DPO2UComplianceRegistry")).deploy(admin.address, 365 * 86_400);
    const pv = await (await ethers.getContractFactory("DPO2UPolicyGroth16Verifier")).deploy();
    const mv = await (await ethers.getContractFactory("DPO2UMembershipGroth16Verifier")).deploy();
    const t = await (await ethers.getContractFactory("MockGatedTarget")).deploy();
    const gate = await (await ethers.getContractFactory("DPO2UTravelRuleGate")).deploy(
      admin.address, await reg.getAddress(), await t.getAddress(), ethers.id("uc"), ethers.ZeroHash, await pv.getAddress(), await mv.getAddress());
    expect(await gate.membershipVerifier()).to.equal(await mv.getAddress());
    expect(await gate.policyVerifier()).to.equal(await pv.getAddress());
  });
});

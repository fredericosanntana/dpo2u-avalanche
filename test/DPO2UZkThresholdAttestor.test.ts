import { expect } from "chai";
import { ethers } from "hardhat";
import fs from "node:fs";
import path from "node:path";

// Fixture: the SP1 v6.1.0 Groth16 proof committed in dpo2u-solana/zk-circuits/proofs
// (score 85 >= threshold 70, subject = commitment of "did:test:company:acme").
const FIX = path.join(__dirname, "fixtures");
const proof = fs.readFileSync(path.join(FIX, "proof.bin"));
const publicValues = fs.readFileSync(path.join(FIX, "public_values.bin"));
const vkey = fs.readFileSync(path.join(FIX, "vkey.hex"), "utf8").trim();

const DAY = 86_400;
const UC = ethers.keccak256(ethers.toUtf8Bytes("zk-threshold@1"));
const META = ethers.keccak256(ethers.toUtf8Bytes("meta"));

describe("DPO2UZkThresholdAttestor (real SP1 v6.1.0 Groth16 proof)", () => {
  async function deploy(opts: { vkey?: string; minThreshold?: number } = {}) {
    const [admin, anyone] = await ethers.getSigners();
    const verifier = await (await ethers.getContractFactory("SP1Verifier")).deploy();
    const reg = await (await ethers.getContractFactory("DPO2UComplianceRegistry")).deploy(admin.address, 365 * DAY);
    await reg.configureUseCase(UC, true, ethers.ZeroHash, 1);
    const attestor = await (await ethers.getContractFactory("DPO2UZkThresholdAttestor")).deploy(
      await verifier.getAddress(),
      opts.vkey ?? vkey,
      await reg.getAddress(),
      UC,
      opts.minThreshold ?? 70,
      90 * DAY,
    );
    await reg.authorizeSubmitter(await attestor.getAddress(), true);
    return { verifier, reg, attestor, anyone };
  }

  it("fixture uses the v6.1.0 Groth16 selector", async () => {
    const { verifier } = await deploy();
    const selector = (await verifier.VERIFIER_HASH()).slice(0, 10);
    expect("0x" + proof.subarray(0, 4).toString("hex")).to.equal(selector);
  });

  it("decodes public values: threshold 70, meets = true", async () => {
    const { attestor } = await deploy();
    const [threshold, , meets] = await attestor.decodePublicValues(publicValues);
    expect(threshold).to.equal(70);
    expect(meets).to.equal(true);
  });

  it("verifies the real proof and seals a MACHINE-origin PASS, permissionlessly", async () => {
    const { reg, attestor, anyone } = await deploy();
    await expect(attestor.connect(anyone).submitProof(publicValues, proof, META)).to.emit(attestor, "ProofSealed");
    const evidenceHash = ethers.sha256(publicValues);
    expect(await reg.isValid(UC, evidenceHash)).to.equal(true);
    const a = await reg.getAttestation(UC, evidenceHash);
    expect(a.origin).to.equal(0); // MACHINE
    const [, subject] = await attestor.decodePublicValues(publicValues);
    expect(await reg.isSubjectCompliant(UC, subject)).to.equal(true);
  });

  it("anti-replay: the same proof cannot be sealed twice", async () => {
    const { reg, attestor } = await deploy();
    await attestor.submitProof(publicValues, proof, META);
    await expect(attestor.submitProof(publicValues, proof, META)).to.be.revertedWithCustomError(reg, "AttestationExists");
  });

  it("rejects a tampered proof", async () => {
    const { attestor } = await deploy();
    const bad = Buffer.from(proof);
    bad[bad.length - 1] ^= 0x01;
    await expect(attestor.submitProof(publicValues, bad, META)).to.be.reverted;
  });

  it("rejects tampered public values (claims a higher threshold)", async () => {
    const { attestor } = await deploy();
    const bad = Buffer.from(publicValues);
    bad[31] = 90;
    await expect(attestor.submitProof(bad, proof, META)).to.be.reverted;
  });

  it("canonical VK pinning: an attestor pinned to another program rejects the proof", async () => {
    const { attestor } = await deploy({ vkey: "0x" + "11".repeat(32) });
    await expect(attestor.submitProof(publicValues, proof, META)).to.be.reverted;
  });

  it("enforces the policy minimum threshold", async () => {
    const { attestor } = await deploy({ minThreshold: 80 });
    await expect(attestor.submitProof(publicValues, proof, META)).to.be.revertedWithCustomError(attestor, "BelowMinimumThreshold");
  });
});

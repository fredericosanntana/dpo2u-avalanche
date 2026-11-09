import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

const DAY = 86_400;
const id = (s: string) => ethers.keccak256(ethers.toUtf8Bytes(s));
const UC = id("travel_rule_v1");

describe("TravelRuleTransferLog (example gate target) — attestation lane end to end", () => {
  it("logs only gate executions backed by a sealed PASS; binds once; refuses direct calls", async () => {
    const [admin, sealer, operator, other] = await ethers.getSigners();
    const reg = await (await ethers.getContractFactory("DPO2UComplianceRegistry")).deploy(admin.address, 365 * DAY);
    await reg.configureUseCase(UC, true, id("pack:travel-rule@1"), 1);
    await reg.authorizeSubmitter(sealer.address, true);
    const log = await (await ethers.getContractFactory("TravelRuleTransferLog")).deploy();
    // Attestation lane only: no proof verifiers (VerifierNotSet on the proof lane).
    const gate = await (await ethers.getContractFactory("DPO2UTravelRuleGate")).deploy(
      admin.address, await reg.getAddress(), await log.getAddress(), UC, ethers.ZeroHash, ethers.ZeroAddress, ethers.ZeroAddress,
    );
    await log.bindGate(await gate.getAddress());
    await expect(log.bindGate(other.address)).to.be.revertedWithCustomError(log, "AlreadyBound");
    await expect(log.connect(other).onGatedExecution(other.address, id("x"), "0x")).to.be.revertedWithCustomError(log, "NotGate");
    await gate.authorizeOperator(operator.address, true);

    const parties = { originator: id("eip155:43113:0xaaa"), beneficiary: id("eip155:43113:0xbbb") };
    const payload = ethers.toUtf8Bytes("ivms101-payload-hash-only");
    const expiresAt = BigInt((await time.latest()) + DAY);
    const ev = await gate.deriveEvidenceHash(operator.address, id("scope"), 1, expiresAt, parties, payload);
    await reg.connect(sealer).registerAttestation(UC, ev, parties.beneficiary, 1, 0, id("m"), BigInt((await time.latest()) + 30 * DAY));

    await expect(gate.connect(operator).execute(id("scope"), 1, expiresAt, ev, parties, payload))
      .to.emit(log, "Logged")
      .withArgs(1, operator.address, ev, ethers.keccak256(payload));
    expect(await log.count()).to.equal(1);
  });
});

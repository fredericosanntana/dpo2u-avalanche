import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import path from "node:path";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const snarkjs = require("snarkjs");

// Real Groth16 on the proof lane: the policy circuit (dpo2u-stellar zk-prover/por/
// compliance_intent_policy.circom, public signals [policy_pass, policy_commit, context]),
// compiled and set up in zk/policy (DEV setup, see zk/PROVENANCE.md), its snarkjs-exported
// verifier deployed as the gate's policyVerifier, and a proof generated here for the exact
// context the gate derives from the intent's evidence hash.
const ZK = path.join(__dirname, "..", "zk", "policy");
const DAY = 86_400;
const id = (s: string) => ethers.keccak256(ethers.toUtf8Bytes(s));
const UC = id("travel-rule-adjacent@1");
const SCOPE = id("rebalance");
const parties = { originator: id("orig"), beneficiary: id("bene") };
const PAYLOAD = ethers.AbiCoder.defaultAbiCoder().encode(["string", "uint256"], ["unwind", 1000n]);
const BASE = { jurisdiction_code: "76", policy_version: "1", mandate_class: "2", risk_bucket: "3", counterparty_class: "4", threshold: "700" };

async function prove(context: bigint, score = "725") {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    { ...BASE, policy_score: score, context: context.toString() },
    path.join(ZK, "compliance_intent_policy.wasm"),
    path.join(ZK, "policy_final.zkey"),
  );
  const calldata = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
  const [a, b, c, signals] = JSON.parse("[" + calldata + "]");
  return { proof: { a, b, c }, signals: signals.map((s: string) => BigInt(s)) as any };
}

describe("DPO2UTravelRuleGate + real Groth16 policy verifier", function () {
  this.timeout(120_000);

  async function deploy() {
    const [admin, operator] = await ethers.getSigners();
    const reg = await (await ethers.getContractFactory("DPO2UComplianceRegistry")).deploy(admin.address, 365 * DAY);
    const verifier = await (await ethers.getContractFactory("DPO2UPolicyGroth16Verifier")).deploy();
    const target = await (await ethers.getContractFactory("MockGatedTarget")).deploy();
    const gate = await (await ethers.getContractFactory("DPO2UTravelRuleGate")).deploy(
      admin.address, await reg.getAddress(), await target.getAddress(), UC, ethers.ZeroHash, await verifier.getAddress(), ethers.ZeroAddress,
    );
    await target.setGate(await gate.getAddress());
    await gate.authorizeOperator(operator.address, true);
    const expiresAt = BigInt((await time.latest()) + DAY);
    const ev = await gate.deriveEvidenceHash(operator.address, SCOPE, 1n, expiresAt, parties, PAYLOAD);
    const run = (p: any, s: bigint[]) => gate.connect(operator).executeWithProof(SCOPE, 1n, expiresAt, ev, parties, PAYLOAD, p, s);
    return { gate, target, verifier, ev, run };
  }

  it("a proof bound to the intent's context executes the target", async () => {
    const { gate, target, ev, run } = await deploy();
    const ctx = await gate.deriveZkContext(ev);
    const { proof, signals } = await prove(ctx);
    expect(signals[0]).to.equal(1n); // policy_pass
    expect(signals[2]).to.equal(ctx);
    await expect(run(proof, signals)).to.emit(gate, "GatedExecution");
    expect(await target.calls()).to.equal(1);
    await expect(run(proof, signals)).to.be.revertedWithCustomError(gate, "EvidenceReplay");
  });

  it("the verifier rejects a tampered proof or commitment", async () => {
    const { gate, verifier, ev, run } = await deploy();
    const ctx = await gate.deriveZkContext(ev);
    const { proof, signals } = await prove(ctx);
    expect(await verifier.verifyProof(proof.a, proof.b, proof.c, signals)).to.equal(true);
    const badCommit: any = [signals[0], signals[1] + 1n, signals[2]];
    expect(await verifier.verifyProof(proof.a, proof.b, proof.c, badCommit)).to.equal(false);
    await expect(run(proof, badCommit)).to.be.revertedWithCustomError(gate, "ZkVerifyFailed");
    const badA = { ...proof, a: [proof.a[0], (BigInt(proof.a[1]) + 1n).toString()] };
    await expect(run(badA, signals)).to.be.revertedWithCustomError(gate, "ZkVerifyFailed");
  });

  it("a valid proof for another intent's context is refused", async () => {
    const { ev, run, gate } = await deploy();
    const other = await prove(await gate.deriveZkContext(ethers.keccak256(ev)));
    await expect(run(other.proof, other.signals)).to.be.revertedWithCustomError(gate, "BadProofContext");
  });

  it("a score below the threshold cannot produce a proof", async () => {
    const { gate, ev } = await deploy();
    await expect(prove(await gate.deriveZkContext(ev), "650")).to.be.rejected;
  });
});

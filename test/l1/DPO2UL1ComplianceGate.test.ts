import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

// Public input layout v0 of DPO2UL1ComplianceGate (provisional until phase A3).
const h = (s: string) => ethers.keccak256(ethers.toUtf8Bytes(s));
const limbs = (v: string): [bigint, bigint] => {
  const n = BigInt(v);
  return [n >> 128n, n & ((1n << 128n) - 1n)];
};
const POLICY = h("policy:travel-rule-fatf@1.0.0");
const VK = h("vk:TravelRuleGate.evaluateTransfer");
const ROOT = h("sanctions-root:2026-11-23");
const PROVIDER = h("provider:fictitious");
const DIGEST = h("verdict-digest");
const TTL = 7 * 24 * 3600;

describe("DPO2U L1: ComplianceGate + VerdictReceiver (phase A1, mock verifier)", () => {
  async function deploy() {
    const [safe, wallet, other, relayer] = await ethers.getSigners();
    const allow = await (await ethers.getContractFactory("MockAllowList")).deploy(safe.address);
    const verifier = await (await ethers.getContractFactory("MockMidnightVerifier")).deploy();
    const gate = await (await ethers.getContractFactory("DPO2UL1ComplianceGate")).deploy(
      await allow.getAddress(),
      await verifier.getAddress(),
      safe.address,
    );
    // Least privilege: the Safe makes the gate a Manager (None <-> Enabled only), not an Admin.
    await allow.setManager(await gate.getAddress());
    await gate.setPolicy(POLICY, VK, TTL, true);
    const now = await time.latest();
    await gate.setProvider(PROVIDER, ROOT, now - 3600, true);
    const chainId = (await ethers.provider.getNetwork()).chainId;

    const statement = async (o: Partial<Record<string, bigint | string>> = {}) => {
      const t = await time.latest();
      const v: Record<string, any> = {
        pass: 1n,
        policy: POLICY,
        root: ROOT,
        provider: PROVIDER,
        issuedAt: BigInt(t - 60),
        validUntil: BigInt(t + 30 * 24 * 3600),
        subject: wallet.address,
        chainId,
        gate: await gate.getAddress(),
        nonce: 1n,
        digest: DIGEST,
        ...o,
      };
      return [
        v.pass,
        ...limbs(v.policy),
        ...limbs(v.root),
        ...limbs(v.provider),
        v.issuedAt,
        v.validUntil,
        BigInt(v.subject),
        BigInt(v.chainId),
        BigInt(v.gate),
        v.nonce,
        ...limbs(v.digest),
      ];
    };
    const proof = "0xdeadbeef";
    const prove = async (pi: bigint[], vk = VK) => {
      await verifier.accept(vk, proof, pi);
      return pi;
    };
    return { safe, wallet, other, relayer, allow, verifier, gate, statement, prove, proof, chainId };
  }

  it("admits a wallet with a valid PASS proof and enables it on the Transaction AllowList", async () => {
    const { gate, allow, wallet, relayer, statement, prove, proof } = await deploy();
    const pi = await prove(await statement());
    expect(await allow.readAllowList(wallet.address)).to.equal(0n);
    await expect(gate.connect(relayer).admit(proof, pi)).to.emit(gate, "Admitted");
    expect(await allow.readAllowList(wallet.address)).to.equal(1n);
    expect(await gate.isAdmitted(wallet.address)).to.equal(true);
    const a = await gate.admissionOf(wallet.address);
    expect(a.digest).to.equal(DIGEST);
    expect(a.policyHash).to.equal(POLICY);
    expect(a.granted).to.equal(true);
  });

  it("refuses a proof the verifier rejects (tampered proof, other VK, changed public input)", async () => {
    const { gate, statement, prove, proof } = await deploy();
    const pi = await prove(await statement());
    await expect(gate.admit("0xdeadbeee", pi)).to.be.revertedWithCustomError(gate, "InvalidProof");
    const changed = [...pi];
    changed[12] = 2n; // nonce
    await expect(gate.admit(proof, changed)).to.be.revertedWithCustomError(gate, "InvalidProof");
    const otherVk = await statement();
    await prove(otherVk, h("vk:other-circuit"));
    await expect(gate.admit(proof, otherVk)).to.be.revertedWithCustomError(gate, "InvalidProof");
  });

  it("refuses FAIL, unknown policy, unpinned provider, other list root, stale list, expired list", async () => {
    const { gate, statement, prove, proof } = await deploy();
    const t = await time.latest();
    const cases: [Record<string, any>, string][] = [
      [{ pass: 0n }, "NotPass"],
      [{ policy: h("policy:other") }, "PolicyNotActive"],
      [{ provider: h("provider:other") }, "ProviderNotPinned"],
      [{ root: h("sanctions-root:other") }, "WrongListRoot"],
      [{ issuedAt: BigInt(t - 7200) }, "StaleList"],
      [{ validUntil: BigInt(t - 1) }, "ListExpired"],
    ];
    for (const [o, err] of cases) {
      const pi = await prove(await statement(o));
      await expect(gate.admit(proof, pi), err).to.be.revertedWithCustomError(gate, err);
    }
  });

  it("binds the proof to this chain, this gate and a single use", async () => {
    const { gate, statement, prove, proof, other } = await deploy();
    let pi = await prove(await statement({ chainId: 1n }));
    await expect(gate.admit(proof, pi)).to.be.revertedWithCustomError(gate, "WrongChain");
    pi = await prove(await statement({ gate: other.address }));
    await expect(gate.admit(proof, pi)).to.be.revertedWithCustomError(gate, "WrongGate");
    pi = await prove(await statement());
    await gate.admit(proof, pi);
    await expect(gate.admit(proof, pi)).to.be.revertedWithCustomError(gate, "NonceUsed");
  });

  it("rejects public inputs outside the layout (wrong count, limb >= 2^128)", async () => {
    const { gate, statement, prove, proof } = await deploy();
    const pi = await statement();
    await prove(pi.slice(0, 14));
    await expect(gate.admit(proof, pi.slice(0, 14))).to.be.revertedWithCustomError(gate, "BadPublicInputs");
    const bad = [...pi];
    bad[1] = 1n << 128n;
    await prove(bad);
    await expect(gate.admit(proof, bad)).to.be.revertedWithCustomError(gate, "BadPublicInputs");
  });

  it("admission lasts the policy TTL, capped by the list's valid_until; anyone can expire it", async () => {
    const { gate, allow, wallet, other, statement, prove, proof } = await deploy();
    const t = await time.latest();
    const pi = await prove(await statement({ validUntil: BigInt(t + 3600) }));
    await gate.admit(proof, pi);
    const a = await gate.admissionOf(wallet.address);
    expect(a.expiresAt).to.equal(BigInt(t + 3600));
    await expect(gate.connect(other).expire(wallet.address)).to.be.revertedWithCustomError(gate, "NotExpired");
    await time.increaseTo(t + 3601);
    expect(await gate.isAdmitted(wallet.address)).to.equal(false);
    await expect(gate.connect(other).expire(wallet.address)).to.emit(gate, "Dropped").withArgs(wallet.address, 1, ethers.ZeroHash);
    expect(await allow.readAllowList(wallet.address)).to.equal(0n);
  });

  it("the Safe revokes and freezes at once; a frozen wallet cannot be re-admitted", async () => {
    const { gate, allow, wallet, other, statement, prove, proof } = await deploy();
    await gate.admit(proof, await prove(await statement()));
    const reason = h("sanctions-freeze");
    await expect(gate.connect(other).setFrozen(wallet.address, true, reason)).to.be.revertedWithCustomError(gate, "AdminOnly");
    await expect(gate.setFrozen(wallet.address, true, reason)).to.emit(gate, "Dropped").withArgs(wallet.address, 2, reason);
    expect(await allow.readAllowList(wallet.address)).to.equal(0n);
    const pi = await prove(await statement({ nonce: 2n }));
    await expect(gate.admit(proof, pi)).to.be.revertedWithCustomError(gate, "SubjectFrozen");
    await gate.setFrozen(wallet.address, false, reason);
    await gate.admit(proof, pi);
    await expect(gate.revoke(wallet.address, reason)).to.emit(gate, "Dropped");
    await expect(gate.revoke(wallet.address, reason)).to.be.revertedWithCustomError(gate, "NotAdmitted");
  });

  it("never touches a wallet the Safe enabled directly or an Admin/Manager", async () => {
    const { gate, allow, safe, wallet, statement, prove, proof } = await deploy();
    await allow.setEnabled(wallet.address); // enabled by the Safe, outside the gate
    await gate.admit(proof, await prove(await statement()));
    expect((await gate.admissionOf(wallet.address)).granted).to.equal(false);
    await gate.revoke(wallet.address, ethers.ZeroHash);
    expect(await allow.readAllowList(wallet.address)).to.equal(1n);
    // The Safe itself (Admin) admitted by proof keeps its Admin role.
    await gate.admit(proof, await prove(await statement({ subject: safe.address, nonce: 3n })));
    await gate.revoke(safe.address, ethers.ZeroHash);
    expect(await allow.readAllowList(safe.address)).to.equal(2n);
  });

  it("admin is two-step and pins are admin-only", async () => {
    const { gate, safe, other } = await deploy();
    await expect(gate.connect(other).setPolicy(POLICY, VK, TTL, false)).to.be.revertedWithCustomError(gate, "AdminOnly");
    await expect(gate.connect(other).setProvider(PROVIDER, ROOT, 0, true)).to.be.revertedWithCustomError(gate, "AdminOnly");
    await expect(gate.setPolicy(POLICY, ethers.ZeroHash, TTL, true)).to.be.revertedWithCustomError(gate, "BadTtl");
    await gate.transferAdmin(other.address);
    expect(await gate.admin()).to.equal(safe.address);
    await gate.connect(other).acceptAdmin();
    expect(await gate.admin()).to.equal(other.address);
  });

  it("ICM: the C-Chain receiver mirrors ADMIT and DROP, only from the pinned L1 and gate, in order", async () => {
    const { gate, safe, wallet, other, statement, prove, proof } = await deploy();
    const tele = await (await ethers.getContractFactory("MockTeleporterMessenger")).deploy();
    const L1 = h("blockchain:dpo2u-l1");
    const rx = await (await ethers.getContractFactory("DPO2UL1VerdictReceiver")).deploy(
      await tele.getAddress(),
      L1,
      await gate.getAddress(),
      safe.address,
    );
    await gate.setTeleporter(await tele.getAddress());
    await gate.addDestination(h("blockchain:c-chain"), await rx.getAddress(), 200_000);

    await gate.admit(proof, await prove(await statement()));
    await gate.revoke(wallet.address, ethers.ZeroHash);
    expect(await tele.sentCount()).to.equal(2n);

    // Unknown source chain is refused; direct calls (not through Teleporter) are refused.
    await expect(tele.deliver(0, h("blockchain:other"))).to.be.revertedWithCustomError(rx, "UnknownSource");
    await expect(rx.connect(other).receiveTeleporterMessage(L1, await gate.getAddress(), "0x")).to.be.revertedWithCustomError(
      rx,
      "NotTeleporter",
    );

    // Delivered out of order: DROP (seq 2) first, then the late ADMIT (seq 1) is ignored.
    await tele.deliver(1, L1);
    await expect(tele.deliver(0, L1)).to.emit(rx, "StaleMessage");
    expect(await rx.isAdmitted(wallet.address)).to.equal(false);

    await gate.admit(proof, await prove(await statement({ nonce: 9n })));
    await tele.deliver(2, L1);
    expect(await rx.isAdmitted(wallet.address)).to.equal(true);
    const s = await rx.statusOf(wallet.address);
    expect(s.digest).to.equal(DIGEST);
    expect(s.seq).to.equal(3n);
  });
});

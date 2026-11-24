import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import fs from "node:fs";
import path from "node:path";

// The REAL TravelRuleGate v12 evaluateTransfer statement (417 values, Midnight preview capture,
// fictitious data), as the precompile vector stores it: big-endian uint256 per value.
const V = path.join(__dirname, "..", "..", "l1", "precompile", "testdata", "travel-rule-gate-v12", "vector.json");
const statement: bigint[] = JSON.parse(fs.readFileSync(V, "utf8")).publicInputs.map((h: string) => BigInt(h));
// transfer_id of that capture ("tr-v12-cap2-20261124T014017", zero padded).
const CAPTURE_TRANSFER_ID = "0x74722d7631322d636170322d3230323631313234543031343031370000000000";

// Statement positions (Stellar thread map): Bytes<32> = 2 values.
const POS = { transferId: 202, status: 208, failReason: 228, policy: 290, root: 311, pepper: 373, provider: 114, validUntil: 353, issuedAt: 394 };
const NO_INDEX = 2 ** 32 - 1;
const VK = ethers.id("vk:TravelRuleGate.v12.evaluateTransfer");
const TTL = 3600;

const pinsFor = (s: bigint[]) => [
  ...[POS.policy, POS.root, POS.pepper, POS.provider].flatMap((i) => [
    { index: i, value: s[i] },
    { index: i + 1, value: s[i + 1] },
  ]),
  { index: POS.status, value: 1n }, // PASS
  { index: POS.failReason, value: 0n },
];

// Compact Bytes<32> -> [b[31], LE(b[0..31])]
const compact = (b32: string): [bigint, bigint] => {
  const b = ethers.getBytes(b32);
  let rest = 0n;
  for (let i = 30; i >= 0; i--) rest = (rest << 8n) | BigInt(b[i]);
  return [BigInt(b[31]), rest];
};

describe("DPO2U L1: Midnight statement lane (real TravelRuleGate v12 statement, mock verifier)", () => {
  async function deployFixture() {
    const [safe, wallet, relayer] = await ethers.getSigners();
    const allow = await (await ethers.getContractFactory("MockAllowList")).deploy(safe.address);
    const verifier = await (await ethers.getContractFactory("MockMidnightVerifier")).deploy();
    const gate = await (await ethers.getContractFactory("DPO2UL1ComplianceGate")).deploy(
      await allow.getAddress(),
      await verifier.getAddress(),
      safe.address,
    );
    await allow.setManager(await gate.getAddress());
    // The capture's list window (issued 2026-11-24 01:39 UTC, valid 24 h) is moved to the test
    // chain's clock: the mock verifier does not check it, and the other values stay real.
    const now = BigInt(await time.latest());
    const base = [...statement];
    base[POS.issuedAt] = now - 60n;
    base[POS.validUntil] = now + 86_400n;
    const policy = {
      vkHash: VK,
      statementLen: statement.length,
      contextIndex: POS.transferId,
      contextEncoding: 1,
      validUntilIndex: POS.validUntil,
      issuedAtIndex: POS.issuedAt,
      minIssuedAt: now - 3600n,
      admissionTtl: TTL,
      active: true,
    };
    await gate.setMidnightPolicy(1, policy, pinsFor(statement));
    return { gate, allow, verifier, safe, wallet, relayer, policy, base };
  }

  const deploy = () => loadFixture(deployFixture);

  // A statement for an L1 admission: the real one with the context written at transfer_id.
  const withContext = (base: bigint[], ctx: string) => {
    const s = [...base];
    [s[POS.transferId], s[POS.transferId + 1]] = compact(ctx);
    return s;
  };

  it("decodes the capture's transfer_id exactly as Compact encodes Bytes<32>", async () => {
    const { gate, verifier, base } = await deploy();
    expect(compact(CAPTURE_TRANSFER_ID)).to.deep.equal([statement[POS.transferId], statement[POS.transferId + 1]]);
    await verifier.accept(VK, "0x01", base);
    expect(await gate.checkMidnight(1, CAPTURE_TRANSFER_ID, "0x01", base)).to.equal(true);
    await expect(gate.checkMidnight(1, ethers.ZeroHash, "0x01", base)).to.be.revertedWithCustomError(gate, "ContextMismatch");
  });

  it("admits the wallet bound by the context and enables it on the AllowList", async () => {
    const { gate, allow, verifier, wallet, relayer, base } = await deploy();
    const ctx = await gate.admissionContext(wallet.address, 7);
    const s = withContext(base, ctx);
    await verifier.accept(VK, "0x02", s);
    await expect(gate.connect(relayer).admitMidnight(1, wallet.address, 7, "0x02", s)).to.emit(gate, "Admitted");
    expect(await allow.readAllowList(wallet.address)).to.equal(1n);
    const a = await gate.admissionOf(wallet.address);
    // capped by the list's valid_until when that comes before now + TTL
    const now = BigInt(await time.latest());
    expect(a.expiresAt).to.equal(now + BigInt(TTL) < base[POS.validUntil] ? now + BigInt(TTL) : base[POS.validUntil]);
    await expect(gate.admitMidnight(1, wallet.address, 7, "0x02", s)).to.be.revertedWithCustomError(gate, "NonceUsed");
  });

  it("refuses the proof for another wallet, another nonce or a FAIL / changed pin", async () => {
    const { gate, verifier, wallet, relayer, base } = await deploy();
    const s = withContext(base, await gate.admissionContext(wallet.address, 1));
    await verifier.accept(VK, "0x03", s);
    await expect(gate.admitMidnight(1, relayer.address, 1, "0x03", s)).to.be.revertedWithCustomError(gate, "ContextMismatch");
    await expect(gate.admitMidnight(1, wallet.address, 2, "0x03", s)).to.be.revertedWithCustomError(gate, "ContextMismatch");
    const fail = [...s];
    fail[POS.status] = 2n;
    await verifier.accept(VK, "0x03", fail);
    await expect(gate.admitMidnight(1, wallet.address, 1, "0x03", fail)).to.be.revertedWithCustomError(gate, "PinMismatch");
    const otherRoot = [...s];
    otherRoot[POS.root + 1] ^= 1n;
    await expect(gate.admitMidnight(1, wallet.address, 1, "0x03", otherRoot)).to.be.revertedWithCustomError(gate, "PinMismatch");
    await expect(gate.admitMidnight(1, wallet.address, 1, "0x04", s)).to.be.revertedWithCustomError(gate, "InvalidProof");
    await expect(gate.admitMidnight(1, wallet.address, 1, "0x03", s.slice(0, 416))).to.be.revertedWithCustomError(gate, "BadPublicInputs");
  });

  it("refuses a stale or expired list and bad policies", async () => {
    const { gate, verifier, wallet, policy, base } = await deploy();
    const s = withContext(base, await gate.admissionContext(wallet.address, 1));
    await verifier.accept(VK, "0x05", s);
    await gate.setMidnightPolicy(1, { ...policy, minIssuedAt: base[POS.issuedAt] + 1n }, pinsFor(statement));
    await expect(gate.admitMidnight(1, wallet.address, 1, "0x05", s)).to.be.revertedWithCustomError(gate, "StaleList");
    await gate.setMidnightPolicy(1, policy, pinsFor(statement));
    await time.increaseTo(Number(base[POS.validUntil]) + 1);
    await expect(gate.admitMidnight(1, wallet.address, 1, "0x05", s)).to.be.revertedWithCustomError(gate, "ListExpired");
    // a pin inside the context, an index out of range, an unknown encoding
    await expect(gate.setMidnightPolicy(2, policy, [{ index: POS.transferId + 1, value: 0n }])).to.be.revertedWithCustomError(gate, "BadMidnightPolicy");
    await expect(gate.setMidnightPolicy(2, { ...policy, validUntilIndex: 417 }, [])).to.be.revertedWithCustomError(gate, "BadMidnightPolicy");
    await expect(gate.setMidnightPolicy(2, { ...policy, contextEncoding: 2 }, [])).to.be.revertedWithCustomError(gate, "BadMidnightPolicy");
    await expect(gate.setMidnightPolicy(2, { ...policy, issuedAtIndex: NO_INDEX, validUntilIndex: NO_INDEX }, [])).to.not.be.reverted;
    await expect(gate.connect(wallet).setMidnightPolicy(3, policy, [])).to.be.revertedWithCustomError(gate, "AdminOnly");
  });
});

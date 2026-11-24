import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";

// CVM test asset + DvP on the DPO2U L1. Admission comes from a switchable mock gate here; the
// local-network script (l1/localnet/a3-cvm-dvp-local-e2e.ts) runs the same flow on the real gate.
describe("DPO2U L1: CVM test security token + DvP", () => {
  async function fixture() {
    const [issuer, seller, buyer, outsider, other] = await ethers.getSigners();
    const gate = await (await ethers.getContractFactory("MockAdmissionGate")).deploy();
    for (const s of [seller, buyer]) await gate.set(s.address, true);
    const terms = ethers.id("dpo2u.cvm-test-asset/terms-v0");
    const token = await (await ethers.getContractFactory("DPO2UL1SecurityToken")).deploy(
      "DPO2U CVM Test Security", "dCVMT", await gate.getAddress(), issuer.address, terms,
    );
    const cash = await (await ethers.getContractFactory("DPO2UL1TestCash")).deploy();
    const dvp = await (await ethers.getContractFactory("DPO2UL1DvP")).deploy(await gate.getAddress());
    await token.mint(seller.address, 100n);
    await cash.mint(buyer.address, 1_000_00n);
    const dvpAddr = await dvp.getAddress();
    await token.connect(seller).approve(dvpAddr, 100n);
    await cash.connect(buyer).approve(dvpAddr, 1_000_00n);
    return { issuer, seller, buyer, outsider, other, gate, token, cash, dvp, terms };
  }

  async function propose(f: Awaited<ReturnType<typeof fixture>>, assetAmount = 10n, cashAmount = 250_00n) {
    const deadline = BigInt(await time.latest()) + 3600n;
    const args = [f.buyer.address, await f.token.getAddress(), assetAmount, await f.cash.getAddress(), cashAmount, deadline, ethers.id("trade-confirmation-1")] as const;
    const id = await f.dvp.connect(f.seller).propose.staticCall(...args);
    await f.dvp.connect(f.seller).propose(...args);
    return { id, deadline };
  }

  describe("token", () => {
    it("is whole-unit and pins the terms hash", async () => {
      const { token, terms } = await loadFixture(fixture);
      expect(await token.decimals()).to.equal(0);
      expect(await token.termsHash()).to.equal(terms);
    });

    it("mints and transfers only between admitted wallets", async () => {
      const { token, seller, buyer, outsider } = await loadFixture(fixture);
      await expect(token.mint(outsider.address, 1n)).to.be.revertedWithCustomError(token, "NotAdmitted").withArgs(outsider.address);
      await expect(token.connect(seller).transfer(outsider.address, 1n)).to.be.revertedWithCustomError(token, "NotAdmitted").withArgs(outsider.address);
      await token.connect(seller).transfer(buyer.address, 5n);
      expect(await token.balanceOf(buyer.address)).to.equal(5n);
      expect(await token.canTransfer(seller.address, outsider.address)).to.equal(false);
    });

    it("an expired or revoked holder can neither send nor receive", async () => {
      const { token, gate, seller, buyer } = await loadFixture(fixture);
      await gate.set(seller.address, false);
      await expect(token.connect(seller).transfer(buyer.address, 1n)).to.be.revertedWithCustomError(token, "NotAdmitted").withArgs(seller.address);
      await expect(token.connect(buyer).transfer(seller.address, 0n)).to.be.revertedWithCustomError(token, "NotAdmitted").withArgs(seller.address);
    });

    it("only the issuer mints, redeems, pauses and makes controller transfers", async () => {
      const { token, gate, issuer, seller, buyer } = await loadFixture(fixture);
      await expect(token.connect(seller).mint(seller.address, 1n)).to.be.revertedWithCustomError(token, "IssuerOnly");
      await expect(token.connect(seller).setPaused(true)).to.be.revertedWithCustomError(token, "IssuerOnly");
      await token.setPaused(true);
      await expect(token.connect(seller).transfer(buyer.address, 1n)).to.be.revertedWithCustomError(token, "Paused");
      await token.setPaused(false);
      // Court order: seller is frozen, issuer moves 7 units to buyer and logs only a hash.
      await gate.set(seller.address, false);
      const reason = ethers.id("ordem-judicial-0001");
      await expect(token.connect(issuer).controllerTransfer(seller.address, buyer.address, 7n, reason))
        .to.emit(token, "ControllerTransfer").withArgs(seller.address, buyer.address, 7n, reason);
      await expect(token.redeem(seller.address, 3n, reason)).to.emit(token, "Redeemed");
      expect(await token.balanceOf(seller.address)).to.equal(90n);
    });

    it("controller transfer still needs an admitted receiver", async () => {
      const { token, seller, outsider } = await loadFixture(fixture);
      await expect(token.controllerTransfer(seller.address, outsider.address, 1n, ethers.ZeroHash))
        .to.be.revertedWithCustomError(token, "NotAdmitted").withArgs(outsider.address);
    });

    it("hands the issuer role over in two steps", async () => {
      const { token, issuer, other } = await loadFixture(fixture);
      await token.transferIssuer(other.address);
      expect(await token.issuer()).to.equal(issuer.address);
      await token.connect(other).acceptIssuer();
      expect(await token.issuer()).to.equal(other.address);
    });
  });

  describe("DvP", () => {
    it("settles both legs atomically", async () => {
      const f = await loadFixture(fixture);
      const { id } = await propose(f);
      await expect(f.dvp.connect(f.buyer).settle(id)).to.emit(f.dvp, "Settled").withArgs(id);
      expect(await f.token.balanceOf(f.buyer.address)).to.equal(10n);
      expect(await f.cash.balanceOf(f.seller.address)).to.equal(250_00n);
      expect((await f.dvp.trade(id)).state).to.equal(2n);
      await expect(f.dvp.connect(f.buyer).settle(id)).to.be.revertedWithCustomError(f.dvp, "NotOpen");
    });

    it("if the payment leg fails, the asset does not move", async () => {
      const f = await loadFixture(fixture);
      const { id } = await propose(f, 10n, 2_000_00n); // buyer holds only 1,000.00
      await expect(f.dvp.connect(f.buyer).settle(id)).to.be.reverted;
      expect(await f.token.balanceOf(f.seller.address)).to.equal(100n);
      expect(await f.token.balanceOf(f.buyer.address)).to.equal(0n);
      expect((await f.dvp.trade(id)).state).to.equal(1n);
    });

    it("if the asset leg fails (token paused), no cash moves", async () => {
      const f = await loadFixture(fixture);
      const { id } = await propose(f);
      await f.token.setPaused(true);
      await expect(f.dvp.connect(f.buyer).settle(id)).to.be.revertedWithCustomError(f.token, "Paused");
      expect(await f.cash.balanceOf(f.buyer.address)).to.equal(1_000_00n);
    });

    it("refuses settlement when a party lost its admission", async () => {
      const f = await loadFixture(fixture);
      const { id } = await propose(f);
      await f.gate.set(f.buyer.address, false);
      await expect(f.dvp.connect(f.buyer).settle(id)).to.be.revertedWithCustomError(f.dvp, "NotAdmitted").withArgs(f.buyer.address);
      await f.gate.set(f.buyer.address, true);
      await f.gate.set(f.seller.address, false);
      await expect(f.dvp.connect(f.buyer).settle(id)).to.be.revertedWithCustomError(f.dvp, "NotAdmitted").withArgs(f.seller.address);
    });

    it("only the named buyer settles, before the deadline", async () => {
      const f = await loadFixture(fixture);
      const { id, deadline } = await propose(f);
      await expect(f.dvp.connect(f.other).settle(id)).to.be.revertedWithCustomError(f.dvp, "NotParty");
      await time.increaseTo(deadline + 1n);
      await expect(f.dvp.connect(f.buyer).settle(id)).to.be.revertedWithCustomError(f.dvp, "Expired");
      await expect(f.dvp.connect(f.other).cancel(id)).to.emit(f.dvp, "Cancelled"); // anyone clears an expired trade
    });

    it("parties may cancel an open trade; outsiders may not before the deadline", async () => {
      const f = await loadFixture(fixture);
      const { id } = await propose(f);
      await expect(f.dvp.connect(f.other).cancel(id)).to.be.revertedWithCustomError(f.dvp, "NotParty");
      await f.dvp.connect(f.buyer).cancel(id);
      await expect(f.dvp.connect(f.buyer).settle(id)).to.be.revertedWithCustomError(f.dvp, "NotOpen");
    });

    it("rejects bad proposals and non-admitted sellers", async () => {
      const f = await loadFixture(fixture);
      const t = await f.token.getAddress(), c = await f.cash.getAddress();
      const dl = BigInt(await time.latest()) + 60n;
      await expect(f.dvp.connect(f.seller).propose(f.seller.address, t, 1n, c, 1n, dl, ethers.ZeroHash)).to.be.revertedWithCustomError(f.dvp, "BadTrade");
      await expect(f.dvp.connect(f.seller).propose(f.buyer.address, t, 0n, c, 1n, dl, ethers.ZeroHash)).to.be.revertedWithCustomError(f.dvp, "BadTrade");
      await expect(f.dvp.connect(f.seller).propose(f.buyer.address, t, 1n, t, 1n, dl, ethers.ZeroHash)).to.be.revertedWithCustomError(f.dvp, "BadTrade");
      await expect(f.dvp.connect(f.seller).propose(f.buyer.address, t, 1n, c, 1n, 1n, ethers.ZeroHash)).to.be.revertedWithCustomError(f.dvp, "Expired");
      await expect(f.dvp.connect(f.outsider).propose(f.buyer.address, t, 1n, c, 1n, dl, ethers.ZeroHash)).to.be.revertedWithCustomError(f.dvp, "NotAdmitted");
    });
  });
});

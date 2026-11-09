import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

const DAY = 86_400;
const id = (s: string) => ethers.keccak256(ethers.toUtf8Bytes(s));
const UC = id("psav_partner_br_v1");
const PACK_ID = id("psav-partner-br@1.0.0");
const PACK_HASH = "0x5098e1806e2a918da1aa7f1db39c0b4e41e022d2d7bad6abcdc511b6ddddab86";
const SUBJECT = id("eip155:43113:0x000000000000000000000000000000000000dead");
const IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

describe("DPO2UPassportOracleV2 — proxy and upgrades", () => {
  async function deploy() {
    const [admin, gateway, issuer, other, safe] = await ethers.getSigners();
    const reg = await (await ethers.getContractFactory("DPO2UComplianceRegistry")).deploy(admin.address, 365 * DAY);
    await reg.configureUseCase(UC, true, PACK_HASH, 10000);
    await reg.authorizeSubmitter(gateway.address, true);
    const impl = await (await ethers.getContractFactory("DPO2UPassportOracleV2")).deploy();
    const init = impl.interface.encodeFunctionData("initialize", [admin.address, await reg.getAddress(), 366 * DAY]);
    const proxy = await (await ethers.getContractFactory("ERC1967Proxy")).deploy(await impl.getAddress(), init);
    const oracle = await ethers.getContractAt("DPO2UPassportOracleV2", await proxy.getAddress());
    await oracle.authorizeIssuer(issuer.address, true);
    return { reg, impl, oracle, admin, gateway, issuer, other, safe };
  }

  async function issueOne(f: any) {
    const now = await time.latest();
    await f.reg.connect(f.gateway).registerAttestation(UC, id("run-1"), SUBJECT, 1, 0, id("m"), BigInt(now + 90 * DAY));
    await f.oracle.connect(f.issuer).issuePassport(SUBJECT, PACK_ID, PACK_HASH, 3, BigInt(now + 31 * DAY), id("pp-1"), UC, id("run-1"));
  }

  it("initializes once; the implementation itself cannot be initialized", async () => {
    const f = await deploy();
    expect(await f.oracle.version()).to.equal("2");
    expect(await f.oracle.admin()).to.equal(f.admin.address);
    expect(await f.oracle.maxValidity()).to.equal(366 * DAY);
    await expect(f.oracle.initialize(f.other.address, await f.reg.getAddress(), DAY)).to.be.revertedWithCustomError(f.oracle, "InvalidInitialization");
    await expect(f.impl.initialize(f.other.address, await f.reg.getAddress(), DAY)).to.be.revertedWithCustomError(f.impl, "InvalidInitialization");
  });

  it("only the admin upgrades; state and address survive the upgrade", async () => {
    const f = await deploy();
    await issueOne(f);
    const v3 = await (await ethers.getContractFactory("PassportOracleV3Mock")).deploy();
    await expect(f.oracle.connect(f.other).upgradeToAndCall(await v3.getAddress(), "0x")).to.be.revertedWithCustomError(f.oracle, "AdminOnly");
    await f.oracle.upgradeToAndCall(await v3.getAddress(), "0x");
    const slot = await ethers.provider.getStorage(await f.oracle.getAddress(), IMPL_SLOT);
    expect(ethers.getAddress("0x" + slot.slice(26))).to.equal(await v3.getAddress());
    expect(await f.oracle.version()).to.equal("3-mock");
    expect(await f.oracle.isValid(SUBJECT, PACK_ID, 3)).to.equal(true);
    expect(await f.oracle.isIssuer(f.issuer.address)).to.equal(true);
    expect(await f.oracle.admin()).to.equal(f.admin.address);
  });

  it("after handing admin to the Safe, only the Safe upgrades", async () => {
    const f = await deploy();
    await f.oracle.transferAdmin(f.safe.address);
    await f.oracle.connect(f.safe).acceptAdmin();
    const v3 = await (await ethers.getContractFactory("PassportOracleV3Mock")).deploy();
    await expect(f.oracle.upgradeToAndCall(await v3.getAddress(), "0x")).to.be.revertedWithCustomError(f.oracle, "AdminOnly");
    await f.oracle.connect(f.safe).upgradeToAndCall(await v3.getAddress(), "0x");
    expect(await f.oracle.version()).to.equal("3-mock");
  });
});

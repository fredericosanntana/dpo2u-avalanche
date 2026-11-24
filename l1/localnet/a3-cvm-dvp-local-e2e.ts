/**
 * Phase A3, local network: a TEST CVM security token and delivery-versus-payment on the DPO2U L1.
 * Only wallets the ComplianceGate admitted (Midnight proof checked by the precompile) can hold
 * the token; the DvP contract swaps token for test BRL atomically between two admitted wallets.
 *
 *   DPO2U_L1_RPC=$(cat l1/precompile/build/localnet-state/rpc-url) MIDNIGHT_SRS=.../bls_midnight_2p14 \
 *     npx hardhat run l1/localnet/a3-cvm-dvp-local-e2e.ts --network dpo2uLocal
 *
 * Admission proofs come from `prove-gate-v0` (TEST circuit, layout v0), as in a3-local-e2e.ts.
 * Hardhat dev keys: local network only. No personal data anywhere: wallets, amounts and hashes.
 */
import { ethers } from "hardhat";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const TX_ALLOW_LIST = "0x0200000000000000000000000000000000000002";
const VERIFIER = "0x03000000000000000000000000000000000000d2";
const ffi = path.join(__dirname, "..", "precompile", "midnight-verifier-ffi");
const prover = path.join(ffi, "target", "release", "prove-gate-v0");
const srs = process.env.MIDNIGHT_SRS!;

const limbs = (h: string): [bigint, bigint] => {
  const v = BigInt(h);
  return [v >> 128n, v & ((1n << 128n) - 1n)];
};
const step = (s: string) => console.log(`\n== ${s}`);

async function expectRevert(p: Promise<unknown>, reason: string, iface: any, errorName: string) {
  try {
    await p;
  } catch (e: any) {
    const data = e?.data ?? e?.info?.error?.data;
    const parsed = data ? iface.parseError(data) : null;
    if (parsed?.name !== errorName) throw new Error(`${reason}: expected ${errorName}, got ${parsed?.name ?? e?.shortMessage ?? e}`);
    console.log(`  refused as expected (${reason}): ${parsed.name}(${parsed.args.join(", ")})`);
    return;
  }
  throw new Error(`expected a revert: ${reason}`);
}

async function main() {
  if (!srs || !fs.existsSync(srs)) throw new Error("set MIDNIGHT_SRS to bls_midnight_2p14");
  const [deployer, safe, relayer, seller, buyer] = await ethers.getSigners();
  const outsider = ethers.Wallet.createRandom().address; // never admitted
  const net = await ethers.provider.getNetwork();
  const allow = new ethers.Contract(TX_ALLOW_LIST, ["function setManager(address)", "function readAllowList(address) view returns (uint256)"], ethers.provider);
  const verifier = new ethers.Contract(VERIFIER, ["function registerVerifyingKey(bytes) returns (bytes32)", "function isRegistered(bytes32) view returns (bool)"], ethers.provider);

  step("1. Gate + admission policy (as in a3-local-e2e)");
  const vkPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "gatev0-")), "vk.bin");
  execFileSync(prover, [srs, "vk", vkPath]);
  const vk = fs.readFileSync(vkPath);
  const vkHash = ethers.keccak256(vk);
  if (!(await verifier.isRegistered(vkHash))) await (await (verifier.connect(deployer) as any).registerVerifyingKey(vk)).wait();
  const gate = await (await ethers.getContractFactory("DPO2UL1ComplianceGate", deployer)).deploy(TX_ALLOW_LIST, VERIFIER, safe.address);
  await gate.waitForDeployment();
  const gateAddr = await gate.getAddress();
  await (await (allow.connect(safe) as any).setManager(gateAddr)).wait();
  const policyHash = ethers.id("dpo2u.l1.local-test-policy/v0");
  const providerId = ethers.id("dpo2u.l1.local-test-provider");
  const listRoot = ethers.id("dpo2u.l1.local-test-list-root");
  const now = BigInt((await ethers.provider.getBlock("latest"))!.timestamp);
  await (await (gate.connect(safe) as any).setPolicy(policyHash, vkHash, 3600, true)).wait();
  await (await (gate.connect(safe) as any).setProvider(providerId, listRoot, now - 3600n, true)).wait();
  console.log(`  gate ${gateAddr}`);

  step("2. Seller and buyer are admitted by Midnight proof (precompile verifies)");
  let nonce = BigInt(Date.now());
  for (const w of [seller, buyer]) {
    await (await deployer.sendTransaction({ to: w.address, value: ethers.parseEther("1") })).wait();
    const pi = [1n, ...limbs(policyHash), ...limbs(listRoot), ...limbs(providerId), now - 60n, now + 7200n,
      BigInt(w.address), net.chainId, BigInt(gateAddr), nonce++, ...limbs(ethers.id(`dpo2u.travel-rule-verdict/1:${w.address}`))];
    const proof = execFileSync(prover, [srs, "prove", ...pi.map((v) => "0x" + v.toString(16))]).toString();
    const rc = await (await (gate.connect(relayer) as any).admit(proof, pi)).wait();
    console.log(`  ${w.address} admitted (gas ${rc!.gasUsed}), AllowList role ${await allow.readAllowList(w.address)}`);
  }

  step("3. Issuer deploys the TEST security token, test BRL and the DvP contract");
  const terms = ethers.id("dpo2u.cvm-test-asset/terms-v0");
  const token = await (await ethers.getContractFactory("DPO2UL1SecurityToken", deployer)).deploy("DPO2U CVM Test Security", "dCVMT", gateAddr, deployer.address, terms);
  const cash = await (await ethers.getContractFactory("DPO2UL1TestCash", deployer)).deploy();
  const dvp = await (await ethers.getContractFactory("DPO2UL1DvP", deployer)).deploy(gateAddr);
  await Promise.all([token.waitForDeployment(), cash.waitForDeployment(), dvp.waitForDeployment()]);
  const [tokenAddr, cashAddr, dvpAddr] = await Promise.all([token.getAddress(), cash.getAddress(), dvp.getAddress()]);
  console.log(`  token ${tokenAddr}\n  tBRL  ${cashAddr}\n  DvP   ${dvpAddr}`);
  await expectRevert(token.mint.staticCall(outsider, 1n), "mint to a wallet without admission", token.interface, "NotAdmitted");
  await (await token.mint(seller.address, 100n)).wait();
  await (await cash.mint(buyer.address, 1_000_00n)).wait();
  await expectRevert((token.connect(seller) as any).transfer.staticCall(outsider, 1n), "transfer to a wallet without admission", token.interface, "NotAdmitted");

  step("4. DvP: 10 units for R$ 250.00, settled in one transaction");
  await (await (token.connect(seller) as any).approve(dvpAddr, 10n)).wait();
  await (await (cash.connect(buyer) as any).approve(dvpAddr, 250_00n)).wait();
  const deadline = BigInt((await ethers.provider.getBlock("latest"))!.timestamp) + 600n;
  const args = [buyer.address, tokenAddr, 10n, cashAddr, 250_00n, deadline, ethers.id("trade-confirmation-local-1")] as const;
  const id = await (dvp.connect(seller) as any).propose.staticCall(...args);
  await (await (dvp.connect(seller) as any).propose(...args)).wait();
  const rc = await (await (dvp.connect(buyer) as any).settle(id)).wait();
  console.log(`  trade ${id} settled, tx ${rc!.hash}, gas ${rc!.gasUsed}`);
  console.log(`  seller: ${await token.balanceOf(seller.address)} dCVMT, ${await cash.balanceOf(seller.address)} centavos tBRL`);
  console.log(`  buyer:  ${await token.balanceOf(buyer.address)} dCVMT, ${await cash.balanceOf(buyer.address)} centavos tBRL`);

  step("5. Buyer loses the admission: a new trade cannot settle, nothing moves");
  await (await (token.connect(seller) as any).approve(dvpAddr, 5n)).wait();
  await (await (cash.connect(buyer) as any).approve(dvpAddr, 100_00n)).wait();
  const args2 = [buyer.address, tokenAddr, 5n, cashAddr, 100_00n, deadline, ethers.id("trade-confirmation-local-2")] as const;
  const id2 = await (dvp.connect(seller) as any).propose.staticCall(...args2);
  await (await (dvp.connect(seller) as any).propose(...args2)).wait();
  await (await (gate.connect(safe) as any).setFrozen(buyer.address, true, ethers.id("local-test-freeze"))).wait();
  await expectRevert((dvp.connect(buyer) as any).settle.staticCall(id2), "buyer frozen", dvp.interface, "NotAdmitted");
  await expectRevert((token.connect(seller) as any).transfer.staticCall(buyer.address, 1n), "token to a frozen wallet", token.interface, "NotAdmitted");
  console.log(`  seller still ${await token.balanceOf(seller.address)} dCVMT; trade ${id2} state ${(await dvp.trade(id2)).state} (1 = open)`);
  await (await (dvp.connect(seller) as any).cancel(id2)).wait();
  console.log(`  seller cancelled trade ${id2}`);

  console.log("\nA3 CVM DvP local end to end: OK");
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});

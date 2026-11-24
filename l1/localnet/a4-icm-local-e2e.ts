/**
 * Phase A4, local network: the gate's admissions reach the C-Chain over ICM (Avalanche Warp +
 * Teleporter), signed by the DPO2U L1 validators and checked by the C-Chain's Warp precompile.
 * No relayer trust: the relayer (`localnet relay`, standing in for icm-relayer) only carries the
 * signed message.
 *
 *   (cd l1/precompile && go build -o build/localnet-bin ./localnet && AVALANCHEGO_PATH=... ./build/localnet-bin start)
 *   DPO2U_L1_RPC=$(cat l1/precompile/build/localnet-state/rpc-url) \
 *   DPO2U_CCHAIN_RPC=$(cat l1/precompile/build/localnet-state/cchain-rpc-url) \
 *   MIDNIGHT_SRS=.../bls_midnight_2p14 npx hardhat run l1/localnet/a4-icm-local-e2e.ts --network dpo2uLocal
 *
 * TeleporterMessenger v1 bytecode comes from the icm-contracts Go module (v1.0.9, Ava Labs
 * Ecosystem License), fetched with `go mod download`; it is not vendored here.
 * Hardhat dev keys: local network only. LGPD: the ICM message carries wallet, policy hash,
 * verdict digest, expiry and a sequence number; no personal data.
 */
import { ethers } from "hardhat";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const TX_ALLOW_LIST = "0x0200000000000000000000000000000000000002";
const DEPLOYER_ALLOW_LIST = "0x0200000000000000000000000000000000000000";
const VERIFIER = "0x03000000000000000000000000000000000000d2";
const ICM_VERSION = "v1.0.9";
const precompileDir = path.join(__dirname, "..", "precompile");
const prover = path.join(precompileDir, "midnight-verifier-ffi", "target", "release", "prove-gate-v0");
const localnetBin = path.join(precompileDir, "build", "localnet-bin");
const srs = process.env.MIDNIGHT_SRS!;
const cRpc = process.env.DPO2U_CCHAIN_RPC!;
const l1Rpc = process.env.DPO2U_L1_RPC!;
// Hardhat dev keys #2 (relayer) and #5 (Teleporter deployer: same nonce 0 on both chains, so
// the messenger has the same address on both, which Teleporter requires).
const RELAYER_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const TELEPORTER_DEPLOYER_KEY = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba";

const limbs = (h: string): [bigint, bigint] => {
  const v = BigInt(h);
  return [v >> 128n, v & ((1n << 128n) - 1n)];
};
const step = (s: string) => console.log(`\n== ${s}`);

function teleporterBytecode(): string {
  const info = JSON.parse(execFileSync("go", ["mod", "download", "-json", `github.com/ava-labs/icm-contracts@${ICM_VERSION}`], { cwd: os.tmpdir() }).toString());
  const src = fs.readFileSync(path.join(info.Dir, "abi-bindings/go/teleporter/TeleporterMessenger/TeleporterMessenger.go"), "utf8");
  const m = src.match(/Bin:\s*"(0x[0-9a-f]+)"/);
  if (!m) throw new Error("TeleporterMessenger bytecode not found");
  return m[1];
}

function relay(tx: string, teleporter: string): string {
  return execFileSync(localnetBin, ["relay", l1Rpc, cRpc, tx, teleporter], { env: { ...process.env, DPO2U_RELAYER_KEY: RELAYER_KEY } }).toString().trim();
}

async function main() {
  for (const [k, v] of Object.entries({ MIDNIGHT_SRS: srs, DPO2U_CCHAIN_RPC: cRpc, DPO2U_L1_RPC: l1Rpc })) if (!v) throw new Error(`set ${k}`);
  const [deployer, safe, , subject] = await ethers.getSigners();
  const l1 = ethers.provider;
  const c = new ethers.JsonRpcProvider(cRpc);
  // NonceManager: the C-Chain RPC can report the previous nonce right after a receipt.
  const cDeployer = new ethers.NonceManager(new ethers.Wallet("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", c));
  const tdL1 = new ethers.NonceManager(new ethers.Wallet(TELEPORTER_DEPLOYER_KEY, l1));
  const tdC = new ethers.NonceManager(new ethers.Wallet(TELEPORTER_DEPLOYER_KEY, c));
  const net = await l1.getNetwork();
  const allow = new ethers.Contract(TX_ALLOW_LIST, ["function setEnabled(address)", "function setManager(address)", "function readAllowList(address) view returns (uint256)"], l1);
  const verifier = new ethers.Contract(VERIFIER, ["function registerVerifyingKey(bytes) returns (bytes32)", "function isRegistered(bytes32) view returns (bool)"], l1);
  console.log(`L1 chain ${net.chainId}; C-Chain ${(await c.getNetwork()).chainId}`);

  step("1. TeleporterMessenger v1 at the same address on the DPO2U L1 and the C-Chain");
  if ((await l1.getTransactionCount(await tdL1.getAddress())) !== 0 || (await c.getTransactionCount(await tdC.getAddress())) !== 0)
    throw new Error("Teleporter deployer already used: start a fresh local network");
  await (await deployer.sendTransaction({ to: await tdL1.getAddress(), value: ethers.parseEther("10") })).wait();
  // L1 AllowLists (transactions and contract deployment): the Safe enables the Teleporter deployer.
  await (await (allow.connect(safe) as any).setEnabled(await tdL1.getAddress())).wait();
  await (await (allow.attach(DEPLOYER_ALLOW_LIST).connect(safe) as any).setEnabled(await tdL1.getAddress())).wait();
  const bin = teleporterBytecode();
  const tAbi = ["function initializeBlockchainID() returns (bytes32)", "function blockchainID() view returns (bytes32)", "function receiptQueues(bytes32) view returns (uint256,uint256)"];
  const deployT = async (w: ethers.Signer) => {
    const ct = await new ethers.ContractFactory(tAbi, bin, w).deploy();
    await ct.waitForDeployment();
    await (await (ct as any).initializeBlockchainID()).wait();
    return ct as any;
  };
  const tL1 = await deployT(tdL1);
  const tC = await deployT(tdC);
  const teleporter = await tL1.getAddress();
  if (teleporter !== (await tC.getAddress())) throw new Error("Teleporter addresses differ");
  const l1Id: string = await tL1.blockchainID();
  const cId: string = await tC.blockchainID();
  console.log(`  TeleporterMessenger ${teleporter} (icm-contracts ${ICM_VERSION})`);
  console.log(`  DPO2U L1 blockchain ID ${l1Id}\n  C-Chain blockchain ID  ${cId}`);

  step("2. Gate on the L1 (Midnight verifier precompile), receiver on the C-Chain");
  const vkPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "gatev0-")), "vk.bin");
  execFileSync(prover, [srs, "vk", vkPath]);
  const vk = fs.readFileSync(vkPath);
  const vkHash = ethers.keccak256(vk);
  if (!(await verifier.isRegistered(vkHash))) await (await (verifier.connect(deployer) as any).registerVerifyingKey(vk)).wait();
  const gate = (await (await ethers.getContractFactory("DPO2UL1ComplianceGate", deployer)).deploy(TX_ALLOW_LIST, VERIFIER, safe.address)) as any;
  await gate.waitForDeployment();
  const gateAddr = await gate.getAddress();
  await (await (allow.connect(safe) as any).setManager(gateAddr)).wait();
  const policyHash = ethers.id("dpo2u.l1.local-test-policy/v0");
  const providerId = ethers.id("dpo2u.l1.local-test-provider");
  const listRoot = ethers.id("dpo2u.l1.local-test-list-root");
  const now = BigInt((await l1.getBlock("latest"))!.timestamp);
  await (await gate.connect(safe).setPolicy(policyHash, vkHash, 3600, true)).wait();
  await (await gate.connect(safe).setProvider(providerId, listRoot, now - 3600n, true)).wait();
  const Receiver = await ethers.getContractFactory("DPO2UL1VerdictReceiver");
  const receiver = (await new ethers.ContractFactory(Receiver.interface, Receiver.bytecode, cDeployer).deploy(teleporter, l1Id, gateAddr, await cDeployer.getAddress())) as any;
  await receiver.waitForDeployment();
  const receiverAddr = await receiver.getAddress();
  await (await gate.connect(safe).setTeleporter(teleporter)).wait();
  await (await gate.connect(safe).addDestination(cId, receiverAddr, 300_000)).wait();
  console.log(`  gate (L1) ${gateAddr}\n  receiver (C-Chain) ${receiverAddr}`);

  step("3. Admission on the L1 is sent over ICM and mirrored on the C-Chain");
  const pi = [1n, ...limbs(policyHash), ...limbs(listRoot), ...limbs(providerId), now - 60n, now + 7200n,
    BigInt(subject.address), net.chainId, BigInt(gateAddr), BigInt(Date.now()), ...limbs(ethers.id("dpo2u.travel-rule-verdict/1:icm-demo"))];
  const proof = execFileSync(prover, [srs, "prove", ...pi.map((v) => "0x" + v.toString(16))]).toString();
  console.log(`  C-Chain before: isAdmitted(${subject.address}) = ${await receiver.isAdmitted(subject.address)}`);
  const admitRc = await (await gate.connect(deployer).admit(proof, pi)).wait();
  console.log(`  L1 admit tx ${admitRc!.hash}, gas ${admitRc!.gasUsed} (proof check + AllowList + ICM send)`);
  console.log("  " + relay(admitRc!.hash, teleporter));
  const st = await receiver.statusOf(subject.address);
  console.log(`  C-Chain after:  isAdmitted = ${await receiver.isAdmitted(subject.address)}; seq ${st.seq}, expiresAt ${st.expiresAt}, policyHash ${st.policyHash === policyHash ? "matches" : "DIFFERS"}`);

  step("4. The same signed message cannot be delivered twice");
  try {
    relay(admitRc!.hash, teleporter);
    throw new Error("replayed ICM message was accepted");
  } catch (e: any) {
    if (String(e.message).includes("was accepted")) throw e;
    console.log("  refused as expected (Teleporter: message already delivered)");
  }

  step("5. Safe revokes on the L1: the DROP reaches the C-Chain");
  const revokeRc = await (await gate.connect(safe).revoke(subject.address, ethers.id("local-test-revocation"))).wait();
  console.log(`  L1 revoke tx ${revokeRc!.hash}`);
  console.log("  " + relay(revokeRc!.hash, teleporter));
  console.log(`  C-Chain: isAdmitted = ${await receiver.isAdmitted(subject.address)}; seq ${(await receiver.statusOf(subject.address)).seq}`);

  console.log("\nA4 local ICM end to end: OK");
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});

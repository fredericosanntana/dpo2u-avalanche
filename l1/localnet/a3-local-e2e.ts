/**
 * Phase A3, local network: the A1 ComplianceGate on a running DPO2U L1 (AvalancheGo + DPO2U VM),
 * admitting a wallet with a genuine Midnight proof checked by the MidnightVerifier precompile.
 *
 *   cd l1/precompile && ./build-ffi.sh && go build -o build/plugins/$(go run ./localnet vmid) ./plugin
 *   AVALANCHEGO_PATH=... go run ./localnet start      # writes build/localnet-state/rpc-url
 *   DPO2U_L1_RPC=$(cat l1/precompile/build/localnet-state/rpc-url) MIDNIGHT_SRS=.../bls_midnight_2p14 \
 *     npx hardhat run l1/localnet/a3-local-e2e.ts --network dpo2uLocal
 *
 * The proof comes from `prove-gate-v0`, a TEST circuit with the gate's 15 public inputs that only
 * constrains pass == 1. It stands in for TravelRuleGate `evaluateTransfer` until that proof arrives.
 */
import { ethers } from "hardhat";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const TX_ALLOW_LIST = "0x0200000000000000000000000000000000000002";
const VERIFIER = "0x03000000000000000000000000000000000000d2";
const ffi = path.join(__dirname, "..", "precompile", "midnight-verifier-ffi");
const prover = path.join(ffi, "target", "release", "prove-gate-v0");
const srs = process.env.MIDNIGHT_SRS!;

const verifierAbi = [
  "function registerVerifyingKey(bytes vk) returns (bytes32)",
  "function isRegistered(bytes32 vkHash) view returns (bool)",
  "function verify(bytes32 vkHash, bytes proof, uint256[] publicInputs) view returns (bool)",
];
const allowListAbi = [
  "function setManager(address addr)",
  "function readAllowList(address addr) view returns (uint256)",
];

const limbs = (h: string): [bigint, bigint] => {
  const v = BigInt(h);
  return [v >> 128n, v & ((1n << 128n) - 1n)];
};

function step(name: string) {
  console.log(`\n== ${name}`);
}

async function expectRevert(p: Promise<unknown>, reason: string, iface?: any, errorName?: string) {
  try {
    await p;
  } catch (e: any) {
    let msg = String(e?.shortMessage ?? e?.message ?? e);
    const data = e?.data ?? e?.info?.error?.data;
    const parsed = iface && data ? iface.parseError(data) : null;
    if (parsed) msg = parsed.name;
    if (errorName && parsed?.name !== errorName) throw new Error(`${reason}: expected ${errorName}, got ${msg}`);
    console.log(`  refused as expected (${reason}): ${msg.slice(0, 120)}`);
    return;
  }
  throw new Error(`expected a revert: ${reason}`);
}

async function main() {
  if (!srs || !fs.existsSync(srs)) throw new Error("set MIDNIGHT_SRS to bls_midnight_2p14");
  const [deployer, safe, relayer, subject] = await ethers.getSigners();
  const net = await ethers.provider.getNetwork();
  console.log(`chain ${net.chainId}; deployer ${deployer.address}; safe ${safe.address}; subject ${subject.address}`);

  const allow = new ethers.Contract(TX_ALLOW_LIST, allowListAbi, ethers.provider);
  const verifier = new ethers.Contract(VERIFIER, verifierAbi, ethers.provider);

  step("1. Transaction AllowList blocks an unknown wallet");
  // Fund the subject (receiving needs no role), then check it cannot send.
  await (await deployer.sendTransaction({ to: subject.address, value: ethers.parseEther("1") })).wait();
  console.log(`  subject role: ${await allow.readAllowList(subject.address)}`);
  await expectRevert(subject.sendTransaction({ to: deployer.address, value: 1n }), "subject not on the AllowList");

  step("2. Register the circuit's verifying key in the MidnightVerifier precompile");
  const vkPath = path.join(fs.mkdtempSync(path.join(require("node:os").tmpdir(), "gatev0-")), "vk.bin");
  execFileSync(prover, [srs, "vk", vkPath]);
  const vk = fs.readFileSync(vkPath);
  const vkHash = ethers.keccak256(vk);
  if (!(await verifier.isRegistered(vkHash))) {
    const r = await (await verifier.connect(deployer).getFunction("registerVerifyingKey")(vk)).wait();
    console.log(`  registered ${vkHash} (${vk.length} B), gas ${r!.gasUsed}`);
  }

  step("3. Deploy the ComplianceGate and make it Manager of the AllowList (Safe)");
  const Gate = await ethers.getContractFactory("DPO2UL1ComplianceGate", deployer);
  const gate = await Gate.deploy(TX_ALLOW_LIST, VERIFIER, safe.address);
  await gate.waitForDeployment();
  const gateAddr = await gate.getAddress();
  console.log(`  gate ${gateAddr}`);
  await (await (allow.connect(safe) as any).setManager(gateAddr)).wait();
  console.log(`  gate role: ${await allow.readAllowList(gateAddr)} (3 = Manager)`);

  const policyHash = ethers.id("dpo2u.l1.local-test-policy/v0");
  const providerId = ethers.id("dpo2u.l1.local-test-provider");
  const listRoot = ethers.id("dpo2u.l1.local-test-list-root");
  const block = await ethers.provider.getBlock("latest");
  const now = BigInt(block!.timestamp);
  await (await (gate.connect(safe) as any).setPolicy(policyHash, vkHash, 3600, true)).wait();
  await (await (gate.connect(safe) as any).setProvider(providerId, listRoot, now - 3600n, true)).wait();

  const digest = ethers.id("dpo2u.travel-rule-verdict/1:local-test");
  const pi = (nonce: bigint) => [
    1n,
    ...limbs(policyHash),
    ...limbs(listRoot),
    ...limbs(providerId),
    now - 60n, // issued_at
    now + 7200n, // valid_until
    BigInt(subject.address),
    net.chainId,
    BigInt(gateAddr),
    nonce,
    ...limbs(digest),
  ];
  const prove = (x: bigint[]) => execFileSync(prover, [srs, "prove", ...x.map((v) => "0x" + v.toString(16))]).toString();

  step("4. Relayer submits the Midnight proof; the precompile checks it on chain");
  const pis = pi(1n);
  const proof = prove(pis);
  console.log(`  precompile verify (eth_call): ${await verifier.verify(vkHash, proof, pis)}`);
  const bad = proof.slice(0, 200) + (proof[200] === "0" ? "1" : "0") + proof.slice(201);
  await expectRevert((gate.connect(relayer) as any).admit.staticCall(bad, pis), "tampered proof", gate.interface, "InvalidProof");
  const rc = await (await (gate.connect(relayer) as any).admit(proof, pis)).wait();
  console.log(`  admit tx ${rc!.hash}, gas ${rc!.gasUsed}`);
  console.log(`  isAdmitted: ${await gate.isAdmitted(subject.address)}; subject role: ${await allow.readAllowList(subject.address)} (1 = Enabled)`);
  await expectRevert((gate.connect(relayer) as any).admit.staticCall(proof, pis), "same nonce replayed", gate.interface, "NonceUsed");
  const otherChain = pi(2n);
  otherChain[10] = 43113n; // a proof made for Fuji is refused here
  await expectRevert((gate.connect(relayer) as any).admit.staticCall(prove(otherChain), otherChain), "proof bound to another chain", gate.interface, "WrongChain");

  step("5. The admitted wallet can now transact on the L1");
  const t = await (await subject.sendTransaction({ to: deployer.address, value: 1n })).wait();
  console.log(`  subject tx ${t!.hash} status ${t!.status}`);

  step("6. Safe revokes: the VM blocks the wallet again");
  await (await (gate.connect(safe) as any).revoke(subject.address, ethers.id("local-test-revocation"))).wait();
  console.log(`  subject role: ${await allow.readAllowList(subject.address)}`);
  await expectRevert(subject.sendTransaction({ to: deployer.address, value: 1n }), "revoked wallet");

  console.log("\nA3 local end to end: OK");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

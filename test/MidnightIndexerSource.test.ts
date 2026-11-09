import { expect } from "chai";
import { IndexerSealSource, GraphQLIndexerTransport, type ContractActionRow, type IndexerTransport, type DecodedSeal } from "../src/midnight-indexer-source";

const H = (n: number) => "0x" + n.toString(16).padStart(64, "0");
const seal = (n: number, verdict: 0 | 1 | 2 = 1): DecodedSeal => ({ evidenceHash: H(n), midnightUseCaseId: H(100), verdict, metadataHash: H(200 + n) });

// Offline: a fake indexer whose "state" is the JSON list of seals after each action.
function fake(tip: number, actions: { kind: string; entryPoint?: string; h: number; tx: number; seals: DecodedSeal[] }[]): IndexerTransport {
  return {
    tipHeight: async () => tip,
    actionsFrom: async (_a, from) =>
      actions.filter((a) => a.h >= from).map<ContractActionRow>((a) => ({ kind: a.kind, entryPoint: a.entryPoint, stateHex: Buffer.from(JSON.stringify(a.seals)).toString("hex"), txHash: H(a.tx).slice(2), blockHeight: a.h })),
  };
}
const decode = (stateHex: string) => JSON.parse(Buffer.from(stateHex, "hex").toString()) as DecodedSeal[];

describe("IndexerSealSource (offline)", () => {
  const history = [
    { kind: "ContractDeploy", h: 10, tx: 1, seals: [] },
    { kind: "ContractCall", entryPoint: "attestUseCase", h: 12, tx: 2, seals: [seal(1)] },
    { kind: "ContractCall", entryPoint: "getUseCaseVerdict", h: 13, tx: 3, seals: [seal(1)] },
    { kind: "ContractCall", entryPoint: "attestUseCase", h: 20, tx: 4, seals: [seal(1), seal(2, 0)] },
    { kind: "ContractCall", entryPoint: "attestUseCase", h: 28, tx: 5, seals: [seal(1), seal(2, 0), seal(3)] },
  ];

  it("attributes each seal to the attestUseCase call that wrote it and stays finalityLag behind the tip", async () => {
    const src = new IndexerSealSource({ transport: fake(30, history), contractAddress: "ab".repeat(32), decode, deployHeight: 10, finalityLag: 5 });
    const { seals, cursor } = await src.sealsSince(undefined);
    expect(cursor).to.equal("25");
    expect(seals.map((s) => s.evidenceHash)).to.deep.equal([H(1), H(2)]); // seal 3 is at 28 > 25
    expect(seals[0].midnightTx).to.equal(H(2));
    expect(seals[1].midnightTx).to.equal(H(4));
    expect(seals[1].midnightVerdict).to.equal(0);
    expect(seals[0].midnightContract).to.equal("0x" + "ab".repeat(32));
  });

  it("reports nothing twice and picks up the deeper seal on the next pass", async () => {
    const src = new IndexerSealSource({ transport: fake(40, history), contractAddress: "ab".repeat(32), decode, deployHeight: 10, finalityLag: 5 });
    const { seals, cursor } = await src.sealsSince("25");
    expect(seals.map((s) => s.evidenceHash)).to.deep.equal([H(3)]);
    expect(cursor).to.equal("35");
    expect((await src.sealsSince("35")).seals).to.have.length(0);
  });

  it("returns the input cursor untouched when nothing is final yet", async () => {
    const src = new IndexerSealSource({ transport: fake(14, history), contractAddress: "ab".repeat(32), decode, deployHeight: 10, finalityLag: 5 });
    expect(await src.sealsSince("12")).to.deep.equal({ seals: [], cursor: "12" });
  });
});

// Live, read-only, against the real Midnight indexer. Runs only where the Midnight v9 tooling is
// installed (MIDNIGHT_TOOLING_DIR), e.g. on the chairman host.
describe("IndexerSealSource (live Midnight preview, read-only)", function () {
  const dir = process.env.MIDNIGHT_TOOLING_DIR;
  before(function () { if (!dir) this.skip(); });
  this.timeout(120_000);

  it("reads the labelled TEST seal from the v9 ComplianceRegistry", async () => {
    const { loadComplianceRegistryDecoder } = await import("../src/midnight-decoder");
    const fs = await import("node:fs");
    const path = await import("node:path");
    const dep = JSON.parse(fs.readFileSync(path.join(dir!, "deployment-preview-v9.json"), "utf8")).contracts.find((c: any) => c.name === "ComplianceRegistry");
    const src = new IndexerSealSource({
      transport: new GraphQLIndexerTransport({ httpUrl: process.env.MIDNIGHT_INDEXER_HTTP || "https://indexer.preview.midnight.network/api/v4/graphql", wsUrl: process.env.MIDNIGHT_INDEXER_WS || "wss://indexer.preview.midnight.network/api/v4/graphql/ws" }),
      contractAddress: dep.contractAddress,
      decode: await loadComplianceRegistryDecoder(dir!),
      deployHeight: dep.blockHeight,
    });
    const { seals, cursor } = await src.sealsSince(undefined);
    const t = seals.find((s) => s.evidenceHash === "0x5283aa4dee855da90f68d3cf51015e7e29a6bc700a0577709425ca519484c1a2");
    expect(t, "TEST seal present").to.not.equal(undefined);
    expect(t!.midnightTx).to.equal("0x79f53b0beafe807780769ce8cb923f58f3843b8ec7bc7c5a53ca5398d0a63adf");
    expect(t!.midnightVerdict).to.equal(0);
    expect(Buffer.from(t!.midnightUseCaseId.slice(2), "hex").toString("utf8").replace(/\0+$/, "")).to.equal("psav_partner_br_v1");
    expect(Number(cursor)).to.be.greaterThan(dep.blockHeight);
  });
});

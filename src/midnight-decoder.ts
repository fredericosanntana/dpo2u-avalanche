// midnight-decoder.ts — builds a StateDecoder from the Midnight tooling installed on this host.
//
// The decoder needs the compiled ComplianceRegistry (its `ledger()`), `ContractState` from the same
// compact-runtime copy, and `SerializedContractState` from midnight-js-types. They are loaded from
// `toolingDir` (a dpo2u-midnight checkout on the ledger-v9 stack) at runtime, so this repository does
// not depend on the Midnight packages. Native `import()` is kept out of the TypeScript CommonJS
// transform on purpose: those packages are ES modules.
import path from "node:path";
import type { DecodedSeal, StateDecoder } from "./midnight-indexer-source";

const nativeImport = new Function("p", "return import(p)") as (p: string) => Promise<any>;

const hex = (b: Uint8Array) => "0x" + Buffer.from(b).toString("hex");

export async function loadComplianceRegistryDecoder(toolingDir: string, era: "v9" = "v9"): Promise<StateDecoder> {
  const nm = path.join(toolingDir, "node_modules");
  const [types, runtime, contract] = await Promise.all([
    nativeImport(path.join(nm, "@midnight-ntwrk/midnight-js-types/dist/index.js")),
    nativeImport(path.join(nm, "@midnight-ntwrk/compact-runtime/dist/index.js")),
    nativeImport(path.join(toolingDir, "build/ComplianceRegistry/contract/index.js")),
  ]);
  return (stateHex: string): DecodedSeal[] => {
    const bytes = new Uint8Array(Buffer.from(stateHex.replace(/^0x/, ""), "hex"));
    const state = types.SerializedContractState.fromBytes(era, bytes).deserialize({ [era]: runtime.ContractState });
    const led = contract.ledger(state.data);
    const out: DecodedSeal[] = [];
    for (const [k, uc] of led.usecase_ids as Iterable<[Uint8Array, Uint8Array]>) {
      const v = Number(led.usecase_verdicts.lookup(k));
      if (v !== 0 && v !== 1 && v !== 2) continue;
      out.push({ evidenceHash: hex(k), midnightUseCaseId: hex(uc), verdict: v, metadataHash: hex(led.usecase_metadata.lookup(k)) });
    }
    return out;
  };
}

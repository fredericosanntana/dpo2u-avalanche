// Avalanche networks in the DPO2U CAIP vocabulary (same keys as
// DPO2U/packages/pilot-gateway/src/lib/engine5710/caip.ts).
export interface AvalancheNetwork {
  name: "fuji" | "avalanche";
  caip2: string;
  chainId: number;
  /** SLIP-44 of AVAX (CAIP-19 `<caip2>/slip44:9000`). */
  nativeSlip44: number;
  nativeSymbol: "AVAX";
  nativeDecimals: 18;
  defaultRpc: string;
  explorer: string;
}

export const AVALANCHE_NETWORKS: Record<AvalancheNetwork["name"], AvalancheNetwork> = {
  fuji: {
    name: "fuji",
    caip2: "eip155:43113",
    chainId: 43113,
    nativeSlip44: 9000,
    nativeSymbol: "AVAX",
    nativeDecimals: 18,
    defaultRpc: "https://api.avax-test.network/ext/bc/C/rpc",
    explorer: "https://testnet.snowtrace.io",
  },
  avalanche: {
    name: "avalanche",
    caip2: "eip155:43114",
    chainId: 43114,
    nativeSlip44: 9000,
    nativeSymbol: "AVAX",
    nativeDecimals: 18,
    defaultRpc: "https://api.avax.network/ext/bc/C/rpc",
    explorer: "https://snowtrace.io",
  },
};

export function resolveAvalancheNetwork(key: string): AvalancheNetwork {
  const k = key.toLowerCase();
  if (k === "fuji" || k === "avalanche") return AVALANCHE_NETWORKS[k];
  const byCaip = Object.values(AVALANCHE_NETWORKS).find((n) => n.caip2 === k);
  if (byCaip) return byCaip;
  throw new Error(`unsupported Avalanche network: "${key}" (supported: fuji, avalanche, eip155:43113, eip155:43114)`);
}

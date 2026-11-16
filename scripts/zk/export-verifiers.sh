#!/usr/bin/env bash
# Regenerates a Groth16 verifier of the DPO2UTravelRuleGate proof lanes from a FINAL zkey.
#
#   bash scripts/zk/export-verifiers.sh policy     <final.zkey> <circuit.wasm> [dev|ceremony]
#   bash scripts/zk/export-verifiers.sh membership <final.zkey> <circuit.wasm> [dev|ceremony]
#
# Use it when the multi-party ceremony (dpo2u-stellar scripts/zk-ceremony*) produces the final
# zkey for a circuit: it replaces the dev setup in zk/<lane>/, rewrites the verifier contract and
# marks zk/setup.json. The mainnet deploy refuses any lane whose setup is not "ceremony".
# Circuits (public signal order must not change):
#   policy      dpo2u-stellar zk-prover/por/compliance_intent_policy.circom  [policy_pass, policy_commit, context]
#   membership  dpo2u-stellar zk-prover/membership/membership_withdraw.circom [root, nullifierHash, recipient, context]
set -euo pipefail
LANE="${1:?lane: policy|membership}"; ZKEY="${2:?final zkey}"; WASM="${3:?circuit wasm}"; SETUP="${4:-dev}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SNARKJS="$ROOT/node_modules/.bin/snarkjs"
case "$LANE" in
  policy) NAME=DPO2UPolicyGroth16Verifier; WOUT=compliance_intent_policy.wasm; NSIG=3 ;;
  membership) NAME=DPO2UMembershipGroth16Verifier; WOUT=membership_withdraw.wasm; NSIG=4 ;;
  *) echo "unknown lane $LANE"; exit 1 ;;
esac
[ "$SETUP" = dev ] || [ "$SETUP" = ceremony ] || { echo "setup must be dev or ceremony"; exit 1; }
mkdir -p "$ROOT/zk/$LANE"
"$SNARKJS" zkey export verificationkey "$ZKEY" "$ROOT/zk/$LANE/verification_key.json"
n="$(node -e "console.log(require('$ROOT/zk/$LANE/verification_key.json').nPublic)")"
[ "$n" = "$NSIG" ] || { echo "zkey has $n public signals, the $LANE lane needs $NSIG"; exit 1; }
"$SNARKJS" zkey export solidityverifier "$ZKEY" "$ROOT/contracts/verifiers/$NAME.sol"
sed -i "s/contract Groth16Verifier {/contract $NAME {/" "$ROOT/contracts/verifiers/$NAME.sol"
# The zkey is committed only when small (the policy lane); the membership zkey stays out of git.
if [ "$(stat -c %s "$ZKEY")" -lt 5000000 ]; then cp "$ZKEY" "$ROOT/zk/$LANE/${LANE}_final.zkey"; cp "$WASM" "$ROOT/zk/$LANE/$WOUT"; fi
node -e "
const f='$ROOT/zk/setup.json'; const s=require(f);
s['$LANE'] = { ...(s['$LANE']||{}), setup: '$SETUP', zkey_sha256: require('crypto').createHash('sha256').update(require('fs').readFileSync('$ZKEY')).digest('hex'), exported_at: new Date().toISOString() };
require('fs').writeFileSync(f, JSON.stringify(s, null, 2) + '\n');"
echo "$LANE verifier -> contracts/verifiers/$NAME.sol (setup: $SETUP)"

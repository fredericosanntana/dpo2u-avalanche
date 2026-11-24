package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/vms/evm/predicate"
	"github.com/ava-labs/libevm/accounts/abi"
	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/common/hexutil"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"
	"github.com/ava-labs/libevm/ethclient"
)

var (
	warpPrecompile       = common.HexToAddress("0x0200000000000000000000000000000000000005")
	sendWarpTopic        = crypto.Keccak256Hash([]byte("SendWarpMessage(address,bytes32,bytes)"))
	receiveMessageAbi, _ = abi.JSON(strings.NewReader(`[{"type":"function","name":"receiveCrossChainMessage","inputs":[{"name":"messageIndex","type":"uint32"},{"name":"relayerRewardAddress","type":"address"}],"outputs":[]}]`))
)

// relay delivers every ICM (Warp) message sent in an L1 transaction to the TeleporterMessenger on
// the destination chain: it asks the L1 node for the validators' aggregate BLS signature, then
// submits receiveCrossChainMessage with the signed message as the Warp predicate (access list).
// Plays the role of icm-relayer for the local demo; it is trusted for liveness only, since the
// destination's Warp precompile checks the signature against the L1 validator set on the P-Chain.
func relay(ctx context.Context, srcRPC, dstRPC, txHash, teleporter, relayerKeyHex string) error {
	src, err := ethclient.DialContext(ctx, srcRPC)
	if err != nil {
		return err
	}
	dst, err := ethclient.DialContext(ctx, dstRPC)
	if err != nil {
		return err
	}
	key, err := crypto.HexToECDSA(strings.TrimPrefix(relayerKeyHex, "0x"))
	if err != nil {
		return err
	}
	r, err := src.TransactionReceipt(ctx, common.HexToHash(txHash))
	if err != nil {
		return fmt.Errorf("source receipt: %w", err)
	}
	to := common.HexToAddress(teleporter)
	n := 0
	for _, l := range r.Logs {
		if l.Address != warpPrecompile || len(l.Topics) < 3 || l.Topics[0] != sendWarpTopic {
			continue
		}
		msgID := ids.ID(l.Topics[2])
		var signed hexutil.Bytes
		// The L1 node collects the BLS signatures of the L1 validators (67% quorum) over p2p.
		if err := src.Client().CallContext(ctx, &signed, "warp_getMessageAggregateSignature", msgID, uint64(67), ""); err != nil {
			return fmt.Errorf("aggregate signature for %s: %w", msgID, err)
		}
		data, err := receiveMessageAbi.Pack("receiveCrossChainMessage", uint32(0), crypto.PubkeyToAddress(key.PublicKey))
		if err != nil {
			return err
		}
		al := types.AccessList{{Address: warpPrecompile, StorageKeys: predicate.New(signed)}}
		rc, err := send(ctx, dst, key, &to, nil, data, al)
		if err != nil {
			return fmt.Errorf("deliver %s: %w", msgID, err)
		}
		if rc.Status != types.ReceiptStatusSuccessful {
			return fmt.Errorf("deliver %s: tx %s reverted", msgID, rc.TxHash)
		}
		fmt.Printf("relayed %s (signed message %d B) -> tx %s gas %d\n", msgID, len(signed), rc.TxHash, rc.GasUsed)
		n++
	}
	if n == 0 {
		fmt.Fprintln(os.Stderr, "no Warp message in that transaction")
	}
	return nil
}

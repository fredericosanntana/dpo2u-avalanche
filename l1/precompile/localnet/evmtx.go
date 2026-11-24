package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"time"

	ethereum "github.com/ava-labs/libevm"
	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"
	"github.com/ava-labs/libevm/ethclient"
)

// send signs and sends a dynamic-fee tx and waits for its receipt.
func send(ctx context.Context, c *ethclient.Client, key *ecdsa.PrivateKey, to *common.Address, value *big.Int, data []byte, al types.AccessList) (*types.Receipt, error) {
	from := crypto.PubkeyToAddress(key.PublicKey)
	chainID, err := c.ChainID(ctx)
	if err != nil {
		return nil, err
	}
	nonce, err := c.PendingNonceAt(ctx, from)
	if err != nil {
		return nil, err
	}
	tip, err := c.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, err
	}
	price, err := c.SuggestGasPrice(ctx)
	if err != nil {
		return nil, err
	}
	feeCap := new(big.Int).Add(new(big.Int).Mul(price, big.NewInt(2)), tip)
	gas, err := c.EstimateGas(ctx, ethereum.CallMsg{From: from, To: to, Value: value, Data: data, AccessList: al})
	if err != nil {
		return nil, fmt.Errorf("estimate gas: %w", err)
	}
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID: chainID, Nonce: nonce, GasTipCap: tip, GasFeeCap: feeCap,
		Gas: gas + gas/5, To: to, Value: value, Data: data, AccessList: al,
	})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), key)
	if err != nil {
		return nil, err
	}
	if err := c.SendTransaction(ctx, signed); err != nil {
		return nil, err
	}
	for {
		r, err := c.TransactionReceipt(ctx, signed.Hash())
		if err == nil {
			return r, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}

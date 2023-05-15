package itest

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/lightninglabs/taro/taprpc"
	"github.com/lightninglabs/taro/taprpc/mintrpc"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

// testRoundTripSend tests that we can properly send the full value of a
// normal asset.
func testRoundTripSend(t *harnessTest) {
	// First, we'll make a normal assets with enough units to allow us to
	// send it around a few times.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tarodHarnessParams) {
			params.startupSyncNode = t.tarod
			params.startupSyncNumAssets = len(rpcAssets)
		},
	)
	defer func() {
		require.NoError(t.t, secondTarod.stop(true))
	}()

	// We'll send half of the minted units to Bob, and then have Bob return
	// half of the units he received.
	fullAmt := rpcAssets[0].Amount
	bobAmt := fullAmt / 2
	aliceAmt := bobAmt / 2

	hashLockPreimage := []byte("hash locks are cool")
	scriptLeaf := test.ScriptHashLock(t.t, hashLockPreimage)
	sibling := commitment.NewPreimageFromLeaf(scriptLeaf)
	siblingBytes, _, err := commitment.MaybeEncodeTapscriptPreimage(sibling)
	require.NoError(t.t, err)

	// First, we'll send half of the units to Bob.
	bobAddr, err := secondTarod.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:          genInfo.AssetId,
		Amt:              bobAmt,
		TapscriptSibling: siblingBytes,
	})
	require.NoError(t.t, err)

	assertAddrCreated(t.t, secondTarod, rpcAssets[0], bobAddr)
	sendResp := sendAssetsToAddr(t, t.tarod, bobAddr)
	sendRespJSON, err := formatProtoJSON(sendResp)
	require.NoError(t.t, err)
	t.Logf("Got response from sending assets: %v", sendRespJSON)

	confirmAndAssertOutboundTransfer(
		t, t.tarod, sendResp, genInfo.AssetId,
		[]uint64{bobAmt, bobAmt}, 0, 1,
	)
	_ = sendProof(t, t.tarod, secondTarod, bobAddr.ScriptKey, genInfo)

	// Now, Alice will request half of the assets she sent to Bob.
	aliceAddr, err := t.tarod.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:          genInfo.AssetId,
		Amt:              aliceAmt,
		TapscriptSibling: siblingBytes,
	})
	require.NoError(t.t, err)

	assertAddrCreated(t.t, t.tarod, rpcAssets[0], aliceAddr)
	sendResp = sendAssetsToAddr(t, secondTarod, aliceAddr)
	sendRespJSON, err = formatProtoJSON(sendResp)
	require.NoError(t.t, err)
	t.Logf("Got response from sending assets: %v", sendRespJSON)

	confirmAndAssertOutboundTransfer(
		t, secondTarod, sendResp, genInfo.AssetId,
		[]uint64{aliceAmt, aliceAmt}, 0, 1,
	)
	_ = sendProof(t, secondTarod, t.tarod, aliceAddr.ScriptKey, genInfo)

	// Give both nodes some time to process the final transfer.
	time.Sleep(time.Second * 1)

	// Check the final state of both nodes. Each node should list
	// one transfer, and Alice should have 3/4 of the total units.
	err = wait.NoError(func() error {
		assertTransfer(t.t, t.tarod, 0, 1, []uint64{bobAmt, bobAmt})
		assertBalanceByID(
			t.t, t.tarod, genInfo.AssetId, bobAmt+aliceAmt,
		)

		assertTransfer(
			t.t, secondTarod, 0, 1, []uint64{aliceAmt, aliceAmt},
		)
		assertBalanceByID(t.t, secondTarod, genInfo.AssetId, aliceAmt)

		return nil
	}, defaultTimeout/2)
	require.NoError(t.t, err)

	// As a final test we make sure we can actually sweep the funds in the
	// output with the tapscript sibling with just the hash preimage,
	// burning the assets in the process.
	transferResp, err := secondTarod.ListTransfers(
		ctxb, &taprpc.ListTransfersRequest{},
	)
	require.NoError(t.t, err)

	// We know the change output is always located at index 0, so the
	// recipient's output is the second one.
	bobToAliceOutput := transferResp.Transfers[0].Outputs[1]
	bobToAliceAnchor := bobToAliceOutput.Anchor
	outpoint, err := parseOutPoint(bobToAliceAnchor.Outpoint)
	require.NoError(t.t, err)

	internalKey, err := btcec.ParsePubKey(bobToAliceAnchor.InternalKey)
	require.NoError(t.t, err)

	// Because we know the internal key and the script we want to spend, we
	// can now create the tapscript struct that's used for assembling the
	// control block and fee estimation.
	tapscript := input.TapscriptPartialReveal(
		internalKey, scriptLeaf, bobToAliceAnchor.TaroRoot,
	)

	// Spend the output again, this time back to a p2wkh address.
	_, p2wkhPkScript := newAddrWithScript(
		t.lndHarness, t.lndHarness.Alice,
		lnrpc.AddressType_WITNESS_PUBKEY_HASH,
	)

	// Create fee estimation for a p2tr input and p2wkh output.
	feeRate := chainfee.FeePerKwFloor
	estimator := input.TxWeightEstimator{}

	// The witness will consist of the preimage and the script plus the
	// control block. The control block will be weighted by the passed
	// tapscript, so we only need to add the length of the other two items.
	estimator.AddTapscriptInput(
		len(hashLockPreimage)+len(scriptLeaf.Script)+1, tapscript,
	)
	estimator.AddP2WKHOutput()
	estimatedWeight := int64(estimator.Weight())
	requiredFee := feeRate.FeeForWeight(estimatedWeight)

	tx := wire.NewMsgTx(2)
	tx.TxIn = []*wire.TxIn{{
		PreviousOutPoint: *outpoint,
	}}
	value := bobToAliceAnchor.Value - int64(requiredFee)
	tx.TxOut = []*wire.TxOut{{
		PkScript: p2wkhPkScript,
		Value:    value,
	}}

	// We can now assemble the witness stack.
	controlBlockBytes, err := tapscript.ControlBlock.ToBytes()
	require.NoError(t.t, err)

	tx.TxIn[0].Witness = wire.TxWitness{
		hashLockPreimage, scriptLeaf.Script, controlBlockBytes,
	}

	// We can now broadcast the transaction and wait for it to be mined.
	// Publish the sweep transaction and then mine it as well.
	var buf bytes.Buffer
	err = tx.Serialize(&buf)
	require.NoError(t.t, err)
	t.lndHarness.Alice.RPC.PublishTransaction(&walletrpc.Transaction{
		TxHex: buf.Bytes(),
	})

	// Mine one block which should contain the sweep transaction.
	block := t.lndHarness.MineBlocksAndAssertNumTxes(1, 1)[0]
	sweepTxHash := tx.TxHash()
	t.lndHarness.Miner.AssertTxInBlock(block, &sweepTxHash)

	unspent := t.lndHarness.Alice.RPC.ListUnspent(
		&walletrpc.ListUnspentRequest{
			MinConfs: 1,
		},
	)
	require.NotEmpty(t.t, unspent.Utxos)
	found := false
	for _, utxo := range unspent.Utxos {
		if utxo.PkScript == hex.EncodeToString(p2wkhPkScript) {
			require.Equal(t.t, value, utxo.AmountSat)
			found = true
			break
		}
	}
	require.True(t.t, found)
}

// newAddrWithScript returns a new bitcoin address and its pkScript.
func newAddrWithScript(ht *lntest.HarnessTest, node *node.HarnessNode,
	addrType lnrpc.AddressType) (btcutil.Address, []byte) {

	p2wkhResp := node.RPC.NewAddress(&lnrpc.NewAddressRequest{
		Type: addrType,
	})
	p2wkhAddr, err := btcutil.DecodeAddress(
		p2wkhResp.Address, harnessNetParams,
	)
	require.NoError(ht, err)

	p2wkhPkScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(ht, err)

	return p2wkhAddr, p2wkhPkScript
}

func parseOutPoint(s string) (*wire.OutPoint, error) {
	split := strings.Split(s, ":")
	if len(split) != 2 {
		return nil, fmt.Errorf("expecting outpoint to be in format of: " +
			"txid:index")
	}

	index, err := strconv.ParseInt(split[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("unable to decode output index: %v", err)
	}

	txid, err := chainhash.NewHashFromStr(split[0])
	if err != nil {
		return nil, fmt.Errorf("unable to parse hex string: %v", err)
	}

	return &wire.OutPoint{
		Hash:  *txid,
		Index: uint32(index),
	}, nil
}

package tapchannel

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
)

var (
	ErrMissingInputs = fmt.Errorf("no inputs provided")

	ErrMissingAllocations = fmt.Errorf("no allocations provided")

	ErrInputOutputSumMismatch = fmt.Errorf("input and output sum mismatch")
)

type Allocation struct {
	// OutputIndex is the output index of the on-chain transaction which
	// the asset allocation is meant for.
	OutputIndex uint32

	// InternalKey is the internal key used for the on-chain transaction
	// output.
	InternalKey *btcec.PublicKey

	// TapscriptSibling is the optional Tapscript preimage that should be
	// used for BTC level output of the asset allocation.
	TapscriptSibling *commitment.TapscriptPreimage

	// ScriptKey is the Taproot tweaked key encoding the different spend
	// conditions possible for the asset allocation.
	ScriptKey asset.ScriptKey

	// Amount is the amount of units for the asset allocation.
	Amount uint64

	// AssetVersion is the version that the asset allocation should use.
	AssetVersion asset.Version

	// BtcAmount is the amount of BTC that should be sent to the output
	// address of the anchor transaction.
	BtcAmount btcutil.Amount
}

type piece struct {
	// assetID is the ID of the asset that is being distributed.
	assetID asset.ID

	sum uint64

	proofs []*proof.Proof

	packet *tappsbt.VPacket
}

func DistributeCoins(ctx context.Context, inputs []*proof.Proof,
	allocations []Allocation, xID, yID, zID asset.ID,
	chainParams *address.ChainParams) ([]*tappsbt.VPacket, error) {

	if len(inputs) == 0 {
		return nil, ErrMissingInputs
	}

	if len(allocations) == 0 {
		return nil, ErrMissingAllocations
	}

	var inputSum uint64
	for _, input := range inputs {
		inputSum += input.Asset.Amount
	}

	var outputSum uint64
	for _, allocation := range allocations {
		outputSum += allocation.Amount
	}

	if inputSum != outputSum {
		return nil, ErrInputOutputSumMismatch
	}

	assetIDs := fn.Map(inputs, func(input *proof.Proof) asset.ID {
		return input.Asset.ID()
	})
	uniqueAssetIDs := fn.NewSet(assetIDs...).ToSlice()
	pieces := make([]*piece, len(uniqueAssetIDs))
	for i, assetID := range uniqueAssetIDs {
		proofsByID := fn.Filter(inputs, func(i *proof.Proof) bool {
			return i.Asset.ID() == assetID
		})
		sumByID := fn.Reduce(
			proofsByID, func(sum uint64, i *proof.Proof) uint64 {
				return sum + i.Asset.Amount
			},
		)

		pkt, err := tappsbt.FromProofs(proofsByID, chainParams)
		if err != nil {
			return nil, err
		}

		pieces[i] = &piece{
			assetID: assetID,
			sum:     sumByID,
			proofs:  proofsByID,
			packet:  pkt,
		}
	}

	// Make sure the pieces are in a stable and reproducible order before we
	// start the distribution.
	sortPiecesWithProofs(pieces)

	// TODO(guggero): finish implementing the algorithm below.
	// algorithm for splitting commitment TX balance:
	//- when multiple asset IDs (should apply to single ID as well, just easier)
	//  - always multiple vPSBTs, one per asset ID
	//  - look at available asset units ordered lexicographically by asset ID, amount, script_key
	//  - initiator always assigned first, then HTLCs ordered, then responder
	//  - don't need to be efficient with number of outputs
	//  - don't need to care about chain-fees or dust
	//  - with no HTLCs, that should result in only one split at max
	//  - examples with 400 units X, 400 units Y in:
	//    - distribution 100 A, 100 H, 600 B: X is split into A+H+B (100, 100, 200), Y goes to B fully
	//    - distribution 400 A, 400 B: X goes to A fully, Y goes to B fully
	//    - distribution 400 A, 50 H, 350 B: X goes to A fully, Y goes to H+B (50, 350)
	//    - distribution 350 A, 50 H, 50 I, 350 B: X goes to A+H (350, 50), Y goes to I+B (50+350)
	//  - examples with 200 units X, 300 units Y, 300 units Z:
	//    - distribution 100 A, 100 H, 600 B: X is split into A+H (100, 100), Y goes to B fully, Z goes to B fully
	//    - distribution 400 A, 400 B: X goes to A fully, Y is split into A+B (200, 100), Z goes to B fully
	//    - distribution 400 A, 50 H, 350 B: X goes to A fully, Y goes to A+H+B (200, 50, 50), Z goes to B fully
	//    - distribution 350 A, 50 H, 50 I, 350 B: X goes to A fully, Y goes to A+H+I+B (150, 50, 50, 50), Z goes to B fully

	// ---------------------------------------------------------------------
	// Below this line is fake code just to make the itest work, but it
	// demonstrates what the algorithm above should do.
	// ---------------------------------------------------------------------

	// This is for the itest, we know exactly how to distribute for this
	// PoC scenario. Remove this once the algorithm above is implemented.
	getPiece := func(assetID asset.ID) *piece {
		p, _ := fn.First(pieces, func(p *piece) bool {
			return p.assetID == assetID
		})
		return p
	}

	pieceX := getPiece(xID)
	pieceY := getPiece(yID)
	pieceZ := getPiece(zID)

	if len(allocations) == 3 {
		err := fakeFundingAllocations(
			ctx, allocations, pieceX, pieceY, pieceZ,
		)
		if err != nil {
			return nil, err
		}
	} else {
		err := fakeCommitmentAllocations(
			ctx, allocations, pieceX, pieceY, pieceZ,
		)
		if err != nil {
			return nil, err
		}
	}

	packets := fn.Map(pieces, func(p *piece) *tappsbt.VPacket {
		return p.packet
	})
	return packets, nil
}

func fakeFundingAllocations(ctx context.Context, allocations []Allocation,
	pieceX, pieceY, pieceZ *piece) error {

	// X is split into channel (idx 0) and change A (idx 2).
	pieceX.packet.Outputs = []*tappsbt.VOutput{
		{
			Amount:                       400,
			ScriptKey:                    allocations[0].ScriptKey,
			AnchorOutputIndex:            0,
			Type:                         tappsbt.TypeSimple,
			AnchorOutputInternalKey:      allocations[0].InternalKey,
			Interactive:                  true,
			AssetVersion:                 allocations[0].AssetVersion,
			AnchorOutputTapscriptSibling: allocations[0].TapscriptSibling,
		},
		{
			Amount:                       300,
			ScriptKey:                    allocations[2].ScriptKey,
			AnchorOutputIndex:            2,
			Type:                         tappsbt.TypeSplitRoot,
			AnchorOutputInternalKey:      allocations[2].InternalKey,
			Interactive:                  true,
			AssetVersion:                 allocations[2].AssetVersion,
			AnchorOutputTapscriptSibling: allocations[2].TapscriptSibling,
		},
	}
	err := tapsend.PrepareOutputAssets(ctx, pieceX.packet)
	if err != nil {
		return fmt.Errorf("error preparing output assets: %w", err)
	}

	// Y is used up fully in the channel (idx 0).
	pieceY.packet.Outputs = []*tappsbt.VOutput{
		{
			Amount:                       400,
			ScriptKey:                    allocations[0].ScriptKey,
			AnchorOutputIndex:            0,
			Type:                         tappsbt.TypeSimple,
			AnchorOutputInternalKey:      allocations[0].InternalKey,
			Interactive:                  true,
			AssetVersion:                 allocations[0].AssetVersion,
			AnchorOutputTapscriptSibling: allocations[0].TapscriptSibling,
		},
	}
	err = tapsend.PrepareOutputAssets(ctx, pieceY.packet)
	if err != nil {
		return fmt.Errorf("error preparing output assets: %w", err)
	}

	// Z is split into channel (idx 0) and change B (idx 1).
	pieceZ.packet.Outputs = []*tappsbt.VOutput{
		{
			Amount:                       100,
			ScriptKey:                    allocations[0].ScriptKey,
			AnchorOutputIndex:            0,
			Type:                         tappsbt.TypeSimple,
			AnchorOutputInternalKey:      allocations[0].InternalKey,
			Interactive:                  true,
			AssetVersion:                 allocations[0].AssetVersion,
			AnchorOutputTapscriptSibling: allocations[0].TapscriptSibling,
		},
		{
			Amount:                       400,
			ScriptKey:                    allocations[1].ScriptKey,
			AnchorOutputIndex:            1,
			Type:                         tappsbt.TypeSplitRoot,
			AnchorOutputInternalKey:      allocations[1].InternalKey,
			Interactive:                  true,
			AssetVersion:                 allocations[1].AssetVersion,
			AnchorOutputTapscriptSibling: allocations[1].TapscriptSibling,
		},
	}
	err = tapsend.PrepareOutputAssets(ctx, pieceZ.packet)
	if err != nil {
		return fmt.Errorf("error preparing output assets: %w", err)
	}

	return nil
}

func fakeCommitmentAllocations(ctx context.Context, allocations []Allocation,
	pieceX, pieceY, pieceZ *piece) error {

	// X sent fully to A (idx 1).
	pieceX.packet.Outputs = []*tappsbt.VOutput{
		{
			Amount:                       400,
			ScriptKey:                    allocations[1].ScriptKey,
			AnchorOutputIndex:            1,
			Type:                         tappsbt.TypeSimple,
			AnchorOutputInternalKey:      allocations[1].InternalKey,
			Interactive:                  true,
			AssetVersion:                 allocations[1].AssetVersion,
			AnchorOutputTapscriptSibling: allocations[1].TapscriptSibling,
		},
	}
	err := tapsend.PrepareOutputAssets(ctx, pieceX.packet)
	if err != nil {
		return fmt.Errorf("error preparing output assets: %w", err)
	}

	// Y is sent fully to B (idx 0).
	pieceY.packet.Outputs = []*tappsbt.VOutput{
		{
			Amount:                       400,
			ScriptKey:                    allocations[0].ScriptKey,
			AnchorOutputIndex:            0,
			Type:                         tappsbt.TypeSimple,
			AnchorOutputInternalKey:      allocations[0].InternalKey,
			Interactive:                  true,
			AssetVersion:                 allocations[0].AssetVersion,
			AnchorOutputTapscriptSibling: allocations[0].TapscriptSibling,
		},
	}
	err = tapsend.PrepareOutputAssets(ctx, pieceY.packet)
	if err != nil {
		return fmt.Errorf("error preparing output assets: %w", err)
	}

	// Z is sent fully to B (idx 0).
	pieceZ.packet.Outputs = []*tappsbt.VOutput{
		{
			Amount:                       100,
			ScriptKey:                    allocations[0].ScriptKey,
			AnchorOutputIndex:            0,
			Type:                         tappsbt.TypeSimple,
			AnchorOutputInternalKey:      allocations[0].InternalKey,
			Interactive:                  true,
			AssetVersion:                 allocations[0].AssetVersion,
			AnchorOutputTapscriptSibling: allocations[0].TapscriptSibling,
		},
	}
	err = tapsend.PrepareOutputAssets(ctx, pieceZ.packet)
	if err != nil {
		return fmt.Errorf("error preparing output assets: %w", err)
	}

	return nil
}

// sortPieces sorts the given pieces by asset ID and the contained proofs by
// amount and then script key.
func sortPiecesWithProofs(pieces []*piece) {
	// Sort pieces by asset ID.
	sort.Slice(pieces, func(i, j int) bool {
		return bytes.Compare(
			pieces[i].assetID[:], pieces[j].assetID[:],
		) < 0
	})

	// Now sort all the proofs within each piece by amount and then script
	// key. This will give us a stable order for all asset UTXOs.
	for idx := range pieces {
		sort.Slice(pieces[idx].proofs, func(i, j int) bool {
			assetI := pieces[idx].proofs[i].Asset
			assetJ := pieces[idx].proofs[j].Asset

			// If amounts are equal, sort by script key.
			if assetI.Amount == assetJ.Amount {
				keyI := assetI.ScriptKey.PubKey
				keyJ := assetJ.ScriptKey.PubKey
				return bytes.Compare(
					keyI.SerializeCompressed(),
					keyJ.SerializeCompressed(),
				) < 0
			}

			// Otherwise, sort by amount, but in reverse order so
			// that the largest amounts are first.
			return assetI.Amount > assetJ.Amount
		})
	}
}

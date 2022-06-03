package rosettaFilecoinLib

import (
	"bytes"
	"encoding/json"
	"fmt"
	filAddr "github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/filecoin-project/specs-actors/v8/actors/builtin"
	"github.com/filecoin-project/specs-actors/v8/actors/builtin/multisig"
	"github.com/ipfs/go-cid"
	"github.com/zondax/rosetta-filecoin-proxy/rosetta/actors"
)

func (r RosettaConstructionFilecoin) parseParamsMultisigTxV8(unsignedMultisigTx string) (string, error) {
	rawIn := json.RawMessage(unsignedMultisigTx)

	txBytes, err := rawIn.MarshalJSON()
	if err != nil {
		return "", err
	}

	var msg types.Message
	err = json.Unmarshal(txBytes, &msg)
	if err != nil {
		return "", err
	}

	var msigMethod = msg.Method
	var msigParams = msg.Params

	if msg.Method == builtin.MethodsMultisig.Propose {
		// Parse propose to get the inner method call
		reader := bytes.NewReader(msg.Params)
		var proposeParams multisig.ProposeParams
		err = proposeParams.UnmarshalCBOR(reader)
		if err != nil {
			return "", err
		}
		msigMethod = proposeParams.Method
		msigParams = proposeParams.Params
	}

	reader := bytes.NewReader(msigParams)

	switch msigMethod {
	case builtin.MethodSend:
		{
			reader := bytes.NewReader(msg.Params)
			var params multisig.ProposeParams
			err := params.UnmarshalCBOR(reader)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtin.MethodsMultisig.Approve,
		builtin.MethodsMultisig.Cancel:
		{
			var params multisig.TxnIDParams
			err := params.UnmarshalCBOR(reader)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtin.MethodsMultisig.AddSigner:
		{
			var params multisig.AddSignerParams
			err := params.UnmarshalCBOR(reader)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtin.MethodsMultisig.RemoveSigner:
		{
			var params multisig.RemoveSignerParams
			err := params.UnmarshalCBOR(reader)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtin.MethodsMultisig.SwapSigner:
		{
			var params multisig.SwapSignerParams
			err := params.UnmarshalCBOR(reader)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtin.MethodsMultisig.ChangeNumApprovalsThreshold:
		{
			var params multisig.ChangeNumApprovalsThresholdParams
			err := params.UnmarshalCBOR(reader)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtin.MethodsMultisig.LockBalance:
		{
			var params multisig.LockBalanceParams
			err := params.UnmarshalCBOR(reader)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	default:
		return "", fmt.Errorf("unknown method")
	}
}

func (r RosettaConstructionFilecoin) ConstructMultisigPaymentV8(request *MultisigPaymentRequest, destinationActorId cid.Cid) (string, error) {
	if destinationActorId != actors.MultisigActorCodeID {
		return "", fmt.Errorf("this actor id is not supported")
	}

	to, err := filAddr.NewFromString(request.Multisig)
	if err != nil {
		return "", err
	}

	from, err := filAddr.NewFromString(request.From)
	if err != nil {
		return "", err
	}

	gasfeecap, err := types.BigFromString(request.Metadata.GasFeeCap)
	if err != nil {
		return "", err
	}

	gaspremium, err := types.BigFromString(request.Metadata.GasPremium)
	if err != nil {
		return "", err
	}

	gaslimit := request.Metadata.GasLimit

	toParams, err := filAddr.NewFromString(request.Params.To)
	if err != nil {
		return "", err
	}

	valueParams, err := types.BigFromString(request.Params.Quantity)
	if err != nil {
		return "", err
	}

	var methodNum abi.MethodNum
	var serializedParams []byte

	methodNum = builtin.MethodsMultisig.Propose
	params := &multisig.ProposeParams{
		To:     toParams,
		Value:  valueParams,
		Method: builtin.MethodSend,
		Params: make([]byte, 0),
	}

	buf := new(bytes.Buffer)
	err = params.MarshalCBOR(buf)
	if err != nil {
		return "", err
	}
	serializedParams = buf.Bytes()

	value := types.NewInt(0)
	msg := &types.Message{Version: types.MessageVersion,
		To:         to,
		From:       from,
		Nonce:      request.Metadata.Nonce,
		Value:      value,
		GasFeeCap:  gasfeecap,
		GasPremium: gaspremium,
		GasLimit:   gaslimit,
		Method:     methodNum,
		Params:     serializedParams,
	}

	tx, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}

	return string(tx), nil
}

func (r RosettaConstructionFilecoin) ConstructSwapAuthorizedPartyV8(request *SwapAuthorizedPartyRequest, destinationActorId cid.Cid) (string, error) {
	if destinationActorId != actors.MultisigActorCodeID {
		return "", fmt.Errorf("this actor id is not supported")
	}

	to, err := filAddr.NewFromString(request.Multisig)
	if err != nil {
		return "", err
	}

	from, err := filAddr.NewFromString(request.From)
	if err != nil {
		return "", err
	}

	gasfeecap, err := types.BigFromString(request.Metadata.GasFeeCap)
	if err != nil {
		return "", err
	}

	gaspremium, err := types.BigFromString(request.Metadata.GasPremium)
	if err != nil {
		return "", err
	}

	gaslimit := request.Metadata.GasLimit

	toParams, err := filAddr.NewFromString(request.Params.To)
	if err != nil {
		return "", err
	}

	fromParams, err := filAddr.NewFromString(request.Params.From)
	if err != nil {
		return "", err
	}

	methodNum := builtin.MethodsMultisig.Propose

	swapSignerParams := &multisig.SwapSignerParams{
		From: fromParams,
		To:   toParams,
	}
	bufSwapSigner := new(bytes.Buffer)
	err = swapSignerParams.MarshalCBOR(bufSwapSigner)
	if err != nil {
		return "", err
	}

	params := &multisig.ProposeParams{
		To:     to,
		Value:  types.NewInt(0),
		Method: builtin.MethodsMultisig.SwapSigner,
		Params: bufSwapSigner.Bytes(),
	}

	buf := new(bytes.Buffer)
	err = params.MarshalCBOR(buf)
	if err != nil {
		return "", err
	}
	serializedParams := buf.Bytes()

	msg := &types.Message{Version: types.MessageVersion,
		To:         to,
		From:       from,
		Nonce:      request.Metadata.Nonce,
		Value:      types.NewInt(0),
		GasFeeCap:  gasfeecap,
		GasPremium: gaspremium,
		GasLimit:   gaslimit,
		Method:     methodNum,
		Params:     serializedParams,
	}

	tx, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}

	return string(tx), nil
}

func (r RosettaConstructionFilecoin) ConstructRemoveAuthorizedPartyV8(request *RemoveAuthorizedPartyRequest, destinationActorId cid.Cid) (string, error) {
	if destinationActorId != actors.MultisigActorCodeID {
		return "", fmt.Errorf("this actor id is not supported")
	}

	to, err := filAddr.NewFromString(request.Multisig)
	if err != nil {
		return "", err
	}

	from, err := filAddr.NewFromString(request.From)
	if err != nil {
		return "", err
	}

	gasfeecap, err := types.BigFromString(request.Metadata.GasFeeCap)
	if err != nil {
		return "", err
	}

	gaspremium, err := types.BigFromString(request.Metadata.GasPremium)
	if err != nil {
		return "", err
	}

	gaslimit := request.Metadata.GasLimit

	decreaseParams := request.Params.Decrease

	toRemoveParams, err := filAddr.NewFromString(request.Params.ToRemove)
	if err != nil {
		return "", err
	}

	methodNum := builtin.MethodsMultisig.Propose

	removeSignerParams := &multisig.RemoveSignerParams{
		Signer:   toRemoveParams,
		Decrease: decreaseParams,
	}
	bufRemoveSigner := new(bytes.Buffer)
	err = removeSignerParams.MarshalCBOR(bufRemoveSigner)
	if err != nil {
		return "", err
	}

	params := &multisig.ProposeParams{
		To:     to,
		Value:  types.NewInt(0),
		Method: builtin.MethodsMultisig.RemoveSigner,
		Params: bufRemoveSigner.Bytes(),
	}

	buf := new(bytes.Buffer)
	err = params.MarshalCBOR(buf)
	if err != nil {
		return "", err
	}
	serializedParams := buf.Bytes()

	msg := &types.Message{Version: types.MessageVersion,
		To:         to,
		From:       from,
		Nonce:      request.Metadata.Nonce,
		Value:      types.NewInt(0),
		GasFeeCap:  gasfeecap,
		GasPremium: gaspremium,
		GasLimit:   gaslimit,
		Method:     methodNum,
		Params:     serializedParams,
	}

	tx, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}

	return string(tx), nil
}

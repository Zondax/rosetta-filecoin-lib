/*******************************************************************************
*   (c) 2020 Zondax GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
package rosettaFilecoinLib

import (
	"bytes"
	"encoding/json"
	"fmt"
	filAddr "github.com/filecoin-project/go-address"
	gocrypto "github.com/filecoin-project/go-crypto"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/crypto"
	"github.com/filecoin-project/lotus/chain/types"
	builtinV1 "github.com/filecoin-project/specs-actors/actors/builtin"
	multisigV1 "github.com/filecoin-project/specs-actors/actors/builtin/multisig"
	builtinV2 "github.com/filecoin-project/specs-actors/v2/actors/builtin"
	multisigV2 "github.com/filecoin-project/specs-actors/v2/actors/builtin/multisig"
	"github.com/ipfs/go-cid"
	"github.com/minio/blake2b-simd"
	cbg "github.com/whyrusleeping/cbor-gen"
	"sync"
)

type RosettaConstructionFilecoin struct {
	Mainnet bool
}

// String returns an address encoded as a string

var filAddrLibMutex sync.Mutex

func formatAddress(network filAddr.Network, addr filAddr.Address) string {
	// the address library is unfortunately not thread-safe so we must use a mutex here
	// so we only temporarily change the value and use to mutex to avoid issues
	filAddrLibMutex.Lock()
	defer filAddrLibMutex.Unlock()

	oldNetworkValue := filAddr.CurrentNetwork
	defer func() { filAddr.CurrentNetwork = oldNetworkValue }()

	filAddr.CurrentNetwork = network
	return addr.String()
}

func signSecp256k1(msg []byte, pk []byte) ([]byte, error) {
	b2sum := blake2b.Sum256(msg)
	sig, err := gocrypto.Sign(pk, b2sum[:])
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// Based on https://github.com/filecoin-project/lotus/blob/master/lib/sigs/secp/init.go#L38-L55
func verifySecp256k1(sig []byte, a filAddr.Address, msg []byte) error {
	b2sum := blake2b.Sum256(msg)
	pubk, err := gocrypto.EcRecover(b2sum[:], sig)
	if err != nil {
		return err
	}

	maybeaddr, err := filAddr.NewSecp256k1Address(pubk)
	if err != nil {
		return err
	}

	if a != maybeaddr {
		return fmt.Errorf("signature did not match")
	}

	if gocrypto.Verify(pubk, b2sum[:], sig) {
		return nil
	}

	return fmt.Errorf("invalid signature")
}

func (r RosettaConstructionFilecoin) DeriveFromPublicKey(publicKey []byte, network filAddr.Network) (string, error) {
	addr, err := filAddr.NewSecp256k1Address(publicKey)
	if err != nil {
		return "", err
	}

	return formatAddress(network, addr), nil
}

func (r RosettaConstructionFilecoin) SignRaw(message []byte, sk []byte) ([]byte, error) {
	return signSecp256k1(message, sk)
}

func (r RosettaConstructionFilecoin) VerifyRaw(message []byte, publicKey []byte, signature []byte) error {
	addr, err := filAddr.NewSecp256k1Address(publicKey)
	if err != nil {
		return err
	}

	return verifySecp256k1(signature, addr, message)
}

func (r RosettaConstructionFilecoin) ConstructPayment(request *PaymentRequest) (string, error) {
	to, err := filAddr.NewFromString(request.To)
	if err != nil {
		return "", err
	}

	from, err := filAddr.NewFromString(request.From)
	if err != nil {
		return "", err
	}

	value := types.NewInt(request.Quantity)
	gasfeecap := abi.NewTokenAmount(request.Metadata.GasFeeCap)
	gaspremium := abi.NewTokenAmount(request.Metadata.GasPremium)
	gaslimit := request.Metadata.GasLimit

	// TODO: How to define when v1 or v2 should be used here?
	methodNum := builtinV1.MethodSend

	msg := &types.Message{Version: types.MessageVersion,
		To:         to,
		From:       from,
		Nonce:      request.Metadata.Nonce,
		Value:      value,
		GasFeeCap:  gasfeecap,
		GasPremium: gaspremium,
		GasLimit:   gaslimit,
		Method:     methodNum,
		Params:     make([]byte, 0),
	}

	tx, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}

	return string(tx), nil
}

func (r RosettaConstructionFilecoin) ConstructMultisigPayment(request *MultisigPaymentRequest, destinationActorId cid.Cid) (string, error) {
	to, err := filAddr.NewFromString(request.Multisig)
	if err != nil {
		return "", err
	}

	from, err := filAddr.NewFromString(request.From)
	if err != nil {
		return "", err
	}

	value := types.NewInt(0)
	gasfeecap := abi.NewTokenAmount(request.Metadata.GasFeeCap)
	gaspremium := abi.NewTokenAmount(request.Metadata.GasPremium)
	gaslimit := request.Metadata.GasLimit

	toParams, err := filAddr.NewFromString(request.Params.To)
	if err != nil {
		return "", err
	}

	valueParams := types.NewInt(request.Params.Quantity)

	var methodNum abi.MethodNum
	var serializedParams []byte

	switch destinationActorId {
	case builtinV1.MultisigActorCodeID:
		methodNum = builtinV1.MethodsMultisig.Propose
		params := &multisigV1.ProposeParams{
			To:     toParams,
			Value:  valueParams,
			Method: builtinV1.MethodSend,
			Params: make([]byte, 0),
		}

		buf := new(bytes.Buffer)
		err = params.MarshalCBOR(buf)
		if err != nil {
			return "", err
		}
		serializedParams = buf.Bytes()

	case builtinV2.MultisigActorCodeID:
		methodNum = builtinV2.MethodsMultisig.Propose
		params := &multisigV2.ProposeParams{
			To:     toParams,
			Value:  valueParams,
			Method: builtinV2.MethodSend,
			Params: make([]byte, 0),
		}

		buf := new(bytes.Buffer)
		err = params.MarshalCBOR(buf)
		if err != nil {
			return "", err
		}
		serializedParams = buf.Bytes()

	default:
		return "", fmt.Errorf("this actor id is not supported")
	}

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

func (r RosettaConstructionFilecoin) ConstructSwapAuthorizedParty(request *SwapAuthorizedPartyRequest, destinationActorId cid.Cid) (string, error) {
	to, err := filAddr.NewFromString(request.Multisig)
	if err != nil {
		return "", err
	}

	from, err := filAddr.NewFromString(request.From)
	if err != nil {
		return "", err
	}

	value := types.NewInt(0)
	gasfeecap := abi.NewTokenAmount(request.Metadata.GasFeeCap)
	gaspremium := abi.NewTokenAmount(request.Metadata.GasPremium)
	gaslimit := request.Metadata.GasLimit

	toParams, err := filAddr.NewFromString(request.Params.To)
	if err != nil {
		return "", err
	}

	fromParams, err := filAddr.NewFromString(request.Params.From)
	if err != nil {
		return "", err
	}

	var methodNum abi.MethodNum
	var serializedParams []byte

	switch destinationActorId {
	case builtinV1.MultisigActorCodeID:
		methodNum = builtinV1.MethodsMultisig.Propose

		swapSignerParams := &multisigV1.SwapSignerParams{
			From: fromParams,
			To:   toParams,
		}
		bufSwapSigner := new(bytes.Buffer)
		err = swapSignerParams.MarshalCBOR(bufSwapSigner)
		if err != nil {
			return "", err
		}

		params := &multisigV1.ProposeParams{
			To:     to,
			Value:  value,
			Method: builtinV1.MethodsMultisig.SwapSigner,
			Params: bufSwapSigner.Bytes(),
		}

		buf := new(bytes.Buffer)
		err = params.MarshalCBOR(buf)
		if err != nil {
			return "", err
		}
		serializedParams = buf.Bytes()

	case builtinV2.MultisigActorCodeID:
		methodNum = builtinV2.MethodsMultisig.Propose

		swapSignerParams := &multisigV2.SwapSignerParams{
			From: fromParams,
			To:   toParams,
		}
		bufSwapSigner := new(bytes.Buffer)
		err = swapSignerParams.MarshalCBOR(bufSwapSigner)
		if err != nil {
			return "", err
		}

		params := &multisigV2.ProposeParams{
			To:     to,
			Value:  value,
			Method: builtinV2.MethodsMultisig.SwapSigner,
			Params: bufSwapSigner.Bytes(),
		}

		buf := new(bytes.Buffer)
		err = params.MarshalCBOR(buf)
		if err != nil {
			return "", err
		}
		serializedParams = buf.Bytes()

	default:
		return "", fmt.Errorf("this actor id is not supported")
	}

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

func (r RosettaConstructionFilecoin) unsignedMessageFromCBOR(messageCbor []byte) (*types.Message, error) {
	br := cbg.GetPeeker(bytes.NewReader(messageCbor))
	scratch := make([]byte, 8)
	maj, extra, err := cbg.CborReadHeaderBuf(br, scratch)

	if err != nil {
		return nil, err
	}

	if maj != cbg.MajArray {
		return nil, fmt.Errorf("cbor input should be of type array")
	}

	if extra != 10 {
		return nil, fmt.Errorf("cbor input had wrong number of fields")
	}

	msg, err := types.DecodeMessage(messageCbor)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func (r RosettaConstructionFilecoin) unsignedMessageFromJSON(unsignedTxJson string) (*types.Message, error) {
	rawIn := json.RawMessage(unsignedTxJson)

	txBytes, err := rawIn.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var msg types.Message
	err = json.Unmarshal(txBytes, &msg)
	if err != nil {
		return nil, err
	}

	return &msg, nil
}

func (r RosettaConstructionFilecoin) EncodeTx(unsignedTxJson string) ([]byte, error) {
	msg, err := r.unsignedMessageFromJSON(unsignedTxJson)
	if err != nil {
		return nil, err
	}

	response, err := msg.Serialize()
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (r RosettaConstructionFilecoin) SignTx(unsignedTx []byte, privateKey []byte) ([]byte, error) {
	msg, err := r.unsignedMessageFromCBOR(unsignedTx)
	if err != nil {
		return nil, err
	}

	digest := msg.Cid().Bytes()

	sig, err := r.SignRaw(digest, privateKey)
	if err != nil {
		return nil, err
	}

	signature := crypto.Signature{
		Type: crypto.SigTypeSecp256k1,
		Data: sig,
	}

	sm := &types.SignedMessage{
		Message:   *msg,
		Signature: signature,
	}

	m, err := json.Marshal(sm)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (r RosettaConstructionFilecoin) SignTxJSON(unsignedTxJson string, privateKey []byte) (string, error) {
	msg, err := r.unsignedMessageFromJSON(unsignedTxJson)
	if err != nil {
		return "", err
	}

	digest := msg.Cid().Bytes()

	sig, err := r.SignRaw(digest, privateKey)
	if err != nil {
		return "", err
	}

	signature := crypto.Signature{
		Type: crypto.SigTypeSecp256k1,
		Data: sig,
	}

	sm := &types.SignedMessage{
		Message:   *msg,
		Signature: signature,
	}

	m, err := json.Marshal(sm)
	if err != nil {
		return "", err
	}

	return string(m), nil
}

func (r RosettaConstructionFilecoin) ParseTx(messageCbor []byte) (string, error) {
	br := cbg.GetPeeker(bytes.NewReader(messageCbor))
	scratch := make([]byte, 8)
	maj, extra, err := cbg.CborReadHeaderBuf(br, scratch)

	if err != nil {
		return "", err
	}

	if maj != cbg.MajArray {
		return "", fmt.Errorf("cbor input should be of type array")
	}

	var msg interface{}

	switch extra {
	case 10:
		// Unsigned message
		msg, err = types.DecodeMessage(messageCbor)
		if err != nil {
			return "", err
		}
	case 2:
		// Signed message
		msg, err = types.DecodeSignedMessage(messageCbor)
		if err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("cbor input had wrong number of fields")
	}

	msgJson, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	return string(msgJson), nil
}

func (r RosettaConstructionFilecoin) parseParamsMultisigTxV1(unsignedMultisigTx string) (string, error) {
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

	switch msg.Method {
	case builtinV1.MethodsMultisig.Propose:
		{
			r := bytes.NewReader(msg.Params)
			var params multisigV1.ProposeParams
			err := params.UnmarshalCBOR(r)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtinV1.MethodsMultisig.Approve:
	case builtinV1.MethodsMultisig.Cancel:
		{
			r := bytes.NewReader(msg.Params)
			var params multisigV1.TxnIDParams
			err := params.UnmarshalCBOR(r)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtinV1.MethodsMultisig.AddSigner:
		{
			r := bytes.NewReader(msg.Params)
			var params multisigV1.AddSignerParams
			err := params.UnmarshalCBOR(r)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtinV1.MethodsMultisig.RemoveSigner:
		{
			r := bytes.NewReader(msg.Params)
			var params multisigV1.RemoveSignerParams
			err := params.UnmarshalCBOR(r)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtinV1.MethodsMultisig.SwapSigner:
		{
			r := bytes.NewReader(msg.Params)
			var params multisigV1.SwapSignerParams
			err := params.UnmarshalCBOR(r)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtinV1.MethodsMultisig.ChangeNumApprovalsThreshold:
		{
			r := bytes.NewReader(msg.Params)
			var params multisigV1.ChangeNumApprovalsThresholdParams
			err := params.UnmarshalCBOR(r)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtinV1.MethodsMultisig.LockBalance:
		{
			r := bytes.NewReader(msg.Params)
			var params multisigV1.LockBalanceParams
			err := params.UnmarshalCBOR(r)
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

	return "", nil
}

func (r RosettaConstructionFilecoin) parseParamsMultisigTxV2(unsignedMultisigTx string) (string, error) {
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

	switch msg.Method {
	case builtinV1.MethodsMultisig.Propose:
		{
			r := bytes.NewReader(msg.Params)
			var params multisigV1.ProposeParams
			err := params.UnmarshalCBOR(r)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtinV1.MethodsMultisig.Approve:
	case builtinV1.MethodsMultisig.Cancel:
		{
			r := bytes.NewReader(msg.Params)
			var params multisigV1.TxnIDParams
			err := params.UnmarshalCBOR(r)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtinV1.MethodsMultisig.AddSigner:
		{
			r := bytes.NewReader(msg.Params)
			var params multisigV1.AddSignerParams
			err := params.UnmarshalCBOR(r)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtinV1.MethodsMultisig.RemoveSigner:
		{
			r := bytes.NewReader(msg.Params)
			var params multisigV1.RemoveSignerParams
			err := params.UnmarshalCBOR(r)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtinV1.MethodsMultisig.SwapSigner:
		{
			r := bytes.NewReader(msg.Params)
			var params multisigV1.SwapSignerParams
			err := params.UnmarshalCBOR(r)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtinV1.MethodsMultisig.ChangeNumApprovalsThreshold:
		{
			r := bytes.NewReader(msg.Params)
			var params multisigV1.ChangeNumApprovalsThresholdParams
			err := params.UnmarshalCBOR(r)
			if err != nil {
				return "", err
			}
			jsonResponse, err := json.Marshal(params)
			if err != nil {
				return "", err
			}
			return string(jsonResponse), nil
		}
	case builtinV1.MethodsMultisig.LockBalance:
		{
			r := bytes.NewReader(msg.Params)
			var params multisigV1.LockBalanceParams
			err := params.UnmarshalCBOR(r)
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

	return "", nil
}

func (r RosettaConstructionFilecoin) ParseParamsMultisigTx(unsignedMultisigTx string, destinationActorId cid.Cid) (string, error) {
	switch destinationActorId {
	case builtinV1.MultisigActorCodeID:
		return r.parseParamsMultisigTxV1(unsignedMultisigTx)

	case builtinV2.MultisigActorCodeID:
		return r.parseParamsMultisigTxV2(unsignedMultisigTx)

	default:
		return "", fmt.Errorf("this actor id is not supported")
	}
}

func (r RosettaConstructionFilecoin) Hash(signedMessage string) (string, error) {
	rawIn := json.RawMessage(signedMessage)

	txBytes, err := rawIn.MarshalJSON()
	if err != nil {
		return "", err
	}

	var msg types.SignedMessage
	err = json.Unmarshal(txBytes, &msg)
	if err != nil {
		return "", err
	}

	return msg.Cid().String(), nil
}

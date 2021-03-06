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
	"sync"

	filAddr "github.com/filecoin-project/go-address"
	gocrypto "github.com/filecoin-project/go-crypto"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/crypto"
	"github.com/filecoin-project/lotus/chain/types"
	builtinV1 "github.com/filecoin-project/specs-actors/actors/builtin"
	builtinV2 "github.com/filecoin-project/specs-actors/v2/actors/builtin"
	builtinV3 "github.com/filecoin-project/specs-actors/v3/actors/builtin"
	builtinV4 "github.com/filecoin-project/specs-actors/v4/actors/builtin"
	builtinV5 "github.com/filecoin-project/specs-actors/v5/actors/builtin"
	multisigV5 "github.com/filecoin-project/specs-actors/v5/actors/builtin/multisig"
	"github.com/ipfs/go-cid"
	"github.com/minio/blake2b-simd"
	cbg "github.com/whyrusleeping/cbor-gen"
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

	value, err := types.BigFromString(request.Quantity)
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
	switch destinationActorId {
	case builtinV1.MultisigActorCodeID:
		return r.ConstructMultisigPaymentV1(request, destinationActorId)

	case builtinV2.MultisigActorCodeID:
		return r.ConstructMultisigPaymentV2(request, destinationActorId)

	case builtinV3.MultisigActorCodeID:
		return r.ConstructMultisigPaymentV3(request, destinationActorId)

	case builtinV4.MultisigActorCodeID:
		return r.ConstructMultisigPaymentV4(request, destinationActorId)

	case builtinV5.MultisigActorCodeID:
		return r.ConstructMultisigPaymentV5(request, destinationActorId)

	default:
		return "", fmt.Errorf("this actor id is not supported")
	}
}

func (r RosettaConstructionFilecoin) ConstructSwapAuthorizedParty(request *SwapAuthorizedPartyRequest, destinationActorId cid.Cid) (string, error) {
	switch destinationActorId {
	case builtinV1.MultisigActorCodeID:
		return r.ConstructSwapAuthorizedPartyV1(request, destinationActorId)

	case builtinV2.MultisigActorCodeID:
		return r.ConstructSwapAuthorizedPartyV2(request, destinationActorId)

	case builtinV3.MultisigActorCodeID:
		return r.ConstructSwapAuthorizedPartyV3(request, destinationActorId)

	case builtinV4.MultisigActorCodeID:
		return r.ConstructSwapAuthorizedPartyV4(request, destinationActorId)

	case builtinV5.MultisigActorCodeID:
		return r.ConstructSwapAuthorizedPartyV5(request, destinationActorId)

	default:
		return "", fmt.Errorf("this actor id is not supported")
	}
}

func (r RosettaConstructionFilecoin) ConstructRemoveAuthorizedParty(request *RemoveAuthorizedPartyRequest, destinationActorId cid.Cid) (string, error) {
	switch destinationActorId {
	case builtinV1.MultisigActorCodeID:
		return r.ConstructRemoveAuthorizedPartyV1(request, destinationActorId)

	case builtinV2.MultisigActorCodeID:
		return r.ConstructRemoveAuthorizedPartyV2(request, destinationActorId)

	case builtinV3.MultisigActorCodeID:
		return r.ConstructRemoveAuthorizedPartyV3(request, destinationActorId)

	case builtinV4.MultisigActorCodeID:
		return r.ConstructRemoveAuthorizedPartyV4(request, destinationActorId)

	case builtinV5.MultisigActorCodeID:
		return r.ConstructRemoveAuthorizedPartyV5(request, destinationActorId)

	default:
		return "", fmt.Errorf("this actor id is not supported")
	}
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

func getMsigMethodString(method abi.MethodNum) (string, error) {
	switch method {
	case builtinV5.MethodSend:
		return "Send", nil
	case builtinV5.MethodsMultisig.Approve:
		return "Approve", nil
	case builtinV5.MethodsMultisig.Cancel:
		return "Cancel", nil
	case builtinV5.MethodsMultisig.SwapSigner:
		return "SwapSigner", nil
	case builtinV5.MethodsMultisig.RemoveSigner:
		return "RemoveSigner", nil
	case builtinV5.MethodsMultisig.AddSigner:
		return "AddSigner", nil
	case builtinV5.MethodsMultisig.ChangeNumApprovalsThreshold:
		return "ChangeNumApprovalsThreshold", nil
	case builtinV5.MethodsMultisig.LockBalance:
		return "LockBalance", nil
	case builtinV5.MethodsMultisig.Constructor:
		return "Constructor", nil
	case builtinV5.MethodsMultisig.Propose:
		return "Propose", nil
	default:
		return "", fmt.Errorf("method not recognized")
	}
}

func (r RosettaConstructionFilecoin) ParseProposeTxParams(unsignedMultisigTx string, destinationActorId cid.Cid) (string, string, error) {
	rawIn := json.RawMessage(unsignedMultisigTx)

	txBytes, err := rawIn.MarshalJSON()
	if err != nil {
		return "", "", err
	}

	var msg types.Message
	err = json.Unmarshal(txBytes, &msg)
	if err != nil {
		return "", "", err
	}

	if msg.Method != builtinV5.MethodsMultisig.Propose {
		return "", "", fmt.Errorf("method does not correspond to a 'Propose' transaction")
	}

	reader := bytes.NewReader(msg.Params)
	var proposeParams multisigV5.ProposeParams
	err = proposeParams.UnmarshalCBOR(reader)
	if err != nil {
		return "", "", err
	}

	innerMethod, err := getMsigMethodString(proposeParams.Method)
	if err != nil {
		return "", "", err
	}

	innerParams, err := r.ParseParamsMultisigTx(unsignedMultisigTx, destinationActorId)
	if err != nil {
		return "", "", err
	}

	return innerMethod, innerParams, nil
}

func (r RosettaConstructionFilecoin) ParseParamsMultisigTx(unsignedMultisigTx string, destinationActorId cid.Cid) (string, error) {
	switch destinationActorId {
	case builtinV1.MultisigActorCodeID:
		return r.parseParamsMultisigTxV1(unsignedMultisigTx)

	case builtinV2.MultisigActorCodeID:
		return r.parseParamsMultisigTxV2(unsignedMultisigTx)

	case builtinV3.MultisigActorCodeID:
		return r.parseParamsMultisigTxV3(unsignedMultisigTx)

	case builtinV4.MultisigActorCodeID:
		return r.parseParamsMultisigTxV4(unsignedMultisigTx)

	case builtinV5.MultisigActorCodeID:
		return r.parseParamsMultisigTxV5(unsignedMultisigTx)

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

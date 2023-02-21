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
	"context"
	"encoding/json"
	"fmt"
	"github.com/filecoin-project/go-state-types/builtin"
	"github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/api/client"
	"github.com/zondax/rosetta-filecoin-lib/actors"
	"go.uber.org/zap"
	"net/http"
	"sync"

	filAddr "github.com/filecoin-project/go-address"
	gocrypto "github.com/filecoin-project/go-crypto"
	"github.com/filecoin-project/go-state-types/abi"
	multisigV10 "github.com/filecoin-project/go-state-types/builtin/v10/multisig"
	"github.com/filecoin-project/go-state-types/crypto"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/ipfs/go-cid"
	"github.com/minio/blake2b-simd"
	cbg "github.com/whyrusleeping/cbor-gen"
)

type RosettaConstructionFilecoin struct {
	networkName   string
	online        bool
	BuiltinActors actors.BuiltinActors
}

type LotusRpcV1 api.FullNode

// NewFilecoinRPCClient creates a new lotus rpc client
func NewFilecoinRPCClient(url string, token string) (LotusRpcV1, error) {
	ctx := context.Background()

	headers := http.Header{}
	if len(token) > 0 {
		headers.Add("Authorization", "Bearer "+token)
	}

	lotusAPI, _, err := client.NewFullNodeRPCV1(ctx, url, headers)
	if err != nil {
		return nil, err
	}

	return lotusAPI, nil
}

func NewRosettaConstructionFilecoin(lotusApi api.FullNode) *RosettaConstructionFilecoin {
	if lotusApi == nil {
		zap.S().Warn("library running in offline mode")
		return &RosettaConstructionFilecoin{
			online: false,
		}
	}

	networkVersion, err := lotusApi.StateNetworkVersion(context.Background(), types.EmptyTSK)
	if err != nil {
		zap.S().Errorf("could not get lotus network version!: %s", err.Error())
		return nil
	}

	networkName, err := lotusApi.StateNetworkName(context.Background())
	if err != nil {
		zap.S().Errorf("could not get lotus network name!: %s", err.Error())
		return nil
	}

	actorCids, err := lotusApi.StateActorCodeCIDs(context.Background(), networkVersion)
	if err != nil {
		zap.S().Errorf("could not get actors cids!: %s", err.Error())
		return nil
	}

	zap.S().Infof("Got actors CIDs for network: '%s' version: '%d'", networkName, networkVersion)

	metadata := actors.BuiltinActorsMetadata{
		Network:          string(networkName),
		Version:          networkVersion,
		ActorsNameCidMap: actorCids,
	}

	return &RosettaConstructionFilecoin{
		networkName:   string(networkName),
		BuiltinActors: actors.BuiltinActors{Metadata: metadata},
		online:        true,
	}
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

func (r *RosettaConstructionFilecoin) DeriveFromPublicKey(publicKey []byte, network filAddr.Network) (string, error) {
	addr, err := filAddr.NewSecp256k1Address(publicKey)
	if err != nil {
		return "", err
	}

	return formatAddress(network, addr), nil
}

func (r *RosettaConstructionFilecoin) SignRaw(message []byte, sk []byte) ([]byte, error) {
	return signSecp256k1(message, sk)
}

func (r *RosettaConstructionFilecoin) VerifyRaw(message []byte, publicKey []byte, signature []byte) error {
	addr, err := filAddr.NewSecp256k1Address(publicKey)
	if err != nil {
		return err
	}

	return verifySecp256k1(signature, addr, message)
}

func (r *RosettaConstructionFilecoin) ConstructPayment(request *PaymentRequest) (string, error) {
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

	methodNum := builtin.MethodSend

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

func (r *RosettaConstructionFilecoin) ConstructMultisigPayment(request *MultisigPaymentRequest) (string, error) {
	actorCid, err := r.BuiltinActors.GetActorCid(actors.ActorMultisigName)
	if err != nil {
		return "", err
	}

	return r.ConstructMultisigPaymentV10(request, actorCid)
}

func (r *RosettaConstructionFilecoin) ConstructSwapAuthorizedParty(request *SwapAuthorizedPartyRequest) (string, error) {
	actorCid, err := r.BuiltinActors.GetActorCid(actors.ActorMultisigName)
	if err != nil {
		return "", err
	}

	return r.ConstructSwapAuthorizedPartyV10(request, actorCid)
}

func (r *RosettaConstructionFilecoin) ConstructRemoveAuthorizedParty(request *RemoveAuthorizedPartyRequest) (string, error) {
	actorCid, err := r.BuiltinActors.GetActorCid(actors.ActorMultisigName)
	if err != nil {
		return "", err
	}

	return r.ConstructRemoveAuthorizedPartyV10(request, actorCid)
}

func (r *RosettaConstructionFilecoin) unsignedMessageFromCBOR(messageCbor []byte) (*types.Message, error) {
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

func (r *RosettaConstructionFilecoin) unsignedMessageFromJSON(unsignedTxJson string) (*types.Message, error) {
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

func (r *RosettaConstructionFilecoin) EncodeTx(unsignedTxJson string) ([]byte, error) {
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

func (r *RosettaConstructionFilecoin) SignTx(unsignedTx []byte, privateKey []byte) ([]byte, error) {
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

func (r *RosettaConstructionFilecoin) SignTxJSON(unsignedTxJson string, privateKey []byte) (string, error) {
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

func (r *RosettaConstructionFilecoin) ParseTx(messageCbor []byte) (string, error) {
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

func (r *RosettaConstructionFilecoin) ParseProposeTxParams(unsignedMultisigTx string, destinationActorId cid.Cid) (string, string, error) {
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

	meta, ok := multisigV10.Methods[msg.Method]
	if !ok || meta.Name != "Propose" {
		return "", "", fmt.Errorf("method does not correspond to a 'Propose' transaction")
	}

	reader := bytes.NewReader(msg.Params)
	var proposeParams multisigV10.ProposeParams
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

func (r *RosettaConstructionFilecoin) GetInnerProposeTxParams(unsignedMultisigTx string) (*multisigV10.ProposeParams, error) {
	rawIn := json.RawMessage(unsignedMultisigTx)

	txBytes, err := rawIn.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var msg types.Message
	err = json.Unmarshal(txBytes, &msg)
	if err != nil {
		return nil, err
	}

	meta, ok := multisigV10.Methods[msg.Method]
	if !ok || meta.Name != "Propose" {
		return nil, fmt.Errorf("method does not correspond to a 'Propose' transaction")
	}

	reader := bytes.NewReader(msg.Params)
	var proposeParams multisigV10.ProposeParams
	err = proposeParams.UnmarshalCBOR(reader)
	if err != nil {
		return nil, err
	}

	return &proposeParams, nil
}

func (r *RosettaConstructionFilecoin) GetProposedMethod(proposeParams *multisigV10.ProposeParams, targetActorId cid.Cid) (string, error) {
	actorName, err := r.BuiltinActors.GetActorNameFromCid(targetActorId)
	if err != nil {
		return "", err
	}

	switch actorName {
	case actors.ActorAccountName, actors.ActorMultisigName:
		innerMethod, err := getMsigMethodString(proposeParams.Method)
		return innerMethod, err
	case actors.ActorStorageMinerName:
		innerMethod, err := getMinerMethodString(proposeParams.Method)
		return innerMethod, err
	case actors.ActorVerifiedRegistryName:
		innerMethod, err := getVerifRegMethodString(proposeParams.Method)
		return innerMethod, err
	default:
		return "", fmt.Errorf("target actor %v currently not supported inside Propose params", targetActorId)
	}
}

func getMsigMethodString(method abi.MethodNum) (string, error) {
	switch method {
	case builtin.MethodSend:
		return "Send", nil
	case builtin.MethodsMultisig.Approve:
		return "Approve", nil
	case builtin.MethodsMultisig.Cancel:
		return "Cancel", nil
	case builtin.MethodsMultisig.SwapSigner:
		return "SwapSigner", nil
	case builtin.MethodsMultisig.RemoveSigner:
		return "RemoveSigner", nil
	case builtin.MethodsMultisig.AddSigner:
		return "AddSigner", nil
	case builtin.MethodsMultisig.ChangeNumApprovalsThreshold:
		return "ChangeNumApprovalsThreshold", nil
	case builtin.MethodsMultisig.LockBalance:
		return "LockBalance", nil
	case builtin.MethodsMultisig.Constructor:
		return "Constructor", nil
	case builtin.MethodsMultisig.Propose:
		return "Propose", nil
	default:
		return "", fmt.Errorf("multisig method %v not recognized", method)
	}
}

func getMinerMethodString(method abi.MethodNum) (string, error) {
	switch method {
	case builtin.MethodSend:
		return "Send", nil
	case builtin.MethodsMiner.WithdrawBalance:
		return "WithdrawBalance", nil
	case builtin.MethodsMiner.ChangeOwnerAddress:
		return "ChangeOwnerAddress", nil
	case builtin.MethodsMiner.ChangeWorkerAddress:
		return "ChangeWorkerAddress", nil
	// TODO: complete with all methods
	default:
		return "", fmt.Errorf("miner method %v not recognized", method)
	}
}

func getVerifRegMethodString(method abi.MethodNum) (string, error) {
	switch method {
	case builtin.MethodsVerifiedRegistry.AddVerifiedClient:
		return "AddVerifiedClient", nil
	case builtin.MethodsVerifiedRegistry.AddVerifier:
		return "AddVerifier", nil
	case builtin.MethodsVerifiedRegistry.RemoveVerifier:
		return "RemoveVerifier", nil
	// TODO: complete with all methods
	default:
		return "", fmt.Errorf("verified registry method %v not recognized", method)
	}
}

func (r *RosettaConstructionFilecoin) ParseParamsMultisigTx(unsignedMultisigTx string, destinationActorId cid.Cid) (string, error) {
	// Try the latest version first
	msigCid, err := r.BuiltinActors.GetActorCid(actors.ActorMultisigName)
	if err != nil {
		return "", err
	}

	if destinationActorId == msigCid {
		return r.parseParamsMultisigTxV10(unsignedMultisigTx)
	}

	// Try legacy actors
	if actors.IsLegacyActor(destinationActorId, actors.ActorMultisigName) {
		return "", fmt.Errorf("actor id '%s' is a legacy actor and is not supported", destinationActorId.String())
	}

	return "", fmt.Errorf("actor id '%s' is not supported", destinationActorId.String())
}

func (r *RosettaConstructionFilecoin) Hash(signedMessage string) (string, error) {
	rawIn := json.RawMessage(signedMessage)

	txBytes, err := rawIn.MarshalJSON()
	if err != nil {
		return "", err
	}

	var msg types.SignedMessage
	err = json.Unmarshal(txBytes, &msg)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	// Verify teh signed message is valid to avoid generating wrong CID
	// see https://github.com/Zondax/rosetta-filecoin-lib/issues/21
	digest := msg.Message.Cid().Bytes()
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	err = verifySecp256k1(msg.Signature.Data, msg.Message.From, digest)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	return msg.Cid().String(), nil
}

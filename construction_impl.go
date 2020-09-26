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
	"fmt"
	"sync"

	filAddr "github.com/filecoin-project/go-address"
	c "github.com/filecoin-project/go-crypto"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/crypto"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/filecoin-project/specs-actors/actors/builtin"
	"github.com/filecoin-project/specs-actors/actors/builtin/multisig"
	"github.com/minio/blake2b-simd"
	cbg "github.com/whyrusleeping/cbor-gen"

	"encoding/base64"
	"encoding/json"
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
	sig, err := c.Sign(pk, b2sum[:])
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// REVIEW: Doesn't actually verify the signature...
// https://github.com/filecoin-project/lotus/blob/master/lib/sigs/secp/init.go#L38-L55
func verifySecp256k1(sig []byte, a filAddr.Address, msg []byte) error {
	b2sum := blake2b.Sum256(msg)
	pubk, err := c.EcRecover(b2sum[:], sig)
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

	if c.Verify(pubk, b2sum[:], sig) {
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

func (r RosettaConstructionFilecoin) Sign(message []byte, sk []byte) ([]byte, error) {
	return signSecp256k1(message, sk)
}

func (r RosettaConstructionFilecoin) Verify(message []byte, publicKey []byte, signature []byte) error {
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
	gaslimit := int64(request.Metadata.GasLimit)

	msg := &types.Message{Version: types.MessageVersion,
		To:         to,
		From:       from,
		Nonce:      request.Metadata.Nonce,
		Value:      value,
		GasFeeCap:  gasfeecap,
		GasPremium: gaspremium,
		GasLimit:   gaslimit,
		Method:     builtin.MethodSend,
		Params:     make([]byte, 0),
	}

	tx, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(tx), nil
}

func (r RosettaConstructionFilecoin) ConstructMultisigPayment(request *MultisigPaymentRequest) (string, error) {
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
	gaslimit := int64(request.Metadata.GasLimit)

	toParams, err := filAddr.NewFromString(request.Params.To)
	if err != nil {
		return "", err
	}

	valueParams := types.NewInt(request.Params.Quantity)

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

	serParams := buf.Bytes()

	msg := &types.Message{Version: types.MessageVersion,
		To:         to,
		From:       from,
		Nonce:      request.Metadata.Nonce,
		Value:      value,
		GasFeeCap:  gasfeecap,
		GasPremium: gaspremium,
		GasLimit:   gaslimit,
		Method:     builtin.MethodsMultisig.Propose,
		Params:     serParams,
	}

	tx, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(tx), nil
}

func (r RosettaConstructionFilecoin) ConstructSwapAuthorizedParty(request *SwapAuthorizedPartyRequest) (string, error) {
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
	gaslimit := int64(request.Metadata.GasLimit)

	toParams, err := filAddr.NewFromString(request.Params.To)
	if err != nil {
		return "", err
	}

	fromParams, err := filAddr.NewFromString(request.Params.From)
	if err != nil {
		return "", err
	}

	swapSignerParams := &multisig.SwapSignerParams{
		From: fromParams,
		To:   toParams,
	}

	bufSwapSigner := new(bytes.Buffer)
	err = swapSignerParams.MarshalCBOR(bufSwapSigner)
	if err != nil {
		return "", err
	}
	serSwapSignersParams := bufSwapSigner.Bytes()

	params := &multisig.ProposeParams{
		To:     to,
		Value:  value,
		Method: builtin.MethodsMultisig.SwapSigner,
		Params: serSwapSignersParams,
	}

	buf := new(bytes.Buffer)
	err = params.MarshalCBOR(buf)
	if err != nil {
		return "", err
	}
	serParams := buf.Bytes()

	msg := &types.Message{Version: types.MessageVersion,
		To:         to,
		From:       from,
		Nonce:      request.Metadata.Nonce,
		Value:      value,
		GasFeeCap:  gasfeecap,
		GasPremium: gaspremium,
		GasLimit:   gaslimit,
		Method:     builtin.MethodsMultisig.Propose,
		Params:     serParams,
	}

	tx, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(tx), nil
}

func (r RosettaConstructionFilecoin) SignTx(unsignedTxBase64 string, privateKey []byte) (string, error) {
	unsignedTransaction, err := base64.StdEncoding.DecodeString(unsignedTxBase64)
	if err != nil {
		return "", err
	}

	rawIn := json.RawMessage(unsignedTransaction)

	txBytes, err := rawIn.MarshalJSON()
	if err != nil {
		return "", err
	}

	var msg types.Message
	err = json.Unmarshal(txBytes, &msg)
	if err != nil {
		return "", err
	}

	digest := msg.Cid().Bytes()

	sig, err := r.Sign(digest, privateKey)
	if err != nil {
		return "", err
	}

	signature := crypto.Signature{
		Type: crypto.SigTypeSecp256k1,
		Data: sig,
	}

	sm := &types.SignedMessage{
		Message:   msg,
		Signature: signature,
	}

	m, err := json.Marshal(sm)
	if err != nil {
		return "", err
	}

	return string(m), nil
}

func (r RosettaConstructionFilecoin) ParseTx(messageBase64 string) (string, error) {
	messageCbor, err := base64.StdEncoding.DecodeString(messageBase64)
	if err != nil {
		return "", err
	}

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

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(msgBytes), nil
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

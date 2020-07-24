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
package rosetta_filecoin_lib

import (
	"bytes"
	"fmt"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/lotus/chain/types"
	c "github.com/filecoin-project/go-crypto"
	"github.com/filecoin-project/specs-actors/actors/crypto"
	"github.com/filecoin-project/specs-actors/actors/builtin/multisig"
	"github.com/filecoin-project/specs-actors/actors/builtin"
	"github.com/minio/blake2b-simd"
	cbg "github.com/whyrusleeping/cbor-gen"

	"encoding/json"
	"encoding/base64"
)

type RosettaConstructionFilecoin struct {
	Mainnet bool
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
func verifySecp256k1(sig []byte, a address.Address, msg []byte) error {
	b2sum := blake2b.Sum256(msg)
	pubk, err := c.EcRecover(b2sum[:], sig)
	if err != nil {
		return err
	}

	maybeaddr, err := address.NewSecp256k1Address(pubk)
	if err != nil {
		return err
	}

	if a != maybeaddr {
		return fmt.Errorf("signature did not match")
	}

	if c.Verify(pubk, b2sum[:], sig) {
		return nil
	}

	return fmt.Errorf("Invalid signature")
}

func (r RosettaConstructionFilecoin) DeriveFromPublicKey(publicKey []byte) (string, error) {
	addr, err := address.NewSecp256k1Address(publicKey)
	if err != nil {
		return "", err
	}
	// FIXME: go=address does not allow setting a network
	// https://github.com/filecoin-project/go-address/issues/6

	return addr.String(), nil
}

func (r RosettaConstructionFilecoin) Sign(message []byte, sk []byte) ([]byte, error) {
	return signSecp256k1(message, sk)
}

func (r RosettaConstructionFilecoin) Verify(message []byte, publicKey []byte, signature []byte) error {
	addr, err := address.NewSecp256k1Address(publicKey)
	if err != nil {
		return err
	}

	return verifySecp256k1(signature, addr, message)
}

func (r RosettaConstructionFilecoin) ConstructPayment(request *PaymentRequest) (string, error) {
	to, err := address.NewFromString(request.To)
	if err != nil {
		return "", err
	}

	from, err := address.NewFromString(request.From)
	if err != nil {
		return "", err
	}

	value := types.NewInt(request.Quantity)

	gasprice, err := types.BigFromString(request.Metadata.GasPrice)
	if err != nil {
		return "", err
	}

	msg := &types.Message{types.MessageVersion,
		to,
		from,
		request.Metadata.Nonce,
		value,
		gasprice,
		request.Metadata.GasLimit,
		builtin.MethodSend,
		make([]byte,0),
	}

	tx, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(tx), nil
}

func (r RosettaConstructionFilecoin) ConstructMultisigPayment(request *MultisigPaymentRequest) (string, error) {
	to, err := address.NewFromString(request.Multisig)
	if err != nil {
		return "", err
	}

	from, err := address.NewFromString(request.From)
	if err != nil {
		return "", err
	}

	value := types.NewInt(0)

	gasprice, err := types.BigFromString(request.Metadata.GasPrice)
	if err != nil {
		return "", err
	}

	toParams, err := address.NewFromString(request.Params.To)
	if err != nil {
		return "", err
	}

	valueParams := types.NewInt(request.Params.Quantity)

	params := &multisig.ProposeParams{
		To: toParams,
		Value: valueParams,
		Method: builtin.MethodSend,
		Params: make([]byte, 0),
	}

	buf := new(bytes.Buffer)
	err = params.MarshalCBOR(buf)
	serParams := buf.Bytes()

	msg := &types.Message{types.MessageVersion,
		to,
		from,
		request.Metadata.Nonce,
		value,
		gasprice,
		request.Metadata.GasLimit,
		builtin.MethodsMultisig.Propose,
		serParams,
	}

	tx, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(tx), nil
}

func (r RosettaConstructionFilecoin) ConstructSwapAuthorizedParty(request *SwapAuthorizedPartyRequest) (string, error) {
	to, err := address.NewFromString(request.Multisig)
	if err != nil {
		return "", err
	}

	from, err := address.NewFromString(request.From)
	if err != nil {
		return "", err
	}

	value := types.NewInt(0)

	gasprice, err := types.BigFromString(request.Metadata.GasPrice)
	if err != nil {
		return "", err
	}

	toParams, err := address.NewFromString(request.Params.To)
	if err != nil {
		return "", err
	}

	fromParams, err := address.NewFromString(request.Params.From)
	if err != nil {
		return "", err
	}

	params := &multisig.SwapSignerParams{
		From: fromParams,
		To: toParams,
	}

	buf := new(bytes.Buffer)
	err = params.MarshalCBOR(buf)
	serParams := buf.Bytes()

	msg := &types.Message{types.MessageVersion,
		to,
		from,
		request.Metadata.Nonce,
		value,
		gasprice,
		request.Metadata.GasLimit,
		7,
		serParams,
	}

	tx, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(tx), nil
}

func (r RosettaConstructionFilecoin) SignTx(unsignedTxBase64 string, privateKey []byte) (string, error) {
	unsignedTransaction, err := base64.StdEncoding.DecodeString(unsignedTxBase64)
	rawIn := json.RawMessage(unsignedTransaction)

	bytes, err := rawIn.MarshalJSON()
	if err != nil {
		return "", err
	}

	var msg types.Message
	err = json.Unmarshal(bytes, &msg)
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
		Message: msg,
		Signature: signature,
	}

	m, err := json.Marshal(sm)
	if err != nil {
		return "", err
	}

	return string(m), nil
}

func (r RosettaConstructionFilecoin) ParseTx(b []byte) (interface{}, error) {
	br := cbg.GetPeeker(bytes.NewReader(b))
	scratch := make([]byte, 8)
	maj, extra, err := cbg.CborReadHeaderBuf(br, scratch)

	if err != nil {
		return nil, err
	}

	if maj != cbg.MajArray {
		return nil, fmt.Errorf("cbor input should be of type array")
	}

	switch extra {
		case 9:
			// Unsigned message
			msg, err := types.DecodeMessage(b)
			if err != nil {
				return nil, err
			}
			return *msg, nil
		case 2:
			// Signed message
			msg, err := types.DecodeSignedMessage(b)
			if err != nil {
				return nil, err
			}
			return *msg, nil
		default:
			return nil, fmt.Errorf("cbor input had wrong number of fields")
	}

}

func (r RosettaConstructionFilecoin) Hash(signedMessage string) (string, error) {
	rawIn := json.RawMessage(signedMessage)

	bytes, err := rawIn.MarshalJSON()
	if err != nil {
		return "", err
	}

	var msg types.SignedMessage
	err = json.Unmarshal(bytes, &msg)
	if err != nil {
		return "", err
	}

	return msg.Cid().String(), nil
}

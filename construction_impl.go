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
	"github.com/filecoin-project/lotus/lib/sigs"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/filecoin-project/specs-actors/actors/crypto"
	cbg "github.com/whyrusleeping/cbor-gen"
	"encoding/json"
)

type RosettaConstructionFilecoin struct {
	Mainnet bool
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

func (r RosettaConstructionFilecoin) Sign(message []byte, privateKey []byte) ([]byte, error) {
	signature, err := sigs.Sign(crypto.SigTypeSecp256k1, privateKey, message)
	if err != nil {
		return nil, err
	}

	return signature.MarshalBinary()
}

func (r RosettaConstructionFilecoin) Verify(message []byte, publicKey []byte, signature []byte) error {
	sig := crypto.Signature{}
	err := sig.UnmarshalBinary(signature)
	if err != nil {
		return err
	}

	addr, err := address.NewSecp256k1Address(publicKey)
	if err != nil {
		return err
	}

	return sigs.Verify(&sig, addr, message)
}

func (r RosettaConstructionFilecoin) ConstructPayment(request *PaymentRequest) ([]byte, error) {
	to, err := address.NewFromString(request.To)
	if err != nil {
		return nil, err
	}

	from, err := address.NewFromString(request.From)
	if err != nil {
		return nil, err
	}

	value := types.NewInt(request.Quantity)

	gasprice, err := types.BigFromString(request.Metadata.GasPrice)
	if err != nil {
		return nil, err
	}

	msg := &types.Message{types.MessageVersion,
		to,
		from,
		request.Metadata.Nonce,
		value,
		gasprice,
		request.Metadata.GasLimit,
		0,
		make([]byte,0),
	}

	return json.Marshal(msg)
}

func (r RosettaConstructionFilecoin) ConstructMultisigPayment(request *MultisigPaymentRequest) (string, error) {
	panic("implement me")
}

func (r RosettaConstructionFilecoin) ConstructSwapAuthorizedParty(request *MultisigPaymentRequest) (string, error) {
	panic("implement me")
}

func (r RosettaConstructionFilecoin) SignTx(unsignedTransaction string, privateKey []byte) ([]byte, error) {
	rawIn := json.RawMessage(unsignedTransaction)

	bytes, err := rawIn.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var msg types.Message
	err = json.Unmarshal(bytes, &msg)
	if err != nil {
		return nil, err
	}

	ser, err := msg.Serialize()
	if err != nil {
		return nil, err
	}

	return r.Sign(ser, privateKey)
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

func (r RosettaConstructionFilecoin) Hash(signedMessage []byte) (string, error) {
	msg, err := r.ParseTx(signedMessage)
	if err != nil {
		return "", err
	}

	switch msg := msg.(type) {
		case types.SignedMessage:
				return msg.Cid().String(), nil
		default:
			return "", fmt.Errorf("Message need to be a SignedMessage")
	}
}

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

import "github.com/filecoin-project/go-address"
import "github.com/filecoin-project/lotus/lib/sigs"
import "github.com/filecoin-project/specs-actors/actors/crypto"

type RosettaConstructionFilecoin struct {
	Mainnet bool
}

func (r RosettaConstructionFilecoin) DeriveFromPublicKey(publicKey []byte) (string, error) {
	addr, err := address.NewSecp256k1Address(publicKey)
	if err != nil {
		return "", err
	}
	// FIXME: go=address does not allow setting a network

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

func (r RosettaConstructionFilecoin) ConstructPayment(request *PaymentRequest) (string, error) {
	panic("implement me")
}

func (r RosettaConstructionFilecoin) ConstructMultisigPayment(request *MultisigPaymentRequest) (string, error) {
	panic("implement me")
}

func (r RosettaConstructionFilecoin) ConstructSwapAuthorizedParty(request *MultisigPaymentRequest) (string, error) {
	panic("implement me")
}

func (r RosettaConstructionFilecoin) SignTx(unsignedTransaction string, privateKey []byte) (string, error) {
//	m := types.Message

	panic("implement me")
}

func (r RosettaConstructionFilecoin) ParseTx(request *ParseTxRequest) (interface{}, error) {
	panic("implement me")
}

func (r RosettaConstructionFilecoin) Hash(signedTx string) (string, error) {
	panic("implement me")
}

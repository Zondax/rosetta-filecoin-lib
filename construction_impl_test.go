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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/filecoin-project/specs-actors/actors/builtin"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
)

const MULTISIG_ADDRESS = "t020286"

var seqMutex sync.Mutex

func seq() func() {
	seqMutex.Lock()
	return func() {
		seqMutex.Unlock()
	}
}

func TestDeriveFromPublicKey(t *testing.T) {
	pk, err := hex.DecodeString("04fc016f3d88dc7070cdd95b5754d32fd5290f850b7c2208fca0f715d35861de1841d9a342a487692a63810a6c906b443a18aa804d9d508d69facc5b06789a01b4")
	if err != nil {
		t.Errorf("Invalid test case")
	}

	r := &RosettaConstructionFilecoin{false}

	testnetAddress, err := r.DeriveFromPublicKey(pk, address.Testnet)
	assert.NoError(t, err)
	assert.Equal(t, "t1rovwtiuo5ncslpmpjftzu5akswbgsgighjazxoi", testnetAddress)

	mainnetAddress, err := r.DeriveFromPublicKey(pk, address.Mainnet)
	assert.NoError(t, err)
	assert.Equal(t, "f1rovwtiuo5ncslpmpjftzu5akswbgsgighjazxoi", mainnetAddress)
}

func TestSign(t *testing.T) {
	unsignedTx := `{
    "To": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "From": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
    "Nonce": 1,
    "Value": "100000",
    "GasFeeCap": "1",
		"GasPremium": "1",
    "GasLimit": 25000,
    "Method": 0,
    "Params": ""
  }`
	sk, err := hex.DecodeString("f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a")
	if err != nil {
		t.Errorf(err.Error())
	}
	r := &RosettaConstructionFilecoin{false}

	rawIn := json.RawMessage(unsignedTx)

	bytes, err := rawIn.MarshalJSON()
	if err != nil {
		t.Errorf(err.Error())
	}

	var msg types.Message
	err = json.Unmarshal(bytes, &msg)
	if err != nil {
		t.Errorf(err.Error())
	}

	digest := msg.Cid().Bytes()

	sig, err := r.SignRaw(digest, sk)
	if err != nil {
		t.Errorf(err.Error())
	}

	if base64.StdEncoding.EncodeToString(sig) != "nFuTI7MxEXqTQ0QmmQTmqbUsNZfHFXlNjz+susVDkAk1SrRCdJKxlVZZrM4vUtVBSYgtMIeigNfpqdKGIFhoWQA=" {
		t.Fail()
	}

}

func TestVerify(t *testing.T) {
	unsignedTx := `{
    "To": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "From": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
    "Nonce": 1,
    "Value": "100000",
		"GasFeeCap": "1",
		"GasPremium": "1",
    "GasLimit": 25000,
    "Method": 0,
    "Params": ""
  }`

	pk, err := hex.DecodeString("0435e752dc6b4113f78edcf2cf7b8082e442021de5f00818f555397a6f181af795ace98f0f7d065793eaffa1b06bf52e572c97030c53a2396dfab40ba0e976b108")
	if err != nil {
		t.Errorf(err.Error())
	}
	sig, err := base64.StdEncoding.DecodeString("nFuTI7MxEXqTQ0QmmQTmqbUsNZfHFXlNjz+susVDkAk1SrRCdJKxlVZZrM4vUtVBSYgtMIeigNfpqdKGIFhoWQA=")
	if err != nil {
		t.Errorf(err.Error())
	}
	r := &RosettaConstructionFilecoin{false}

	rawIn := json.RawMessage(unsignedTx)

	bytes, err := rawIn.MarshalJSON()
	if err != nil {
		t.Errorf(err.Error())
	}

	var msg types.Message
	err = json.Unmarshal(bytes, &msg)
	if err != nil {
		t.Errorf(err.Error())
	}

	digest := msg.Cid().Bytes()

	err = r.VerifyRaw(digest, pk, sig)

	if err != nil {
		t.Fail()
	}

}

func TestConstructPayment(t *testing.T) {
	expected := `{"Version":0,"To":"t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy","From":"t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba","Nonce":1,"Value":"100000","GasLimit":25000,"GasFeeCap":"1","GasPremium":"1","Method":0,"Params":""}`
	r := &RosettaConstructionFilecoin{false}
	mtx := TxMetadata{
		Nonce:      1,
		GasFeeCap:  1,
		GasPremium: 1,
		GasLimit:   25000,
	}
	pr := &PaymentRequest{
		From:     "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
		To:       "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
		Quantity: 100000,
		Metadata: mtx,
	}

	tx, err := r.ConstructPayment(pr)
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Equal(t, tx, expected)
}

func TestConstructMultisigPayment(t *testing.T) {
	expected := `{"Version":0,"To":"t01002","From":"t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba","Nonce":1,"Value":"0","GasLimit":25000,"GasFeeCap":"1","GasPremium":"1","Method":2,"Params":"hFUB/R0PTfzX6Zr8uZqDJrfcRZ0yxihDAAPoAEA="}`
	r := &RosettaConstructionFilecoin{false}
	mtx := TxMetadata{
		Nonce:      1,
		GasFeeCap:  1,
		GasPremium: 1,
		GasLimit:   25000,
	}
	params := MultisigPaymentParams{
		To:       "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
		Quantity: 1000,
	}
	request := &MultisigPaymentRequest{
		Multisig: "t01002",
		From:     "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
		Metadata: mtx,
		Params:   params,
	}

	tx, err := r.ConstructMultisigPayment(request)
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Equal(t, tx, expected)
}

func TestConstructSwapAuthorizedParty(t *testing.T) {
	expected := `{"Version":0,"To":"t01002","From":"t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy","Nonce":1,"Value":"0","GasLimit":25000,"GasFeeCap":"1","GasPremium":"1","Method":2,"Params":"hEMA6gdAB1gtglUB3+SRhNRq3I+J1EY4vrRfePytJZBVAeQ8w10L4iTPA9V+iE3/tipwhzV8"}`
	r := &RosettaConstructionFilecoin{false}
	mtx := TxMetadata{
		Nonce:      1,
		GasFeeCap:  1,
		GasPremium: 1,
		GasLimit:   25000,
	}
	params := SwapAuthorizedPartyParams{
		From: "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy",
		To:   "t14q6mgxil4ism6a6vp2ee375wfjyionl46wtle5q",
	}
	request := &SwapAuthorizedPartyRequest{
		Multisig: "t01002",
		From:     "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy",
		Metadata: mtx,
		Params:   params,
	}

	tx, err := r.ConstructSwapAuthorizedParty(request)
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Equal(t, tx, expected)
}

func TestSignTx(t *testing.T) {
	unsignedTx := `{"Version":0,"To":"t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy","From":"t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba","Nonce":1,"Value":"100000","GasFeeCap":"1","GasPremium":"1","GasLimit":25000,"Method":0,"Params":""}`
	sk := "f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a"
	r := &RosettaConstructionFilecoin{false}

	skBytes, err := hex.DecodeString(sk)
	if err != nil {
		t.Errorf("Invalid test case")
	}

	signedTx, err := r.SignTxJSON(unsignedTx, skBytes)
	if err != nil {
		t.Error(err)
	}

	t.Log(signedTx)

	rawIn := json.RawMessage(signedTx)

	bytes, err := rawIn.MarshalJSON()
	if err != nil {
		t.Errorf("Not a json string")
	}

	var msg types.SignedMessage
	err = json.Unmarshal(bytes, &msg)
	if err != nil {
		t.Errorf("Not a SignedMessage")
	}

	dataSignature := base64.StdEncoding.EncodeToString(msg.Signature.Data)
	if dataSignature != "nFuTI7MxEXqTQ0QmmQTmqbUsNZfHFXlNjz+susVDkAk1SrRCdJKxlVZZrM4vUtVBSYgtMIeigNfpqdKGIFhoWQA=" {
		t.Fail()
	}

}

func TestParseTx(t *testing.T) {
	expected := `{"Version":0,"To":"t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy","From":"t1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi","Nonce":1,"Value":"100000","GasLimit":25000,"GasFeeCap":"1","GasPremium":"1","Method":0,"Params":null}`
	serializedTx := "8A005501FD1D0F4DFCD7E99AFCB99A8326B7DC459D32C6285501B882619D46558F3D9E316D11B48DCF211327025A0144000186A01961A84200014200010040"

	r := &RosettaConstructionFilecoin{false}
	blob, err := hex.DecodeString(serializedTx)

	if err != nil {
		t.Errorf("Invalid test case")
	}

	msgJson, err := r.ParseTx(blob)

	t.Log(msgJson)

	if err != nil {
		t.Errorf("Parsing failed")
	}

	assert.Equal(t, msgJson, expected)
}

func TestExpandMultisigJSON(t *testing.T) {
	expectedParams := `{"To":"t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy","Value":"1000","Method":0,"Params":null}`

	r := &RosettaConstructionFilecoin{false}
	mtx := TxMetadata{
		Nonce:      1,
		GasFeeCap:  1,
		GasPremium: 1,
		GasLimit:   25000,
	}

	request := &MultisigPaymentRequest{
		Multisig: "t01002",
		From:     "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
		Metadata: mtx,
		Params: MultisigPaymentParams{
			To:       "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
			Quantity: 1000,
		},
	}

	tx, err := r.ConstructMultisigPayment(request)
	if err != nil {
		t.Errorf(err.Error())
	}

	expandedParams, err := r.ParseParamsMultisigTx(tx, builtin.MultisigActorCodeID)
	if err != nil {
		t.Errorf(err.Error())
	}

	t.Log(tx)
	t.Log(expandedParams)

	assert.Equal(t, expectedParams, expandedParams)
}

func TestHash(t *testing.T) {
	signedTx := `{
    "Message": {
      "To": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
      "From": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
      "Nonce": 1,
      "Value": "100000",
      "GasFeeCap": "1",
  	  "GasPremium": "1",
      "GasLimit": 2500000,
      "Method": 0,
      "Params": ""
    },
    "Signature": {
      "Type": 1,
      "Data": "0wRrFJZFIVh8m0JD+f5C55YrxD6YAWtCXWYihrPTKdMfgMhYAy86MVhs43hSLXnV+47UReRIe8qFdHRJqFlreAE="
    }
  }`
	r := &RosettaConstructionFilecoin{false}

	cid, err := r.Hash(signedTx)

	if err != nil {
		t.Errorf("Something went Wrong")
	}

	t.Log(cid)
	assert.Equal(t, cid, "bafy2bzacebaiinljwwctblf7czp4zxwhz4747z6tpricgn5cumd4xhebftcvu")
}

/*  On Chain Tests */

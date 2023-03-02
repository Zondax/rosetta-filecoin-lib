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
	"sync"
	"testing"

	"github.com/filecoin-project/go-state-types/manifest"
	"github.com/ipfs/go-cid"
	"github.com/zondax/rosetta-filecoin-lib/actors"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/stretchr/testify/assert"
)

const (
	MULTISIG_ADDRESS          = "t01005"
	EXPECTED                  = `{"Version":0,"To":"f01002","From":"f137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy","Nonce":1,"Value":"0","GasLimit":25000,"GasFeeCap":"1","GasPremium":"1","Method":2,"Params":"hEMA6gdABlgYglUB5DzDXQviJM8D1X6ITf+2KnCHNXz0","CID":{"/":"bafy2bzacebjapltkq2nazgzxinzgxd4y4wrr227qhbvto3e4fdzy5rcr2vzs6"}}`
	EXPECTED_MULTISIG_PAYMENT = `{"Version":0,"To":"f01002","From":"f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba","Nonce":1,"Value":"0","GasLimit":25000,"GasFeeCap":"1","GasPremium":"1","Method":2,"Params":"hFUB/R0PTfzX6Zr8uZqDJrfcRZ0yxihDAAPoAEA=","CID":{"/":"bafy2bzaceaeyq6sksxeo7yoftkblpt6sd5umv34ha3qjdubk52u4rxleiq6eo"}}`
	EXPECTED_SWAP_AUTHORIZED  = `{"Version":0,"To":"f01002","From":"f137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy","Nonce":1,"Value":"0","GasLimit":25000,"GasFeeCap":"1","GasPremium":"1","Method":2,"Params":"hEMA6gdAB1gtglUB3+SRhNRq3I+J1EY4vrRfePytJZBVAeQ8w10L4iTPA9V+iE3/tipwhzV8","CID":{"/":"bafy2bzacebyohxxqn66r22dumjqcqyuqqdehz5jrnrwwcnycezyaakc45glp6"}}`
	EXPECTED_SIGNATURE        = "nFuTI7MxEXqTQ0QmmQTmqbUsNZfHFXlNjz+susVDkAk1SrRCdJKxlVZZrM4vUtVBSYgtMIeigNfpqdKGIFhoWQA="
)

var seqMutex sync.Mutex

func seq() func() {
	seqMutex.Lock()
	return func() {
		seqMutex.Unlock()
	}
}

func verify(unsignedTx string, pkHex string, sigBase64 string) error {
	pk, err := hex.DecodeString(pkHex)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return err
	}
	r := NewRosettaConstructionFilecoin(nil)

	rawIn := json.RawMessage(unsignedTx)

	bytes, err := rawIn.MarshalJSON()
	if err != nil {
		return err
	}

	var msg types.Message
	err = json.Unmarshal(bytes, &msg)
	if err != nil {
		return err
	}

	digest := msg.Cid().Bytes()

	err = r.VerifyRaw(digest, pk, sig)

	if err != nil {
		return err
	}

	return nil
}

func TestDeriveFromPublicKey(t *testing.T) {
	rosettaLib := NewRosettaConstructionFilecoin(nil)
	testActorCidMap := make(map[string]cid.Cid)
	testActorCidMap[manifest.MultisigKey] = cid.Cid{}
	rosettaLib.BuiltinActors.Metadata.ActorsNameCidMap = testActorCidMap

	pk, err := hex.DecodeString("04fc016f3d88dc7070cdd95b5754d32fd5290f850b7c2208fca0f715d35861de1841d9a342a487692a63810a6c906b443a18aa804d9d508d69facc5b06789a01b4")
	if err != nil {
		t.Errorf("Invalid test case")
	}

	testnetAddress, err := rosettaLib.DeriveFromPublicKey(pk, address.Testnet)
	assert.NoError(t, err)
	assert.Equal(t, "t1rovwtiuo5ncslpmpjftzu5akswbgsgighjazxoi", testnetAddress)

	mainnetAddress, err := rosettaLib.DeriveFromPublicKey(pk, address.Mainnet)
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

	rosettaLib := NewRosettaConstructionFilecoin(nil)
	testActorCidMap := make(map[string]cid.Cid)
	testActorCidMap[manifest.MultisigKey] = cid.Cid{}
	rosettaLib.BuiltinActors.Metadata.ActorsNameCidMap = testActorCidMap

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

	sig, err := rosettaLib.SignRaw(digest, sk)
	if err != nil {
		t.Errorf(err.Error())
	}

	if base64.StdEncoding.EncodeToString(sig) != EXPECTED_SIGNATURE {
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

	pkHex := "0435e752dc6b4113f78edcf2cf7b8082e442021de5f00818f555397a6f181af795ace98f0f7d065793eaffa1b06bf52e572c97030c53a2396dfab40ba0e976b108"

	sigBase64 := EXPECTED_SIGNATURE

	err := verify(unsignedTx, pkHex, sigBase64)
	if err != nil {
		t.Fail()
	}
}

func TestVerify2(t *testing.T) {
	unsignedTx := `{
		"To": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
		"From": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
		"Nonce": 1,
		"Value": "100000",
		"GasFeeCap": "1",
		"GasPremium": "1",
		"GasLimit": 2500000,
		"Method": 0,
		"Params": ""
  }`

	pkHex := "0435e752dc6b4113f78edcf2cf7b8082e442021de5f00818f555397a6f181af795ace98f0f7d065793eaffa1b06bf52e572c97030c53a2396dfab40ba0e976b108"
	sigBase64 := "0wRrFJZFIVh8m0JD+f5C55YrxD6YAWtCXWYihrPTKdMfgMhYAy86MVhs43hSLXnV+47UReRIe8qFdHRJqFlreAE="

	err := verify(unsignedTx, pkHex, sigBase64)
	if err != nil {
		t.Fail()
	}
}

func TestConstructPayment(t *testing.T) {
	expected := `{"Version":0,"To":"f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy","From":"f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba","Nonce":1,"Value":"100000","GasLimit":25000,"GasFeeCap":"1","GasPremium":"1","Method":0,"Params":"","CID":{"/":"bafy2bzaceduq6pnkpz7xhs6d24epnu47hjpn3oucoq3xnkc4g5b7hgcdw4now"}}`
	rosettaLib := NewRosettaConstructionFilecoin(nil)
	testActorCidMap := make(map[string]cid.Cid)
	testActorCidMap[manifest.MultisigKey] = cid.Cid{}
	rosettaLib.BuiltinActors.Metadata.ActorsNameCidMap = testActorCidMap

	mtx := TxMetadata{
		Nonce:      1,
		GasFeeCap:  "1",
		GasPremium: "1",
		GasLimit:   25000,
	}
	pr := &PaymentRequest{
		From:     "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
		To:       "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
		Quantity: "100000",
		Metadata: mtx,
	}

	tx, err := rosettaLib.ConstructPayment(pr)
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Equal(t, expected, tx)
}

func TestConstructPayment_f410(t *testing.T) {
	expected := `{"Version":0,"To":"f410f4wpf3mfwravsgjzsgaaxzc7aj3dxplmfqylctxy","From":"f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba","Nonce":1,"Value":"100000","GasLimit":25000,"GasFeeCap":"1","GasPremium":"1","Method":3844450837,"Params":"","CID":{"/":"bafy2bzaceaoqmxcyaoffakwxhu6amadvkufd2wphlkejvfqkup5q26sh7no5o"}}`
	rosettaLib := NewRosettaConstructionFilecoin(nil)
	testActorCidMap := make(map[string]cid.Cid)
	testActorCidMap[manifest.MultisigKey] = cid.Cid{}
	rosettaLib.BuiltinActors.Metadata.ActorsNameCidMap = testActorCidMap

	mtx := TxMetadata{
		Nonce:      1,
		GasFeeCap:  "1",
		GasPremium: "1",
		GasLimit:   25000,
	}
	pr := &PaymentRequest{
		From:     "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
		To:       "f410f4wpf3mfwravsgjzsgaaxzc7aj3dxplmfqylctxy",
		Quantity: "100000",
		Metadata: mtx,
	}

	tx, err := rosettaLib.ConstructPayment(pr)
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Equal(t, expected, tx)
}

func TestConstructMultisigPaymentLatest(t *testing.T) {
	expected := EXPECTED_MULTISIG_PAYMENT
	rosettaLib := NewRosettaConstructionFilecoin(nil)
	testActorCidMap := make(map[string]cid.Cid)
	testActorCidMap[manifest.MultisigKey] = cid.Cid{}
	rosettaLib.BuiltinActors.Metadata.ActorsNameCidMap = testActorCidMap

	mtx := TxMetadata{
		Nonce:      1,
		GasFeeCap:  "1",
		GasPremium: "1",
		GasLimit:   25000,
	}
	params := MultisigPaymentParams{
		To:       "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
		Quantity: "1000",
	}
	request := &MultisigPaymentRequest{
		Multisig: "t01002",
		From:     "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
		Metadata: mtx,
		Params:   params,
	}

	tx, err := rosettaLib.ConstructMultisigPayment(request)
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Equal(t, expected, tx)
}

func TestConstructSwapAuthorizedPartyLatest(t *testing.T) {
	expected := EXPECTED_SWAP_AUTHORIZED
	rosettaLib := NewRosettaConstructionFilecoin(nil)
	testActorCidMap := make(map[string]cid.Cid)
	testActorCidMap[manifest.MultisigKey] = cid.Cid{}
	rosettaLib.BuiltinActors.Metadata.ActorsNameCidMap = testActorCidMap

	mtx := TxMetadata{
		Nonce:      1,
		GasFeeCap:  "1",
		GasPremium: "1",
		GasLimit:   25000,
	}
	params := SwapAuthorizedPartyParams{
		From: "f137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy",
		To:   "f14q6mgxil4ism6a6vp2ee375wfjyionl46wtle5q",
	}
	request := &SwapAuthorizedPartyRequest{
		Multisig: "f01002",
		From:     "f137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy",
		Metadata: mtx,
		Params:   params,
	}

	tx, err := rosettaLib.ConstructSwapAuthorizedParty(request)
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Equal(t, expected, tx)
}

func TestConstructRemoveAuthorizedPartyLatest(t *testing.T) {
	expected := EXPECTED
	rosettaLib := NewRosettaConstructionFilecoin(nil)
	testActorCidMap := make(map[string]cid.Cid)
	testActorCidMap[manifest.MultisigKey] = cid.Cid{}
	rosettaLib.BuiltinActors.Metadata.ActorsNameCidMap = testActorCidMap

	mtx := TxMetadata{
		Nonce:      1,
		GasFeeCap:  "1",
		GasPremium: "1",
		GasLimit:   25000,
	}
	params := RemoveAuthorizedPartyParams{
		ToRemove: "f14q6mgxil4ism6a6vp2ee375wfjyionl46wtle5q",
		Decrease: false,
	}
	request := &RemoveAuthorizedPartyRequest{
		Multisig: "f01002",
		From:     "f137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy",
		Metadata: mtx,
		Params:   params,
	}

	tx, err := rosettaLib.ConstructRemoveAuthorizedParty(request)
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Equal(t, expected, tx)
}

func TestSignTx(t *testing.T) {
	unsignedTx := `{"Version":0,"To":"t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy","From":"t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba","Nonce":1,"Value":"100000","GasFeeCap":"1","GasPremium":"1","GasLimit":25000,"Method":0,"Params":""}`
	sk := "f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a"
	rosettaLib := NewRosettaConstructionFilecoin(nil)
	testActorCidMap := make(map[string]cid.Cid)
	testActorCidMap[manifest.MultisigKey] = cid.Cid{}
	rosettaLib.BuiltinActors.Metadata.ActorsNameCidMap = testActorCidMap

	skBytes, err := hex.DecodeString(sk)
	if err != nil {
		t.Errorf("Invalid test case")
	}

	signedTx, err := rosettaLib.SignTxJSON(unsignedTx, skBytes)
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
	if dataSignature != EXPECTED_SIGNATURE {
		t.Fail()
	}

}

func TestParseTx(t *testing.T) {
	expected := `{"Version":0,"To":"f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy","From":"f1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi","Nonce":1,"Value":"100000","GasLimit":25000,"GasFeeCap":"1","GasPremium":"1","Method":0,"Params":null,"CID":{"/":"bafy2bzaceb4ppnxrndvbonqhmf2yqtlvtde7ojsnsv453nnrckchvnkpyvkrm"}}`
	serializedTx := "8A005501FD1D0F4DFCD7E99AFCB99A8326B7DC459D32C6285501B882619D46558F3D9E316D11B48DCF211327025A0144000186A01961A84200014200010040"

	rosettaLib := NewRosettaConstructionFilecoin(nil)
	testActorCidMap := make(map[string]cid.Cid)
	testActorCidMap[manifest.MultisigKey] = cid.Cid{}
	rosettaLib.BuiltinActors.Metadata.ActorsNameCidMap = testActorCidMap

	blob, err := hex.DecodeString(serializedTx)

	if err != nil {
		t.Errorf("Invalid test case")
	}

	msgJson, err := rosettaLib.ParseTx(blob)

	t.Log(msgJson)

	if err != nil {
		t.Errorf("Parsing failed")
	}

	assert.Equal(t, expected, msgJson)
}

func TestGasFieldOrderParse(t *testing.T) {
	expected := `{"Version":0,"To":"f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy","From":"f1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi","Nonce":1,"Value":"100000","GasLimit":25000,"GasFeeCap":"2","GasPremium":"1","Method":0,"Params":null,"CID":{"/":"bafy2bzaceae65bxgk6ur35lx4cs6e3hrk52my44p4l7trfsgwrttsriogh3ww"}}`
	serializedTx := "8A005501FD1D0F4DFCD7E99AFCB99A8326B7DC459D32C6285501B882619D46558F3D9E316D11B48DCF211327025A0144000186A01961A84200024200010040"

	rosettaLib := NewRosettaConstructionFilecoin(nil)
	testActorCidMap := make(map[string]cid.Cid)
	testActorCidMap[manifest.MultisigKey] = cid.Cid{}
	rosettaLib.BuiltinActors.Metadata.ActorsNameCidMap = testActorCidMap

	blob, err := hex.DecodeString(serializedTx)

	if err != nil {
		t.Errorf("Invalid test case")
	}

	msgJson, err := rosettaLib.ParseTx(blob)

	t.Log(msgJson)

	if err != nil {
		t.Errorf("Parsing failed")
	}

	assert.Equal(t, expected, msgJson)
}

func TestParseParamsMultisigPaymentTx(t *testing.T) {
	expectedParams := `{"To":"f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy","Value":"1000","Method":0,"Params":null}`

	rosettaLib := NewRosettaConstructionFilecoin(nil)
	testActorCidMap := make(map[string]cid.Cid)
	testActorCidMap[manifest.MultisigKey] = cid.Cid{}
	rosettaLib.BuiltinActors.Metadata.ActorsNameCidMap = testActorCidMap

	mtx := TxMetadata{
		Nonce:      1,
		GasFeeCap:  "1",
		GasPremium: "1",
		GasLimit:   25000,
	}

	request := &MultisigPaymentRequest{
		Multisig: "f01002",
		From:     "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
		Metadata: mtx,
		Params: MultisigPaymentParams{
			To:       "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
			Quantity: "1000",
		},
	}

	msigActorCidLatest, err := rosettaLib.BuiltinActors.GetActorCid(actors.ActorMultisigName)
	if err != nil {
		t.Errorf(err.Error())
	}

	txLatest, err := rosettaLib.ConstructMultisigPayment(request)
	if err != nil {
		t.Errorf(err.Error())
	}

	expandedParamsLatest, err := rosettaLib.ParseParamsMultisigTx(txLatest, msigActorCidLatest)
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Equal(t, expectedParams, expandedParamsLatest)
}

func TestParseParamsMultisigSwapAuthTx(t *testing.T) {
	expectedParamsPrevious := `{"From":"f137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy","To":"f14q6mgxil4ism6a6vp2ee375wfjyionl46wtle5q"}`
	expectedParamsLatest := expectedParamsPrevious

	rosettaLib := NewRosettaConstructionFilecoin(nil)
	testActorCidMap := make(map[string]cid.Cid)
	testActorCidMap[manifest.MultisigKey] = cid.Cid{}
	rosettaLib.BuiltinActors.Metadata.ActorsNameCidMap = testActorCidMap

	mtx := TxMetadata{
		Nonce:      1,
		GasFeeCap:  "1",
		GasPremium: "1",
		GasLimit:   25000,
	}

	params := SwapAuthorizedPartyParams{
		From: "f137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy",
		To:   "f14q6mgxil4ism6a6vp2ee375wfjyionl46wtle5q",
	}
	request := &SwapAuthorizedPartyRequest{
		Multisig: "f01002",
		From:     "f137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy",
		Metadata: mtx,
		Params:   params,
	}

	msigActorCidLatest, err := rosettaLib.BuiltinActors.GetActorCid(actors.ActorMultisigName)
	if err != nil {
		t.Errorf(err.Error())
	}

	txLatest, err := rosettaLib.ConstructSwapAuthorizedParty(request)
	if err != nil {
		t.Errorf(err.Error())
	}

	expandedParamsLatest, err := rosettaLib.ParseParamsMultisigTx(txLatest, msigActorCidLatest)
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Equal(t, expectedParamsLatest, expandedParamsLatest)
}

func TestParseParamsMultisigRemoveSignerTx(t *testing.T) {
	expectedParamsPrevious := `{"Signer":"f14q6mgxil4ism6a6vp2ee375wfjyionl46wtle5q","Decrease":false}`
	expectedParamsLatest := expectedParamsPrevious

	rosettaLib := NewRosettaConstructionFilecoin(nil)
	testActorCidMap := make(map[string]cid.Cid)
	testActorCidMap[manifest.MultisigKey] = cid.Cid{}
	rosettaLib.BuiltinActors.Metadata.ActorsNameCidMap = testActorCidMap

	mtx := TxMetadata{
		Nonce:      1,
		GasFeeCap:  "1",
		GasPremium: "1",
		GasLimit:   25000,
	}

	params := RemoveAuthorizedPartyParams{
		ToRemove: "f14q6mgxil4ism6a6vp2ee375wfjyionl46wtle5q",
		Decrease: false,
	}
	request := &RemoveAuthorizedPartyRequest{
		Multisig: "f01002",
		From:     "f137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy",
		Metadata: mtx,
		Params:   params,
	}

	msigActorCidLatest, err := rosettaLib.BuiltinActors.GetActorCid(actors.ActorMultisigName)
	if err != nil {
		t.Errorf(err.Error())
	}

	txLatest, err := rosettaLib.ConstructRemoveAuthorizedParty(request)
	if err != nil {
		t.Errorf(err.Error())
	}

	expandedParamsLatest, err := rosettaLib.ParseParamsMultisigTx(txLatest, msigActorCidLatest)
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Equal(t, expectedParamsLatest, expandedParamsLatest)
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
	rosettaLib := NewRosettaConstructionFilecoin(nil)
	testActorCidMap := make(map[string]cid.Cid)
	testActorCidMap[manifest.MultisigKey] = cid.Cid{}
	rosettaLib.BuiltinActors.Metadata.ActorsNameCidMap = testActorCidMap

	responseCID, err := rosettaLib.Hash(signedTx)

	if err != nil {
		t.Errorf("Something went Wrong")
	}

	t.Log(responseCID)
	assert.Equal(t, responseCID, "bafy2bzacebaiinljwwctblf7czp4zxwhz4747z6tpricgn5cumd4xhebftcvu")
}

func TestEthToFilAddress(t *testing.T) {
	// Test from lotus ethtypes_test.go
	var ethAddress = "ff00000000000000000000000000000000000001"
	f4Addr, err := EthereumAddressToFilecoin(ethAddress)

	if err != nil {
		t.Errorf("Something went Wrong")
	}
	t.Log(f4Addr)
	assert.Equal(t, f4Addr.String(), "f01")
	a, _ := address.NewIDAddress(1)
	ethAddressFound, _ := FilToEthAddress(a)
	assert.Equal(t, ethAddressFound.String(), ethAddress)

	ethAddress = "ff00000000000000000000000000000000000002"
	f4Addr, err = EthereumAddressToFilecoin(ethAddress)

	if err != nil {
		t.Errorf("Something went Wrong")
	}
	t.Log(f4Addr)
	assert.Equal(t, f4Addr.String(), "f02")
	a, _ = address.NewIDAddress(2)
	ethAddressFound, _ = FilToEthAddress(a)
	assert.Equal(t, ethAddressFound.String(), ethAddress)

	ethAddress = "ff00000000000000000000000000000000000003"
	f4Addr, err = EthereumAddressToFilecoin(ethAddress)

	if err != nil {
		t.Errorf("Something went Wrong")
	}
	t.Log(f4Addr)
	assert.Equal(t, f4Addr.String(), "f03")
	a, _ = address.NewIDAddress(3)
	ethAddressFound, _ = FilToEthAddress(a)
	assert.Equal(t, ethAddressFound.String(), ethAddress)

	ethAddress = "ff00000000000000000000000000000000000064"
	f4Addr, err = EthereumAddressToFilecoin(ethAddress)

	if err != nil {
		t.Errorf("Something went Wrong")
	}
	t.Log(f4Addr)
	assert.Equal(t, f4Addr.String(), "f0100")
	a, _ = address.NewIDAddress(100)
	ethAddressFound, _ = FilToEthAddress(a)
	assert.Equal(t, ethAddressFound.String(), ethAddress)

	ethAddress = "ff00000000000000000000000000000000000065"
	f4Addr, err = EthereumAddressToFilecoin(ethAddress)

	if err != nil {
		t.Errorf("Something went Wrong")
	}
	t.Log(f4Addr)
	assert.Equal(t, f4Addr.String(), "f0101")
	a, _ = address.NewIDAddress(101)
	ethAddressFound, _ = FilToEthAddress(a)
	assert.Equal(t, ethAddressFound.String(), ethAddress)

	var ethHexaddr = "d4c5fb16488Aa48081296299d54b0c648C9333dA"
	f4Addr, err = EthereumAddressToFilecoin(ethHexaddr)

	if err != nil {
		t.Errorf("Something went Wrong")
	}
	t.Log(f4Addr)
	assert.Equal(t, f4Addr.String(), "f410f2tc7wfsirksibajjmkm5ksymmsgjgm62hjnomwa")
	a, _ = address.NewFromString("f410f2tc7wfsirksibajjmkm5ksymmsgjgm62hjnomwa")
	ethAddressFound, _ = FilToEthAddress(a)
	assert.Equal(t, ethAddressFound.String(), ethAddress)

	ethHexaddr = "0xd4c5fb16488Aa48081296299d54b0c648C9333dA"
	f4Addr, err = EthereumAddressToFilecoin(ethHexaddr)

	if err != nil {
		t.Errorf("Something went Wrong")
	}
	t.Log(f4Addr)
	assert.Equal(t, f4Addr.String(), "f410f2tc7wfsirksibajjmkm5ksymmsgjgm62hjnomwa")
	a, _ = address.NewFromString("f410f2tc7wfsirksibajjmkm5ksymmsgjgm62hjnomwa")
	ethAddressFound, _ = FilToEthAddress(a)
	assert.Equal(t, ethAddressFound.String(), ethAddress)
}

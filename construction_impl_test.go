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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/filecoin-project/lotus/chain/types"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestDeriveFromPublicKey(t *testing.T) {
	pk, err := hex.DecodeString("04fc016f3d88dc7070cdd95b5754d32fd5290f850b7c2208fca0f715d35861de1841d9a342a487692a63810a6c906b443a18aa804d9d508d69facc5b06789a01b4")
	if err != nil {
		t.Errorf("Invalid test case")
	}

	r := &RosettaConstructionFilecoin{false}

	address, err := r.DeriveFromPublicKey(pk)
	if err != nil {
		t.Errorf("FIX ME")
	}

	if address != "t1rovwtiuo5ncslpmpjftzu5akswbgsgighjazxoi" {
		t.Fail()
	}

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
		t.Errorf("FIX ME")
	}
	r := &RosettaConstructionFilecoin{false}

	rawIn := json.RawMessage(unsignedTx)

	bytes, err := rawIn.MarshalJSON()
	if err != nil {
		t.Errorf("FIX ME")
	}

	var msg types.Message
	err = json.Unmarshal(bytes, &msg)
	if err != nil {
		t.Errorf("FIX ME")
	}

	digest := msg.Cid().Bytes()

	sig, err := r.Sign(digest, sk)
	if err != nil {
		t.Errorf("FIX ME")
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
		t.Errorf("FIX ME")
	}
	sig, err := base64.StdEncoding.DecodeString("nFuTI7MxEXqTQ0QmmQTmqbUsNZfHFXlNjz+susVDkAk1SrRCdJKxlVZZrM4vUtVBSYgtMIeigNfpqdKGIFhoWQA=")
	if err != nil {
		t.Errorf("FIX ME")
	}
	r := &RosettaConstructionFilecoin{false}

	rawIn := json.RawMessage(unsignedTx)

	bytes, err := rawIn.MarshalJSON()
	if err != nil {
		t.Errorf("FIX ME")
	}

	var msg types.Message
	err = json.Unmarshal(bytes, &msg)
	if err != nil {
		t.Errorf("FIX ME")
	}

	digest := msg.Cid().Bytes()

	err = r.Verify(digest, pk, sig)

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

	txBase64, err := r.ConstructPayment(pr)
	if err != nil {
		t.Errorf("FIX ME")
	}

	if txBase64 != base64.StdEncoding.EncodeToString([]byte(expected)) {
		t.Fail()
	}

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

	txBase64, err := r.ConstructMultisigPayment(request)
	if err != nil {
		t.Errorf("FIX ME")
	}

	if txBase64 != base64.StdEncoding.EncodeToString([]byte(expected)) {
		t.Fail()
	}
}

func TestConstructSwapAuthorizedParty(t *testing.T) {
	expected := `{"Version":0,"To":"t01002","From":"t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba","Nonce":1,"Value":"0","GasLimit":25000,"GasFeeCap":"1","GasPremium":"1","Method":7,"Params":"glUB/R0PTfzX6Zr8uZqDJrfcRZ0yxihYMQOuzzY13jMOTmpShDszOIxbNhcAhlxVLRYZmVI87UlsVOZXuGJil7OSixyQSOsTXug="}`
	r := &RosettaConstructionFilecoin{false}
	mtx := TxMetadata{
		Nonce:      1,
		GasFeeCap:  1,
		GasPremium: 1,
		GasLimit:   25000,
	}
	params := SwapAuthorizedPartyParams{
		From: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
		To:   "t3v3htmno6gmhe42ssqq5tgoemlm3boaeglrks2fqztfjdz3kjnrkomv5ymjrjpm4srmojashlcnporcluiyaa",
	}
	request := &SwapAuthorizedPartyRequest{
		Multisig: "t01002",
		From:     "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
		Metadata: mtx,
		Params:   params,
	}

	txBase64, err := r.ConstructSwapAuthorizedParty(request)
	if err != nil {
		t.Errorf("FIX ME")
	}

	if txBase64 != base64.StdEncoding.EncodeToString([]byte(expected)) {
		t.Fail()
	}

}

func TestSignTx(t *testing.T) {
	unsignedTxBase64 := "eyJWZXJzaW9uIjowLCJUbyI6InQxN3VvcTZ0cDQyN3V6djdmenRrYnNubjY0aXdvdGZycmlzdHdwcnl5IiwiRnJvbSI6InQxZDJ4cnpjc2x4N3hsYmJ5bGM1YzNkNWx2YW5kcXc0aXdsNmVweGJhIiwiTm9uY2UiOjEsIlZhbHVlIjoiMTAwMDAwIiwiR2FzRmVlQ2FwIjoiMSIsIkdhc1ByZW1pdW0iOiIxIiwiR2FzTGltaXQiOjI1MDAwLCJNZXRob2QiOjAsIlBhcmFtcyI6IiJ9"
	sk := "f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a"
	r := &RosettaConstructionFilecoin{false}

	skBytes, err := hex.DecodeString(sk)

	if err != nil {
		t.Errorf("Invalid test case")
	}

	signedTx, err := r.SignTx(unsignedTxBase64, skBytes)
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
	b, err := hex.DecodeString(serializedTx)

	msgBase64 := base64.StdEncoding.EncodeToString(b)

	if err != nil {
		t.Errorf("Invalid test case")
	}

	msg, err := r.ParseTx(msgBase64)

	t.Log(msg)

	if err != nil {
		t.Errorf("Parsing failed")
	}

	if msg != base64.StdEncoding.EncodeToString([]byte(expected)) {
		t.Fail()
	}

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

	if cid != "bafy2bzacebaiinljwwctblf7czp4zxwhz4747z6tpricgn5cumd4xhebftcvu" {
		t.Fail()
	}
}

/*  On Chain Tests */

// send from regular address
func TestSendTransaction(t *testing.T) {
	/* Secret Key */
	sk, _ := hex.DecodeString("f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a")

	/* Get Nonce */
	data := []byte(`{"jsonrpc": "2.0","method": "Filecoin.MpoolGetNonce","id": 1, "params": ["t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"]}`)

	req, err := http.NewRequest("POST", os.Getenv("LOTUS_URL"), bytes.NewBuffer(data))
	if err != nil {
		t.Errorf("Fail to get nonce")
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("LOTUS_JWT"))

	// Set client timeout
	client := &http.Client{Timeout: time.Second * 10}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("Fail to get nonce")
	}

	var res map[string]interface{}

	t.Log(resp)

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		t.Errorf("FIX ME")
	}

	t.Log(res["result"])

	nonce := res["result"].(float64)
	if err != nil {
		t.Errorf("FIX ME")
	}

	/* Create Transaction */

	r := &RosettaConstructionFilecoin{false}
	mtx := TxMetadata{
		Nonce:      uint64(nonce) + 1,
		GasFeeCap:  2500,
		GasPremium: 2500,
		GasLimit:   2500000,
	}
	pr := &PaymentRequest{
		From:     "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
		To:       "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
		Quantity: 100000,
		Metadata: mtx,
	}

	unsignedTxBase64, err := r.ConstructPayment(pr)
	if err != nil {
		t.Errorf("FIX ME")
	}

	signedTx, err := r.SignTx(unsignedTxBase64, sk)
	if err != nil {
		t.Error(err)
	}

	t.Log(signedTx)

	data = []byte(`{"jsonrpc": "2.0","method": "Filecoin.MpoolPush","id": 1, "params": [` + signedTx + `]}`)

	t.Log(string(data))

	req, err = http.NewRequest("POST", os.Getenv("LOTUS_URL"), bytes.NewBuffer(data))
	if err != nil {
		t.Errorf("FIX ME")
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("LOTUS_JWT"))

	// Set client timeout
	client = &http.Client{Timeout: time.Second * 10}

	// Send request
	resp, err = client.Do(req)
	if err != nil {
		t.Errorf("FIX ME")
	}

	var res2 map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&res2)
	if err != nil {
		t.Errorf("FIX ME")
	}

	t.Log(res2)

	if res2["result"] == nil {
		t.Errorf("FIX ME")
	}
}

// Send from multisig
func TestSendFromMultisig(t *testing.T) {
	/* Secret Key */
	sk, _ := hex.DecodeString("f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a")

	/* Get Nonce */
	data := []byte(`{"jsonrpc": "2.0","method": "Filecoin.MpoolGetNonce","id": 1, "params": ["t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"]}`)

	req, err := http.NewRequest("POST", os.Getenv("LOTUS_URL"), bytes.NewBuffer(data))
	if err != nil {
		t.Errorf("Fail to get nonce")
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("LOTUS_JWT"))

	// Set client timeout
	client := &http.Client{Timeout: time.Second * 10}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("Fail to get nonce")
	}

	var res map[string]interface{}

	t.Log(resp)

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		t.Errorf("FIX ME")
	}

	t.Log(res["result"])

	nonce := res["result"].(float64)
	if err != nil {
		t.Errorf("FIX ME")
	}

	/* Create Transaction */

	r := &RosettaConstructionFilecoin{false}
	mtx := TxMetadata{
		Nonce:      uint64(nonce) + 1,
		GasFeeCap:  2500,
		GasPremium: 2500,
		GasLimit:   2500000,
	}
	params := MultisigPaymentParams{
		To:       "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
		Quantity: 1000,
	}
	request := &MultisigPaymentRequest{
		Multisig: "t01002", // Update with Multisig address from space_race
		From:     "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
		Metadata: mtx,
		Params:   params,
	}

	unsignedTxBase64, err := r.ConstructMultisigPayment(request)
	if err != nil {
		t.Errorf("FIX ME")
	}

	signedTx, err := r.SignTx(unsignedTxBase64, sk)
	if err != nil {
		t.Error(err)
	}

	t.Log(signedTx)

	data = []byte(`{"jsonrpc": "2.0","method": "Filecoin.MpoolPush","id": 1, "params": [` + signedTx + `]}`)

	t.Log(string(data))

	req, err = http.NewRequest("POST", os.Getenv("LOTUS_URL"), bytes.NewBuffer(data))
	if err != nil {
		t.Errorf("FIX ME")
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("LOTUS_JWT"))

	// Set client timeout
	client = &http.Client{Timeout: time.Second * 10}

	// Send request
	resp, err = client.Do(req)
	if err != nil {
		t.Errorf("FIX ME")
	}

	var res2 map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&res2)
	if err != nil {
		t.Errorf("FIX ME")
	}

	t.Log(res2)

	if res2["result"] == nil {
		t.Errorf("FIX ME")
	}
}

// Key swap for a multisig
func TestSwapKeysMultisig(t *testing.T) {
	/* Secret Key */
	sk, _ := hex.DecodeString("f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a")

	/* Get Nonce */
	data := []byte(`{"jsonrpc": "2.0","method": "Filecoin.MpoolGetNonce","id": 1, "params": ["t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"]}`)

	req, err := http.NewRequest("POST", os.Getenv("LOTUS_URL"), bytes.NewBuffer(data))
	if err != nil {
		t.Errorf("Fail to get nonce")
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("LOTUS_JWT"))

	// Set client timeout
	client := &http.Client{Timeout: time.Second * 10}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("Fail to get nonce")
	}

	var res map[string]interface{}

	t.Log(resp)

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		t.Errorf("FIX ME")
	}

	t.Log(res["result"])

	nonce := res["result"].(float64)
	if err != nil {
		t.Errorf("FIX ME")
	}

	/* Create Transaction */

	r := &RosettaConstructionFilecoin{false}
	mtx := TxMetadata{
		Nonce:      uint64(nonce) + 1,
		GasFeeCap:  2500,
		GasPremium: 2500,
		GasLimit:   2500000,
	}
	params := SwapAuthorizedPartyParams{
		From: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
		To:   "t3v3htmno6gmhe42ssqq5tgoemlm3boaeglrks2fqztfjdz3kjnrkomv5ymjrjpm4srmojashlcnporcluiyaa",
	}
	request := &SwapAuthorizedPartyRequest{
		Multisig: "t01002", // Update with multisig
		From:     "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
		Metadata: mtx,
		Params:   params,
	}

	unsignedTxBase64, err := r.ConstructSwapAuthorizedParty(request)
	if err != nil {
		t.Errorf("FIX ME")
	}

	signedTx, err := r.SignTx(unsignedTxBase64, sk)
	if err != nil {
		t.Error(err)
	}

	t.Log(signedTx)

	data = []byte(`{"jsonrpc": "2.0","method": "Filecoin.MpoolPush","id": 1, "params": [` + signedTx + `]}`)

	t.Log(string(data))

	req, err = http.NewRequest("POST", os.Getenv("LOTUS_URL"), bytes.NewBuffer(data))
	if err != nil {
		t.Errorf("FIX ME")
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("LOTUS_JWT"))

	// Set client timeout
	client = &http.Client{Timeout: time.Second * 10}

	// Send request
	resp, err = client.Do(req)
	if err != nil {
		t.Errorf("FIX ME")
	}

	var res2 map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&res2)
	if err != nil {
		t.Errorf("FIX ME")
	}

	t.Log(res2)

	if res2["result"] == nil {
		t.Errorf("FIX ME")
	}
}

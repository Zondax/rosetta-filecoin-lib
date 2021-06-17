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
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	builtinV5 "github.com/filecoin-project/specs-actors/v5/actors/builtin"
)

const MULTISIG_ADDRESS_ON_CHAIN = "t01005"

// send from regular address
func TestSendTransaction(t *testing.T) {
	defer seq()()
	lotusURL, found := os.LookupEnv("LOTUS_URL")
	if !found {
		t.Errorf("Lotus URL has not been defined")
		t.FailNow()
	}

	lotusJWT, found := os.LookupEnv("LOTUS_JWT")
	if !found {
		t.Errorf("Lotus JWT has not been defined")
		t.FailNow()
	}

	/* Secret Key */
	sk, _ := hex.DecodeString("f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a")

	/* Get Nonce */
	data := []byte(`{"jsonrpc": "2.0","method": "Filecoin.MpoolGetNonce","id": 1, "params": ["f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"]}`)

	req, err := http.NewRequest("POST", lotusURL, bytes.NewBuffer(data))
	if err != nil {
		t.Errorf("Fail to get nonce: " + err.Error())
		t.FailNow()
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+lotusJWT)

	// Set client timeout
	client := &http.Client{Timeout: time.Second * 60}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	var res map[string]interface{}

	t.Log(resp)

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		t.Errorf(err.Error())
	}

	t.Log(res["result"])

	nonce := res["result"].(float64)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	/* Create Transaction */

	r := &RosettaConstructionFilecoin{false}
	mtx := TxMetadata{
		Nonce:      uint64(nonce),
		GasFeeCap:  "149794",
		GasPremium: "149470",
		GasLimit:   2180810,
	}
	pr := &PaymentRequest{
		From:     "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
		To:       "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
		Quantity: "1",
		Metadata: mtx,
	}

	unsignedTxBase64, err := r.ConstructPayment(pr)
	if err != nil {
		t.Errorf(err.Error())
	}

	signedTx, err := r.SignTxJSON(unsignedTxBase64, sk)
	if err != nil {
		t.Error(err)
	}

	t.Log(signedTx)

	data = []byte(`{"jsonrpc": "2.0","method": "Filecoin.MpoolPush","id": 1, "params": [` + signedTx + `]}`)

	t.Log(string(data))

	req, err = http.NewRequest("POST", lotusURL, bytes.NewBuffer(data))
	if err != nil {
		t.Errorf(err.Error())
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("LOTUS_JWT"))

	// Set client timeout
	client = &http.Client{Timeout: time.Second * 60}

	// Send request
	resp, err = client.Do(req)
	if err != nil {
		t.Errorf(err.Error())
	}

	var res2 map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&res2)
	if err != nil {
		t.Errorf(err.Error())
	}

	t.Log(res2)

	if res2["result"] == nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	h, err := json.Marshal(res2["result"])
	if err != nil {
		t.Errorf(err.Error())
	}

	data = []byte(`{"jsonrpc": "2.0","method": "Filecoin.StateWaitMsg","id": 1, "params": [` + string(h) + `, null]}`)

	t.Log(string(data))

	req, err = http.NewRequest("POST", lotusURL, bytes.NewBuffer(data))
	if err != nil {
		t.Errorf(err.Error())
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+lotusJWT)

	// Set client timeout
	client = &http.Client{Timeout: time.Second * 600}
	// Send request
	resp, err = client.Do(req)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	var res3 map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&res3)
	if err != nil {
		t.Errorf(err.Error())
	}

	t.Log(res3)

	if res3["result"] == nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	var result = res3["result"].(map[string]interface{})
	var receipt = result["Receipt"].(map[string]interface{})
	var exitCode = receipt["ExitCode"].(float64)

	if exitCode != 0 {
		t.Errorf(err.Error())
		t.FailNow()
	}

}

// Send from multisig
func TestSendFromMultisig(t *testing.T) {
	defer seq()()
	lotusURL, found := os.LookupEnv("LOTUS_URL")
	if !found {
		t.Errorf("Lotus URL has not been defined")
		t.FailNow()
	}

	lotusJWT, found := os.LookupEnv("LOTUS_JWT")
	if !found {
		t.Errorf("Lotus JWT has not been defined")
		t.FailNow()
	}

	/* Secret Key */
	sk, _ := hex.DecodeString("f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a")

	/* Get Nonce */
	data := []byte(`{"jsonrpc": "2.0","method": "Filecoin.MpoolGetNonce","id": 1, "params": ["f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"]}`)

	req, err := http.NewRequest("POST", lotusURL, bytes.NewBuffer(data))
	if err != nil {
		t.Errorf("Fail to get nonce: " + err.Error())
		t.FailNow()
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+lotusJWT)

	// Set client timeout
	client := &http.Client{Timeout: time.Second * 60}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	var res map[string]interface{}

	t.Log(resp)

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		t.Errorf(err.Error())
	}

	t.Log(res["result"])

	nonce := res["result"].(float64)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	/* Create Transaction */

	r := &RosettaConstructionFilecoin{false}
	mtx := TxMetadata{
		Nonce:      uint64(nonce),
		GasFeeCap:  "101120",
		GasPremium: "100066",
		GasLimit:   4629707,
	}
	params := MultisigPaymentParams{
		To:       "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
		Quantity: "1",
	}
	request := &MultisigPaymentRequest{
		Multisig: MULTISIG_ADDRESS_ON_CHAIN,
		From:     "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
		Metadata: mtx,
		Params:   params,
	}

	unsignedTxBase64, err := r.ConstructMultisigPayment(request, builtinV5.MultisigActorCodeID)
	if err != nil {
		t.Errorf(err.Error())
	}

	signedTx, err := r.SignTxJSON(unsignedTxBase64, sk)
	if err != nil {
		t.Error(err)
	}

	t.Log(signedTx)

	data = []byte(`{"jsonrpc": "2.0","method": "Filecoin.MpoolPush","id": 1, "params": [` + signedTx + `]}`)

	t.Log(string(data))

	req, err = http.NewRequest("POST", lotusURL, bytes.NewBuffer(data))
	if err != nil {
		t.Errorf(err.Error())
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+lotusJWT)

	// Set client timeout
	client = &http.Client{Timeout: time.Second * 60}

	// Send request
	resp, err = client.Do(req)
	if err != nil {
		t.Errorf(err.Error())
	}

	var res2 map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&res2)
	if err != nil {
		t.Errorf(err.Error())
	}

	t.Log(res2)

	if res2["result"] == nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	h, err := json.Marshal(res2["result"])
	if err != nil {
		t.Errorf(err.Error())
	}

	data = []byte(`{"jsonrpc": "2.0","method": "Filecoin.StateWaitMsg","id": 1, "params": [` + string(h) + `, null]}`)

	t.Log(string(data))

	req, err = http.NewRequest("POST", lotusURL, bytes.NewBuffer(data))
	if err != nil {
		t.Errorf(err.Error())
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+lotusJWT)

	// Set client timeout
	client = &http.Client{Timeout: time.Second * 600}
	// Send request
	resp, err = client.Do(req)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	var res3 map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&res3)
	if err != nil {
		t.Errorf(err.Error())
	}

	t.Log(res3)

	if res3["result"] == nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	var result = res3["result"].(map[string]interface{})
	var receipt = result["Receipt"].(map[string]interface{})
	var exitCode = receipt["ExitCode"].(float64)

	if exitCode != 0 {
		t.Errorf(err.Error())
		t.FailNow()
	}

}

// Key swap for a multisig
func TestSwapKeysMultisig(t *testing.T) {
	defer seq()()
	lotusURL, found := os.LookupEnv("LOTUS_URL")
	if !found {
		t.Errorf("Lotus URL has not been defined")
		t.FailNow()
	}

	lotusJWT, found := os.LookupEnv("LOTUS_JWT")
	if !found {
		t.Errorf("Lotus JWT has not been defined")
		t.FailNow()
	}

	/* Secret Key */
	sk, _ := hex.DecodeString("f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a")

	/* Addresses */
	proposeSenderAdd := "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"
	signerAdd1 := "t1x5x7ekq5f2cjkk57ee3lismwmzu5rbhkhnsrooa"
	signerAdd2 := "f1itpqzzcx6yf52oc35dgsoxfqkoxpy6kdmygbaja"

	addressID2 := "t01002" // ID of signerAdd1

	/* Get Multisig signers */
	data := []byte(`{"jsonrpc": "2.0","method": "Filecoin.StateReadState","id": 1, "params": ["` + MULTISIG_ADDRESS_ON_CHAIN + `", null]}`)

	req, err := http.NewRequest("POST", lotusURL, bytes.NewBuffer(data))
	if err != nil {
		t.Errorf("Fail to get nonce: " + err.Error())
		t.FailNow()
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+lotusJWT)

	// Set client timeout
	client := &http.Client{Timeout: time.Second * 60}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	t.Log(resp)

	var res map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		t.Errorf(err.Error())
	}

	result := res["result"].(map[string]interface{})
	t.Log(result)
	state := result["State"].(map[string]interface{})
	signers := state["Signers"].([]interface{})

	var (
		toParams   string // new signer address
		fromParams string //old signer address
		secretKey  []byte
	)

	if signers[0] == addressID2 || signers[1] == addressID2 {
		fromParams = signerAdd1
		toParams = signerAdd2
		secretKey = sk
	} else {
		fromParams = signerAdd2
		toParams = signerAdd1
		secretKey = sk
	}

	/* Get Nonce */
	data = []byte(`{"jsonrpc": "2.0","method": "Filecoin.MpoolGetNonce","id": 1, "params": ["` + proposeSenderAdd + `"]}`)

	req, err = http.NewRequest("POST", lotusURL, bytes.NewBuffer(data))
	if err != nil {
		t.Errorf("Fail to get nonce: " + err.Error())
		t.FailNow()
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+lotusJWT)

	// Set client timeout
	client = &http.Client{Timeout: time.Second * 60}

	// Send request
	resp, err = client.Do(req)
	if err != nil {
		t.Errorf(err.Error())
	}

	var res1 map[string]interface{}

	err = json.NewDecoder(resp.Body).Decode(&res1)
	if err != nil {
		t.Errorf(err.Error())
	}

	t.Log(res1["result"])

	nonce := res1["result"].(float64)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	/* Create Transaction */

	r := &RosettaConstructionFilecoin{false}
	mtx := TxMetadata{
		Nonce:      uint64(nonce),
		GasFeeCap:  "149794",
		GasPremium: "149470",
		GasLimit:   5180810,
	}
	params := SwapAuthorizedPartyParams{
		From: fromParams,
		To:   toParams,
	}
	request := &SwapAuthorizedPartyRequest{
		Multisig: MULTISIG_ADDRESS_ON_CHAIN,
		From:     proposeSenderAdd,
		Metadata: mtx,
		Params:   params,
	}

	unsignedTxBase64, err := r.ConstructSwapAuthorizedParty(request, builtinV5.MultisigActorCodeID)
	if err != nil {
		t.Errorf(err.Error())
	}

	signedTx, err := r.SignTxJSON(unsignedTxBase64, secretKey)
	if err != nil {
		t.Error(err)
	}

	t.Log(signedTx)

	data = []byte(`{"jsonrpc": "2.0","method": "Filecoin.MpoolPush","id": 1, "params": [` + signedTx + `]}`)

	t.Log(string(data))

	req, err = http.NewRequest("POST", lotusURL, bytes.NewBuffer(data))
	if err != nil {
		t.Errorf(err.Error())
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+lotusJWT)

	// Set client timeout
	client = &http.Client{Timeout: time.Second * 60}

	// Send request
	resp, err = client.Do(req)
	if err != nil {
		t.Errorf(err.Error())
	}

	var res2 map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&res2)
	if err != nil {
		t.Errorf(err.Error())
	}

	t.Log(res2)

	if res2["result"] == nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	h, err := json.Marshal(res2["result"])
	if err != nil {
		t.Errorf(err.Error())
	}

	data = []byte(`{"jsonrpc": "2.0","method": "Filecoin.StateWaitMsg","id": 1, "params": [` + string(h) + `, null]}`)

	t.Log(string(data))

	req, err = http.NewRequest("POST", lotusURL, bytes.NewBuffer(data))
	if err != nil {
		t.Errorf(err.Error())
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+lotusJWT)

	// Set client timeout
	client = &http.Client{Timeout: time.Second * 600}
	// Send request
	resp, err = client.Do(req)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	var res3 map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&res3)
	if err != nil {
		t.Errorf(err.Error())
	}

	t.Log(res3)

	if res3["result"] == nil {
		if err != nil {
			t.Errorf(err.Error())
		}
		t.FailNow()
	}

	result = res3["result"].(map[string]interface{})
	receipt := result["Receipt"].(map[string]interface{})
	exitCode := receipt["ExitCode"].(float64)

	if exitCode != 0 {
		if err != nil {
			t.Errorf(err.Error())
		}
		t.FailNow()
	}
}

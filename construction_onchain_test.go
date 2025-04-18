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
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/filecoin-project/go-state-types/big"
	"github.com/stretchr/testify/assert"
)

const SourceAddress1 = "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"
const SourceAddressSK = "f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a"
const DestAddress1 = "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy"

const GasFeeCap = "10049794"
const GasPremium = "10049470"
const GasLimit = 200180810

const Signer1long = "t1x5x7ekq5f2cjkk57ee3lismwmzu5rbhkhnsrooa"
const Signer1short = "t01003"
const Signer2long = "t1itpqzzcx6yf52oc35dgsoxfqkoxpy6kdmygbaja"
const Signer2short = "t01004"

const StateWaitMsg = "Filecoin.StateWaitMsg"

func getCredentials() (string, string, error) {
	lotusURL, found := os.LookupEnv("LOTUS_URL")
	if !found {
		return "", "", fmt.Errorf("lotus URL has not been defined")
	}

	auth, found := os.LookupEnv("AUTH_JWT")
	if !found {
		return "", "", fmt.Errorf("authentication header not found")
	}

	return lotusURL, auth, nil
}

func sendLotusRequest(method string, id int, params string) (map[string]interface{}, error) {
	lotusURL, auth, err := getCredentials()
	if err != nil {
		return nil, err
	}

	data := []byte(fmt.Sprintf("{\"jsonrpc\": \"2.0\",\"method\": \"%s\",\"id\": %d, \"params\": [%s]}", method, id, params))
	fmt.Println("request: ", string(data))

	req, err := http.NewRequest("POST", lotusURL, bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth))

	// Set client timeout
	client := &http.Client{Timeout: time.Second * 60}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close() // Ensure body is closed

	// Check HTTP status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Try to read body for more details, but don't fail if it's empty
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("received non-2xx status code: %d - %s. Body: %s", resp.StatusCode, resp.Status, string(bodyBytes))
	}

	var res map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&res)
	return res, err
}

func getNonce(params string) (uint64, error) {
	// Send request
	res, err := sendLotusRequest(
		"Filecoin.MpoolGetNonce",
		1,
		`"`+params+`"`,
	)

	if err != nil {
		return 0, err
	}

	if val, ok := res["error"]; ok {
		println(val)
		return 0, nil
	}

	return uint64(res["result"].(float64)), nil
}

func getBalance(params string) (big.Int, error) {
	// Send request
	res, err := sendLotusRequest(
		"Filecoin.WalletBalance",
		1,
		`"`+params+`"`,
	)

	if err != nil {
		return big.Zero(), err
	}

	value, err := big.FromString(res["result"].(string))
	if err != nil {
		return big.Zero(), err
	}

	return value, nil
}

func TestGetNonce(t *testing.T) {
	defer seq()()
	nonceSource, err := getNonce(SourceAddress1)
	assert.NoError(t, err)

	nonceDest, err := getNonce(DestAddress1)
	assert.NoError(t, err)

	nonceMsig, err := getNonce(MULTISIG_ADDRESS)
	assert.NoError(t, err)

	t.Logf("Source  : %d", nonceSource)
	t.Logf("Dest    : %d", nonceDest)
	t.Logf("Msig    : %d", nonceMsig)
}

func TestCheckBalances(t *testing.T) {
	defer seq()()
	balanceSource, err := getBalance(SourceAddress1)
	assert.NoError(t, err)

	balanceDest, err := getBalance(DestAddress1)
	assert.NoError(t, err)

	balanceMsig, err := getBalance(MULTISIG_ADDRESS)
	assert.NoError(t, err)

	balanceInvalid, err := getBalance("t01105")
	assert.NoError(t, err)

	t.Logf("Source  : %s", balanceSource.String())
	t.Logf("Dest    : %s", balanceDest.String())
	t.Logf("Msig    : %s", balanceMsig.String())
	t.Logf("invalid : %s", balanceInvalid.String())

	assert.True(t, balanceSource.GreaterThan(big.Zero()))
	assert.True(t, balanceDest.GreaterThanEqual(big.Zero()))
	assert.True(t, balanceMsig.GreaterThan(big.Zero()))
	assert.True(t, balanceInvalid.Equals(big.Zero()))
}

// send from regular address
func TestSendTransaction(t *testing.T) {
	defer seq()()

	/* Secret Key */
	sk, _ := hex.DecodeString(SourceAddressSK)
	nonce, err := getNonce(SourceAddress1)
	assert.NoError(t, err)

	/* Create Transaction */

	r := NewRosettaConstructionFilecoin(nil)
	pr := &PaymentRequest{
		From:     SourceAddress1,
		To:       DestAddress1,
		Quantity: "1",
		Metadata: TxMetadata{
			Nonce:      nonce,
			GasFeeCap:  GasFeeCap,
			GasPremium: GasPremium,
			GasLimit:   GasLimit,
		},
	}

	unsignedTxBase64, err := r.ConstructPayment(pr)
	assert.NoError(t, err)

	signedTx, err := r.SignTxJSON(unsignedTxBase64, sk)
	assert.NoError(t, err)

	// Send request
	res, err := sendLotusRequest("Filecoin.MpoolPush", 1, signedTx)
	fmt.Printf("%v\n", res)
	assert.NoError(t, err)
	assert.NotNil(t, res["result"])

	txHash, err := json.Marshal(res["result"])
	assert.NoError(t, err)

	res, err = sendLotusRequest(StateWaitMsg, 1, string(txHash)+", null, null, null")
	assert.NoError(t, err)
	assert.NotNil(t, res["result"])
	assert.Nil(t, res["error"])

	var result = res["result"].(map[string]interface{})
	var receipt = result["Receipt"].(map[string]interface{})
	exitCode := int64(receipt["ExitCode"].(float64))

	assert.EqualValues(t, exitCode, 0)

	balanceSource, err := getBalance(SourceAddress1)
	assert.NoError(t, err)

	balanceDest, err := getBalance(DestAddress1)
	assert.NoError(t, err)

	t.Logf("Source: %d", balanceSource)
	t.Logf("Dest  : %d", balanceDest)
}

// Send from multisig
func TestSendFromMultisig(t *testing.T) {
	defer seq()()

	/* Secret Key */
	sk, _ := hex.DecodeString(SourceAddressSK)
	nonce, err := getNonce(SourceAddress1)
	assert.NoError(t, err)

	/* Create Transaction */
	url, token, _ := getCredentials()
	client, err := NewFilecoinRPCClient(url, token)
	assert.NoError(t, err)
	r := NewRosettaConstructionFilecoin(client)

	mtx := TxMetadata{
		Nonce:      nonce,
		GasFeeCap:  GasFeeCap,
		GasPremium: GasPremium,
		GasLimit:   GasLimit,
	}

	request := &MultisigPaymentRequest{
		Multisig: MULTISIG_ADDRESS,
		From:     SourceAddress1,
		Metadata: mtx,
		Params: MultisigPaymentParams{
			To:       DestAddress1,
			Quantity: "1",
		},
	}

	unsignedTxBase64, err := r.ConstructMultisigPayment(request)
	assert.NoError(t, err)

	signedTx, err := r.SignTxJSON(unsignedTxBase64, sk)
	assert.NoError(t, err)

	// Send request
	res, err := sendLotusRequest("Filecoin.MpoolPush", 1, signedTx)
	assert.NoError(t, err)
	assert.Nil(t, res["error"])
	assert.NotNil(t, res["result"])

	txHash, err := json.Marshal(res["result"])
	assert.NoError(t, err)

	res, err = sendLotusRequest(StateWaitMsg, 1, string(txHash)+", null, null, null")
	assert.NoError(t, err)
	assert.Nil(t, res["error"])
	assert.NotNil(t, res["result"])

	var result = res["result"].(map[string]interface{})
	var receipt = result["Receipt"].(map[string]interface{})
	exitCode := int64(receipt["ExitCode"].(float64))

	assert.EqualValues(t, exitCode, 0)

	balanceSource, err := getBalance(SourceAddress1)
	assert.NoError(t, err)

	balanceDest, err := getBalance(DestAddress1)
	assert.NoError(t, err)

	t.Logf("Source: %d", balanceSource)
	t.Logf("Dest  : %d", balanceDest)
}

// Key swap for a multisig
func TestSwapKeysMultisig(t *testing.T) {
	defer seq()()

	/* Secret Key */
	sk, _ := hex.DecodeString(SourceAddressSK)

	/* Get Current Multisig signers */
	res, err := sendLotusRequest("Filecoin.StateReadState", 1, `"`+MULTISIG_ADDRESS+`"`+", null")
	assert.NoError(t, err)

	result := res["result"].(map[string]interface{})
	state := result["State"].(map[string]interface{})
	signers := state["Signers"].([]interface{})

	fromParams := Signer1long // old signer address
	toParams := Signer2long   // new signer address

	if signers[0] == Signer2short || signers[1] == Signer2short {
		fromParams = Signer2long
		toParams = Signer1long
	}

	/* Get Nonce */
	nonce, err := getNonce(SourceAddress1)
	assert.NoError(t, err)

	/* Create Transaction */
	url, token, _ := getCredentials()
	client, err := NewFilecoinRPCClient(url, token)
	assert.NoError(t, err)
	r := NewRosettaConstructionFilecoin(client)

	mtx := TxMetadata{
		Nonce:      nonce,
		GasFeeCap:  GasFeeCap,
		GasPremium: GasPremium,
		GasLimit:   GasLimit,
	}
	params := SwapAuthorizedPartyParams{
		From: fromParams,
		To:   toParams,
	}
	request := &SwapAuthorizedPartyRequest{
		Multisig: MULTISIG_ADDRESS,
		From:     SourceAddress1,
		Metadata: mtx,
		Params:   params,
	}

	unsignedTxBase64, err := r.ConstructSwapAuthorizedParty(request)
	assert.NoError(t, err)

	signedTx, err := r.SignTxJSON(unsignedTxBase64, sk)
	assert.NoError(t, err)

	t.Log(signedTx)

	res, err = sendLotusRequest("Filecoin.MpoolPush", 1, signedTx)
	assert.NoError(t, err)
	assert.Nil(t, res["error"])
	assert.NotNil(t, res["result"])

	txHash, err := json.Marshal(res["result"])
	assert.NoError(t, err)

	res, err = sendLotusRequest(StateWaitMsg, 1, string(txHash)+", null, null, null")
	assert.NoError(t, err)
	assert.Nil(t, res["error"])
	assert.NotNil(t, res["result"])

	result = res["result"].(map[string]interface{})
	receipt := result["Receipt"].(map[string]interface{})
	exitCode := int64(receipt["ExitCode"].(float64))

	assert.EqualValues(t, exitCode, 0)

	// Check they have been swapped
	res, err = sendLotusRequest("Filecoin.StateReadState", 1, `"`+MULTISIG_ADDRESS+`"`+", null")
	assert.NoError(t, err)

	result = res["result"].(map[string]interface{})
	state = result["State"].(map[string]interface{})
	signers = state["Signers"].([]interface{})

	assert.Equal(t, "t01002", signers[0])
	if toParams == Signer1long {
		assert.Equal(t, Signer1short, signers[1])
	} else {
		assert.Equal(t, Signer2short, signers[1])
	}
}

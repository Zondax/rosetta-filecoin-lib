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

//func TestParseMultisigTx(t *testing.T) {
//	// First create a multisig t
//	r := &RosettaConstructionFilecoin{false}
//
//	mtx := TxMetadata{
//		Nonce:      uint64(777),
//		GasFeeCap:  149794,
//		GasPremium: 149470,
//		GasLimit:   2180810,
//	}
//	params := MultisigPaymentParams{
//		To:       "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
//		Quantity: 1,
//	}
//
//	request := &MultisigPaymentRequest{
//		Multisig: MULTISIG_ADDRESS,
//		From:     "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
//		Metadata: mtx,
//		Params:   params,
//	}
//
//	unsignedTxJSONBase64, err := r.ConstructMultisigPayment(request)
//	if err != nil {
//		t.Errorf(err.Error())
//	}
//
//	t.Log(unsignedTxJSONBase64);
//
//	// Now try parsing the tx
//	msg, err := r.ParseMultisigTx(unsignedTxJSON)
//
//	t.Log(msg)
//
//	if err != nil {
//		t.Errorf("Parsing failed")
//	}
//
//}

/*  On Chain Tests */

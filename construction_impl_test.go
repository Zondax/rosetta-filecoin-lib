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
  "testing"
  "encoding/hex"
  "github.com/filecoin-project/lotus/chain/types"
  "github.com/filecoin-project/specs-actors/actors/abi"
)

func TestDeriveFromPublicKey(t *testing.T) {
  t.Errorf("No test")
}

func TestSign(t *testing.T) {
  t.Errorf("No test")
}

func TestVerify(t *testing.T) {
  t.Errorf("No test")
}

func TestConstructPayment(t *testing.T) {
  t.Errorf("No test")
}

func TestConstructMultisigPayment(t *testing.T) {
  t.Errorf("No test")
}

func TestConstructSwapAuthorizedParty(t *testing.T) {
  t.Errorf("No test")
}

func TestSignTx(t *testing.T) {
  t.Errorf("No test")
}

func TestParseTx(t *testing.T) {
  serialized_tx := "89005501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6285501b882619d46558f3d9e316d11b48dcf211327025a0144000186a0430009c41961a80040"
  r := &RosettaConstructionFilecoin{true}
  b, err := hex.DecodeString(serialized_tx)

  if err != nil {
    t.Errorf("Invalid test case")
  }

  msg, err := r.ParseTx(b)

  if err != nil {
    t.Fail()
  }

  switch msg := msg.(type) {
    case types.Message:
      if msg.To.String() != "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy" {
        t.Errorf("Invalid To address returned")
      }
      if msg.From.String() != "t1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi" {
        t.Errorf("Invalid From address returned")
      }
      if msg.Nonce != uint64(1) {
        t.Errorf("Invalid Nonce returned")
      }
      if types.BigCmp(msg.Value, types.NewInt(100000)) > 0 {
        t.Errorf("Invalid Value returned")
      }
      if types.BigCmp(msg.GasPrice,types.NewInt(2500)) > 0 {
        t.Errorf("Invalid GasPrice returned")
      }
      if msg.GasLimit != int64(25000) {
        t.Errorf("Invalid GasLimit returned")
      }
      if msg.Method != abi.MethodNum(0) {
        t.Errorf("Invalid Method returned")
      }
      // FIXME
      /*if msg.Params != make([]byte, 0) {
        t.Errorf("Invalid Params returned")
      }*/
    case types.SignedMessage:
      t.Log(msg.Message.To)
    default:
      t.Errorf("This should never happened")

  }
}

func TestHash(t *testing.T) {
  serialized_signed_tx := "8289005501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855011eaf1c8a4bbfeeb0870b1745b1f57503470b71160144000186a0430009c41909c4004058420106398485060ca2a4deb97027f518f45569360c3873a4303926fa6909a7299d4c55883463120836358ff3396882ee0dc2cf15961bd495cdfb3de1ee2e8bd3768e01"
  r := &RosettaConstructionFilecoin{true}
  b, err := hex.DecodeString(serialized_signed_tx)

  if err != nil {
    t.Errorf("Invalid test case")
  }

  cid, err := r.Hash(b)

  if err != nil {
    t.Errorf("Something went Wrong")
  }

  t.Log(cid)

  if cid != "bafy2bzacedt2zox7kxwtuhorhtwsaxkjs5hz2t543uf5fjvwlcu5uqzgfzxwy" {
      t.Fail()
  }
}

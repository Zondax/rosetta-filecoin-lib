package rosettaFilecoinLib

import (
	"github.com/filecoin-project/go-address"
	"github.com/ipfs/go-cid"
)

type RosettaConstructionTool interface {
	// DeriveFromPublicKey defines the function to derive the address from an public key (secp256k1)
	// @return
	//   - derivedAddress [string]
	//   - error when deriving address from the public key
	DeriveFromPublicKey(publicKey []byte, network address.Network) (string, error)

	// Sign defines the function to sign an arbitrary message with the secret key (secp256k1)
	// @message [[]byte] a digest
	// @return (secp256k1)
	//   - signature [string] the signature after the message is signed with the private key
	//   - error when signing a message
	SignRaw(message []byte, sk []byte) ([]byte, error)

	// Verify defines the function to verify the signature of an arbitrary message with the public key (secp256k1)
	// @message [[]byte] a digest
	// @return
	//   - error if invalid signature
	VerifyRaw(message []byte, publicKey []byte, signature []byte) error

	// ConstructPayment creates transaction for a normal send
	// @return
	//   - unsigned transaction as json [string]
	//   - error while constructing the normal send transaction
	ConstructPayment(request *PaymentRequest) (string, error)

	// ConstructMultisigPayment creates transaction for a multisig send
	// @return
	//   - unsigned transaction as json [string]
	//   - error while constructing the multisig send transaction
	ConstructMultisigPayment(request *MultisigPaymentRequest, destinationActorId cid.Cid) (string, error)

	// ConstructSwapAuthorizedParty creates transaction for a multisig SwapAuthorizedParty call
	// @return
	//   - unsigned transaction as json [string]
	//   - error while constructing the multisig SwapAuthorizedParty call
	ConstructSwapAuthorizedParty(request *MultisigPaymentRequest, destinationActorId cid.Cid) (string, error)

	// SignTx signs an unsignedTx (CBOR) using the secret key (secp256k1) and returns a signedTx
	// @unsignedTransaction [string] unsigned transaction as CBOR
	// @sk [[]byte] secp256k1 secret key
	// @return
	//   - signedTx [string] the signed transaction as CBOR
	//   - error when signing a transaction
	SignTx(unsignedTx []byte, sk []byte) ([]byte, error)

	// SignTxJSON signs an unsignedTx (JSON) using the secret key (secp256k1) and return a signedTx
	// @unsignedTransaction [string] unsigned transaction as JSON
	// @sk [[]byte] secp256k1 secret key
	// @return
	//   - signedTx [string] the signed transaction
	//   - error when signing a transaction
	SignTxJSON(unsignedTransaction string, sk []byte) (string, error)

	// ParseTx parses CBOR encoded transaction
	// @tx [[]byte] signed or unsigned transaction CBOR encoded
	// @return
	//   - message [string] the parsed transaction (message or unsigned message) represented as a JSON string
	//   - error when parsing a transaction
	ParseTx(messageCbor []byte) (string, error)

	// ParseParamsMultisigTx parses a JSON encoded transaction and decodes actor paramss assuming the destination
	// address correspond to a multisig actor
	// @tx [string] signed or unsigned transaction JSON encoded
	// @return
	//   - message [string] the parsed params represented as a JSON string
	//   - error when parsing a transaction
	ParseParamsMultisigTx(message string, destinationActorId cid.Cid) (string, error)

	// Hash defines the function to calculate a tx hash
	// @signedTx [string] base64 encoded signed transaction
	// @return
	//   - txHash [string] transaction hash
	//   - error when calculating the tx hash
	Hash(signedTx string) (string, error)
}

// Modify this as needed to add in new fields
type TxMetadata struct {
	Nonce      uint64 `json:"nonce"`
	GasFeeCap  int64  `json:"gasFeeCap"`
	GasPremium int64  `json:"gasPremium"`
	GasLimit   int64  `json:"gasLimit,omitempty"`
	ChainID    string `json:"chainId,omitempty"`
	Method     uint64 `json:"method,omitempty"`
	Params     []byte `json:"params,omitempty"`
}

// PaymentRequest defines the input to ConstructPayment
type PaymentRequest struct {
	From     string     `json:"from"`
	To       string     `json:"to"`
	Quantity uint64     `json:"quantity"`
	Metadata TxMetadata `json:"metadata"`
}

// MultisigPaymentParams defines params for MultisigPaymentRequest
type MultisigPaymentParams struct {
	To       string `json:"to"`
	Quantity uint64 `json:"quantity"`
}

// MultisigPaymentRequest defines the input to ConstructMultisigPayment
type MultisigPaymentRequest struct {
	Multisig string                `json:"multisig"`
	From     string                `json:"from"`
	Quantity uint64                `json:"quantity"`
	Metadata TxMetadata            `json:"metadata"`
	Params   MultisigPaymentParams `json:"params"`
}

// SwapAuthorizedPartyParams defines the params
type SwapAuthorizedPartyParams struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// SwapAuthorizedPartyRequest defines the input to ConstructSwapAuthorizedParty
type SwapAuthorizedPartyRequest struct {
	Multisig string                    `json:"multisig"`
	From     string                    `json:"from"`
	Metadata TxMetadata                `json:"metadata"`
	Params   SwapAuthorizedPartyParams `json:"params"`
}

package rosettaFilecoinLib

type RosettaConstructionTool interface {
	// DeriveFromPublicKey defines the function to derive the address from an public key (secp256k1)
	// @return
	//   - derivedAddress [string]
	//   - error when deriving address from the public key
	DeriveFromPublicKey(publicKey []byte) (string, error)

	// Sign defines the function to sign an arbitrary message with the secret key (secp256k1)
	// @return (secp256k1)
	//   - signature [string] the signature after the message is signed with the private key
	//   - error when signing a message
	Sign(message []byte, sk []byte) ([]byte, error)

	// Verify defines the function to verify the signature of an arbitrary message with the public key (secp256k1)
	// @return
	//   - error if invalid signature
	Verify(message []byte, publicKey []byte, signature []byte) error

	// ConstructPayment creates transaction for a normal send
	// @return
	//   - unsignedTx [string] base64 encoded unsigned transaction
	//   - error while constructing the normal send transaction
	ConstructPayment(request *PaymentRequest) (string, error)

	// ConstructMultisigPayment creates transaction for a multisig send
	// @return
	//   - unsignedTx [string] base64 encoded unsigned transaction
	//   - error while constructing the multisig send transaction
	ConstructMultisigPayment(request *MultisigPaymentRequest) (string, error)

	// ConstructSwapAuthorizedParty creates transaction for a multisig SwapAuthorizedParty call
	// @return
	//   - unsignedTx [string] base64 encoded unsigned transaction
	//   - error while constructing the multisig SwapAuthorizedParty call
	ConstructSwapAuthorizedParty(request *MultisigPaymentRequest) (string, error)

	// SignTx signs an unsignedTx using the secret key (secp256k1) and return a signedTx that can be submitted to the node
	// @unsignedTransaction [string] base64 encoded unsigned transaction
	// @sk [[]byte] secp256k1 secret key
	// @return
	//   - signedTx [string] the signed transaction
	//   - error when signing a transaction
	SignTx(unsignedTransaction string, sk []byte) (string, error)

	// ParseTx defines the function to parse a transaction
	// @tx [string] signed or unsigned transaction base64 encoded
	// @return
	//   - message [string] the parsed transaction (message or unsigned message) represented as a base64 string
	//   - error when parsing a transaction
	ParseTx(tx string) (string, error)

	// Hash defines the function to calculate a tx hash
	// @signedTx [string] base64 encoded signed transaction
	// @return
	//   - txHash [string] transaction hash
	//   - error when calculating the tx hash
	Hash(signedTx string) (string, error)
}

// Modify this as needed to add in new fields
type TxMetadata struct {
	Nonce    uint64 `json:"nonce"`
	GasPrice uint64 `json:"gasPrice,omitempty"`
	GasLimit uint64 `json:"gasLimit,omitempty"`
	ChainID  string `json:"chainId"`
	Method   uint64 `json:"method,omitempty"`
	Params   []byte `json:"params,omitempty"`
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

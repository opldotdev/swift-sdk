package main

import (
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	scriptpkg "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

const (
	transactionJSONMaximumTransactionBytes = 64 * 1024
	transactionJSONMaximumDocumentBytes    = 384 * 1024
	transactionJSONMaximumScriptBytes      = 32 * 1024
)

func executeTransactionJSONOperation(operation string, raw json.RawMessage) (any, error) {
	switch operation {
	case "transaction.json.marshal":
		var args struct {
			Bytes string `json:"bytes"`
		}
		if err := decodeArgs(raw, &args); err != nil {
			return nil, err
		}
		if len(args.Bytes) > transactionJSONMaximumTransactionBytes*2 {
			return nil, categorizedError{"resourceLimit", "transaction exceeds JSON operation limit"}
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		if _, err := preflightTransactionPacket(data, false); err != nil {
			return nil, err
		}
		tx, err := transaction.NewTransactionFromBytes(data)
		if err != nil {
			return nil, err
		}
		document, err := json.Marshal(tx)
		if err != nil {
			return nil, err
		}
		if len(document) > transactionJSONMaximumDocumentBytes {
			return nil, categorizedError{"resourceLimit", "transaction JSON exceeds operation limit"}
		}
		return map[string]string{"json": hex.EncodeToString(document)}, nil

	case "transaction.json.unmarshal":
		var args struct {
			JSON string `json:"json"`
		}
		if err := decodeArgs(raw, &args); err != nil {
			return nil, err
		}
		document, err := transactionJSONDocument(args.JSON)
		if err != nil {
			return nil, err
		}
		var tx transaction.Transaction
		if err := json.Unmarshal(document, &tx); err != nil {
			return nil, err
		}
		data := tx.Bytes()
		if len(data) > transactionJSONMaximumTransactionBytes {
			return nil, categorizedError{"resourceLimit", "transaction exceeds JSON operation limit"}
		}
		return map[string]string{"bytes": hex.EncodeToString(data)}, nil

	case "transaction.input.json.marshal":
		var args struct {
			UnlockingScript string `json:"unlockingScript"`
			TxID            string `json:"txid"`
			Vout            string `json:"vout"`
			Sequence        string `json:"sequence"`
		}
		if err := decodeArgs(raw, &args); err != nil {
			return nil, err
		}
		txID, err := transactionJSONTransactionID(args.TxID)
		if err != nil {
			return nil, err
		}
		script, err := transactionJSONScript(args.UnlockingScript)
		if err != nil {
			return nil, err
		}
		vout, err := decimalUint(args.Vout, 32)
		if err != nil {
			return nil, err
		}
		sequence, err := decimalUint(args.Sequence, 32)
		if err != nil {
			return nil, err
		}
		value := &transaction.TransactionInput{
			SourceTXID:       txID,
			UnlockingScript:  script,
			SourceTxOutIndex: uint32(vout),
			SequenceNumber:   uint32(sequence),
		}
		document, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		return transactionJSONDocumentResult(document)

	case "transaction.input.json.unmarshal":
		var args struct {
			JSON string `json:"json"`
		}
		if err := decodeArgs(raw, &args); err != nil {
			return nil, err
		}
		document, err := transactionJSONDocument(args.JSON)
		if err != nil {
			return nil, err
		}
		var value transaction.TransactionInput
		if err := json.Unmarshal(document, &value); err != nil {
			return nil, err
		}
		if value.SourceTXID == nil || value.UnlockingScript == nil {
			return nil, categorizedError{"invalidEncoding", "input JSON omitted required fields"}
		}
		if len(*value.UnlockingScript) > transactionJSONMaximumScriptBytes {
			return nil, categorizedError{"resourceLimit", "input script exceeds JSON operation limit"}
		}
		return map[string]string{
			"sequence":        decimalString(uint64(value.SequenceNumber)),
			"txid":            value.SourceTXID.String(),
			"unlockingScript": hex.EncodeToString(value.UnlockingScript.Bytes()),
			"vout":            decimalString(uint64(value.SourceTxOutIndex)),
		}, nil

	case "transaction.output.json.marshal":
		var args struct {
			Satoshis      string `json:"satoshis"`
			LockingScript string `json:"lockingScript"`
		}
		if err := decodeArgs(raw, &args); err != nil {
			return nil, err
		}
		satoshis, err := decimalUint(args.Satoshis, 64)
		if err != nil {
			return nil, err
		}
		script, err := transactionJSONScript(args.LockingScript)
		if err != nil {
			return nil, err
		}
		value := &transaction.TransactionOutput{Satoshis: satoshis, LockingScript: script}
		document, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		return transactionJSONDocumentResult(document)

	case "transaction.output.json.unmarshal":
		var args struct {
			JSON string `json:"json"`
		}
		if err := decodeArgs(raw, &args); err != nil {
			return nil, err
		}
		document, err := transactionJSONDocument(args.JSON)
		if err != nil {
			return nil, err
		}
		var value transaction.TransactionOutput
		if err := json.Unmarshal(document, &value); err != nil {
			return nil, err
		}
		if value.LockingScript == nil {
			return nil, categorizedError{"invalidEncoding", "output JSON omitted lockingScript"}
		}
		if len(*value.LockingScript) > transactionJSONMaximumScriptBytes {
			return nil, categorizedError{"resourceLimit", "output script exceeds JSON operation limit"}
		}
		return map[string]string{
			"lockingScript": hex.EncodeToString(value.LockingScript.Bytes()),
			"satoshis":      decimalString(value.Satoshis),
		}, nil
	default:
		return nil, categorizedError{"unsupportedOperation", "transaction JSON operation is not supported"}
	}
}

func transactionJSONDocument(text string) ([]byte, error) {
	if len(text) > transactionJSONMaximumDocumentBytes*2 {
		return nil, categorizedError{"resourceLimit", "transaction JSON exceeds operation limit"}
	}
	return protocolHex(text)
}

func transactionJSONDocumentResult(document []byte) (any, error) {
	if len(document) > transactionJSONMaximumDocumentBytes {
		return nil, categorizedError{"resourceLimit", "transaction JSON exceeds operation limit"}
	}
	return map[string]string{"json": hex.EncodeToString(document)}, nil
}

func transactionJSONTransactionID(text string) (*chainhash.Hash, error) {
	if len(text) != 64 {
		return nil, categorizedError{"invalidLength", "transaction ID must contain exactly 32 bytes"}
	}
	if _, err := protocolHex(text); err != nil {
		return nil, err
	}
	return chainhash.NewHashFromHex(text)
}

func transactionJSONScript(text string) (*scriptpkg.Script, error) {
	if len(text) > transactionJSONMaximumScriptBytes*2 {
		return nil, categorizedError{"resourceLimit", "script exceeds transaction JSON operation limit"}
	}
	data, err := protocolHex(text)
	if err != nil {
		return nil, err
	}
	return scriptpkg.NewFromBytes(data), nil
}

func decimalString(value uint64) string {
	return strconv.FormatUint(value, 10)
}

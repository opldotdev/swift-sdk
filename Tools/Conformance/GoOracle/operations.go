package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	base58 "github.com/bsv-blockchain/go-sdk/compat/base58"
	bsmcompat "github.com/bsv-blockchain/go-sdk/compat/bsm"
	eciescompat "github.com/bsv-blockchain/go-sdk/compat/ecies"
	messagepkg "github.com/bsv-blockchain/go-sdk/message"
	aesgcmprimitive "github.com/bsv-blockchain/go-sdk/primitives/aesgcm"
	drbgprimitive "github.com/bsv-blockchain/go-sdk/primitives/drbg"
	ecprimitive "github.com/bsv-blockchain/go-sdk/primitives/ec"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/hash"
	schnorrprimitive "github.com/bsv-blockchain/go-sdk/primitives/schnorr"
	scriptpkg "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	interpreterdebug "github.com/bsv-blockchain/go-sdk/script/interpreter/debug"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/spv"
	"github.com/bsv-blockchain/go-sdk/transaction"
	feemodelpkg "github.com/bsv-blockchain/go-sdk/transaction/fee_model"
	sighashpkg "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	p2pkhpkg "github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/bsv-blockchain/go-sdk/util"
)

type oracleChainTracker struct {
	validRoots map[uint32]chainhash.Hash
}

func executeScriptPair(raw json.RawMessage) (any, error) {
	var args struct {
		UnlockingScript    string   `json:"unlockingScript"`
		LockingScript      string   `json:"lockingScript"`
		Era                string   `json:"era"`
		Flags              []string `json:"flags,omitempty"`
		TransactionVersion *string  `json:"transactionVersion,omitempty"`
		Transaction        *string  `json:"transaction,omitempty"`
		InputIndex         *string  `json:"inputIndex,omitempty"`
		SourceSatoshis     *string  `json:"sourceSatoshis,omitempty"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	unlockingBytes, err := protocolHex(args.UnlockingScript)
	if err != nil {
		return nil, err
	}
	lockingBytes, err := protocolHex(args.LockingScript)
	if err != nil {
		return nil, err
	}
	unlockingScript := scriptpkg.NewFromBytes(unlockingBytes)
	lockingScript := scriptpkg.NewFromBytes(lockingBytes)

	var flags scriptflag.Flag
	for _, name := range args.Flags {
		switch name {
		case "p2sh":
			flags |= scriptflag.Bip16
		case "cleanStack":
			flags |= scriptflag.VerifyCleanStack
		case "minimalData":
			flags |= scriptflag.VerifyMinimalData
		case "minimalIf":
			flags |= scriptflag.VerifyMinimalIf
		case "signaturePushOnly":
			flags |= scriptflag.VerifySigPushOnly
		case "strictMultiSignatureDummy":
			flags |= scriptflag.StrictMultiSig
		case "derSignatures":
			flags |= scriptflag.VerifyDERSignatures
		case "lowS":
			flags |= scriptflag.VerifyLowS
		case "nullFail":
			flags |= scriptflag.VerifyNullFail
		case "enableForkID":
			flags |= scriptflag.EnableSighashForkID
		case "strictEncoding":
			flags |= scriptflag.VerifyStrictEncoding
		case "bip143SignatureHash":
			flags |= scriptflag.VerifyBip143SigHash
		default:
			return nil, categorizedError{"invalidEncoding", "unknown script flag: " + name}
		}
	}

	options := []interpreter.ExecutionOptionFunc{
		interpreter.WithScripts(lockingScript, unlockingScript),
		interpreter.WithFlags(flags),
	}
	contextFieldCount := 0
	if args.Transaction != nil {
		contextFieldCount++
	}
	if args.InputIndex != nil {
		contextFieldCount++
	}
	if args.SourceSatoshis != nil {
		contextFieldCount++
	}
	if contextFieldCount != 0 && contextFieldCount != 3 {
		return nil, categorizedError{"invalidEncoding", "transaction, inputIndex, and sourceSatoshis must be supplied together"}
	}
	if contextFieldCount == 3 {
		if args.TransactionVersion != nil {
			return nil, categorizedError{"invalidEncoding", "transactionVersion cannot accompany a complete transaction"}
		}
		transactionBytes, err := protocolHex(*args.Transaction)
		if err != nil {
			return nil, err
		}
		tx, err := transaction.NewTransactionFromBytes(transactionBytes)
		if err != nil {
			return nil, err
		}
		inputIndex, err := decimalUint(*args.InputIndex, 32)
		if err != nil {
			return nil, err
		}
		if inputIndex >= uint64(len(tx.Inputs)) {
			return nil, categorizedError{"invalidIndex", "input index is outside transaction inputs"}
		}
		if !bytes.Equal(tx.Inputs[inputIndex].UnlockingScript.Bytes(), unlockingBytes) {
			return nil, categorizedError{"invalidEncoding", "transaction unlocking script does not match request"}
		}
		satoshis, err := decimalUint(*args.SourceSatoshis, 64)
		if err != nil {
			return nil, err
		}
		options = append(options, interpreter.WithTx(
			tx,
			int(inputIndex),
			&transaction.TransactionOutput{
				Satoshis:      satoshis,
				LockingScript: lockingScript,
			},
		))
	}
	if args.TransactionVersion != nil {
		version, err := decimalUint(*args.TransactionVersion, 32)
		if err != nil {
			return nil, err
		}
		tx := &transaction.Transaction{
			Version: uint32(version),
			Inputs: []*transaction.TransactionInput{{
				UnlockingScript: unlockingScript,
			}},
		}
		options = append(options, interpreter.WithTx(
			tx,
			0,
			&transaction.TransactionOutput{LockingScript: lockingScript},
		))
	}
	switch args.Era {
	case "legacy":
	case "genesis":
		options = append(options, interpreter.WithAfterGenesis())
	case "chronicle":
		options = append(options, interpreter.WithAfterChronicle())
	default:
		return nil, categorizedError{"invalidEncoding", "script era must be legacy, genesis, or chronicle"}
	}

	debugger := interpreterdebug.NewDebugger()
	var finalStack [][]byte
	debugger.AttachAfterExecute(func(state *interpreter.State) {
		finalStack = make([][]byte, len(state.DataStack))
		for i := range state.DataStack {
			finalStack[i] = append([]byte(nil), state.DataStack[i]...)
		}
	})
	options = append(options, interpreter.WithDebugger(debugger))
	if err := interpreter.NewEngine().Execute(options...); err != nil {
		return nil, err
	}

	stack := make([]string, len(finalStack))
	for i := range finalStack {
		stack[i] = hex.EncodeToString(finalStack[i])
	}
	return map[string]any{"stack": stack, "valid": true}, nil
}

func (o oracleChainTracker) IsValidRootForHeight(
	_ context.Context,
	root *chainhash.Hash,
	height uint32,
) (bool, error) {
	expected, ok := o.validRoots[height]
	return ok && root != nil && expected.IsEqual(root), nil
}

func (o oracleChainTracker) CurrentHeight(_ context.Context) (uint32, error) {
	var current uint32
	for height := range o.validRoots {
		if height > current {
			current = height
		}
	}
	return current, nil
}

func summarizeBeef(beef *transaction.Beef) map[string]any {
	transactionIDs := make([]chainhash.Hash, 0, len(beef.Transactions))
	for transactionID := range beef.Transactions {
		transactionIDs = append(transactionIDs, transactionID)
	}
	sort.Slice(transactionIDs, func(i, j int) bool {
		return transactionIDs[i].String() < transactionIDs[j].String()
	})
	transactions := make([]map[string]string, 0, len(transactionIDs))
	for _, transactionID := range transactionIDs {
		entry := beef.Transactions[transactionID]
		summary := map[string]string{
			"format":        strconv.Itoa(int(entry.DataFormat)),
			"transactionID": transactionID.String(),
		}
		if entry.DataFormat == transaction.RawTxAndBumpIndex {
			summary["bumpIndex"] = strconv.Itoa(entry.BumpIndex)
		}
		transactions = append(transactions, summary)
	}
	return map[string]any{
		"bumps":        strconv.Itoa(len(beef.BUMPs)),
		"transactions": transactions,
		"version":      strconv.FormatUint(uint64(beef.Version), 10),
	}
}

func execute(req request, meta metadata) (result any, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = categorizedError{"oraclePanic", "operation panicked"}
		}
	}()

	switch req.Op {
	case "metadata":
		var args struct{}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		return meta, nil
	case "bytes.reverse":
		var args struct {
			Hex string `json:"hex"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Hex)
		if err != nil {
			return nil, err
		}
		return map[string]string{"hex": hex.EncodeToString(util.ReverseBytes(data))}, nil
	case "u16.encode", "u32.encode", "u64.encode":
		return encodeUnsigned(req.Op, req.Args)
	case "u16.decode", "u32.decode", "u64.decode":
		return decodeUnsigned(req.Op, req.Args)
	case "hex.encode":
		var args struct {
			Bytes string `json:"bytes"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		return map[string]string{"text": hex.EncodeToString(data)}, nil
	case "hex.decode":
		var args struct {
			Text string `json:"text"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := hex.DecodeString(args.Text)
		if err != nil {
			return nil, err
		}
		return map[string]string{"bytes": hex.EncodeToString(data)}, nil
	case "base64.encode":
		var args struct {
			Bytes string `json:"bytes"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		return map[string]string{"text": base64.StdEncoding.EncodeToString(data)}, nil
	case "base64.decode":
		var args struct {
			Text   string          `json:"text"`
			Policy json.RawMessage `json:"policy,omitempty"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		policy := "strict"
		if len(args.Policy) > 0 {
			if err := json.Unmarshal(args.Policy, &policy); err != nil {
				return nil, categorizedError{"invalidEncoding", "base64 policy must be a string"}
			}
		}
		encoding := base64.StdEncoding.Strict()
		switch policy {
		case "strict":
		case "goSDK":
			encoding = base64.StdEncoding
		default:
			return nil, categorizedError{"invalidEncoding", "base64 policy must be strict or goSDK"}
		}
		data, err := encoding.DecodeString(args.Text)
		if err != nil {
			return nil, err
		}
		return map[string]string{"bytes": hex.EncodeToString(data)}, nil
	case "varint.encode":
		var args struct {
			Value string `json:"value"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		value, err := decimalUint(args.Value, 64)
		if err != nil {
			return nil, err
		}
		return map[string]string{"bytes": hex.EncodeToString(util.VarInt(value).Bytes())}, nil
	case "varint.decode":
		return decodeVarIntArgs(req.Args)
	case "varbytes.encode":
		var args struct {
			Bytes string `json:"bytes"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		writer := util.NewWriter()
		writer.WriteIntBytes(data)
		return map[string]string{"bytes": hex.EncodeToString(writer.Buf)}, nil
	case "varbytes.decode":
		return decodeVarBytesArgs(req.Args)
	case "hash.sha256", "hash.sha256d", "hash.sha512", "hash.ripemd160", "hash.hash160":
		var args struct {
			Bytes string `json:"bytes"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		var digest []byte
		switch req.Op {
		case "hash.sha256":
			digest = primitives.Sha256(data)
		case "hash.sha256d":
			digest = primitives.Sha256d(data)
		case "hash.sha512":
			digest = primitives.Sha512(data)
		case "hash.ripemd160":
			digest = primitives.Ripemd160(data)
		default:
			digest = primitives.Hash160(data)
		}
		return map[string]string{"bytes": hex.EncodeToString(digest)}, nil
	case "hmac.sha256", "hmac.sha512":
		var args struct {
			Key     string `json:"key"`
			Message string `json:"message"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		key, err := protocolHex(args.Key)
		if err != nil {
			return nil, err
		}
		message, err := protocolHex(args.Message)
		if err != nil {
			return nil, err
		}
		var digest []byte
		if req.Op == "hmac.sha256" {
			digest = primitives.Sha256HMAC(message, key)
		} else {
			digest = primitives.Sha512HMAC(message, key)
		}
		return map[string]string{"bytes": hex.EncodeToString(digest)}, nil
	case "digest32.parse":
		var args struct {
			Display string `json:"display"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		if len(args.Display) != 64 {
			return nil, categorizedError{"invalidLength", "digest display must contain exactly 64 hexadecimal characters"}
		}
		hash, err := chainhash.NewHashFromHex(args.Display)
		if err != nil {
			return nil, err
		}
		return map[string]string{"bytes": hex.EncodeToString(hash[:])}, nil
	case "digest32.display":
		var args struct {
			Bytes string `json:"bytes"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		hash, err := chainhash.NewHash(data)
		if err != nil {
			return nil, categorizedError{"invalidLength", err.Error()}
		}
		return map[string]string{"display": hash.String()}, nil
	case "drbg.generate":
		return generateDRBG(req.Args)
	case "base58.encode":
		var args struct {
			Bytes string `json:"bytes"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		return map[string]string{"text": base58.Encode(data)}, nil
	case "base58.decode":
		var args struct {
			Text string `json:"text"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := base58.Decode(args.Text)
		if err != nil {
			return nil, err
		}
		if len(data) > maxLineBytes/2 {
			return nil, categorizedError{"resourceLimit", "decoded Base58 exceeds protocol resource limit"}
		}
		return map[string]string{"bytes": hex.EncodeToString(data)}, nil
	case "base58check.encode":
		return encodeBase58Check(req.Args)
	case "base58check.decode":
		return decodeBase58Check(req.Args)
	case "big.umod":
		var args struct {
			Dividend string `json:"dividend"`
			Divisor  string `json:"divisor"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		x, ok := new(big.Int).SetString(args.Dividend, 10)
		if !ok || canonicalInt(x) != args.Dividend {
			return nil, categorizedError{"invalidEncoding", "dividend is not a canonical decimal integer"}
		}
		y, ok := new(big.Int).SetString(args.Divisor, 10)
		if !ok || canonicalInt(y) != args.Divisor {
			return nil, categorizedError{"invalidEncoding", "divisor is not a canonical decimal integer"}
		}
		return map[string]string{"value": util.Umod(x, y).String()}, nil
	case "brc42.private.derive":
		var args struct {
			RecipientPrivateKey string `json:"recipientPrivateKey"`
			SenderPublicKey     string `json:"senderPublicKey"`
			InvoiceNumber       string `json:"invoiceNumber"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		recipient, err := protocolPrivateKey(args.RecipientPrivateKey)
		if err != nil {
			return nil, err
		}
		sender, err := protocolPublicKey(args.SenderPublicKey)
		if err != nil {
			return nil, err
		}
		child, err := recipient.DeriveChild(sender, args.InvoiceNumber)
		if err != nil || child == nil {
			return nil, categorizedError{"key", "BRC-42 private derivation failed"}
		}
		return map[string]string{"privateKey": hex.EncodeToString(child.Serialize())}, nil
	case "brc42.public.derive":
		var args struct {
			RecipientPublicKey string `json:"recipientPublicKey"`
			SenderPrivateKey   string `json:"senderPrivateKey"`
			InvoiceNumber      string `json:"invoiceNumber"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		recipient, err := protocolPublicKey(args.RecipientPublicKey)
		if err != nil {
			return nil, err
		}
		sender, err := protocolPrivateKey(args.SenderPrivateKey)
		if err != nil {
			return nil, err
		}
		child, err := recipient.DeriveChild(sender, args.InvoiceNumber)
		if err != nil || child == nil || !child.Validate() {
			return nil, categorizedError{"key", "BRC-42 public derivation failed"}
		}
		return map[string]string{"publicKey": hex.EncodeToString(child.Compressed())}, nil
	case "brc94.generate":
		var args struct {
			ProverPrivateKey      string `json:"proverPrivateKey"`
			CounterpartyPublicKey string `json:"counterpartyPublicKey"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		prover, err := protocolPrivateKey(args.ProverPrivateKey)
		if err != nil {
			return nil, err
		}
		counterparty, err := protocolPublicKey(args.CounterpartyPublicKey)
		if err != nil {
			return nil, err
		}
		sharedSecret, err := prover.DeriveSharedSecret(counterparty)
		if err != nil {
			return nil, err
		}
		proof, err := schnorrprimitive.New().GenerateProof(
			prover, prover.PubKey(), counterparty, sharedSecret,
		)
		if err != nil {
			return nil, err
		}
		return map[string]string{
			"noncePublicKey":    hex.EncodeToString(proof.R.Compressed()),
			"nonceSharedSecret": hex.EncodeToString(proof.SPrime.Compressed()),
			"proverPublicKey":   hex.EncodeToString(prover.PubKey().Compressed()),
			"sharedSecret":      hex.EncodeToString(sharedSecret.Compressed()),
			"response":          fmt.Sprintf("%064x", proof.Z),
		}, nil
	case "brc94.verify":
		var args struct {
			ProverPublicKey       string `json:"proverPublicKey"`
			CounterpartyPublicKey string `json:"counterpartyPublicKey"`
			SharedSecret          string `json:"sharedSecret"`
			NoncePublicKey        string `json:"noncePublicKey"`
			NonceSharedSecret     string `json:"nonceSharedSecret"`
			Response              string `json:"response"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		prover, err := protocolPublicKey(args.ProverPublicKey)
		if err != nil {
			return nil, err
		}
		counterparty, err := protocolPublicKey(args.CounterpartyPublicKey)
		if err != nil {
			return nil, err
		}
		sharedSecret, err := protocolPublicKey(args.SharedSecret)
		if err != nil {
			return nil, err
		}
		noncePublicKey, err := protocolPublicKey(args.NoncePublicKey)
		if err != nil {
			return nil, err
		}
		nonceSharedSecret, err := protocolPublicKey(args.NonceSharedSecret)
		if err != nil {
			return nil, err
		}
		responseBytes, err := protocolHex(args.Response)
		if err != nil {
			return nil, err
		}
		if len(responseBytes) != 32 {
			return nil, categorizedError{"invalidLength", "BRC-94 response must be 32 bytes"}
		}
		responseScalar := new(big.Int).SetBytes(responseBytes)
		if responseScalar.Sign() <= 0 || responseScalar.Cmp(ecprimitive.S256().N) >= 0 {
			return nil, categorizedError{"scalar", "BRC-94 response is outside scalar range"}
		}
		valid := schnorrprimitive.New().VerifyProof(
			prover,
			counterparty,
			sharedSecret,
			&schnorrprimitive.Proof{
				R: noncePublicKey, SPrime: nonceSharedSecret, Z: responseScalar,
			},
		)
		return map[string]bool{"valid": valid}, nil
	case "bsm.sign":
		var args struct {
			PrivateKey string `json:"privateKey"`
			Message    string `json:"message"`
			Compressed bool   `json:"compressed"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		privateKey, err := protocolPrivateKey(args.PrivateKey)
		if err != nil {
			return nil, err
		}
		message, err := protocolHex(args.Message)
		if err != nil {
			return nil, err
		}
		if len(message) > maxLineBytes {
			return nil, categorizedError{"resourceLimit", "BSM message exceeds protocol resource limit"}
		}
		signature, err := bsmcompat.SignMessageWithCompression(
			privateKey,
			message,
			args.Compressed,
		)
		if err != nil {
			return nil, categorizedError{"signature", err.Error()}
		}
		if len(signature) != 65 {
			return nil, categorizedError{"internal", "pinned Go BSM signer returned an invalid signature length"}
		}
		return map[string]string{"signature": hex.EncodeToString(signature)}, nil
	case "bsm.recover":
		var args struct {
			Signature string `json:"signature"`
			Message   string `json:"message"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		signature, err := protocolHex(args.Signature)
		if err != nil {
			return nil, err
		}
		if len(signature) != 65 {
			return nil, categorizedError{"invalidLength", "BSM signature must be exactly 65 bytes"}
		}
		message, err := protocolHex(args.Message)
		if err != nil {
			return nil, err
		}
		if len(message) > maxLineBytes {
			return nil, categorizedError{"resourceLimit", "BSM message exceeds protocol resource limit"}
		}
		publicKey, compressed, err := bsmcompat.PubKeyFromSignature(signature, message)
		if err != nil {
			return nil, categorizedError{"signature", err.Error()}
		}
		return map[string]any{
			"publicKey":  hex.EncodeToString(publicKey.Compressed()),
			"compressed": compressed,
		}, nil
	case "ecies.electrum.encrypt":
		var args struct {
			Plaintext           string `json:"plaintext"`
			RecipientPublicKey  string `json:"recipientPublicKey"`
			SenderPrivateKey    string `json:"senderPrivateKey"`
			OmitSenderPublicKey bool   `json:"omitSenderPublicKey"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		plaintext, err := protocolHex(args.Plaintext)
		if err != nil {
			return nil, err
		}
		recipient, err := protocolPublicKey(args.RecipientPublicKey)
		if err != nil {
			return nil, err
		}
		sender, err := protocolPrivateKey(args.SenderPrivateKey)
		if err != nil {
			return nil, err
		}
		envelope, err := eciescompat.ElectrumEncrypt(
			plaintext,
			recipient,
			sender,
			args.OmitSenderPublicKey,
		)
		if err != nil {
			return nil, err
		}
		return map[string]string{"envelope": hex.EncodeToString(envelope)}, nil
	case "ecies.electrum.decrypt":
		var args struct {
			Envelope            string `json:"envelope"`
			RecipientPrivateKey string `json:"recipientPrivateKey"`
			SenderPublicKey     string `json:"senderPublicKey"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		envelope, err := protocolHex(args.Envelope)
		if err != nil {
			return nil, err
		}
		recipient, err := protocolPrivateKey(args.RecipientPrivateKey)
		if err != nil {
			return nil, err
		}
		var sender *ecprimitive.PublicKey
		headerByteCount := 4
		minimumByteCount := 4 + 16 + 32
		if args.SenderPublicKey == "" {
			headerByteCount += ecprimitive.PubKeyBytesLenCompressed
			minimumByteCount += ecprimitive.PubKeyBytesLenCompressed
		} else {
			sender, err = protocolPublicKey(args.SenderPublicKey)
			if err != nil {
				return nil, err
			}
		}
		if len(envelope) < minimumByteCount {
			return nil, categorizedError{"invalidLength", "Electrum ECIES envelope is below its minimum length"}
		}
		if !bytes.Equal(envelope[:4], []byte("BIE1")) {
			return nil, categorizedError{"invalidEncoding", "Electrum ECIES magic is invalid"}
		}
		if args.SenderPublicKey == "" {
			if _, err := protocolPublicKey(hex.EncodeToString(envelope[4:37])); err != nil {
				return nil, err
			}
		} else if len(envelope) > 69 {
			// Pinned Go treats every external-key packet over 69 bytes as though a
			// 33-byte key were embedded. Reject the resulting non-block slice here
			// instead of allowing cipher.BlockMode.CryptBlocks to panic.
			goHeuristicCiphertextByteCount := len(envelope) - 37 - 32
			if goHeuristicCiphertextByteCount <= 0 || goHeuristicCiphertextByteCount%16 != 0 {
				return nil, categorizedError{"invalidLength", "pinned Go Electrum external-key heuristic misclassifies this omitted-key envelope"}
			}
		}
		ciphertextByteCount := len(envelope) - headerByteCount - 32
		if ciphertextByteCount <= 0 || ciphertextByteCount%16 != 0 {
			return nil, categorizedError{"invalidLength", "Electrum ECIES ciphertext must be nonempty and block aligned"}
		}
		plaintext, err := eciescompat.ElectrumDecrypt(envelope, recipient, sender)
		if err != nil {
			return nil, err
		}
		return map[string]string{"plaintext": hex.EncodeToString(plaintext)}, nil
	case "ecies.bitcore.encrypt":
		var args struct {
			Plaintext            string `json:"plaintext"`
			RecipientPublicKey   string `json:"recipientPublicKey"`
			SenderPrivateKey     string `json:"senderPrivateKey"`
			InitializationVector string `json:"initializationVector"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		plaintext, err := protocolHex(args.Plaintext)
		if err != nil {
			return nil, err
		}
		recipient, err := protocolPublicKey(args.RecipientPublicKey)
		if err != nil {
			return nil, err
		}
		sender, err := protocolPrivateKey(args.SenderPrivateKey)
		if err != nil {
			return nil, err
		}
		initializationVector, err := protocolHex(args.InitializationVector)
		if err != nil {
			return nil, err
		}
		if len(initializationVector) != 16 {
			return nil, categorizedError{"invalidLength", "Bitcore ECIES initialization vector must be exactly 16 bytes"}
		}
		envelope, err := eciescompat.BitcoreEncrypt(
			plaintext,
			recipient,
			sender,
			initializationVector,
		)
		if err != nil {
			return nil, err
		}
		return map[string]string{"envelope": hex.EncodeToString(envelope)}, nil
	case "ecies.bitcore.decrypt":
		var args struct {
			Envelope            string `json:"envelope"`
			RecipientPrivateKey string `json:"recipientPrivateKey"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		envelope, err := protocolHex(args.Envelope)
		if err != nil {
			return nil, err
		}
		recipient, err := protocolPrivateKey(args.RecipientPrivateKey)
		if err != nil {
			return nil, err
		}
		const bitcoreMinimumEnvelopeByteCount = 33 + 16 + 16 + 32
		if len(envelope) < bitcoreMinimumEnvelopeByteCount {
			return nil, categorizedError{"invalidLength", "Bitcore ECIES envelope is below its minimum length"}
		}
		if _, err := protocolPublicKey(hex.EncodeToString(envelope[:33])); err != nil {
			return nil, err
		}
		ciphertextByteCount := len(envelope) - 33 - 16 - 32
		if ciphertextByteCount <= 0 || ciphertextByteCount%16 != 0 {
			return nil, categorizedError{"invalidLength", "Bitcore ECIES ciphertext must be nonempty and block aligned"}
		}
		plaintext, err := eciescompat.BitcoreDecrypt(envelope, recipient)
		if err != nil {
			return nil, err
		}
		return map[string]string{"plaintext": hex.EncodeToString(plaintext)}, nil
	case "keyshares.split":
		return splitKeyShares(req.Args)
	case "keyshares.recover":
		return recoverKeyShares(req.Args)
	case "portable.encrypted.decrypt":
		return decryptPortableMessage(req.Args)
	case "portable.encrypted.encrypt":
		return encryptPortableMessage(req.Args)
	case "portable.signed.sign":
		return signPortableMessage(req.Args)
	case "portable.signed.verify":
		return verifyPortableMessage(req.Args)
	case "scriptnum.encode":
		return encodeScriptNumber(req.Args)
	case "scriptnum.decode":
		return decodeScriptNumber(req.Args)
	case "script.execute":
		return executeScriptPair(req.Args)
	case "script.asm.decode":
		var args struct {
			Text string `json:"text"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		script, err := scriptpkg.NewFromASM(args.Text)
		if err != nil {
			return nil, err
		}
		return map[string]string{"bytes": hex.EncodeToString(script.Bytes())}, nil
	case "script.asm.encode":
		var args struct {
			Bytes string `json:"bytes"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		script := scriptpkg.NewFromBytes(data)
		return map[string]string{"text": script.ToASM()}, nil
	case "script.asm.names":
		var args struct{}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		names := make([]string, 256)
		for raw := 0; raw < 256; raw++ {
			name, present := scriptpkg.OpCodeValues[byte(raw)]
			if !present {
				return nil, categorizedError{"internal", "pinned Go opcode name table is incomplete"}
			}
			names[raw] = name
		}
		return map[string]any{"names": names}, nil
	case "spv.verify":
		var args struct {
			Bytes               string  `json:"bytes"`
			SatoshisPerKilobyte *string `json:"satoshisPerKilobyte,omitempty"`
			ValidRoots          []struct {
				BlockHeight string `json:"blockHeight"`
				Root        string `json:"root"`
			} `json:"validRoots"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		tx, err := transaction.NewTransactionFromBEEF(data)
		if err != nil {
			return nil, err
		}
		roots := make(map[uint32]chainhash.Hash, len(args.ValidRoots))
		for _, item := range args.ValidRoots {
			height, err := decimalUint(item.BlockHeight, 32)
			if err != nil {
				return nil, err
			}
			root, err := chainhash.NewHashFromHex(item.Root)
			if err != nil {
				return nil, err
			}
			roots[uint32(height)] = *root
		}
		var feeModel transaction.FeeModel
		if args.SatoshisPerKilobyte != nil {
			rate, err := decimalUint(*args.SatoshisPerKilobyte, 64)
			if err != nil {
				return nil, err
			}
			feeModel = &feemodelpkg.SatoshisPerKilobyte{Satoshis: rate}
		}
		valid, err := spv.Verify(
			context.Background(),
			tx,
			oracleChainTracker{validRoots: roots},
			feeModel,
		)
		if err != nil {
			return nil, err
		}
		return map[string]bool{"valid": valid}, nil
	case "symmetric.encrypt":
		var args struct {
			Key       string `json:"key"`
			Plaintext string `json:"plaintext"`
			Nonce     string `json:"nonce"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		key, err := protocolSymmetricKey(args.Key)
		if err != nil {
			return nil, err
		}
		plaintext, err := protocolHex(args.Plaintext)
		if err != nil {
			return nil, err
		}
		nonce, err := protocolHex(args.Nonce)
		if err != nil {
			return nil, err
		}
		if len(nonce) != 32 {
			return nil, categorizedError{"invalidLength", "symmetric nonce must be 32 bytes"}
		}
		ciphertext, tag, err := aesgcmprimitive.AESGCMEncrypt(
			plaintext, key.ToBytes(), nonce, []byte{},
		)
		if err != nil {
			return nil, err
		}
		envelope := make([]byte, 0, len(nonce)+len(ciphertext)+len(tag))
		envelope = append(envelope, nonce...)
		envelope = append(envelope, ciphertext...)
		envelope = append(envelope, tag...)
		return map[string]string{"envelope": hex.EncodeToString(envelope)}, nil
	case "symmetric.decrypt":
		var args struct {
			Key      string `json:"key"`
			Envelope string `json:"envelope"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		key, err := protocolSymmetricKey(args.Key)
		if err != nil {
			return nil, err
		}
		envelope, err := protocolHex(args.Envelope)
		if err != nil {
			return nil, err
		}
		plaintext, err := key.Decrypt(envelope)
		if err != nil {
			return nil, err
		}
		return map[string]string{"plaintext": hex.EncodeToString(plaintext)}, nil
	case "transaction.decode":
		var args struct {
			Bytes string `json:"bytes"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
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
		return map[string]string{
			"bytes":    hex.EncodeToString(tx.Bytes()),
			"inputs":   strconv.Itoa(len(tx.Inputs)),
			"lockTime": strconv.FormatUint(uint64(tx.LockTime), 10),
			"outputs":  strconv.Itoa(len(tx.Outputs)),
			"txid":     tx.TxID().String(),
			"version":  strconv.FormatUint(uint64(tx.Version), 10),
		}, nil
	case "transaction.ef.encode":
		var args struct {
			Bytes   string `json:"bytes"`
			Sources []struct {
				Satoshis      string `json:"satoshis"`
				LockingScript string `json:"lockingScript"`
			} `json:"sources"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		rawBytes, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		if len(rawBytes) >= 10 && bytes.Equal(rawBytes[4:10], extendedTransactionMarker) {
			return nil, categorizedError{"invalidEncoding", "bytes must be a raw transaction, not Extended Format"}
		}
		summary, err := preflightTransactionPacket(rawBytes, false)
		if err != nil {
			return nil, err
		}
		if len(args.Sources) != summary.inputCount {
			return nil, categorizedError{"invalidLength", "sources must contain exactly one entry per input"}
		}
		sourceScripts := make([][]byte, len(args.Sources))
		sourceSatoshis := make([]uint64, len(args.Sources))
		estimatedEFLength := len(rawBytes) + len(extendedTransactionMarker)
		for index, source := range args.Sources {
			satoshis, parseErr := decimalUint(source.Satoshis, 64)
			if parseErr != nil {
				return nil, parseErr
			}
			lockingScript, parseErr := protocolHex(source.LockingScript)
			if parseErr != nil {
				return nil, parseErr
			}
			increment := 8 + varIntLength(uint64(len(lockingScript))) + len(lockingScript)
			if increment > maxLineBytes-estimatedEFLength {
				return nil, categorizedError{"resourceLimit", "Extended Format result exceeds protocol bounds"}
			}
			estimatedEFLength += increment
			sourceScripts[index] = lockingScript
			sourceSatoshis[index] = satoshis
		}
		if !hexResponseFits(estimatedEFLength, len(rawBytes), 0, 0) {
			return nil, categorizedError{"resourceLimit", "Extended Format result exceeds protocol bounds"}
		}
		tx, err := transaction.NewTransactionFromBytes(rawBytes)
		if err != nil {
			return nil, err
		}
		for index := range args.Sources {
			tx.Inputs[index].SetSourceTxOutput(&transaction.TransactionOutput{
				Satoshis:      sourceSatoshis[index],
				LockingScript: scriptpkg.NewFromBytes(sourceScripts[index]),
			})
		}
		extendedBytes, err := tx.EF()
		if err != nil {
			return nil, err
		}
		return map[string]string{
			"bytes":    hex.EncodeToString(extendedBytes),
			"rawBytes": hex.EncodeToString(tx.Bytes()),
			"txid":     tx.TxID().String(),
		}, nil
	case "transaction.ef.decode":
		var args struct {
			Bytes string `json:"bytes"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		extendedBytes, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		summary, err := preflightTransactionPacket(extendedBytes, true)
		if err != nil {
			return nil, err
		}
		if !hexResponseFits(
			len(extendedBytes), summary.rawByteCount, summary.sourceScriptByteCount, summary.inputCount,
		) {
			return nil, categorizedError{"resourceLimit", "Extended Format result exceeds protocol bounds"}
		}
		tx, err := transaction.NewTransactionFromBytes(extendedBytes)
		if err != nil {
			return nil, err
		}
		canonicalEF, err := tx.EF()
		if err != nil {
			return nil, err
		}
		sources := make([]map[string]string, len(tx.Inputs))
		for index, input := range tx.Inputs {
			source := input.SourceTxOutput()
			if source == nil || source.LockingScript == nil {
				return nil, categorizedError{"internal", "pinned Go omitted a preflighted source output"}
			}
			sources[index] = map[string]string{
				"satoshis":      strconv.FormatUint(source.Satoshis, 10),
				"lockingScript": hex.EncodeToString(*source.LockingScript),
			}
		}
		return map[string]any{
			"bytes":    hex.EncodeToString(canonicalEF),
			"rawBytes": hex.EncodeToString(tx.Bytes()),
			"txid":     tx.TxID().String(),
			"version":  strconv.FormatUint(uint64(tx.Version), 10),
			"inputs":   strconv.Itoa(len(tx.Inputs)),
			"outputs":  strconv.Itoa(len(tx.Outputs)),
			"lockTime": strconv.FormatUint(uint64(tx.LockTime), 10),
			"sources":  sources,
		}, nil
	case "transaction.beef.decode":
		var args struct {
			Bytes string `json:"bytes"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		var beef *transaction.Beef
		atomicSubject := ""
		if len(data) >= 4 && binary.LittleEndian.Uint32(data[:4]) == transaction.ATOMIC_BEEF {
			var subject *chainhash.Hash
			beef, subject, err = transaction.NewBeefFromAtomicBytes(data)
			if subject != nil {
				atomicSubject = subject.String()
			}
		} else {
			beef, err = transaction.NewBeefFromBytes(data)
		}
		if err != nil {
			return nil, err
		}
		newest := ""
		if beef.NewestTxID != nil {
			newest = beef.NewestTxID.String()
		}
		return map[string]string{
			"atomicSubject": atomicSubject,
			"bumps":         strconv.Itoa(len(beef.BUMPs)),
			"newestTxid":    newest,
			"transactions":  strconv.Itoa(len(beef.Transactions)),
			"version":       strconv.FormatUint(uint64(beef.Version), 10),
		}, nil
	case "transaction.beef.reencode":
		var args struct {
			Bytes string `json:"bytes"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		var encoded []byte
		if len(data) >= 4 && binary.LittleEndian.Uint32(data[:4]) == transaction.ATOMIC_BEEF {
			beef, subject, parseErr := transaction.NewBeefFromAtomicBytes(data)
			if parseErr != nil {
				return nil, parseErr
			}
			encoded, err = beef.AtomicBytes(subject)
		} else {
			beef, parseErr := transaction.NewBeefFromBytes(data)
			if parseErr != nil {
				return nil, parseErr
			}
			encoded, err = beef.Bytes()
		}
		if err != nil {
			return nil, err
		}
		return map[string]string{"bytes": hex.EncodeToString(encoded)}, nil
	case "transaction.beef.validate":
		var args struct {
			AllowTransactionIDOnly bool   `json:"allowTransactionIDOnly"`
			Bytes                  string `json:"bytes"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		beef, err := transaction.NewBeefFromBytes(data)
		if err != nil {
			return nil, err
		}
		return map[string]bool{"valid": beef.IsValid(args.AllowTransactionIDOnly)}, nil
	case "transaction.beef.verify":
		var args struct {
			AllowTransactionIDOnly bool   `json:"allowTransactionIDOnly"`
			Bytes                  string `json:"bytes"`
			ValidRoots             []struct {
				BlockHeight string `json:"blockHeight"`
				Root        string `json:"root"`
			} `json:"validRoots"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		beef, err := transaction.NewBeefFromBytes(data)
		if err != nil {
			return nil, err
		}
		roots := make(map[uint32]chainhash.Hash, len(args.ValidRoots))
		for _, item := range args.ValidRoots {
			height, err := decimalUint(item.BlockHeight, 32)
			if err != nil {
				return nil, err
			}
			root, err := chainhash.NewHashFromHex(item.Root)
			if err != nil {
				return nil, err
			}
			roots[uint32(height)] = *root
		}
		valid, err := beef.Verify(
			context.Background(),
			oracleChainTracker{validRoots: roots},
			args.AllowTransactionIDOnly,
		)
		if err != nil {
			return nil, err
		}
		return map[string]bool{"valid": valid}, nil
	case "transaction.beef.merge":
		var args struct {
			Left  string `json:"left"`
			Right string `json:"right"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		leftBytes, err := protocolHex(args.Left)
		if err != nil {
			return nil, err
		}
		rightBytes, err := protocolHex(args.Right)
		if err != nil {
			return nil, err
		}
		left, err := transaction.NewBeefFromBytes(leftBytes)
		if err != nil {
			return nil, err
		}
		right, err := transaction.NewBeefFromBytes(rightBytes)
		if err != nil {
			return nil, err
		}
		if err := left.MergeBeef(right); err != nil {
			return nil, err
		}
		return summarizeBeef(left), nil
	case "transaction.beef.txidonly":
		var args struct {
			Bytes string `json:"bytes"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		beef, err := transaction.NewBeefFromBytes(data)
		if err != nil {
			return nil, err
		}
		projected, err := beef.TxidOnly()
		if err != nil {
			return nil, err
		}
		return summarizeBeef(projected), nil
	case "transaction.beef.trim":
		var args struct {
			Bytes               string   `json:"bytes"`
			KnownTransactionIDs []string `json:"knownTransactionIDs"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		beef, err := transaction.NewBeefFromBytes(data)
		if err != nil {
			return nil, err
		}
		beef.TrimknownTxIDs(args.KnownTransactionIDs)
		return summarizeBeef(beef), nil
	case "transaction.fee":
		var args struct {
			Bytes               string    `json:"bytes"`
			SatoshisPerKilobyte string    `json:"satoshisPerKilobyte"`
			UnlockingByteCounts []*string `json:"unlockingByteCounts"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		rate, err := decimalUint(args.SatoshisPerKilobyte, 64)
		if err != nil {
			return nil, err
		}
		tx, err := transaction.NewTransactionFromBytes(data)
		if err != nil {
			return nil, err
		}
		if len(args.UnlockingByteCounts) != len(tx.Inputs) {
			return nil, categorizedError{"invalidLength", "unlockingByteCounts must have one entry per input"}
		}
		for inputIndex, encodedCount := range args.UnlockingByteCounts {
			if encodedCount == nil {
				continue
			}
			count, err := decimalUint(*encodedCount, 32)
			if err != nil {
				return nil, err
			}
			tx.Inputs[inputIndex].UnlockingScriptTemplate = fixedLengthUnlocker(count)
		}
		fee, err := (&feemodelpkg.SatoshisPerKilobyte{Satoshis: rate}).ComputeFee(tx)
		if err != nil {
			return nil, err
		}
		return map[string]string{"fee": strconv.FormatUint(fee, 10)}, nil
	case "transaction.merklepath.combine":
		var args struct {
			Left  string `json:"left"`
			Right string `json:"right"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		leftBytes, err := protocolHex(args.Left)
		if err != nil {
			return nil, err
		}
		rightBytes, err := protocolHex(args.Right)
		if err != nil {
			return nil, err
		}
		left, err := transaction.NewMerklePathFromBinary(leftBytes)
		if err != nil {
			return nil, err
		}
		right, err := transaction.NewMerklePathFromBinary(rightBytes)
		if err != nil {
			return nil, err
		}
		if err := left.Combine(right); err != nil {
			return nil, err
		}
		return map[string]string{"bytes": hex.EncodeToString(left.Bytes())}, nil
	case "transaction.merklepath.decode":
		var args struct {
			Bytes string `json:"bytes"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		path, err := transaction.NewMerklePathFromBinary(data)
		if err != nil {
			return nil, err
		}
		return map[string]string{
			"blockHeight": strconv.FormatUint(uint64(path.BlockHeight), 10),
			"bytes":       hex.EncodeToString(path.Bytes()),
			"treeHeight":  strconv.Itoa(len(path.Path)),
		}, nil
	case "transaction.merklepath.root":
		var args struct {
			Bytes string `json:"bytes"`
			Txid  string `json:"txid"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		path, err := transaction.NewMerklePathFromBinary(data)
		if err != nil {
			return nil, err
		}
		root, err := path.ComputeRootHex(&args.Txid)
		if err != nil {
			return nil, err
		}
		return map[string]string{"root": root}, nil
	case "transaction.sighash":
		var args struct {
			Bytes          string `json:"bytes"`
			InputIndex     string `json:"inputIndex"`
			SourceSatoshis string `json:"sourceSatoshis"`
			SourceScript   string `json:"sourceScript"`
			SignatureHash  string `json:"signatureHash"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		inputIndex, err := decimalUint(args.InputIndex, 32)
		if err != nil {
			return nil, err
		}
		satoshis, err := decimalUint(args.SourceSatoshis, 64)
		if err != nil {
			return nil, err
		}
		sourceScript, err := protocolHex(args.SourceScript)
		if err != nil {
			return nil, err
		}
		flag, err := protocolSignatureHashFlag(args.SignatureHash)
		if err != nil {
			return nil, err
		}
		tx, err := transaction.NewTransactionFromBytes(data)
		if err != nil {
			return nil, err
		}
		if inputIndex >= uint64(len(tx.Inputs)) {
			return nil, categorizedError{"invalidIndex", "input index is outside transaction inputs"}
		}
		tx.Inputs[inputIndex].SetSourceTxOutput(&transaction.TransactionOutput{
			Satoshis:      satoshis,
			LockingScript: scriptpkg.NewFromBytes(sourceScript),
		})
		var preimage []byte
		if flag.Has(sighashpkg.ForkID) {
			preimage, err = tx.CalcInputPreimage(uint32(inputIndex), flag)
		} else {
			preimage, err = tx.CalcInputPreimageLegacy(uint32(inputIndex), flag)
		}
		if err != nil {
			return nil, err
		}
		digest, err := tx.CalcInputSignatureHash(uint32(inputIndex), flag)
		if err != nil {
			return nil, err
		}
		return map[string]string{
			"digest":   hex.EncodeToString(digest),
			"preimage": hex.EncodeToString(preimage),
		}, nil
	case "transaction.p2pkh.sign":
		var args struct {
			Bytes          string `json:"bytes"`
			InputIndex     string `json:"inputIndex"`
			SourceSatoshis string `json:"sourceSatoshis"`
			SourceScript   string `json:"sourceScript"`
			SignatureHash  string `json:"signatureHash"`
			PrivateKey     string `json:"privateKey"`
		}
		if err := decodeArgs(req.Args, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.Bytes)
		if err != nil {
			return nil, err
		}
		inputIndex, err := decimalUint(args.InputIndex, 32)
		if err != nil {
			return nil, err
		}
		satoshis, err := decimalUint(args.SourceSatoshis, 64)
		if err != nil {
			return nil, err
		}
		sourceScript, err := protocolHex(args.SourceScript)
		if err != nil {
			return nil, err
		}
		flag, err := protocolForkIDFlag(args.SignatureHash)
		if err != nil {
			return nil, err
		}
		privateKeyBytes, err := protocolHex(args.PrivateKey)
		if err != nil {
			return nil, err
		}
		if len(privateKeyBytes) != 32 {
			return nil, categorizedError{"invalidLength", "privateKey must contain exactly 32 bytes"}
		}
		privateKey, _ := ecprimitive.PrivateKeyFromBytes(privateKeyBytes)
		if privateKey.D.Sign() <= 0 || privateKey.D.Cmp(ecprimitive.S256().Params().N) >= 0 {
			return nil, categorizedError{"invalidKey", "privateKey scalar is outside secp256k1 range"}
		}
		tx, err := transaction.NewTransactionFromBytes(data)
		if err != nil {
			return nil, err
		}
		if inputIndex >= uint64(len(tx.Inputs)) {
			return nil, categorizedError{"invalidIndex", "input index is outside transaction inputs"}
		}
		tx.Inputs[inputIndex].SetSourceTxOutput(&transaction.TransactionOutput{
			Satoshis:      satoshis,
			LockingScript: scriptpkg.NewFromBytes(sourceScript),
		})
		unlocker, err := p2pkhpkg.Unlock(privateKey, &flag)
		if err != nil {
			return nil, err
		}
		unlockingScript, err := unlocker.Sign(tx, uint32(inputIndex))
		if err != nil {
			return nil, err
		}
		return map[string]string{"unlockingScript": hex.EncodeToString(*unlockingScript)}, nil
	default:
		return nil, categorizedError{"unsupportedOperation", "operation is not in the pinned registry"}
	}
}

func splitKeyShares(raw json.RawMessage) (any, error) {
	var args struct {
		PrivateKey string `json:"privateKey"`
		Threshold  string `json:"threshold"`
		ShareCount string `json:"shareCount"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	privateKey, err := protocolPrivateKey(args.PrivateKey)
	if err != nil {
		return nil, err
	}
	threshold, err := decimalUint(args.Threshold, 8)
	if err != nil {
		return nil, err
	}
	shareCount, err := decimalUint(args.ShareCount, 8)
	if err != nil {
		return nil, err
	}
	if threshold < 2 || threshold > 20 || shareCount < 2 || shareCount > 20 || threshold > shareCount {
		return nil, categorizedError{"invalidEncoding", "key-share threshold and count must satisfy 2 <= threshold <= shareCount <= 20"}
	}

	shares, err := privateKey.ToBackupShares(int(threshold), int(shareCount))
	if err != nil {
		return nil, categorizedError{"internal", "pinned Go key-share split failed"}
	}
	if len(shares) != int(shareCount) {
		return nil, categorizedError{"internal", "pinned Go key-share split returned an unexpected count"}
	}
	for _, share := range shares {
		fields := strings.Split(share, ".")
		if len([]byte(share)) == 0 || len([]byte(share)) > 128 || len(fields) != 4 {
			return nil, categorizedError{"internal", "pinned Go key-share split returned invalid framing"}
		}
		for _, field := range fields {
			if field == "" {
				return nil, categorizedError{"internal", "pinned Go key-share split returned invalid framing"}
			}
		}
	}
	return map[string]any{"shares": shares}, nil
}

func recoverKeyShares(raw json.RawMessage) (any, error) {
	var args struct {
		Shares []string `json:"shares"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if len(args.Shares) < 2 || len(args.Shares) > 20 {
		return nil, categorizedError{"invalidLength", "key-share recovery requires 2 through 20 shares"}
	}
	seen := make(map[string]struct{}, len(args.Shares))
	for _, share := range args.Shares {
		if len([]byte(share)) > 128 {
			return nil, categorizedError{"resourceLimit", "key-share text exceeds 128 UTF-8 bytes"}
		}
		fields := strings.Split(share, ".")
		if len(fields) != 4 {
			return nil, categorizedError{"invalidEncoding", "key share must contain exactly four fields"}
		}
		for _, field := range fields {
			if field == "" {
				return nil, categorizedError{"invalidEncoding", "key-share fields must not be empty"}
			}
		}
		if _, duplicate := seen[share]; duplicate {
			return nil, categorizedError{"invalidEncoding", "duplicate key share"}
		}
		seen[share] = struct{}{}
	}

	privateKey, err := ecprimitive.PrivateKeyFromBackupShares(args.Shares)
	if err != nil || privateKey == nil {
		// Go errors may echo complete share strings. Keep secret-bearing backup
		// material out of the normalized protocol error surface.
		return nil, categorizedError{"invalidEncoding", "pinned Go key-share recovery rejected the shares"}
	}
	serialized := privateKey.Serialize()
	if len(serialized) != ecprimitive.PrivateKeyBytesLen {
		return nil, categorizedError{"internal", "pinned Go key-share recovery returned an invalid key length"}
	}
	return map[string]string{"privateKey": hex.EncodeToString(serialized)}, nil
}

type fixedLengthUnlocker uint32

func (f fixedLengthUnlocker) Sign(*transaction.Transaction, uint32) (*scriptpkg.Script, error) {
	return nil, errors.New("fixed-length oracle unlocker cannot sign")
}

func (f fixedLengthUnlocker) EstimateLength(*transaction.Transaction, uint32) uint32 {
	return uint32(f)
}

const portableContentMaximumByteCount = (maxLineBytes - 4096) / 2
const portableVerificationFieldMaximumByteCount = (maxLineBytes - 4096) / 4

var portableSignedVersion = []byte{0x42, 0x42, 0x33, 0x01}
var portableEncryptedVersion = []byte{0x42, 0x42, 0x10, 0x33}

func signPortableMessage(raw json.RawMessage) (any, error) {
	var args struct {
		Message            *string `json:"message"`
		SenderPrivateKey   *string `json:"senderPrivateKey"`
		RecipientPublicKey *string `json:"recipientPublicKey,omitempty"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if args.Message == nil || args.SenderPrivateKey == nil {
		return nil, categorizedError{"invalidEncoding", "portable signing arguments must not be null"}
	}
	messageBytes, err := portableHex(*args.Message, portableContentMaximumByteCount)
	if err != nil {
		return nil, err
	}
	sender, err := portablePrivateKey(*args.SenderPrivateKey)
	if err != nil {
		return nil, err
	}
	var recipient *ecprimitive.PublicKey
	if args.RecipientPublicKey != nil {
		recipient, err = portablePublicKey(*args.RecipientPublicKey)
		if err != nil {
			return nil, err
		}
	}
	envelope, err := messagepkg.Sign(messageBytes, sender, recipient)
	if err != nil {
		return nil, categorizedError{"internal", "pinned Go portable signing failed"}
	}
	if _, err := preflightPortableSigned(envelope); err != nil {
		return nil, categorizedError{"internal", "pinned Go portable signing returned an invalid envelope"}
	}
	return map[string]string{"envelope": hex.EncodeToString(envelope)}, nil
}

func verifyPortableMessage(raw json.RawMessage) (any, error) {
	var args struct {
		Message             *string `json:"message"`
		Envelope            *string `json:"envelope"`
		RecipientPrivateKey *string `json:"recipientPrivateKey,omitempty"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if args.Message == nil || args.Envelope == nil {
		return nil, categorizedError{"invalidEncoding", "portable verification arguments must not be null"}
	}
	messageBytes, err := portableHex(*args.Message, portableVerificationFieldMaximumByteCount)
	if err != nil {
		return nil, err
	}
	envelope, err := portableHex(*args.Envelope, portableVerificationFieldMaximumByteCount)
	if err != nil {
		return nil, err
	}
	requiredRecipient, err := preflightPortableSigned(envelope)
	if err != nil {
		return nil, err
	}
	var recipient *ecprimitive.PrivateKey
	if args.RecipientPrivateKey != nil {
		recipient, err = portablePrivateKey(*args.RecipientPrivateKey)
		if err != nil {
			return nil, err
		}
	}
	if requiredRecipient != nil {
		if recipient == nil || !bytes.Equal(
			requiredRecipient.Compressed(),
			recipient.PubKey().Compressed(),
		) {
			return nil, categorizedError{"recipientMismatch", "portable signature recipient does not match"}
		}
	}
	valid, err := messagepkg.Verify(messageBytes, envelope, recipient)
	if err != nil {
		return nil, categorizedError{"internal", "pinned Go portable verification failed"}
	}
	return map[string]bool{"valid": valid}, nil
}

func encryptPortableMessage(raw json.RawMessage) (any, error) {
	var args struct {
		Plaintext          *string `json:"plaintext"`
		SenderPrivateKey   *string `json:"senderPrivateKey"`
		RecipientPublicKey *string `json:"recipientPublicKey"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if args.Plaintext == nil || args.SenderPrivateKey == nil || args.RecipientPublicKey == nil {
		return nil, categorizedError{"invalidEncoding", "portable encryption arguments must not be null"}
	}
	plaintext, err := portableHex(*args.Plaintext, portableContentMaximumByteCount)
	if err != nil {
		return nil, err
	}
	sender, err := portablePrivateKey(*args.SenderPrivateKey)
	if err != nil {
		return nil, err
	}
	recipient, err := portablePublicKey(*args.RecipientPublicKey)
	if err != nil {
		return nil, err
	}
	envelope, err := messagepkg.Encrypt(plaintext, sender, recipient)
	if err != nil {
		return nil, categorizedError{"internal", "pinned Go portable encryption failed"}
	}
	if _, err := preflightPortableEncrypted(envelope); err != nil {
		return nil, categorizedError{"internal", "pinned Go portable encryption returned an invalid envelope"}
	}
	return map[string]string{"envelope": hex.EncodeToString(envelope)}, nil
}

func decryptPortableMessage(raw json.RawMessage) (any, error) {
	var args struct {
		Envelope            *string `json:"envelope"`
		RecipientPrivateKey *string `json:"recipientPrivateKey"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if args.Envelope == nil || args.RecipientPrivateKey == nil {
		return nil, categorizedError{"invalidEncoding", "portable decryption arguments must not be null"}
	}
	envelope, err := portableHex(*args.Envelope, portableContentMaximumByteCount)
	if err != nil {
		return nil, err
	}
	requiredRecipient, err := preflightPortableEncrypted(envelope)
	if err != nil {
		return nil, err
	}
	recipient, err := portablePrivateKey(*args.RecipientPrivateKey)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(requiredRecipient.Compressed(), recipient.PubKey().Compressed()) {
		return nil, categorizedError{"recipientMismatch", "portable encryption recipient does not match"}
	}
	plaintext, err := messagepkg.Decrypt(envelope, recipient)
	if err != nil {
		return nil, categorizedError{"authenticationFailed", "portable message authentication failed"}
	}
	return map[string]string{"plaintext": hex.EncodeToString(plaintext)}, nil
}

func preflightPortableSigned(envelope []byte) (*ecprimitive.PublicKey, error) {
	if len(envelope) < len(portableSignedVersion) {
		return nil, categorizedError{"invalidLength", "portable signed envelope is too short"}
	}
	if !bytes.Equal(envelope[:len(portableSignedVersion)], portableSignedVersion) {
		return nil, categorizedError{"unsupportedVersion", "portable signed version is unsupported"}
	}
	const anyoneMinimumByteCount = 4 + 33 + 1 + 32 + 8
	if len(envelope) < anyoneMinimumByteCount {
		return nil, categorizedError{"invalidLength", "portable signed envelope is too short"}
	}
	if _, err := portablePublicKeyBytes(envelope[4:37]); err != nil {
		return nil, err
	}
	cursor := 37
	var recipient *ecprimitive.PublicKey
	if envelope[cursor] == 0 {
		cursor++
	} else {
		const specificMinimumByteCount = 4 + 33 + 33 + 32 + 8
		if len(envelope) < specificMinimumByteCount {
			return nil, categorizedError{"invalidLength", "portable signed envelope is too short"}
		}
		var err error
		recipient, err = portablePublicKeyBytes(envelope[cursor : cursor+33])
		if err != nil {
			return nil, err
		}
		cursor += 33
	}
	cursor += 32
	signatureBytes := envelope[cursor:]
	signature, err := ecprimitive.ParseDERSignature(signatureBytes)
	if err != nil {
		return nil, categorizedError{"invalidSignature", "portable signature is not canonical DER"}
	}
	canonicalDER, err := signature.ToDER()
	if err != nil || !bytes.Equal(canonicalDER, signatureBytes) {
		return nil, categorizedError{"invalidSignature", "portable signature is not canonical DER"}
	}
	return recipient, nil
}

func preflightPortableEncrypted(envelope []byte) (*ecprimitive.PublicKey, error) {
	if len(envelope) < len(portableEncryptedVersion) {
		return nil, categorizedError{"invalidLength", "portable encrypted envelope is too short"}
	}
	if !bytes.Equal(envelope[:len(portableEncryptedVersion)], portableEncryptedVersion) {
		return nil, categorizedError{"unsupportedVersion", "portable encrypted version is unsupported"}
	}
	const minimumByteCount = 4 + 33 + 33 + 32 + 32 + 16
	if len(envelope) < minimumByteCount {
		return nil, categorizedError{"invalidLength", "portable encrypted envelope is too short"}
	}
	if _, err := portablePublicKeyBytes(envelope[4:37]); err != nil {
		return nil, err
	}
	return portablePublicKeyBytes(envelope[37:70])
}

func portableHex(text string, maximumByteCount int) ([]byte, error) {
	if len(text)%2 != 0 || text != strings.ToLower(text) {
		return nil, categorizedError{"invalidHex", "portable byte fields require lowercase even hexadecimal"}
	}
	data, err := hex.DecodeString(text)
	if err != nil {
		return nil, categorizedError{"invalidHex", "portable byte fields require lowercase even hexadecimal"}
	}
	if len(data) > maximumByteCount {
		return nil, categorizedError{"resourceLimit", "portable byte field exceeds protocol resource limit"}
	}
	return data, nil
}

func portablePrivateKey(text string) (*ecprimitive.PrivateKey, error) {
	data, err := portableHex(text, ecprimitive.PrivateKeyBytesLen)
	if err != nil {
		return nil, err
	}
	if len(data) != ecprimitive.PrivateKeyBytesLen {
		return nil, categorizedError{"invalidLength", "portable private key must be exactly 32 bytes"}
	}
	scalar := new(big.Int).SetBytes(data)
	if scalar.Sign() <= 0 || scalar.Cmp(ecprimitive.S256().N) >= 0 {
		return nil, categorizedError{"invalidPrivateKey", "portable private key is invalid"}
	}
	privateKey, _ := ecprimitive.PrivateKeyFromBytes(data)
	return privateKey, nil
}

func portablePublicKey(text string) (*ecprimitive.PublicKey, error) {
	data, err := portableHex(text, ecprimitive.PubKeyBytesLenCompressed)
	if err != nil {
		return nil, err
	}
	if len(data) != ecprimitive.PubKeyBytesLenCompressed {
		return nil, categorizedError{"invalidLength", "portable public key must use compressed SEC1"}
	}
	return portablePublicKeyBytes(data)
}

func portablePublicKeyBytes(data []byte) (*ecprimitive.PublicKey, error) {
	if len(data) != ecprimitive.PubKeyBytesLenCompressed ||
		(data[0] != 0x02 && data[0] != 0x03) {
		return nil, categorizedError{"invalidPublicKey", "portable public key is invalid"}
	}
	publicKey, err := ecprimitive.ParsePubKey(data)
	if err != nil || publicKey == nil || !publicKey.Validate() {
		return nil, categorizedError{"invalidPublicKey", "portable public key is invalid"}
	}
	return publicKey, nil
}

func generateDRBG(raw json.RawMessage) (any, error) {
	var args drbgGenerateArgs
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if args.Actions == nil {
		return nil, categorizedError{"invalidEncoding", "actions must be a JSON array"}
	}
	entropy, err := protocolHex(args.Entropy)
	if err != nil {
		return nil, err
	}
	if len(entropy) < 32 {
		return nil, categorizedError{"insufficientEntropy", "entropy must contain at least 32 bytes"}
	}
	nonce, err := protocolHex(args.Nonce)
	if err != nil {
		return nil, err
	}
	generator, err := drbgprimitive.NewDRBG(entropy, nonce)
	if err != nil {
		return nil, categorizedError{"internal", "pinned DRBG rejected validated initialization"}
	}

	outputs := make([]string, 0)
	estimatedResponseByteCount := 256
	for _, action := range args.Actions {
		switch action.Type {
		case "generate":
			if action.Count == nil || action.Entropy != nil {
				return nil, categorizedError{"invalidEncoding", "generate action requires only count"}
			}
			count64, err := strconv.ParseInt(*action.Count, 10, 64)
			if err != nil || strconv.FormatInt(count64, 10) != *action.Count {
				return nil, categorizedError{"invalidEncoding", "count must be a canonical decimal integer"}
			}
			if count64 < 0 {
				return nil, categorizedError{"invalidRequestedByteCount", "requested byte count must not be negative"}
			}
			if generator.ReseedCounter > 10000 {
				return nil, categorizedError{"reseedRequired", "DRBG reseed is required"}
			}
			if count64 > 937 {
				return nil, categorizedError{"requestTooLarge", "requested byte count exceeds 937"}
			}
			count := int(count64)
			estimatedOutputByteCount := count*2 + 3
			if estimatedResponseByteCount > maxLineBytes-estimatedOutputByteCount {
				return nil, categorizedError{"resourceLimit", "DRBG output exceeds protocol resource limit"}
			}
			output, err := generator.Generate(count)
			if err != nil {
				return nil, categorizedError{"internal", "pinned DRBG rejected validated generation"}
			}
			estimatedResponseByteCount += estimatedOutputByteCount
			outputs = append(outputs, hex.EncodeToString(output))
		case "reseed":
			if action.Entropy == nil || action.Count != nil {
				return nil, categorizedError{"invalidEncoding", "reseed action requires only entropy"}
			}
			reseedEntropy, err := protocolHex(*action.Entropy)
			if err != nil {
				return nil, err
			}
			if len(reseedEntropy) < 32 {
				return nil, categorizedError{"insufficientEntropy", "reseed entropy must contain at least 32 bytes"}
			}
			if err := generator.Reseed(reseedEntropy); err != nil {
				return nil, categorizedError{"internal", "pinned DRBG rejected validated reseed"}
			}
		default:
			return nil, categorizedError{"invalidEncoding", "action type must be generate or reseed"}
		}
	}

	return map[string]any{
		"outputs":       outputs,
		"reseedCounter": strconv.Itoa(generator.ReseedCounter),
	}, nil
}

func decodeArgs(raw json.RawMessage, destination any) error {
	if len(raw) == 0 {
		return categorizedError{"invalidEncoding", "args is required"}
	}
	var supplied map[string]json.RawMessage
	if err := json.Unmarshal(raw, &supplied); err != nil || supplied == nil {
		return categorizedError{"invalidEncoding", "args must be a JSON object"}
	}
	typeOfDestination := reflect.TypeOf(destination)
	if typeOfDestination.Kind() != reflect.Pointer || typeOfDestination.Elem().Kind() != reflect.Struct {
		return categorizedError{"internal", "operation argument destination is not a struct pointer"}
	}
	argumentType := typeOfDestination.Elem()
	for index := 0; index < argumentType.NumField(); index++ {
		tagParts := strings.Split(argumentType.Field(index).Tag.Get("json"), ",")
		name := tagParts[0]
		optional := false
		for _, option := range tagParts[1:] {
			if option == "omitempty" {
				optional = true
			}
		}
		if name != "" && name != "-" && !optional {
			if _, present := supplied[name]; !present {
				return categorizedError{"invalidEncoding", "missing required argument: " + name}
			}
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return categorizedError{"invalidEncoding", "invalid operation arguments: " + err.Error()}
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return categorizedError{"trailingData", "trailing JSON value in args"}
	}
	return nil
}

func protocolHex(text string) ([]byte, error) {
	if len(text)%2 != 0 {
		return nil, categorizedError{"invalidLength", "hex bytes must have even length"}
	}
	if text != strings.ToLower(text) {
		return nil, categorizedError{"invalidEncoding", "hex bytes must be lowercase"}
	}
	data, err := hex.DecodeString(text)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func protocolPrivateKey(text string) (*ecprimitive.PrivateKey, error) {
	data, err := protocolHex(text)
	if err != nil {
		return nil, err
	}
	if len(data) != ecprimitive.PrivateKeyBytesLen {
		return nil, categorizedError{"invalidLength", "private key must be exactly 32 bytes"}
	}
	scalar := new(big.Int).SetBytes(data)
	if scalar.Sign() <= 0 || scalar.Cmp(ecprimitive.S256().N) >= 0 {
		return nil, categorizedError{"scalar", "private key is outside scalar range"}
	}
	privateKey, _ := ecprimitive.PrivateKeyFromBytes(data)
	return privateKey, nil
}

func protocolPublicKey(text string) (*ecprimitive.PublicKey, error) {
	data, err := protocolHex(text)
	if err != nil {
		return nil, err
	}
	if len(data) != ecprimitive.PubKeyBytesLenCompressed {
		return nil, categorizedError{"invalidLength", "public key must use 33-byte compressed SEC1"}
	}
	publicKey, err := ecprimitive.ParsePubKey(data)
	if err != nil || !publicKey.Validate() {
		return nil, categorizedError{"key", "public key is invalid"}
	}
	return publicKey, nil
}

func protocolSymmetricKey(text string) (*ecprimitive.SymmetricKey, error) {
	data, err := protocolHex(text)
	if err != nil {
		return nil, err
	}
	if len(data) < 1 || len(data) > 32 {
		return nil, categorizedError{"invalidLength", "symmetric key must contain 1 through 32 bytes"}
	}
	return ecprimitive.NewSymmetricKey(data), nil
}

func decimalUint(text string, bits int) (uint64, error) {
	if text == "" || (len(text) > 1 && text[0] == '0') || strings.HasPrefix(text, "+") || strings.HasPrefix(text, "-") {
		return 0, categorizedError{"invalidEncoding", "integer must be canonical unsigned decimal"}
	}
	value, err := strconv.ParseUint(text, 10, bits)
	if err != nil {
		return 0, categorizedError{"overflow", "integer is outside requested width"}
	}
	return value, nil
}

var extendedTransactionMarker = []byte{0, 0, 0, 0, 0, 0xef}

type transactionPacketSummary struct {
	inputCount            int
	rawByteCount          int
	sourceScriptByteCount int
}

// preflightTransactionPacket validates complete transaction syntax without
// allocating from attacker-controlled counts or lengths. Only after this scan
// succeeds may an EF operation call the pinned SDK parser.
func preflightTransactionPacket(data []byte, extended bool) (transactionPacketSummary, error) {
	index := 0
	skip := func(count int) error {
		if count < 0 || count > len(data)-index {
			return categorizedError{"invalidLength", "transaction packet is truncated"}
		}
		index += count
		return nil
	}
	readVarInt := func() (uint64, error) { return 0, nil }
	readVarInt = func() (uint64, error) {
		if err := skip(1); err != nil {
			return 0, err
		}
		prefix := data[index-1]
		width := 0
		switch prefix {
		case 0xfd:
			width = 2
		case 0xfe:
			width = 4
		case 0xff:
			width = 8
		default:
			return uint64(prefix), nil
		}
		if err := skip(width); err != nil {
			return 0, err
		}
		start := index - width
		switch width {
		case 2:
			return uint64(binary.LittleEndian.Uint16(data[start:index])), nil
		case 4:
			return uint64(binary.LittleEndian.Uint32(data[start:index])), nil
		default:
			return binary.LittleEndian.Uint64(data[start:index]), nil
		}
	}
	skipVarBytes := func() (int, error) { return 0, nil }
	skipVarBytes = func() (int, error) {
		length, err := readVarInt()
		if err != nil {
			return 0, err
		}
		if length > uint64(len(data)-index) {
			return 0, categorizedError{"invalidLength", "transaction script is truncated"}
		}
		lengthInt := int(length)
		if err := skip(lengthInt); err != nil {
			return 0, err
		}
		return lengthInt, nil
	}

	if err := skip(4); err != nil {
		return transactionPacketSummary{}, err
	}
	if extended {
		if len(data)-index < len(extendedTransactionMarker) {
			return transactionPacketSummary{}, categorizedError{"invalidLength", "Extended Format marker is truncated"}
		}
		if !bytes.Equal(data[index:index+len(extendedTransactionMarker)], extendedTransactionMarker) {
			return transactionPacketSummary{}, categorizedError{"invalidEncoding", "Extended Format marker is not literal"}
		}
		index += len(extendedTransactionMarker)
	}
	inputCount, err := readVarInt()
	if err != nil {
		return transactionPacketSummary{}, err
	}
	minimumInputLength := uint64(41)
	if extended {
		minimumInputLength = 50
	}
	if inputCount > uint64(len(data)-index)/minimumInputLength {
		return transactionPacketSummary{}, categorizedError{"resourceLimit", "input count exceeds remaining packet capacity"}
	}
	summary := transactionPacketSummary{inputCount: int(inputCount)}
	for input := uint64(0); input < inputCount; input++ {
		if err := skip(36); err != nil {
			return transactionPacketSummary{}, err
		}
		if _, err := skipVarBytes(); err != nil {
			return transactionPacketSummary{}, err
		}
		if err := skip(4); err != nil {
			return transactionPacketSummary{}, err
		}
		if extended {
			if err := skip(8); err != nil {
				return transactionPacketSummary{}, err
			}
			scriptLength, err := skipVarBytes()
			if err != nil {
				return transactionPacketSummary{}, err
			}
			summary.sourceScriptByteCount += scriptLength
		}
	}
	outputCount, err := readVarInt()
	if err != nil {
		return transactionPacketSummary{}, err
	}
	if outputCount > uint64(len(data)-index)/9 {
		return transactionPacketSummary{}, categorizedError{"resourceLimit", "output count exceeds remaining packet capacity"}
	}
	for output := uint64(0); output < outputCount; output++ {
		if err := skip(8); err != nil {
			return transactionPacketSummary{}, err
		}
		if _, err := skipVarBytes(); err != nil {
			return transactionPacketSummary{}, err
		}
	}
	if err := skip(4); err != nil {
		return transactionPacketSummary{}, err
	}
	if index != len(data) {
		return transactionPacketSummary{}, categorizedError{"trailingData", "transaction packet has trailing bytes"}
	}
	rawAdjustment := 0
	if extended {
		rawAdjustment = len(extendedTransactionMarker) + extendedMetadataMinimumByteCount(
			inputCount, summary.sourceScriptByteCount,
		)
	}
	summary.rawByteCount = len(data) - rawAdjustment
	return summary, nil
}

func extendedMetadataMinimumByteCount(inputCount uint64, sourceScriptBytes int) int {
	// Every extended input adds eight satoshi bytes, one VarInt prefix of at
	// least one byte, and its source script payload. Nonminimal source prefixes
	// only make this conservative raw-size estimate larger than the true value.
	count := int(inputCount)
	return count*9 + sourceScriptBytes
}

func varIntLength(value uint64) int {
	switch {
	case value <= 0xfc:
		return 1
	case value <= 0xffff:
		return 3
	case value <= 0xffff_ffff:
		return 5
	default:
		return 9
	}
}

func hexResponseFits(packetBytes, rawBytes, sourceScriptBytes, sourceCount int) bool {
	if packetBytes < 0 || rawBytes < 0 || sourceScriptBytes < 0 || sourceCount < 0 {
		return false
	}
	// Reserve keys, punctuation, IDs, and scalar fields, then account for two
	// hex characters per binary byte. Each decoded source object additionally
	// needs keys/punctuation and up to 20 decimal UInt64 digits; 96 bytes is a
	// conservative per-entry bound. All additions are checked against the line
	// ceiling before they are performed.
	estimated := 4096
	for _, byteCount := range []int{packetBytes, rawBytes, sourceScriptBytes} {
		if byteCount > (maxLineBytes-estimated)/2 {
			return false
		}
		estimated += byteCount * 2
	}
	const sourceJSONOverhead = 96
	if sourceCount > (maxLineBytes-estimated)/sourceJSONOverhead {
		return false
	}
	estimated += sourceCount * sourceJSONOverhead
	return estimated <= maxLineBytes
}

func protocolForkIDFlag(text string) (sighashpkg.Flag, error) {
	value, err := decimalUint(text, 8)
	if err != nil {
		return 0, err
	}
	flag := sighashpkg.Flag(value)
	baseFlag := flag & sighashpkg.Mask
	if !flag.Has(sighashpkg.ForkID) ||
		(baseFlag != sighashpkg.All && baseFlag != sighashpkg.None && baseFlag != sighashpkg.Single) ||
		flag & ^(sighashpkg.AnyOneCanPay|sighashpkg.ForkID|sighashpkg.Mask) != 0 {
		return 0, categorizedError{"invalidEncoding", "signatureHash must be one of the six ForkID combinations"}
	}
	return flag, nil
}

func protocolSignatureHashFlag(text string) (sighashpkg.Flag, error) {
	value, err := decimalUint(text, 8)
	if err != nil {
		return 0, err
	}
	flag := sighashpkg.Flag(value)
	baseFlag := flag & sighashpkg.Mask
	if (baseFlag != sighashpkg.All && baseFlag != sighashpkg.None && baseFlag != sighashpkg.Single) ||
		flag & ^(sighashpkg.AnyOneCanPay|sighashpkg.ForkID|sighashpkg.Mask) != 0 {
		return 0, categorizedError{"invalidEncoding", "signatureHash must be a canonical legacy or ForkID combination"}
	}
	return flag, nil
}

func canonicalInt(value *big.Int) string {
	if value == nil {
		return ""
	}
	return value.String()
}

func byteOrder(name string) (binary.ByteOrder, error) {
	if name == "little" {
		return binary.LittleEndian, nil
	}
	if name == "big" {
		return binary.BigEndian, nil
	}
	return nil, categorizedError{"invalidEncoding", "endian must be little or big"}
}

func encodeUnsigned(op string, raw json.RawMessage) (any, error) {
	var args struct {
		Value  string `json:"value"`
		Endian string `json:"endian"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	bits := 16
	if strings.HasPrefix(op, "u32") {
		bits = 32
	} else if strings.HasPrefix(op, "u64") {
		bits = 64
	}
	value, err := decimalUint(args.Value, bits)
	if err != nil {
		return nil, err
	}
	order, err := byteOrder(args.Endian)
	if err != nil {
		return nil, err
	}
	data := make([]byte, bits/8)
	if bits == 16 {
		order.PutUint16(data, uint16(value))
	} else if bits == 32 {
		order.PutUint32(data, uint32(value))
	} else {
		order.PutUint64(data, value)
	}
	return map[string]string{"bytes": hex.EncodeToString(data)}, nil
}

func decodeUnsigned(op string, raw json.RawMessage) (any, error) {
	var args struct {
		Bytes  string `json:"bytes"`
		Endian string `json:"endian"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	data, err := protocolHex(args.Bytes)
	if err != nil {
		return nil, err
	}
	order, err := byteOrder(args.Endian)
	if err != nil {
		return nil, err
	}
	bits := 16
	if strings.HasPrefix(op, "u32") {
		bits = 32
	} else if strings.HasPrefix(op, "u64") {
		bits = 64
	}
	if len(data) != bits/8 {
		return nil, categorizedError{"invalidLength", "encoded integer has wrong byte length"}
	}
	var value uint64
	if bits == 16 {
		value = uint64(order.Uint16(data))
	} else if bits == 32 {
		value = uint64(order.Uint32(data))
	} else {
		value = order.Uint64(data)
	}
	return map[string]string{"value": strconv.FormatUint(value, 10)}, nil
}

func parseVarInt(data []byte) (uint64, int, bool, error) {
	if len(data) == 0 {
		return 0, 0, false, ioUnexpectedEOF()
	}
	consumed := 1
	switch data[0] {
	case 0xfd:
		consumed = 3
	case 0xfe:
		consumed = 5
	case 0xff:
		consumed = 9
	}
	if len(data) < consumed {
		return 0, 0, false, ioUnexpectedEOF()
	}
	value, _ := util.NewVarIntFromBytes(data[:consumed])
	canonical := bytes.Equal(util.VarInt(value).Bytes(), data[:consumed])
	return uint64(value), consumed, canonical, nil
}

func ioUnexpectedEOF() error { return categorizedError{"truncated", "encoded value is truncated"} }

func decodeVarIntArgs(raw json.RawMessage) (any, error) {
	var args struct {
		Bytes     string `json:"bytes"`
		Canonical string `json:"canonical"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	data, err := protocolHex(args.Bytes)
	if err != nil {
		return nil, err
	}
	value, consumed, canonical, err := parseVarInt(data)
	if err != nil {
		return nil, err
	}
	if consumed != len(data) {
		return nil, categorizedError{"trailingData", "bytes remain after CompactSize"}
	}
	if args.Canonical != "permissive" && args.Canonical != "required" {
		return nil, categorizedError{"invalidEncoding", "canonical must be permissive or required"}
	}
	if args.Canonical == "required" && !canonical {
		return nil, categorizedError{"noncanonical", "CompactSize is not minimally encoded"}
	}
	return map[string]any{"value": strconv.FormatUint(value, 10), "bytesConsumed": strconv.Itoa(consumed), "isCanonical": canonical}, nil
}

func decodeVarBytesArgs(raw json.RawMessage) (any, error) {
	var args struct {
		Bytes     string `json:"bytes"`
		Canonical string `json:"canonical"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	data, err := protocolHex(args.Bytes)
	if err != nil {
		return nil, err
	}
	value, prefix, canonical, err := parseVarInt(data)
	if err != nil {
		return nil, err
	}
	if args.Canonical != "permissive" && args.Canonical != "required" {
		return nil, categorizedError{"invalidEncoding", "canonical must be permissive or required"}
	}
	if args.Canonical == "required" && !canonical {
		return nil, categorizedError{"noncanonical", "CompactSize length is not minimally encoded"}
	}
	if value > uint64(maxLineBytes) {
		return nil, categorizedError{"resourceLimit", "declared VarBytes length exceeds protocol limit"}
	}
	if value > uint64(len(data)-prefix) {
		return nil, categorizedError{"truncated", "VarBytes payload is truncated"}
	}
	consumed := prefix + int(value)
	if consumed != len(data) {
		return nil, categorizedError{"trailingData", "bytes remain after VarBytes"}
	}
	return map[string]any{"bytes": hex.EncodeToString(data[prefix:consumed]), "bytesConsumed": strconv.Itoa(consumed), "isCanonical": canonical}, nil
}

func encodeBase58Check(raw json.RawMessage) (any, error) {
	var args struct {
		Payload string `json:"payload"`
		Version string `json:"version"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	payload, err := protocolHex(args.Payload)
	if err != nil {
		return nil, err
	}
	version, err := decimalUint(args.Version, 8)
	if err != nil {
		return nil, categorizedError{"version", err.Error()}
	}
	body := append([]byte{byte(version)}, payload...)
	encoded := append(body, primitives.Sha256d(body)[:4]...)
	return map[string]string{"text": base58.Encode(encoded)}, nil
}

func decodeBase58Check(raw json.RawMessage) (any, error) {
	var args struct {
		Text string `json:"text"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	decoded, err := base58.Decode(args.Text)
	if err != nil {
		return nil, err
	}
	if len(decoded) < 5 {
		return nil, categorizedError{"invalidLength", "Base58Check requires version and four-byte checksum"}
	}
	body, checksum := decoded[:len(decoded)-4], decoded[len(decoded)-4:]
	expected := primitives.Sha256d(body)[:4]
	if subtle.ConstantTimeCompare(checksum, expected) != 1 {
		return nil, categorizedError{"checksum", "Base58Check checksum mismatch"}
	}
	return map[string]string{"payload": hex.EncodeToString(body[1:]), "version": strconv.Itoa(int(body[0]))}, nil
}

func scriptEra(name string) (bool, int, error) {
	switch name {
	case "preGenesis":
		return false, 4, nil
	case "postGenesis":
		return true, 750000, nil
	case "chronicle":
		return true, interpreter.MaxScriptNumberLengthAfterChronicle, nil
	default:
		return false, 0, categorizedError{"invalidEncoding", "era must be preGenesis, postGenesis, or chronicle"}
	}
}

func encodeScriptNumber(raw json.RawMessage) (any, error) {
	var args struct {
		Value string `json:"value"`
		Era   string `json:"era"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	value, ok := new(big.Int).SetString(args.Value, 10)
	if !ok || canonicalInt(value) != args.Value {
		return nil, categorizedError{"invalidEncoding", "value is not a canonical decimal integer"}
	}
	afterGenesis, _, err := scriptEra(args.Era)
	if err != nil {
		return nil, err
	}
	number := &interpreter.ScriptNumber{Val: value, AfterGenesis: afterGenesis}
	return map[string]string{"bytes": hex.EncodeToString(number.Bytes())}, nil
}

func decodeScriptNumber(raw json.RawMessage) (any, error) {
	var args struct {
		Bytes    string `json:"bytes"`
		Era      string `json:"era"`
		Minimal  bool   `json:"minimal"`
		MaxBytes string `json:"maxBytes"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	data, err := protocolHex(args.Bytes)
	if err != nil {
		return nil, err
	}
	afterGenesis, eraMax, err := scriptEra(args.Era)
	if err != nil {
		return nil, err
	}
	maximum, err := decimalUint(args.MaxBytes, 32)
	if err != nil || maximum > math.MaxInt32 {
		return nil, categorizedError{"overflow", "maxBytes is outside supported range"}
	}
	if maximum > uint64(eraMax) {
		return nil, categorizedError{"resourceLimit", "maxBytes exceeds selected era limit"}
	}
	number, err := interpreter.MakeScriptNumber(data, int(maximum), args.Minimal, afterGenesis)
	if err != nil {
		return nil, err
	}
	return map[string]string{"value": number.Val.String()}, nil
}

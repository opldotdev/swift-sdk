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
	"unicode/utf8"

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
	"github.com/bsv-blockchain/go-sdk/wallet"
	walletserializer "github.com/bsv-blockchain/go-sdk/wallet/serializer"
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
	case "auth.message.reencode", "auth.payload.request.encode", "auth.payload.response.encode":
		return executeAuthOperation(req.Op, req.Args)
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
	case "block.header.inspect":
		return inspectBlockHeader(req.Args)
	case "block.header.reencode":
		return reencodeBlockHeader(req.Args)
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
	case "script.bip276.decode":
		return executeCompatibilityTailBIP276Decode(req.Args)
	case "script.bip276.encode":
		return executeCompatibilityTailBIP276Encode(req.Args)
	case "script.json.marshal":
		return marshalScriptJSON(req.Args)
	case "script.json.unmarshal":
		return unmarshalScriptJSON(req.Args)
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
	case "transaction.input.json.marshal", "transaction.input.json.unmarshal",
		"transaction.json.marshal", "transaction.json.unmarshal",
		"transaction.output.json.marshal", "transaction.output.json.unmarshal":
		return executeTransactionJSONOperation(req.Op, req.Args)
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
	case "wallet.wire.request.inspect", "wallet.wire.request.reencode":
		return walletWireRequestOperation(req.Op, req.Args)
	case "wallet.wire.result.inspect", "wallet.wire.result.reencode":
		return walletWireResultOperation(req.Op, req.Args)
	default:
		return nil, categorizedError{"unsupportedOperation", "operation is not in the pinned registry"}
	}
}

const (
	scriptJSONMaximumScriptBytes   = 128 * 1024
	scriptJSONMaximumDocumentBytes = scriptJSONMaximumScriptBytes*2 + 2
)

func marshalScriptJSON(raw json.RawMessage) (any, error) {
	var args struct {
		Bytes string `json:"bytes"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if len(args.Bytes) > scriptJSONMaximumScriptBytes*2 {
		return nil, categorizedError{"resourceLimit", "script exceeds operation limit"}
	}
	data, err := protocolHex(args.Bytes)
	if err != nil {
		return nil, err
	}
	value := scriptpkg.NewFromBytes(data)
	document, err := value.MarshalJSON()
	if err != nil {
		return nil, err
	}
	if len(document) > scriptJSONMaximumDocumentBytes {
		return nil, categorizedError{"resourceLimit", "Script JSON exceeds operation limit"}
	}
	return map[string]string{"json": hex.EncodeToString(document)}, nil
}

func unmarshalScriptJSON(raw json.RawMessage) (any, error) {
	var args struct {
		JSON string `json:"json"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if len(args.JSON) > scriptJSONMaximumDocumentBytes*2 {
		return nil, categorizedError{"resourceLimit", "Script JSON exceeds operation limit"}
	}
	document, err := protocolHex(args.JSON)
	if err != nil {
		return nil, err
	}
	var value scriptpkg.Script
	if err := value.UnmarshalJSON(document); err != nil {
		return nil, err
	}
	if len(value) > scriptJSONMaximumScriptBytes {
		return nil, categorizedError{"resourceLimit", "script exceeds operation limit"}
	}
	return map[string]string{"bytes": hex.EncodeToString(value.Bytes())}, nil
}

const walletWireMaximumBytes = 256 * 1024

const (
	walletWireMaximumProtocolBytes = 400
	walletWireMaximumKeyIDBytes    = 800
	walletWireMaximumReasonBytes   = 1024
	walletWireMaximumTextBytes     = 2000
	walletWireMaximumMessageBytes  = 2000
	walletWireMaximumStackBytes    = 8192
	walletWireMaximumDERBytes      = 72
)

var walletWireSecp256k1Order = [32]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
	0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
}

var walletWireSecp256k1HalfOrder = [32]byte{
	0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
	0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
}

var walletWireCalls = map[byte]bool{
	1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true,
	8: true, 9: true, 10: true, 11: true, 12: true, 13: true, 14: true, 15: true, 16: true,
	17: true, 18: true, 19: true, 20: true, 21: true, 22: true,
	23: true, 24: true, 25: true, 26: true, 27: true, 28: true,
}

func walletWireArguments(raw json.RawMessage) (byte, []byte, error) {
	var args struct {
		Call  string `json:"call"`
		Bytes string `json:"bytes"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return 0, nil, err
	}
	callValue, err := decimalUint(args.Call, 8)
	if err != nil || callValue == 0 || callValue > 28 || !walletWireCalls[byte(callValue)] {
		return 0, nil, categorizedError{"invalidEncoding", "call is not a supported wallet-wire call"}
	}
	if len(args.Bytes) > walletWireMaximumBytes*2 {
		return 0, nil, categorizedError{"resourceLimit", "wallet-wire input exceeds operation limit"}
	}
	data, err := protocolHex(args.Bytes)
	if err != nil {
		return 0, nil, err
	}
	if len(data) > walletWireMaximumBytes {
		return 0, nil, categorizedError{"resourceLimit", "wallet-wire input exceeds operation limit"}
	}
	return byte(callValue), data, nil
}

func walletWireRequestOperation(operation string, raw json.RawMessage) (any, error) {
	call, data, err := walletWireArguments(raw)
	if err != nil {
		return nil, err
	}
	if len(data) < 2 {
		return nil, categorizedError{"truncated", "wallet-wire request is truncated"}
	}
	if data[0] != call {
		return nil, categorizedError{"invalidEncoding", "request call does not match selected call"}
	}
	originatorCount := int(data[1])
	if originatorCount > len(data)-2 {
		return nil, categorizedError{"truncated", "wallet-wire originator is truncated"}
	}
	if !utf8.Valid(data[2 : 2+originatorCount]) {
		return nil, categorizedError{"invalidEncoding", "wallet-wire originator is not UTF-8"}
	}
	parameterBytes := data[2+originatorCount:]
	if err := walletWirePreflightRequestParameters(call, parameterBytes); err != nil {
		return nil, err
	}
	canonicalParameters, err := walletWireReencodeRequestParameters(call, parameterBytes)
	if err != nil {
		return nil, categorizedError{"invalidEncoding", "pinned Go rejected wallet-wire request parameters"}
	}
	if operation == "wallet.wire.request.inspect" {
		return map[string]string{
			"call":                        strconv.Itoa(int(call)),
			"originatorUTF8ByteCount":     strconv.Itoa(originatorCount),
			"parameterByteCount":          strconv.Itoa(len(parameterBytes)),
			"canonicalParameterByteCount": strconv.Itoa(len(canonicalParameters)),
		}, nil
	}
	frame, err := walletserializer.ReadRequestFrame(data)
	if err != nil {
		return nil, categorizedError{"invalidEncoding", "pinned Go rejected wallet-wire request frame"}
	}
	encoded := walletserializer.WriteRequestFrame(walletserializer.RequestFrame{
		Call:       frame.Call,
		Originator: frame.Originator,
		Params:     canonicalParameters,
	})
	return map[string]string{"bytes": hex.EncodeToString(encoded)}, nil
}

type walletWireResultPreflight struct {
	success      bool
	payload      []byte
	code         byte
	message      []byte
	stack        []byte
	messageBytes int
	stackBytes   int
}

func walletWireResultOperation(operation string, raw json.RawMessage) (any, error) {
	call, data, err := walletWireArguments(raw)
	if err != nil {
		return nil, err
	}
	frame, err := walletWirePreflightResult(data)
	if err != nil {
		return nil, err
	}
	if !frame.success {
		if operation == "wallet.wire.result.inspect" {
			return map[string]string{
				"call":             strconv.Itoa(int(call)),
				"kind":             "failure",
				"code":             strconv.Itoa(int(frame.code)),
				"messageByteCount": strconv.Itoa(frame.messageBytes),
				"stackByteCount":   strconv.Itoa(frame.stackBytes),
			}, nil
		}
		encoded := walletserializer.WriteResultFrame(nil, &wallet.Error{
			Code: frame.code, Message: string(frame.message), Stack: string(frame.stack),
		})
		return map[string]string{"bytes": hex.EncodeToString(encoded)}, nil
	}
	if err := walletWirePreflightResultPayload(call, frame.payload); err != nil {
		return nil, err
	}
	canonicalPayload, err := walletWireReencodeResultPayload(call, frame.payload)
	if err != nil {
		return nil, categorizedError{"invalidEncoding", "pinned Go rejected wallet-wire result payload"}
	}
	if operation == "wallet.wire.result.inspect" {
		return map[string]string{
			"call":                      strconv.Itoa(int(call)),
			"kind":                      "success",
			"payloadByteCount":          strconv.Itoa(len(frame.payload)),
			"canonicalPayloadByteCount": strconv.Itoa(len(canonicalPayload)),
		}, nil
	}
	return map[string]string{
		"bytes": hex.EncodeToString(walletserializer.WriteResultFrame(canonicalPayload, nil)),
	}, nil
}

func walletWirePreflightResult(data []byte) (walletWireResultPreflight, error) {
	if len(data) == 0 {
		return walletWireResultPreflight{}, categorizedError{"truncated", "wallet-wire result is truncated"}
	}
	if data[0] == 0 {
		return walletWireResultPreflight{success: true, payload: data[1:]}, nil
	}
	position := 1
	messageCount, err := walletWireCompactSize(data, &position)
	if err != nil {
		return walletWireResultPreflight{}, err
	}
	if messageCount > walletWireMaximumMessageBytes {
		return walletWireResultPreflight{}, categorizedError{"resourceLimit", "wallet-wire error message exceeds operation limit"}
	}
	if messageCount > uint64(len(data)-position) {
		return walletWireResultPreflight{}, categorizedError{"truncated", "wallet-wire error message is truncated"}
	}
	messageBytes := data[position : position+int(messageCount)]
	position += int(messageCount)
	stackCount, err := walletWireCompactSize(data, &position)
	if err != nil {
		return walletWireResultPreflight{}, err
	}
	if stackCount > walletWireMaximumStackBytes {
		return walletWireResultPreflight{}, categorizedError{"resourceLimit", "wallet-wire error stack exceeds operation limit"}
	}
	if stackCount > uint64(len(data)-position) {
		return walletWireResultPreflight{}, categorizedError{"truncated", "wallet-wire error stack is truncated"}
	}
	stackBytes := data[position : position+int(stackCount)]
	position += int(stackCount)
	if position != len(data) {
		return walletWireResultPreflight{}, categorizedError{"trailingData", "wallet-wire error has trailing data"}
	}
	if !utf8.Valid(messageBytes) || !utf8.Valid(stackBytes) {
		return walletWireResultPreflight{}, categorizedError{"invalidEncoding", "wallet-wire error text is not UTF-8"}
	}
	return walletWireResultPreflight{
		success:      false,
		code:         data[0],
		message:      messageBytes,
		stack:        stackBytes,
		messageBytes: len(messageBytes),
		stackBytes:   len(stackBytes),
	}, nil
}

type walletWireScanner struct {
	data     []byte
	position int
}

func (s *walletWireScanner) remaining() int {
	return len(s.data) - s.position
}

func (s *walletWireScanner) readByte(kind string) (byte, error) {
	if s.position >= len(s.data) {
		return 0, categorizedError{"truncated", "wallet-wire " + kind + " is truncated"}
	}
	value := s.data[s.position]
	s.position++
	return value, nil
}

func (s *walletWireScanner) readCompactSize() (uint64, error) {
	value, err := walletWireCompactSize(s.data, &s.position)
	if err != nil {
		return 0, err
	}
	return value, nil
}

func (s *walletWireScanner) take(count uint64, maximum uint64, kind string) ([]byte, error) {
	if count > maximum {
		return nil, categorizedError{"resourceLimit", "wallet-wire " + kind + " exceeds operation limit"}
	}
	if count > uint64(s.remaining()) {
		return nil, categorizedError{"truncated", "wallet-wire " + kind + " is truncated"}
	}
	start := s.position
	s.position += int(count)
	return s.data[start:s.position], nil
}

func (s *walletWireScanner) takeFixed(count int, kind string) ([]byte, error) {
	return s.take(uint64(count), uint64(count), kind)
}

func (s *walletWireScanner) readVarBytes(maximum uint64, kind string) ([]byte, error) {
	count, err := s.readCompactSize()
	if err != nil {
		return nil, err
	}
	return s.take(count, maximum, kind)
}

func (s *walletWireScanner) requireEnd() error {
	if s.position != len(s.data) {
		return categorizedError{"trailingData", "wallet-wire value has trailing data"}
	}
	return nil
}

func (s *walletWireScanner) readOptionalBool(kind string) error {
	value, err := s.readByte(kind)
	if err != nil {
		return err
	}
	if value != 0 && value != 1 && value != 0xff {
		return categorizedError{"invalidEncoding", "wallet-wire " + kind + " discriminator is invalid"}
	}
	return nil
}

func (s *walletWireScanner) readText(maximum uint64, allowEmpty bool, kind string) ([]byte, error) {
	value, err := s.readVarBytes(maximum, kind)
	if err != nil {
		return nil, err
	}
	if !allowEmpty && len(value) == 0 {
		return nil, categorizedError{"invalidArgument", "wallet-wire " + kind + " must not be empty"}
	}
	if !utf8.Valid(value) {
		return nil, categorizedError{"invalidEncoding", "wallet-wire " + kind + " is not UTF-8"}
	}
	return value, nil
}

func (s *walletWireScanner) readAccess() error {
	if err := s.readOptionalBool("privileged flag"); err != nil {
		return err
	}
	marker, err := s.readByte("privileged reason")
	if err != nil {
		return err
	}
	if marker == 0xff {
		return nil
	}
	s.position--
	_, err = s.readText(walletWireMaximumReasonBytes, false, "privileged reason")
	return err
}

func walletWireCanonicalProtocolName(value []byte) bool {
	if len(value) < 5 || len(value) > walletWireMaximumProtocolBytes {
		return false
	}
	for index, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != ' ' {
			return false
		}
		if character == ' ' && (index == 0 || index == len(value)-1 || value[index-1] == ' ') {
			return false
		}
	}
	return !bytes.HasPrefix(value, []byte("admin")) && !bytes.HasSuffix(value, []byte(" protocol"))
}

func (s *walletWireScanner) readKeyParameters() error {
	level, err := s.readByte("protocol security level")
	if err != nil {
		return err
	}
	if level > 2 {
		return categorizedError{"invalidEncoding", "wallet-wire protocol security level is invalid"}
	}
	protocolName, err := s.readText(walletWireMaximumProtocolBytes, false, "protocol name")
	if err != nil {
		return err
	}
	if !walletWireCanonicalProtocolName(protocolName) {
		return categorizedError{"invalidArgument", "wallet-wire protocol name is not canonical"}
	}
	if _, err := s.readText(walletWireMaximumKeyIDBytes, false, "key ID"); err != nil {
		return err
	}
	counterparty, err := s.readByte("counterparty")
	if err != nil {
		return err
	}
	switch counterparty {
	case 0x0b, 0x0c:
	case 0x02, 0x03:
		if _, err := s.takeFixed(32, "counterparty public key"); err != nil {
			return err
		}
	default:
		return categorizedError{"invalidEncoding", "wallet-wire counterparty discriminator is invalid"}
	}
	return s.readAccess()
}

func walletWireCompareScalar(value []byte, bound [32]byte) int {
	if len(value) > len(bound) {
		return 1
	}
	offset := len(bound) - len(value)
	for index := 0; index < len(bound); index++ {
		var byteValue byte
		if index >= offset {
			byteValue = value[index-offset]
		}
		if byteValue < bound[index] {
			return -1
		}
		if byteValue > bound[index] {
			return 1
		}
	}
	return 0
}

func walletWireDERStatus(value []byte) (valid bool, lowS bool) {
	if len(value) < 8 || len(value) > walletWireMaximumDERBytes || value[0] != 0x30 || int(value[1]) != len(value)-2 {
		return false, false
	}
	position := 2
	var sScalar []byte
	for integer := 0; integer < 2; integer++ {
		if position+2 > len(value) || value[position] != 0x02 {
			return false, false
		}
		count := int(value[position+1])
		position += 2
		if count == 0 || count > 33 || position+count > len(value) {
			return false, false
		}
		first := value[position]
		if first&0x80 != 0 || (count > 1 && first == 0 && value[position+1]&0x80 == 0) {
			return false, false
		}
		scalar := value[position : position+count]
		if scalar[0] == 0 {
			scalar = scalar[1:]
		}
		if len(scalar) == 0 || walletWireCompareScalar(scalar, walletWireSecp256k1Order) >= 0 {
			return false, false
		}
		if integer == 1 {
			sScalar = scalar
		}
		position += count
	}
	if position != len(value) {
		return false, false
	}
	return true, walletWireCompareScalar(sScalar, walletWireSecp256k1HalfOrder) <= 0
}

func (s *walletWireScanner) readSignaturePayload(rejectEmpty bool) error {
	discriminator, err := s.readByte("signature payload")
	if err != nil {
		return err
	}
	switch discriminator {
	case 1:
		value, err := s.readVarBytes(walletWireMaximumBytes, "signature data")
		if err != nil {
			return err
		}
		if rejectEmpty && len(value) == 0 {
			return categorizedError{"invalidArgument", "wallet-wire verify-signature data must not be empty"}
		}
		return nil
	case 2:
		_, err := s.takeFixed(32, "signature digest")
		return err
	default:
		return categorizedError{"invalidEncoding", "wallet-wire signature payload discriminator is invalid"}
	}
}

const walletWireMaximumCollectionCount = 10000

func (s *walletWireScanner) readOptionalUint32(kind string) error {
	value, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if value != math.MaxUint64 && value > math.MaxUint32 {
		return categorizedError{"invalidArgument", "wallet-wire " + kind + " exceeds UInt32"}
	}
	return nil
}

func (s *walletWireScanner) readOptionalPageLimit(kind string) error {
	value, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if value == math.MaxUint64 {
		return nil
	}
	if value == 0 || value > wallet.MaxActionsLimit {
		return categorizedError{"invalidArgument", "wallet-wire " + kind + " is outside 1...10000"}
	}
	return nil
}

func (s *walletWireScanner) readRequiredUint32(kind string) error {
	value, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if value > math.MaxUint32 {
		return categorizedError{"invalidArgument", "wallet-wire " + kind + " exceeds UInt32"}
	}
	return nil
}

func (s *walletWireScanner) readOptionalVarBytes(maximum uint64, kind string, rejectEmpty bool) ([]byte, bool, error) {
	count, err := s.readCompactSize()
	if err != nil {
		return nil, false, err
	}
	if count == math.MaxUint64 {
		return nil, false, nil
	}
	if rejectEmpty && count == 0 {
		return nil, false, categorizedError{"invalidArgument", "wallet-wire empty optional " + kind + " is not round-trippable"}
	}
	value, err := s.take(count, maximum, kind)
	return value, true, err
}

func (s *walletWireScanner) readOptionalText(maximum uint64, kind string) error {
	value, present, err := s.readOptionalVarBytes(maximum, kind, true)
	if err != nil || !present {
		return err
	}
	if !utf8.Valid(value) {
		return categorizedError{"invalidEncoding", "wallet-wire " + kind + " is not UTF-8"}
	}
	return nil
}

func (s *walletWireScanner) readStringSlice(kind string, optional bool) error {
	count, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if count == math.MaxUint64 {
		if optional {
			return nil
		}
		return categorizedError{"invalidArgument", "wallet-wire absent " + kind + " is not representable"}
	}
	if count > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire " + kind + " count exceeds operation limit"}
	}
	if count > uint64(s.remaining()) {
		return categorizedError{"truncated", "wallet-wire " + kind + " are truncated"}
	}
	for index := uint64(0); index < count; index++ {
		length, err := s.readCompactSize()
		if err != nil {
			return err
		}
		if length == math.MaxUint64 {
			continue
		}
		if length == 0 {
			return categorizedError{"invalidArgument", "wallet-wire empty " + kind + " entry is noncanonical"}
		}
		value, err := s.take(length, walletWireMaximumTextBytes, kind)
		if err != nil {
			return err
		}
		if !utf8.Valid(value) {
			return categorizedError{"invalidEncoding", "wallet-wire " + kind + " entry is not UTF-8"}
		}
	}
	return nil
}

func (s *walletWireScanner) readTransactionIDs(kind string) error {
	count, err := s.readCompactSize()
	if err != nil || count == math.MaxUint64 {
		return err
	}
	if count > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire " + kind + " count exceeds operation limit"}
	}
	if count > uint64(s.remaining()/32) {
		return categorizedError{"truncated", "wallet-wire " + kind + " are truncated"}
	}
	_, err = s.takeFixed(int(count)*32, kind)
	return err
}

func (s *walletWireScanner) readActionOutpoint() error {
	if _, err := s.takeFixed(32, "outpoint transaction ID"); err != nil {
		return err
	}
	return s.readRequiredUint32("outpoint index")
}

func (s *walletWireScanner) readCertificatePublicKey(kind string) error {
	key, err := s.takeFixed(33, kind)
	if err != nil {
		return err
	}
	if key[0] != 0x02 && key[0] != 0x03 {
		return categorizedError{"invalidEncoding", "wallet-wire " + kind + " is invalid"}
	}
	if _, err := ecprimitive.ParsePubKey(key); err != nil {
		return categorizedError{"invalidEncoding", "wallet-wire " + kind + " is invalid"}
	}
	return nil
}

func (s *walletWireScanner) readCertificateOutpoint() error {
	if _, err := s.takeFixed(32, "certificate outpoint transaction ID"); err != nil {
		return err
	}
	return s.readRequiredUint32("certificate outpoint index")
}

func walletWireStrictlyOrdered(previous, current []byte) bool {
	return previous == nil || bytes.Compare(previous, current) < 0
}

func (s *walletWireScanner) readCertificateMap(
	kind string,
	valuesAreText bool,
	valuesAreCanonicalBase64 bool,
	rejectEmpty bool,
) error {
	count, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if count > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire " + kind + " count exceeds operation limit"}
	}
	if rejectEmpty && count == 0 {
		return categorizedError{"invalidArgument", "wallet-wire present " + kind + " must not be empty"}
	}
	if count > uint64(s.remaining()/2) {
		return categorizedError{"truncated", "wallet-wire " + kind + " is truncated"}
	}
	var previous []byte
	for index := uint64(0); index < count; index++ {
		name, err := s.readText(50, false, kind+" name")
		if err != nil {
			return err
		}
		if !walletWireStrictlyOrdered(previous, name) {
			return categorizedError{"invalidArgument", "wallet-wire " + kind + " keys are not strictly sorted"}
		}
		previous = name
		value, err := s.readVarBytes(walletWireMaximumBytes, kind+" value")
		if err != nil {
			return err
		}
		if valuesAreText && !utf8.Valid(value) {
			return categorizedError{"invalidEncoding", "wallet-wire " + kind + " value is not UTF-8"}
		}
		if valuesAreCanonicalBase64 {
			decoded, decodeErr := base64.StdEncoding.DecodeString(string(value))
			if decodeErr != nil || base64.StdEncoding.EncodeToString(decoded) != string(value) {
				return categorizedError{"invalidEncoding", "wallet-wire " + kind + " value is not canonical Base64"}
			}
		}
	}
	return nil
}

func (s *walletWireScanner) readCertificateSignature(optional bool) error {
	signature, err := s.readVarBytes(walletWireMaximumDERBytes, "certificate signature")
	if err != nil {
		return err
	}
	if optional && len(signature) == 0 {
		return nil
	}
	valid, lowS := walletWireDERStatus(signature)
	if !valid {
		return categorizedError{"invalidEncoding", "wallet-wire certificate signature is invalid"}
	}
	if !lowS {
		return categorizedError{"invalidArgument", "wallet-wire high-S certificate signature is not round-trippable"}
	}
	return nil
}

func (s *walletWireScanner) readCertificateBinary(requireSignature bool) error {
	if _, err := s.takeFixed(32, "certificate type"); err != nil {
		return err
	}
	if _, err := s.takeFixed(32, "certificate serial number"); err != nil {
		return err
	}
	if err := s.readCertificatePublicKey("certificate subject"); err != nil {
		return err
	}
	if err := s.readCertificatePublicKey("certificate certifier"); err != nil {
		return err
	}
	if err := s.readCertificateOutpoint(); err != nil {
		return err
	}
	if err := s.readCertificateMap("certificate fields", true, true, false); err != nil {
		return err
	}
	signature := s.data[s.position:]
	if len(signature) == 0 && !requireSignature {
		s.position = len(s.data)
		return nil
	}
	valid, lowS := walletWireDERStatus(signature)
	if !valid {
		return categorizedError{"invalidEncoding", "wallet-wire certificate signature is invalid"}
	}
	if !lowS {
		return categorizedError{"invalidArgument", "wallet-wire high-S certificate signature is not round-trippable"}
	}
	s.position = len(s.data)
	return nil
}

func (s *walletWireScanner) readAcquireCertificateRequest() error {
	if _, err := s.takeFixed(32, "certificate type"); err != nil {
		return err
	}
	if err := s.readCertificatePublicKey("certificate certifier"); err != nil {
		return err
	}
	if err := s.readCertificateMap("certificate fields", true, false, false); err != nil {
		return err
	}
	if err := s.readAccess(); err != nil {
		return err
	}
	protocol, err := s.readByte("certificate acquisition protocol")
	if err != nil {
		return err
	}
	switch protocol {
	case 1:
		if _, err := s.takeFixed(32, "certificate serial number"); err != nil {
			return err
		}
		if err := s.readCertificateOutpoint(); err != nil {
			return err
		}
		if err := s.readCertificateSignature(false); err != nil {
			return err
		}
		revealer, err := s.readByte("keyring revealer")
		if err != nil {
			return err
		}
		if revealer != 11 {
			if revealer != 2 && revealer != 3 {
				return categorizedError{"invalidEncoding", "wallet-wire keyring revealer is invalid"}
			}
			if _, err := s.takeFixed(32, "keyring revealer public key"); err != nil {
				return err
			}
		}
		return s.readCertificateMap("subject keyring", false, false, false)
	case 2:
		_, err := s.readText(walletWireMaximumTextBytes, false, "certifier URL")
		return err
	default:
		return categorizedError{"invalidEncoding", "wallet-wire certificate acquisition protocol is invalid"}
	}
}

func (s *walletWireScanner) readListCertificatesRequest() error {
	certifiers, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if certifiers > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire certifier count exceeds operation limit"}
	}
	if certifiers > uint64(s.remaining()/33) {
		return categorizedError{"truncated", "wallet-wire certifiers are truncated"}
	}
	for index := uint64(0); index < certifiers; index++ {
		if err := s.readCertificatePublicKey("certificate certifier"); err != nil {
			return err
		}
	}
	types, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if types > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire certificate type count exceeds operation limit"}
	}
	if _, err := s.take(types*32, walletWireMaximumBytes, "certificate types"); err != nil {
		return err
	}
	if err := s.readOptionalPageLimit("certificate limit"); err != nil {
		return err
	}
	if err := s.readOptionalUint32("certificate offset"); err != nil {
		return err
	}
	return s.readAccess()
}

func (s *walletWireScanner) readProveCertificateRequest() error {
	if _, err := s.takeFixed(32, "certificate type"); err != nil {
		return err
	}
	if err := s.readCertificatePublicKey("certificate subject"); err != nil {
		return err
	}
	if _, err := s.takeFixed(32, "certificate serial number"); err != nil {
		return err
	}
	if err := s.readCertificatePublicKey("certificate certifier"); err != nil {
		return err
	}
	if err := s.readCertificateOutpoint(); err != nil {
		return err
	}
	if err := s.readCertificateSignature(true); err != nil {
		return err
	}
	if err := s.readCertificateMap("certificate fields", true, true, false); err != nil {
		return err
	}
	count, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if count > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire fields-to-reveal count exceeds operation limit"}
	}
	if count > uint64(s.remaining()) {
		return categorizedError{"truncated", "wallet-wire fields to reveal are truncated"}
	}
	seen := make(map[string]struct{}, min(int(count), walletWireMaximumCollectionCount))
	for index := uint64(0); index < count; index++ {
		field, err := s.readText(50, false, "field to reveal")
		if err != nil {
			return err
		}
		if _, duplicate := seen[string(field)]; duplicate {
			return categorizedError{"invalidArgument", "wallet-wire fields to reveal contain a duplicate"}
		}
		seen[string(field)] = struct{}{}
	}
	if err := s.readCertificatePublicKey("certificate verifier"); err != nil {
		return err
	}
	return s.readAccess()
}

func (s *walletWireScanner) readDiscoveryRequest(identity bool) error {
	if identity {
		if err := s.readCertificatePublicKey("identity key"); err != nil {
			return err
		}
	} else if err := s.readCertificateMap("certificate attributes", true, false, false); err != nil {
		return err
	}
	if err := s.readOptionalPageLimit("discovery limit"); err != nil {
		return err
	}
	if err := s.readOptionalUint32("discovery offset"); err != nil {
		return err
	}
	return s.readOptionalBool("seek-permission flag")
}

func (s *walletWireScanner) readLinkageResult(specific bool) error {
	for _, kind := range []string{"linkage prover", "linkage verifier", "linkage counterparty"} {
		if err := s.readCertificatePublicKey(kind); err != nil {
			return err
		}
	}
	if specific {
		level, err := s.readByte("protocol security level")
		if err != nil {
			return err
		}
		if level > 2 {
			return categorizedError{"invalidEncoding", "wallet-wire protocol security level is invalid"}
		}
		name, err := s.readText(walletWireMaximumProtocolBytes, false, "protocol name")
		if err != nil {
			return err
		}
		if !walletWireCanonicalProtocolName(name) {
			return categorizedError{"invalidArgument", "wallet-wire protocol name is not canonical"}
		}
		if _, err := s.readText(walletWireMaximumKeyIDBytes, false, "key ID"); err != nil {
			return err
		}
	} else if _, err := s.readText(walletWireMaximumTextBytes, true, "revelation time"); err != nil {
		return err
	}
	if _, err := s.readVarBytes(walletWireMaximumBytes, "encrypted linkage"); err != nil {
		return err
	}
	if _, err := s.readVarBytes(walletWireMaximumBytes, "encrypted linkage proof"); err != nil {
		return err
	}
	if specific {
		_, err := s.readByte("linkage proof type")
		return err
	}
	return nil
}

func (s *walletWireScanner) readListCertificatesResult() error {
	count, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if count > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire certificate count exceeds operation limit"}
	}
	for index := uint64(0); index < count; index++ {
		certificate, err := s.readVarBytes(walletWireMaximumBytes, "certificate")
		if err != nil {
			return err
		}
		nested := walletWireScanner{data: certificate}
		if err := nested.readCertificateBinary(true); err != nil {
			return err
		}
		presence, err := s.readByte("certificate keyring presence")
		if err != nil {
			return err
		}
		switch presence {
		case 0:
		case 1:
			if err := s.readCertificateMap("certificate keyring", false, false, true); err != nil {
				return err
			}
		default:
			return categorizedError{"invalidEncoding", "wallet-wire certificate keyring presence is invalid"}
		}
		if _, err := s.readVarBytes(walletWireMaximumBytes, "certificate verifier"); err != nil {
			return err
		}
	}
	return nil
}

func (s *walletWireScanner) readIdentityCertificate() error {
	certificate, err := s.readVarBytes(walletWireMaximumBytes, "identity certificate")
	if err != nil {
		return err
	}
	nested := walletWireScanner{data: certificate}
	if err := nested.readCertificateBinary(true); err != nil {
		return err
	}
	for _, kind := range []string{"certifier name", "certifier icon URL", "certifier description"} {
		if _, err := s.readText(walletWireMaximumTextBytes, true, kind); err != nil {
			return err
		}
	}
	trust, err := s.readByte("certifier trust")
	if err != nil {
		return err
	}
	if trust > 10 {
		return categorizedError{"invalidArgument", "wallet-wire certifier trust exceeds 10"}
	}
	if err := s.readCertificateMap("public keyring", false, false, false); err != nil {
		return err
	}
	return s.readCertificateMap("decrypted fields", true, false, false)
}

func (s *walletWireScanner) readDiscoveryResult() error {
	count, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if count > 1 {
		return categorizedError{"invalidArgument", "pinned Go cannot read a multi-certificate discovery result"}
	}
	for index := uint64(0); index < count; index++ {
		if err := s.readIdentityCertificate(); err != nil {
			return err
		}
	}
	return nil
}

func (s *walletWireScanner) readOutpointCollection(kind string) error {
	count, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if count == math.MaxUint64 {
		return categorizedError{"invalidArgument", "wallet-wire nested absent " + kind + " is not round-trippable"}
	}
	if count > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire " + kind + " count exceeds operation limit"}
	}
	if count > uint64(s.remaining()/33) {
		return categorizedError{"truncated", "wallet-wire " + kind + " are truncated"}
	}
	for index := uint64(0); index < count; index++ {
		if err := s.readActionOutpoint(); err != nil {
			return err
		}
	}
	return s.requireEnd()
}

func (s *walletWireScanner) readCreateInputs() error {
	count, err := s.readCompactSize()
	if err != nil || count == math.MaxUint64 {
		return err
	}
	if count == 0 {
		return categorizedError{"invalidArgument", "wallet-wire empty create-action inputs are not round-trippable"}
	}
	if count > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire input count exceeds operation limit"}
	}
	for index := uint64(0); index < count; index++ {
		if err := s.readActionOutpoint(); err != nil {
			return err
		}
		_, present, err := s.readOptionalVarBytes(walletWireMaximumBytes, "unlocking script", true)
		if err != nil {
			return err
		}
		if !present {
			if err := s.readRequiredUint32("unlocking script length"); err != nil {
				return err
			}
		}
		if _, err := s.readText(walletWireMaximumTextBytes, true, "input description"); err != nil {
			return err
		}
		if err := s.readOptionalUint32("sequence number"); err != nil {
			return err
		}
	}
	return nil
}

func (s *walletWireScanner) readCreateOutputs() error {
	count, err := s.readCompactSize()
	if err != nil || count == math.MaxUint64 {
		return err
	}
	if count > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire output count exceeds operation limit"}
	}
	for index := uint64(0); index < count; index++ {
		script, err := s.readVarBytes(walletWireMaximumBytes, "locking script")
		if err != nil {
			return err
		}
		if len(script) == 0 {
			return categorizedError{"invalidArgument", "wallet-wire empty create-action locking script is not round-trippable"}
		}
		if _, err := s.readCompactSize(); err != nil {
			return err
		}
		if _, err := s.readText(walletWireMaximumTextBytes, true, "output description"); err != nil {
			return err
		}
		if err := s.readOptionalText(walletWireMaximumTextBytes, "basket"); err != nil {
			return err
		}
		if err := s.readOptionalText(walletWireMaximumTextBytes, "custom instructions"); err != nil {
			return err
		}
		if err := s.readStringSlice("tags", false); err != nil {
			return err
		}
	}
	return nil
}

func (s *walletWireScanner) readCreateOptions() error {
	flag, err := s.readByte("create options")
	if err != nil {
		return err
	}
	if flag == 0 {
		return nil
	}
	if flag != 1 {
		return categorizedError{"invalidEncoding", "wallet-wire create options discriminator is invalid"}
	}
	if err := s.readOptionalBool("sign-and-process flag"); err != nil {
		return err
	}
	if err := s.readOptionalBool("delayed-broadcast flag"); err != nil {
		return err
	}
	trust, err := s.readByte("trust-self flag")
	if err != nil {
		return err
	}
	if trust != 1 && trust != 0xff {
		return categorizedError{"invalidEncoding", "wallet-wire trust-self discriminator is invalid"}
	}
	if err := s.readTransactionIDs("known transaction IDs"); err != nil {
		return err
	}
	if err := s.readOptionalBool("return-transaction-ID-only flag"); err != nil {
		return err
	}
	if err := s.readOptionalBool("no-send flag"); err != nil {
		return err
	}
	change, present, err := s.readOptionalVarBytes(walletWireMaximumBytes, "no-send change", true)
	if err != nil {
		return err
	}
	if present {
		nested := walletWireScanner{data: change}
		if err := nested.readOutpointCollection("no-send change"); err != nil {
			return err
		}
	}
	if err := s.readTransactionIDs("send-with transaction IDs"); err != nil {
		return err
	}
	return s.readOptionalBool("randomize-outputs flag")
}

func (s *walletWireScanner) readCreateActionRequest() error {
	if _, err := s.readText(walletWireMaximumTextBytes, true, "action description"); err != nil {
		return err
	}
	if _, _, err := s.readOptionalVarBytes(walletWireMaximumBytes, "input BEEF", true); err != nil {
		return err
	}
	if err := s.readCreateInputs(); err != nil {
		return err
	}
	if err := s.readCreateOutputs(); err != nil {
		return err
	}
	if err := s.readOptionalUint32("lock time"); err != nil {
		return err
	}
	if err := s.readOptionalUint32("version"); err != nil {
		return err
	}
	if err := s.readStringSlice("labels", true); err != nil {
		return err
	}
	return s.readCreateOptions()
}

func (s *walletWireScanner) readSignOptions() error {
	flag, err := s.readByte("sign options")
	if err != nil {
		return err
	}
	if flag == 0 {
		return nil
	}
	if flag != 1 {
		return categorizedError{"invalidEncoding", "wallet-wire sign options discriminator is invalid"}
	}
	if err := s.readOptionalBool("delayed-broadcast flag"); err != nil {
		return err
	}
	if err := s.readOptionalBool("return-transaction-ID-only flag"); err != nil {
		return err
	}
	if err := s.readOptionalBool("no-send flag"); err != nil {
		return err
	}
	return s.readTransactionIDs("send-with transaction IDs")
}

func (s *walletWireScanner) readSignActionRequest() error {
	count, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if count > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire spend count exceeds operation limit"}
	}
	var prior uint64
	for index := uint64(0); index < count; index++ {
		inputIndex, err := s.readCompactSize()
		if err != nil {
			return err
		}
		if inputIndex > math.MaxUint32 {
			return categorizedError{"invalidArgument", "wallet-wire spend index exceeds UInt32"}
		}
		if index > 0 && inputIndex <= prior {
			return categorizedError{"invalidArgument", "wallet-wire spend indexes are not strictly sorted"}
		}
		prior = inputIndex
		if _, err := s.readVarBytes(walletWireMaximumBytes, "unlocking script"); err != nil {
			return err
		}
		if err := s.readOptionalUint32("sequence number"); err != nil {
			return err
		}
	}
	if _, err := s.readVarBytes(walletWireMaximumBytes, "reference"); err != nil {
		return err
	}
	return s.readSignOptions()
}

func (s *walletWireScanner) readListActionsRequest() error {
	if err := s.readStringSlice("labels", false); err != nil {
		return err
	}
	mode, err := s.readByte("label query mode")
	if err != nil {
		return err
	}
	if mode != 1 && mode != 2 && mode != 0xff {
		return categorizedError{"invalidEncoding", "wallet-wire label query mode is invalid"}
	}
	for index := 0; index < 6; index++ {
		if err := s.readOptionalBool("list-actions include flag"); err != nil {
			return err
		}
	}
	position := s.position
	limit, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if limit != math.MaxUint64 && (limit == 0 || limit > wallet.MaxActionsLimit) {
		return categorizedError{"invalidArgument", "wallet-wire action limit is outside 1...10000"}
	}
	_ = position
	if err := s.readOptionalUint32("offset"); err != nil {
		return err
	}
	return s.readOptionalBool("seek-permission flag")
}

func (s *walletWireScanner) readInternalizeActionRequest() error {
	if _, err := s.readVarBytes(walletWireMaximumBytes, "Atomic BEEF"); err != nil {
		return err
	}
	count, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if count > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire internalize output count exceeds operation limit"}
	}
	for index := uint64(0); index < count; index++ {
		if err := s.readRequiredUint32("output index"); err != nil {
			return err
		}
		protocol, err := s.readByte("internalize protocol")
		if err != nil {
			return err
		}
		switch protocol {
		case 1:
			key, err := s.takeFixed(33, "sender identity key")
			if err != nil {
				return err
			}
			if key[0] != 2 && key[0] != 3 {
				return categorizedError{"invalidEncoding", "wallet-wire sender identity key is invalid"}
			}
			if _, err := s.readVarBytes(walletWireMaximumBytes, "derivation prefix"); err != nil {
				return err
			}
			if _, err := s.readVarBytes(walletWireMaximumBytes, "derivation suffix"); err != nil {
				return err
			}
		case 2:
			if _, err := s.readText(walletWireMaximumTextBytes, true, "basket"); err != nil {
				return err
			}
			if err := s.readOptionalText(walletWireMaximumTextBytes, "custom instructions"); err != nil {
				return err
			}
			if err := s.readStringSlice("tags", false); err != nil {
				return err
			}
		default:
			return categorizedError{"invalidEncoding", "wallet-wire internalize protocol is invalid"}
		}
	}
	if err := s.readStringSlice("labels", false); err != nil {
		return err
	}
	if _, err := s.readText(walletWireMaximumTextBytes, true, "action description"); err != nil {
		return err
	}
	return s.readOptionalBool("seek-permission flag")
}

func (s *walletWireScanner) readListOutputsRequest() error {
	if _, err := s.readText(walletWireMaximumTextBytes, true, "basket"); err != nil {
		return err
	}
	if err := s.readStringSlice("tags", false); err != nil {
		return err
	}
	mode, err := s.readByte("tag query mode")
	if err != nil {
		return err
	}
	if mode != 1 && mode != 2 && mode != 0xff {
		return categorizedError{"invalidEncoding", "wallet-wire tag query mode is invalid"}
	}
	include, err := s.readByte("output include")
	if err != nil {
		return err
	}
	if include != 1 && include != 2 && include != 0xff {
		return categorizedError{"invalidEncoding", "wallet-wire output include is invalid"}
	}
	for index := 0; index < 3; index++ {
		if err := s.readOptionalBool("list-outputs include flag"); err != nil {
			return err
		}
	}
	limit, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if limit != math.MaxUint64 && (limit == 0 || limit > wallet.MaxActionsLimit) {
		return categorizedError{"invalidArgument", "wallet-wire output limit is outside 1...10000"}
	}
	if err := s.readOptionalUint32("offset"); err != nil {
		return err
	}
	return s.readOptionalBool("seek-permission flag")
}

func (s *walletWireScanner) readRequiredGoTransactionID(kind string) error {
	flag, err := s.readByte(kind)
	if err != nil {
		return err
	}
	if flag == 0 {
		return categorizedError{"invalidArgument", "wallet-wire absent pinned Go transaction ID is not round-trippable"}
	}
	if flag != 1 {
		return categorizedError{"invalidEncoding", "wallet-wire transaction ID discriminator is invalid"}
	}
	_, err = s.takeFixed(32, kind)
	return err
}

func (s *walletWireScanner) readOptionalAtomicBEEF() error {
	flag, err := s.readByte("transaction")
	if err != nil {
		return err
	}
	if flag == 0 {
		return nil
	}
	if flag != 1 {
		return categorizedError{"invalidEncoding", "wallet-wire transaction discriminator is invalid"}
	}
	_, err = s.readVarBytes(walletWireMaximumBytes, "Atomic BEEF")
	return err
}

func (s *walletWireScanner) readSendWithResults() error {
	count, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if count > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire send-with result count exceeds operation limit"}
	}
	if count > uint64(s.remaining()/33) {
		return categorizedError{"truncated", "wallet-wire send-with results are truncated"}
	}
	for index := uint64(0); index < count; index++ {
		if _, err := s.takeFixed(32, "send-with transaction ID"); err != nil {
			return err
		}
		status, err := s.readByte("send-with status")
		if err != nil {
			return err
		}
		if status < 1 || status > 3 {
			return categorizedError{"invalidEncoding", "wallet-wire send-with status is invalid"}
		}
	}
	return nil
}

func (s *walletWireScanner) readNestedOutpoints(kind string) error {
	value, present, err := s.readOptionalVarBytes(walletWireMaximumBytes, kind, true)
	if err != nil || !present {
		return err
	}
	nested := walletWireScanner{data: value}
	return nested.readOutpointCollection(kind)
}

func (s *walletWireScanner) readCreateActionResult() error {
	status, err := s.readByte("nested create-action status")
	if err != nil {
		return err
	}
	if status != 0 {
		return categorizedError{"invalidEncoding", "wallet-wire nested create-action status is invalid"}
	}
	if err := s.readRequiredGoTransactionID("create-action transaction ID"); err != nil {
		return err
	}
	if err := s.readOptionalAtomicBEEF(); err != nil {
		return err
	}
	if err := s.readNestedOutpoints("no-send change"); err != nil {
		return err
	}
	if err := s.readSendWithResults(); err != nil {
		return err
	}
	flag, err := s.readByte("signable transaction")
	if err != nil {
		return err
	}
	if flag == 1 {
		return categorizedError{"invalidArgument", "wallet-wire pinned Go signable result is not representable by the Swift ABI"}
	}
	if flag != 0 {
		return categorizedError{"invalidEncoding", "wallet-wire signable transaction discriminator is invalid"}
	}
	return nil
}

func (s *walletWireScanner) readSignActionResult() error {
	if err := s.readRequiredGoTransactionID("sign-action transaction ID"); err != nil {
		return err
	}
	if err := s.readOptionalAtomicBEEF(); err != nil {
		return err
	}
	return s.readSendWithResults()
}

func (s *walletWireScanner) readActionInputs() error {
	count, err := s.readCompactSize()
	if err != nil || count == math.MaxUint64 {
		return err
	}
	if count == 0 {
		return categorizedError{"invalidArgument", "wallet-wire empty action inputs are not round-trippable"}
	}
	if count > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire action input count exceeds operation limit"}
	}
	for index := uint64(0); index < count; index++ {
		if err := s.readActionOutpoint(); err != nil {
			return err
		}
		if _, err := s.readCompactSize(); err != nil {
			return err
		}
		_, sourcePresent, err := s.readOptionalVarBytes(walletWireMaximumBytes, "source locking script", true)
		if err != nil {
			return err
		}
		if !sourcePresent {
			return categorizedError{"invalidArgument", "wallet-wire absent action source locking script is not readable by pinned Go"}
		}
		_, unlockingPresent, err := s.readOptionalVarBytes(walletWireMaximumBytes, "unlocking script", true)
		if err != nil {
			return err
		}
		if !unlockingPresent {
			return categorizedError{"invalidArgument", "wallet-wire absent action unlocking script is not readable by pinned Go"}
		}
		if _, err := s.readText(walletWireMaximumTextBytes, true, "input description"); err != nil {
			return err
		}
		if err := s.readRequiredUint32("sequence number"); err != nil {
			return err
		}
	}
	return nil
}

func (s *walletWireScanner) readActionOutputs() error {
	count, err := s.readCompactSize()
	if err != nil || count == math.MaxUint64 {
		return err
	}
	if count == 0 {
		return categorizedError{"invalidArgument", "wallet-wire empty action outputs are not round-trippable"}
	}
	if count > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire action output count exceeds operation limit"}
	}
	for index := uint64(0); index < count; index++ {
		if err := s.readRequiredUint32("output index"); err != nil {
			return err
		}
		if _, err := s.readCompactSize(); err != nil {
			return err
		}
		_, scriptPresent, err := s.readOptionalVarBytes(walletWireMaximumBytes, "locking script", true)
		if err != nil {
			return err
		}
		if !scriptPresent {
			return categorizedError{"invalidArgument", "wallet-wire absent action output locking script is not readable by pinned Go"}
		}
		spendable, err := s.readByte("spendable")
		if err != nil {
			return err
		}
		if spendable != 0 && spendable != 1 {
			return categorizedError{"invalidEncoding", "wallet-wire spendable discriminator is invalid"}
		}
		if _, err := s.readText(walletWireMaximumTextBytes, true, "output description"); err != nil {
			return err
		}
		if _, err := s.readText(walletWireMaximumTextBytes, true, "basket"); err != nil {
			return err
		}
		if err := s.readStringSlice("tags", false); err != nil {
			return err
		}
		if err := s.readOptionalText(walletWireMaximumTextBytes, "custom instructions"); err != nil {
			return err
		}
	}
	return nil
}

func (s *walletWireScanner) readListActionsResult() error {
	count, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if count > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire action count exceeds operation limit"}
	}
	for index := uint64(0); index < count; index++ {
		if _, err := s.takeFixed(32, "action transaction ID"); err != nil {
			return err
		}
		if _, err := s.readCompactSize(); err != nil {
			return err
		}
		status, err := s.readByte("action status")
		if err != nil {
			return err
		}
		if status < 1 || status > 7 {
			return categorizedError{"invalidEncoding", "wallet-wire action status is invalid"}
		}
		outgoing, err := s.readByte("is outgoing")
		if err != nil {
			return err
		}
		if outgoing != 0 && outgoing != 1 {
			return categorizedError{"invalidEncoding", "wallet-wire is-outgoing discriminator is invalid"}
		}
		if _, err := s.readText(walletWireMaximumTextBytes, true, "action description"); err != nil {
			return err
		}
		if err := s.readStringSlice("labels", true); err != nil {
			return err
		}
		if err := s.readRequiredUint32("version"); err != nil {
			return err
		}
		if err := s.readRequiredUint32("lock time"); err != nil {
			return err
		}
		if err := s.readActionInputs(); err != nil {
			return err
		}
		if err := s.readActionOutputs(); err != nil {
			return err
		}
	}
	return nil
}

func (s *walletWireScanner) readListOutputsResult() error {
	count, err := s.readCompactSize()
	if err != nil {
		return err
	}
	if count > walletWireMaximumCollectionCount {
		return categorizedError{"resourceLimit", "wallet-wire output count exceeds operation limit"}
	}
	if _, _, err := s.readOptionalVarBytes(walletWireMaximumBytes, "BEEF", true); err != nil {
		return err
	}
	for index := uint64(0); index < count; index++ {
		if err := s.readActionOutpoint(); err != nil {
			return err
		}
		if _, err := s.readCompactSize(); err != nil {
			return err
		}
		if _, _, err := s.readOptionalVarBytes(walletWireMaximumBytes, "locking script", true); err != nil {
			return err
		}
		if err := s.readOptionalText(walletWireMaximumTextBytes, "custom instructions"); err != nil {
			return err
		}
		if err := s.readStringSlice("tags", true); err != nil {
			return err
		}
		if err := s.readStringSlice("labels", true); err != nil {
			return err
		}
	}
	return nil
}

func walletWirePreflightRequestParameters(call byte, data []byte) error {
	s := walletWireScanner{data: data}
	switch call {
	case 1:
		if err := s.readCreateActionRequest(); err != nil {
			return err
		}
	case 2:
		if err := s.readSignActionRequest(); err != nil {
			return err
		}
	case 3:
		if len(data) > walletWireMaximumBytes {
			return categorizedError{"resourceLimit", "wallet-wire reference exceeds operation limit"}
		}
		s.position = len(data)
	case 4:
		if err := s.readListActionsRequest(); err != nil {
			return err
		}
	case 5:
		if err := s.readInternalizeActionRequest(); err != nil {
			return err
		}
	case 6:
		if err := s.readListOutputsRequest(); err != nil {
			return err
		}
	case 7:
		if _, err := s.readText(walletWireMaximumTextBytes, true, "basket"); err != nil {
			return err
		}
		if err := s.readActionOutpoint(); err != nil {
			return err
		}
	case 8:
		identity, err := s.readByte("identity-key flag")
		if err != nil {
			return err
		}
		switch identity {
		case 0:
			if err := s.readKeyParameters(); err != nil {
				return err
			}
			if err := s.readOptionalBool("for-self flag"); err != nil {
				return err
			}
		case 1:
			if err := s.readAccess(); err != nil {
				return err
			}
		default:
			return categorizedError{"invalidEncoding", "wallet-wire identity-key discriminator is invalid"}
		}
		if err := s.readOptionalBool("seek-permission flag"); err != nil {
			return err
		}
	case 9:
		if err := s.readAccess(); err != nil {
			return err
		}
		if err := s.readCertificatePublicKey("linkage counterparty"); err != nil {
			return err
		}
		if err := s.readCertificatePublicKey("linkage verifier"); err != nil {
			return err
		}
	case 10:
		if err := s.readKeyParameters(); err != nil {
			return err
		}
		if err := s.readCertificatePublicKey("linkage verifier"); err != nil {
			return err
		}
	case 11, 12, 13:
		if err := s.readKeyParameters(); err != nil {
			return err
		}
		if _, err := s.readVarBytes(walletWireMaximumBytes, "request data"); err != nil {
			return err
		}
		if err := s.readOptionalBool("seek-permission flag"); err != nil {
			return err
		}
	case 14:
		if err := s.readKeyParameters(); err != nil {
			return err
		}
		if _, err := s.takeFixed(32, "HMAC"); err != nil {
			return err
		}
		if _, err := s.readVarBytes(walletWireMaximumBytes, "HMAC data"); err != nil {
			return err
		}
		if err := s.readOptionalBool("seek-permission flag"); err != nil {
			return err
		}
	case 15:
		if err := s.readKeyParameters(); err != nil {
			return err
		}
		if err := s.readSignaturePayload(false); err != nil {
			return err
		}
		if err := s.readOptionalBool("seek-permission flag"); err != nil {
			return err
		}
	case 16:
		if err := s.readKeyParameters(); err != nil {
			return err
		}
		if err := s.readOptionalBool("for-self flag"); err != nil {
			return err
		}
		signature, err := s.readVarBytes(walletWireMaximumDERBytes, "signature")
		if err != nil {
			return err
		}
		validDER, lowS := walletWireDERStatus(signature)
		if !validDER {
			return categorizedError{"invalidEncoding", "wallet-wire signature encoding is invalid"}
		}
		if !lowS {
			return categorizedError{"invalidArgument", "wallet-wire high-S signature is not round-trippable"}
		}
		if err := s.readSignaturePayload(true); err != nil {
			return err
		}
		if err := s.readOptionalBool("seek-permission flag"); err != nil {
			return err
		}
	case 17:
		if err := s.readAcquireCertificateRequest(); err != nil {
			return err
		}
	case 18:
		if err := s.readListCertificatesRequest(); err != nil {
			return err
		}
	case 19:
		certificateType, err := s.takeFixed(32, "certificate type")
		if err != nil {
			return err
		}
		if bytes.Equal(certificateType, make([]byte, 32)) {
			return categorizedError{"invalidArgument", "wallet-wire prove-certificate type must not be zero"}
		}
		s.position -= 32
		if err := s.readProveCertificateRequest(); err != nil {
			return err
		}
	case 20:
		certificateType, err := s.takeFixed(32, "certificate type")
		if err != nil {
			return err
		}
		if bytes.Equal(certificateType, make([]byte, 32)) {
			return categorizedError{"invalidArgument", "wallet-wire relinquish-certificate type must not be zero"}
		}
		serialNumber, err := s.takeFixed(32, "certificate serial number")
		if err != nil {
			return err
		}
		if bytes.Equal(serialNumber, make([]byte, 32)) {
			return categorizedError{"invalidArgument", "wallet-wire relinquish-certificate serial number must not be zero"}
		}
		if err := s.readCertificatePublicKey("certificate certifier"); err != nil {
			return err
		}
	case 21:
		if err := s.readDiscoveryRequest(true); err != nil {
			return err
		}
	case 22:
		if err := s.readDiscoveryRequest(false); err != nil {
			return err
		}
	case 23, 24, 25, 27, 28:
		// These calls have no request parameters.
	case 26:
		height, err := s.readCompactSize()
		if err != nil {
			return err
		}
		if height > math.MaxUint32 {
			return categorizedError{"invalidArgument", "wallet-wire height exceeds UInt32"}
		}
	default:
		return categorizedError{"invalidEncoding", "wallet-wire request call is unsupported"}
	}
	return s.requireEnd()
}

func walletWirePreflightResultPayload(call byte, data []byte) error {
	s := walletWireScanner{data: data}
	switch call {
	case 1:
		if err := s.readCreateActionResult(); err != nil {
			return err
		}
	case 2:
		if err := s.readSignActionResult(); err != nil {
			return err
		}
	case 3, 5, 7:
		// These successful action results have an empty payload.
	case 4:
		if err := s.readListActionsResult(); err != nil {
			return err
		}
	case 6:
		if err := s.readListOutputsResult(); err != nil {
			return err
		}
	case 8:
		key, err := s.takeFixed(33, "public key")
		if err != nil {
			return err
		}
		if key[0] != 0x02 && key[0] != 0x03 {
			return categorizedError{"invalidEncoding", "wallet-wire public key encoding is invalid"}
		}
	case 11, 12:
		if len(data) > walletWireMaximumBytes {
			return categorizedError{"resourceLimit", "wallet-wire result payload exceeds operation limit"}
		}
		s.position = len(data)
	case 13:
		if _, err := s.takeFixed(32, "HMAC result"); err != nil {
			return err
		}
	case 14, 16, 24:
		// These successful results have an empty payload.
	case 15:
		if len(data) > walletWireMaximumDERBytes {
			return categorizedError{"resourceLimit", "wallet-wire signature exceeds operation limit"}
		}
		validDER, lowS := walletWireDERStatus(data)
		if !validDER {
			return categorizedError{"invalidEncoding", "wallet-wire signature encoding is invalid"}
		}
		if !lowS {
			return categorizedError{"invalidArgument", "wallet-wire high-S signature is not round-trippable"}
		}
		s.position = len(data)
	case 9:
		if err := s.readLinkageResult(false); err != nil {
			return err
		}
	case 10:
		if err := s.readLinkageResult(true); err != nil {
			return err
		}
	case 17:
		if err := s.readCertificateBinary(true); err != nil {
			return err
		}
	case 18:
		if err := s.readListCertificatesResult(); err != nil {
			return err
		}
	case 19:
		if err := s.readCertificateMap("verifier keyring", false, false, false); err != nil {
			return err
		}
	case 20:
		// A successful relinquish-certificate result has an empty payload.
	case 21, 22:
		if err := s.readDiscoveryResult(); err != nil {
			return err
		}
	case 23:
		value, err := s.readByte("authentication result")
		if err != nil {
			return err
		}
		if value != 0 && value != 1 {
			return categorizedError{"invalidEncoding", "wallet-wire authentication result discriminator is invalid"}
		}
	case 25:
		height, err := s.readCompactSize()
		if err != nil {
			return err
		}
		if height > math.MaxUint32 {
			return categorizedError{"invalidArgument", "wallet-wire height exceeds UInt32"}
		}
	case 26:
		if _, err := s.takeFixed(80, "block header"); err != nil {
			return err
		}
	case 27:
		value, err := s.readByte("network result")
		if err != nil {
			return err
		}
		if value != 0 && value != 1 {
			return categorizedError{"invalidEncoding", "wallet-wire network result discriminator is invalid"}
		}
	case 28:
		if len(data) > walletWireMaximumTextBytes {
			return categorizedError{"resourceLimit", "wallet-wire version exceeds operation limit"}
		}
		if !utf8.Valid(data) {
			return categorizedError{"invalidEncoding", "wallet-wire version is not UTF-8"}
		}
		s.position = len(data)
	default:
		return categorizedError{"invalidEncoding", "wallet-wire result call is unsupported"}
	}
	return s.requireEnd()
}

func walletWireCompactSize(data []byte, position *int) (uint64, error) {
	if *position >= len(data) {
		return 0, categorizedError{"truncated", "wallet-wire CompactSize is truncated"}
	}
	prefix := data[*position]
	*position++
	if prefix < 0xfd {
		return uint64(prefix), nil
	}
	byteCount := 8
	minimum := uint64(0x1_0000_0000)
	if prefix == 0xfd {
		byteCount, minimum = 2, 0xfd
	} else if prefix == 0xfe {
		byteCount, minimum = 4, 0x1_0000
	}
	if byteCount > len(data)-*position {
		return 0, categorizedError{"truncated", "wallet-wire CompactSize is truncated"}
	}
	var value uint64
	for offset := 0; offset < byteCount; offset++ {
		value |= uint64(data[*position+offset]) << (8 * offset)
	}
	*position += byteCount
	if value < minimum {
		return 0, categorizedError{"noncanonical", "wallet-wire CompactSize is noncanonical"}
	}
	return value, nil
}

func walletWireReencodeRequestParameters(call byte, data []byte) ([]byte, error) {
	switch call {
	case 1:
		value, err := walletserializer.DeserializeCreateActionArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeCreateActionArgs(value)
	case 2:
		value, err := walletserializer.DeserializeSignActionArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeSignActionArgs(value)
	case 3:
		value, err := walletserializer.DeserializeAbortActionArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeAbortActionArgs(value)
	case 4:
		value, err := walletserializer.DeserializeListActionsArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeListActionsArgs(value)
	case 5:
		value, err := walletserializer.DeserializeInternalizeActionArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeInternalizeActionArgs(value)
	case 6:
		value, err := walletserializer.DeserializeListOutputsArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeListOutputsArgs(value)
	case 7:
		value, err := walletserializer.DeserializeRelinquishOutputArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeRelinquishOutputArgs(value)
	case 8:
		value, err := walletserializer.DeserializeGetPublicKeyArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeGetPublicKeyArgs(value)
	case 9:
		value, err := walletserializer.DeserializeRevealCounterpartyKeyLinkageArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeRevealCounterpartyKeyLinkageArgs(value)
	case 10:
		value, err := walletserializer.DeserializeRevealSpecificKeyLinkageArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeRevealSpecificKeyLinkageArgs(value)
	case 11:
		value, err := walletserializer.DeserializeEncryptArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeEncryptArgs(value)
	case 12:
		value, err := walletserializer.DeserializeDecryptArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeDecryptArgs(value)
	case 13:
		value, err := walletserializer.DeserializeCreateHMACArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeCreateHMACArgs(value)
	case 14:
		value, err := walletserializer.DeserializeVerifyHMACArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeVerifyHMACArgs(value)
	case 15:
		value, err := walletserializer.DeserializeCreateSignatureArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeCreateSignatureArgs(value)
	case 16:
		value, err := walletserializer.DeserializeVerifySignatureArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeVerifySignatureArgs(value)
	case 17:
		value, err := walletserializer.DeserializeAcquireCertificateArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeAcquireCertificateArgs(value)
	case 18:
		value, err := walletserializer.DeserializeListCertificatesArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeListCertificatesArgs(value)
	case 19:
		value, err := walletserializer.DeserializeProveCertificateArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeProveCertificateArgs(value)
	case 20:
		value, err := walletserializer.DeserializeRelinquishCertificateArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeRelinquishCertificateArgs(value)
	case 21:
		value, err := walletserializer.DeserializeDiscoverByIdentityKeyArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeDiscoverByIdentityKeyArgs(value)
	case 22:
		value, err := walletserializer.DeserializeDiscoverByAttributesArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeDiscoverByAttributesArgs(value)
	case 23, 24, 25, 27, 28:
		if len(data) != 0 {
			return nil, errors.New("no-argument call has parameters")
		}
		return nil, nil
	case 26:
		value, err := walletserializer.DeserializeGetHeaderArgs(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeGetHeaderArgs(value)
	default:
		return nil, errors.New("unsupported wallet-wire request call")
	}
}

func walletWireReencodeResultPayload(call byte, data []byte) ([]byte, error) {
	switch call {
	case 1:
		value, err := walletserializer.DeserializeCreateActionResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeCreateActionResult(value)
	case 2:
		value, err := walletserializer.DeserializeSignActionResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeSignActionResult(value)
	case 3:
		value, err := walletserializer.DeserializeAbortActionResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeAbortActionResult(value)
	case 4:
		value, err := walletserializer.DeserializeListActionsResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeListActionsResult(value)
	case 5:
		value, err := walletserializer.DeserializeInternalizeActionResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeInternalizeActionResult(value)
	case 6:
		value, err := walletserializer.DeserializeListOutputsResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeListOutputsResult(value)
	case 7:
		value, err := walletserializer.DeserializeRelinquishOutputResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeRelinquishOutputResult(value)
	case 8:
		value, err := walletserializer.DeserializeGetPublicKeyResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeGetPublicKeyResult(value)
	case 9:
		value, err := walletserializer.DeserializeRevealCounterpartyKeyLinkageResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeRevealCounterpartyKeyLinkageResult(value)
	case 10:
		value, err := walletserializer.DeserializeRevealSpecificKeyLinkageResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeRevealSpecificKeyLinkageResult(value)
	case 11:
		value, err := walletserializer.DeserializeEncryptResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeEncryptResult(value)
	case 12:
		value, err := walletserializer.DeserializeDecryptResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeDecryptResult(value)
	case 13:
		value, err := walletserializer.DeserializeCreateHMACResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeCreateHMACResult(value)
	case 14:
		value, err := walletserializer.DeserializeVerifyHMACResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeVerifyHMACResult(value)
	case 15:
		value, err := walletserializer.DeserializeCreateSignatureResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeCreateSignatureResult(value)
	case 16:
		value, err := walletserializer.DeserializeVerifySignatureResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeVerifySignatureResult(value)
	case 17:
		value, err := walletserializer.DeserializeCertificate(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeCertificate(value)
	case 18:
		value, err := walletserializer.DeserializeListCertificatesResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeListCertificatesResult(value)
	case 19:
		// The pinned writer ranges over this map without sorting. The strict
		// preflight establishes canonical order, and the pinned reader validates
		// the typed shape. Preserve those canonical bytes instead of returning
		// nondeterministic map iteration output.
		if _, err := walletserializer.DeserializeProveCertificateResult(data); err != nil {
			return nil, err
		}
		return append([]byte(nil), data...), nil
	case 20:
		value, err := walletserializer.DeserializeRelinquishCertificateResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeRelinquishCertificateResult(value)
	case 21, 22:
		value, err := walletserializer.DeserializeDiscoverCertificatesResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeDiscoverCertificatesResult(value)
	case 23:
		value, err := walletserializer.DeserializeIsAuthenticatedResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeIsAuthenticatedResult(value)
	case 24:
		value, err := walletserializer.DeserializeWaitAuthenticatedResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeWaitAuthenticatedResult(value)
	case 25:
		value, err := walletserializer.DeserializeGetHeightResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeGetHeightResult(value)
	case 26:
		value, err := walletserializer.DeserializeGetHeaderResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeGetHeaderResult(value)
	case 27:
		value, err := walletserializer.DeserializeGetNetworkResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeGetNetworkResult(value)
	case 28:
		value, err := walletserializer.DeserializeGetVersionResult(data)
		if err != nil {
			return nil, err
		}
		return walletserializer.SerializeGetVersionResult(value)
	default:
		return nil, errors.New("unsupported wallet-wire result call")
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

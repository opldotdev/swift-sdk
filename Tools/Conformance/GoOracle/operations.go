package main

import (
	"bytes"
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
	"strconv"
	"strings"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	base58 "github.com/bsv-blockchain/go-sdk/compat/base58"
	drbgprimitive "github.com/bsv-blockchain/go-sdk/primitives/drbg"
	ecprimitive "github.com/bsv-blockchain/go-sdk/primitives/ec"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/hash"
	scriptpkg "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighashpkg "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	p2pkhpkg "github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/bsv-blockchain/go-sdk/util"
)

func execute(req request, meta metadata) (result any, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = categorizedError{"oraclePanic", fmt.Sprintf("operation panicked: %v", recovered)}
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
	case "scriptnum.encode":
		return encodeScriptNumber(req.Args)
	case "scriptnum.decode":
		return decodeScriptNumber(req.Args)
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
		flag, err := protocolForkIDFlag(args.SignatureHash)
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
		preimage, err := tx.CalcInputPreimage(uint32(inputIndex), flag)
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

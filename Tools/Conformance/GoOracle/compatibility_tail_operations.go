package main

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	scriptpkg "github.com/bsv-blockchain/go-sdk/script"
)

const compatibilityTailMaximumBIP276DataBytes = 32 * 1024
const compatibilityTailMaximumBIP276PrefixBytes = 128

func executeCompatibilityTailBIP276Encode(raw json.RawMessage) (any, error) {
	var args struct {
		Prefix  string `json:"prefix"`
		Version string `json:"version"`
		Network string `json:"network"`
		Data    string `json:"data"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if err := compatibilityTailBIP276Prefix(args.Prefix); err != nil {
		return nil, err
	}
	version, err := decimalUint(args.Version, 8)
	if err != nil {
		return nil, err
	}
	if version == 0 {
		return nil, categorizedError{"unsupportedVersion", "version must be a nonzero uint8"}
	}
	network, err := decimalUint(args.Network, 8)
	if err != nil {
		return nil, err
	}
	if network == 0 {
		return nil, categorizedError{"unsupportedNetwork", "network must be a nonzero uint8"}
	}
	if len(args.Data) > 2*compatibilityTailMaximumBIP276DataBytes {
		return nil, categorizedError{"resourceLimit", "BIP-276 data exceeds 32 KiB"}
	}
	data, err := protocolHex(args.Data)
	if err != nil {
		return nil, err
	}
	if len(data) > compatibilityTailMaximumBIP276DataBytes {
		return nil, categorizedError{"resourceLimit", "BIP-276 data exceeds 32 KiB"}
	}
	text := scriptpkg.EncodeBIP276(scriptpkg.BIP276{
		Prefix: args.Prefix, Version: int(version), Network: int(network), Data: data,
	})
	if text == "ERROR" {
		return nil, categorizedError{"internal", "pinned BIP-276 encoder rejected preflighted input"}
	}
	return map[string]string{"text": text}, nil
}

func executeCompatibilityTailBIP276Decode(raw json.RawMessage) (any, error) {
	var args struct {
		Text string `json:"text"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if len(args.Text) > compatibilityTailMaximumBIP276PrefixBytes+13+2*compatibilityTailMaximumBIP276DataBytes {
		return nil, categorizedError{"resourceLimit", "BIP-276 text exceeds adapter limit"}
	}
	separator := strings.LastIndexByte(args.Text, ':')
	if separator <= 0 || len(args.Text)-separator-1 < 12 {
		return nil, categorizedError{"invalidEncoding", "invalid BIP-276 shape"}
	}
	if err := compatibilityTailBIP276Prefix(args.Text[:separator]); err != nil {
		return nil, err
	}
	hexPart := args.Text[separator+1:]
	if len(hexPart) < 12 || len(hexPart)%2 != 0 {
		return nil, categorizedError{"invalidEncoding", "BIP-276 hexadecimal suffix must have even length"}
	}
	if len(hexPart)-12 > 2*compatibilityTailMaximumBIP276DataBytes {
		return nil, categorizedError{"resourceLimit", "BIP-276 data exceeds 32 KiB"}
	}
	decodedHex, err := hex.DecodeString(hexPart)
	if err != nil {
		return nil, err
	}
	if len(decodedHex) < 2 {
		return nil, categorizedError{"invalidEncoding", "BIP-276 version and network are truncated"}
	}
	if decodedHex[0] == 0 {
		return nil, categorizedError{"unsupportedVersion", "version must be a nonzero uint8"}
	}
	if decodedHex[1] == 0 {
		return nil, categorizedError{"unsupportedNetwork", "network must be a nonzero uint8"}
	}
	decoded, err := scriptpkg.DecodeBIP276(args.Text)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"prefix":  decoded.Prefix,
		"version": strconv.Itoa(decoded.Version),
		"network": strconv.Itoa(decoded.Network),
		"data":    hex.EncodeToString(decoded.Data),
	}, nil
}

func compatibilityTailBIP276Prefix(prefix string) error {
	if len(prefix) == 0 || len(prefix) > compatibilityTailMaximumBIP276PrefixBytes {
		return categorizedError{"resourceLimit", "BIP-276 prefix length is outside 1...128 bytes"}
	}
	for _, value := range []byte(prefix) {
		if value < 0x21 || value > 0x7e || value == ':' {
			return categorizedError{"invalidEncoding", "BIP-276 prefix must be printable ASCII without colon"}
		}
	}
	return nil
}

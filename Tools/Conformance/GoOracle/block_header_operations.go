package main

import (
	"encoding/hex"
	"encoding/json"
	"strconv"

	blockpkg "github.com/bsv-blockchain/go-sdk/block"
)

func parseBlockHeaderArgs(raw json.RawMessage) (*blockpkg.Header, error) {
	var args struct {
		Bytes *string `json:"bytes"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if args.Bytes == nil {
		return nil, categorizedError{"invalidArgument", "block header bytes are required"}
	}
	data, err := protocolHex(*args.Bytes)
	if err != nil {
		return nil, err
	}
	if len(data) != blockpkg.HeaderSize {
		return nil, categorizedError{"invalidLength", "block header must contain exactly 80 bytes"}
	}
	header, err := blockpkg.NewHeaderFromBytes(data)
	if err != nil {
		return nil, categorizedError{"invalidEncoding", "pinned Go rejected block header"}
	}
	return header, nil
}

func inspectBlockHeader(raw json.RawMessage) (any, error) {
	header, err := parseBlockHeaderArgs(raw)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"bits":              strconv.FormatUint(uint64(header.Bits), 10),
		"bytes":             hex.EncodeToString(header.Bytes()),
		"hash":              header.Hash().String(),
		"merkleRoot":        header.MerkleRoot.String(),
		"nonce":             strconv.FormatUint(uint64(header.Nonce), 10),
		"previousBlockHash": header.PrevHash.String(),
		"timestamp":         strconv.FormatUint(uint64(header.Timestamp), 10),
		"version":           strconv.FormatInt(int64(header.Version), 10),
	}, nil
}

func reencodeBlockHeader(raw json.RawMessage) (any, error) {
	header, err := parseBlockHeaderArgs(raw)
	if err != nil {
		return nil, err
	}
	return map[string]string{"bytes": hex.EncodeToString(header.Bytes())}, nil
}

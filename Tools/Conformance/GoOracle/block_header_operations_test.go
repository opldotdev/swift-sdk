package main

import (
	"reflect"
	"strings"
	"testing"
)

const genesisBlockHeaderHex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"

func TestBlockHeaderOperations(t *testing.T) {
	got, err := execute(testRequest("block.header.inspect", `{"bytes":"`+genesisBlockHeaderHex+`"}`), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"bits":              "486604799",
		"bytes":             genesisBlockHeaderHex,
		"hash":              "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
		"merkleRoot":        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
		"nonce":             "2083236893",
		"previousBlockHash": strings.Repeat("00", 32),
		"timestamp":         "1231006505",
		"version":           "1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	reencoded, err := execute(testRequest("block.header.reencode", `{"bytes":"`+genesisBlockHeaderHex+`"}`), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reencoded, map[string]string{"bytes": genesisBlockHeaderHex}) {
		t.Fatalf("got %#v", reencoded)
	}
}

func TestBlockHeaderOperationsRejectHostileArguments(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     string
		category string
	}{
		{"missing bytes", `{}`, "invalidEncoding"},
		{"null bytes", `{"bytes":null}`, "invalidArgument"},
		{"unknown field", `{"bytes":"","extra":true}`, "invalidEncoding"},
		{"odd hex", `{"bytes":"0"}`, "invalidLength"},
		{"uppercase hex", `{"bytes":"AA"}`, "invalidEncoding"},
		{"short header", `{"bytes":"00"}`, "invalidLength"},
		{"long header", `{"bytes":"` + strings.Repeat("00", 81) + `"}`, "invalidLength"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := execute(testRequest("block.header.inspect", tc.args), metadata{})
			if err == nil {
				t.Fatal("expected error")
			}
			if got := normalizeError(err).Category; got != tc.category {
				t.Fatalf("got %s, want %s", got, tc.category)
			}
		})
	}
}

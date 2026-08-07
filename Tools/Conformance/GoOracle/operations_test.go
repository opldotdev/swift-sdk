package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func testRequest(op, args string) request {
	return request{Schema: protocolSchema, ID: "case", Op: op, Args: json.RawMessage(args)}
}

// These constants come from the relevant wire-format definitions, FIPS 180,
// RFC 4231, and the Bitcoin Base58Check address example, not oracle output.
func TestKnownStandardValues(t *testing.T) {
	type vector struct {
		op, args string
		want     any
	}
	display := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	wire := "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
	vectors := []vector{
		{"u16.encode", `{"value":"4660","endian":"little"}`, map[string]string{"bytes": "3412"}},
		{"u16.encode", `{"value":"4660","endian":"big"}`, map[string]string{"bytes": "1234"}},
		{"u16.decode", `{"bytes":"3412","endian":"little"}`, map[string]string{"value": "4660"}},
		{"u32.encode", `{"value":"305419896","endian":"little"}`, map[string]string{"bytes": "78563412"}},
		{"u32.encode", `{"value":"305419896","endian":"big"}`, map[string]string{"bytes": "12345678"}},
		{"u32.decode", `{"bytes":"12345678","endian":"big"}`, map[string]string{"value": "305419896"}},
		{"u64.encode", `{"value":"81985529216486895","endian":"little"}`, map[string]string{"bytes": "efcdab8967452301"}},
		{"u64.encode", `{"value":"81985529216486895","endian":"big"}`, map[string]string{"bytes": "0123456789abcdef"}},
		{"u64.decode", `{"bytes":"efcdab8967452301","endian":"little"}`, map[string]string{"value": "81985529216486895"}},
		{"hex.encode", `{"bytes":"00ff10"}`, map[string]string{"text": "00ff10"}},
		{"hex.decode", `{"text":"00FF10"}`, map[string]string{"bytes": "00ff10"}},
		{"base64.encode", `{"bytes":"666f6f"}`, map[string]string{"text": "Zm9v"}},
		{"base64.decode", `{"text":"Zm9v"}`, map[string]string{"bytes": "666f6f"}},
		{"bytes.reverse", `{"hex":"000102ff"}`, map[string]string{"hex": "ff020100"}},
		{"varint.encode", `{"value":"253"}`, map[string]string{"bytes": "fdfd00"}},
		{"varint.decode", `{"bytes":"fdfc00","canonical":"permissive"}`, map[string]any{"value": "252", "bytesConsumed": "3", "isCanonical": false}},
		{"varbytes.encode", `{"bytes":"aabb"}`, map[string]string{"bytes": "02aabb"}},
		{"varbytes.decode", `{"bytes":"02aabb","canonical":"required"}`, map[string]any{"bytes": "aabb", "bytesConsumed": "3", "isCanonical": true}},
		{"hash.sha256", `{"bytes":""}`, map[string]string{"bytes": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},
		{"hash.sha256d", `{"bytes":""}`, map[string]string{"bytes": "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"}},
		{"hash.sha512", `{"bytes":""}`, map[string]string{"bytes": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"}},
		{"hash.ripemd160", `{"bytes":""}`, map[string]string{"bytes": "9c1185a5c5e9fc54612808977ee8f548b2258d31"}},
		{"hash.hash160", `{"bytes":""}`, map[string]string{"bytes": "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"}},
		{"hmac.sha256", `{"key":"` + strings.Repeat("0b", 20) + `","message":"4869205468657265"}`, map[string]string{"bytes": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"}},
		{"hmac.sha512", `{"key":"` + strings.Repeat("0b", 20) + `","message":"4869205468657265"}`, map[string]string{"bytes": "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"}},
		{"digest32.parse", `{"display":"` + strings.ToUpper(display) + `"}`, map[string]string{"bytes": wire}},
		{"digest32.display", `{"bytes":"` + wire + `"}`, map[string]string{"display": display}},
		{"base58.encode", `{"bytes":"0001"}`, map[string]string{"text": "12"}},
		{"base58.decode", `{"text":"12"}`, map[string]string{"bytes": "0001"}},
		{"base58check.encode", `{"payload":"0000000000000000000000000000000000000000","version":"0"}`, map[string]string{"text": "1111111111111111111114oLvT2"}},
		{"base58check.decode", `{"text":"1111111111111111111114oLvT2"}`, map[string]string{"payload": "0000000000000000000000000000000000000000", "version": "0"}},
		{"big.umod", `{"dividend":"-5","divisor":"3"}`, map[string]string{"value": "1"}},
		{"scriptnum.encode", `{"value":"-128","era":"postGenesis"}`, map[string]string{"bytes": "8080"}},
		{"scriptnum.decode", `{"bytes":"8080","era":"postGenesis","minimal":true,"maxBytes":"4"}`, map[string]string{"value": "-128"}},
	}
	for _, tc := range vectors {
		t.Run(tc.op+"/"+tc.args, func(t *testing.T) {
			got, err := execute(testRequest(tc.op, tc.args), metadata{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestBase64DecodePolicies(t *testing.T) {
	for _, tc := range []struct {
		name string
		args string
		want map[string]string
	}{
		{"absent policy is strict", `{"text":"Zm9v"}`, map[string]string{"bytes": "666f6f"}},
		{"named strict policy", `{"text":"Zm9v","policy":"strict"}`, map[string]string{"bytes": "666f6f"}},
		{"goSDK tolerates newline", `{"text":"Zm\n9v","policy":"goSDK"}`, map[string]string{"bytes": "666f6f"}},
		{"goSDK tolerates discarded bits", `{"text":"Zh==","policy":"goSDK"}`, map[string]string{"bytes": "66"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := execute(testRequest("base64.decode", tc.args), metadata{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name string
		args string
	}{
		{"strict rejects discarded bits", `{"text":"Zh==","policy":"strict"}`},
		{"invalid policy", `{"text":"Zm9v","policy":"other"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := execute(testRequest("base64.decode", tc.args), metadata{})
			if err == nil {
				t.Fatal("expected error")
			}
			if got := normalizeError(err).Category; got != "invalidEncoding" {
				t.Fatalf("got %s, want invalidEncoding (%v)", got, err)
			}
		})
	}
}

func TestCompleteOperationRegistry(t *testing.T) {
	expected := []string{
		"base58.decode", "base58.encode", "base58check.decode", "base58check.encode",
		"base64.decode", "base64.encode", "big.umod", "bytes.reverse", "digest32.display",
		"digest32.parse", "drbg.generate", "hash.hash160", "hash.ripemd160", "hash.sha256", "hash.sha256d",
		"hash.sha512", "hex.decode", "hex.encode", "hmac.sha256", "hmac.sha512", "metadata",
		"scriptnum.decode", "scriptnum.encode", "u16.decode", "u16.encode", "u32.decode",
		"u32.encode", "u64.decode", "u64.encode", "varbytes.decode", "varbytes.encode",
		"varint.decode", "varint.encode",
	}
	if !reflect.DeepEqual(operations, expected) {
		t.Fatalf("registry mismatch\n got: %v\nwant: %v", operations, expected)
	}
}

func TestEveryOperationHasDeterministicSuccess(t *testing.T) {
	base58check, err := execute(testRequest("base58check.encode", `{"payload":"0102","version":"0"}`), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	base58checkText := base58check.(map[string]string)["text"]

	cases := []request{
		testRequest("metadata", `{}`), testRequest("bytes.reverse", `{"hex":"0102"}`),
		testRequest("u16.encode", `{"value":"513","endian":"little"}`), testRequest("u16.decode", `{"bytes":"0102","endian":"little"}`),
		testRequest("u32.encode", `{"value":"1","endian":"big"}`), testRequest("u32.decode", `{"bytes":"00000001","endian":"big"}`),
		testRequest("u64.encode", `{"value":"1","endian":"little"}`), testRequest("u64.decode", `{"bytes":"0100000000000000","endian":"little"}`),
		testRequest("hex.encode", `{"bytes":"00ff"}`), testRequest("hex.decode", `{"text":"00FF"}`),
		testRequest("base64.encode", `{"bytes":"666f6f"}`), testRequest("base64.decode", `{"text":"Zm9v"}`),
		testRequest("varint.encode", `{"value":"253"}`), testRequest("varint.decode", `{"bytes":"fdfd00","canonical":"required"}`),
		testRequest("varbytes.encode", `{"bytes":"0102"}`), testRequest("varbytes.decode", `{"bytes":"020102","canonical":"required"}`),
		testRequest("hash.sha256", `{"bytes":""}`), testRequest("hash.sha256d", `{"bytes":"00"}`), testRequest("hash.sha512", `{"bytes":"00"}`),
		testRequest("hash.ripemd160", `{"bytes":"00"}`), testRequest("hash.hash160", `{"bytes":"00"}`),
		testRequest("hmac.sha256", `{"key":"00","message":"01"}`), testRequest("hmac.sha512", `{"key":"00","message":"01"}`),
		testRequest("digest32.parse", `{"display":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}`),
		testRequest("digest32.display", `{"bytes":"1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"}`),
		testRequest("base58.encode", `{"bytes":"0001"}`), testRequest("base58.decode", `{"text":"12"}`),
		testRequest("base58check.encode", `{"payload":"0102","version":"0"}`), testRequest("base58check.decode", `{"text":"`+base58checkText+`"}`),
		testRequest("big.umod", `{"dividend":"-5","divisor":"3"}`),
		testRequest("scriptnum.encode", `{"value":"-128","era":"postGenesis"}`),
		testRequest("scriptnum.decode", `{"bytes":"8080","era":"postGenesis","minimal":true,"maxBytes":"4"}`),
	}
	for _, tc := range cases {
		t.Run(tc.Op, func(t *testing.T) {
			if _, err := execute(tc, metadata{}); err != nil {
				t.Fatalf("%s: %v", tc.Op, err)
			}
		})
	}
}

func TestNormalizedFailures(t *testing.T) {
	cases := []struct {
		name     string
		req      request
		category string
	}{
		{"odd hex", testRequest("bytes.reverse", `{"hex":"0"}`), "invalidLength"},
		{"uppercase protocol hex", testRequest("bytes.reverse", `{"hex":"AA"}`), "invalidEncoding"},
		{"bad hex", testRequest("hex.decode", `{"text":"zz"}`), "invalidCharacter"},
		{"bad base64", testRequest("base64.decode", `{"text":"%%%="}`), "invalidEncoding"},
		{"truncated varint", testRequest("varint.decode", `{"bytes":"fd00","canonical":"permissive"}`), "truncated"},
		{"trailing varint", testRequest("varint.decode", `{"bytes":"0100","canonical":"permissive"}`), "trailingData"},
		{"noncanonical varint", testRequest("varint.decode", `{"bytes":"fd0100","canonical":"required"}`), "noncanonical"},
		{"truncated varbytes", testRequest("varbytes.decode", `{"bytes":"0201","canonical":"required"}`), "truncated"},
		{"checksum", testRequest("base58check.decode", `{"text":"11111"}`), "checksum"},
		{"number too large", testRequest("scriptnum.decode", `{"bytes":"0100000000","era":"preGenesis","minimal":false,"maxBytes":"4"}`), "numberTooLarge"},
		{"nonminimal", testRequest("scriptnum.decode", `{"bytes":"00","era":"preGenesis","minimal":true,"maxBytes":"4"}`), "nonminimal"},
		{"panic", testRequest("big.umod", `{"dividend":"1","divisor":"0"}`), "oraclePanic"},
		{"unsupported", testRequest("future.operation", `{}`), "unsupportedOperation"},
		{"unknown args", testRequest("bytes.reverse", `{"hex":"00","extra":true}`), "invalidEncoding"},
		{"missing args", testRequest("bytes.reverse", `{}`), "invalidEncoding"},
		{"overflow", testRequest("u16.encode", `{"value":"65536","endian":"big"}`), "overflow"},
		{"short digest", testRequest("digest32.parse", `{"display":"00"}`), "invalidLength"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := execute(tc.req, metadata{})
			if err == nil {
				t.Fatal("expected error")
			}
			if got := normalizeError(err).Category; got != tc.category {
				t.Fatalf("got %s, want %s (%v)", got, tc.category, err)
			}
		})
	}
}

func TestPinnedStringMappingIsIsolated(t *testing.T) {
	for _, tc := range []struct{ message, category string }{
		{"bad character in encoding", "invalidCharacter"}, {"checksum failed", "checksum"},
		{"unexpected EOF", "truncated"}, {"resource limit exceeded", "resourceLimit"},
		{"something new", "internal"},
	} {
		if got := mapPinnedMessage(tc.message).Category; got != tc.category {
			t.Fatalf("%q mapped to %s", tc.message, got)
		}
	}
	if normalizeError(errors.New("bad character in encoding")).Category != "invalidCharacter" {
		t.Fatal("fallback mapping not used")
	}
}

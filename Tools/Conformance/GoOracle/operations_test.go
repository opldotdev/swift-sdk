package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
		{"script.asm.decode", `{"text":"OP_DUP OP_HASH160 0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG"}`, map[string]string{"bytes": "76a914000000000000000000000000000000000000000088ac"}},
		{"script.asm.encode", `{"bytes":"0051b3ff"}`, map[string]string{"text": "OP_FALSE OP_TRUE OP_SUBSTR OP_INVALIDOPCODE"}},
		{"transaction.decode", `{"bytes":"01000000000000000000"}`, map[string]string{
			"bytes": "01000000000000000000", "inputs": "0", "lockTime": "0",
			"outputs": "0", "txid": "d21633ba23f70118185227be58a63527675641ad37967e2aa461559f577aec43", "version": "1",
		}},
		{"transaction.beef.decode", `{"bytes":"0200beef000102` + strings.Repeat("00", 32) + `"}`, map[string]string{
			"atomicSubject": "", "bumps": "0", "newestTxid": strings.Repeat("00", 32),
			"transactions": "1", "version": "4022206466",
		}},
		{"transaction.beef.decode", `{"bytes":"01010101` + strings.Repeat("00", 32) + `0200beef000102` + strings.Repeat("00", 32) + `"}`, map[string]string{
			"atomicSubject": strings.Repeat("00", 32), "bumps": "0", "newestTxid": strings.Repeat("00", 32),
			"transactions": "1", "version": "4022206466",
		}},
		{"transaction.beef.reencode", `{"bytes":"0200beef000102` + strings.Repeat("00", 32) + `"}`, map[string]string{
			"bytes": "0200beef000102" + strings.Repeat("00", 32),
		}},
		{"transaction.beef.reencode", `{"bytes":"01010101` + strings.Repeat("00", 32) + `0200beef000102` + strings.Repeat("00", 32) + `"}`, map[string]string{
			"bytes": "01010101" + strings.Repeat("00", 32) + "0200beef000102" + strings.Repeat("00", 32),
		}},
		{"transaction.beef.verify", `{"allowTransactionIDOnly":true,"bytes":"0200beef000102` + strings.Repeat("00", 32) + `","validRoots":[]}`, map[string]bool{
			"valid": true,
		}},
		{"transaction.merklepath.decode", `{"bytes":"0101010002` + strings.Repeat("00", 32) + `"}`, map[string]string{
			"blockHeight": "1", "bytes": "0101010002" + strings.Repeat("00", 32), "treeHeight": "1",
		}},
		{"transaction.merklepath.root", `{"bytes":"0101010002` + strings.Repeat("00", 32) + `","txid":"` + strings.Repeat("00", 32) + `"}`, map[string]string{
			"root": strings.Repeat("00", 32),
		}},
		{"transaction.merklepath.combine", `{"left":"0101010002` + strings.Repeat("00", 32) + `","right":"0101010002` + strings.Repeat("00", 32) + `"}`, map[string]string{
			"bytes": "0101010002" + strings.Repeat("00", 32),
		}},
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

func TestScriptASMNamesAndArtifacts(t *testing.T) {
	result, err := execute(testRequest("script.asm.names", `{}`), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	names, ok := result.(map[string]any)["names"].([]string)
	if !ok || len(names) != 256 {
		t.Fatalf("unexpected opcode names result: %#v", result)
	}
	for raw, want := range map[int]string{
		0x00: "OP_FALSE", 0x50: "OP_BASE", 0x51: "OP_TRUE",
		0xb1: "OP_NOP2", 0xb2: "OP_NOP3", 0xb3: "OP_SUBSTR",
		0xb6: "OP_LSHIFTNUM", 0xb7: "OP_RSHIFTNUM", 0xb8: "OP_NOP9",
		0xb9: "OP_NOP10", 0xfa: "OP_SMALLINTEGER", 0xfb: "OP_PUBKEYS",
		0xfc: "OP_UNKNOWN252", 0xfd: "OP_PUBKEYHASH", 0xfe: "OP_PUBKEY",
		0xff: "OP_INVALIDOPCODE",
	} {
		if names[raw] != want {
			t.Fatalf("opcode 0x%02x: got %q, want %q", raw, names[raw], want)
		}
	}

	for _, tc := range []struct {
		op, args string
		want     any
	}{
		{"script.asm.encode", `{"bytes":"4c"}`, map[string]string{"text": ""}},
		{"script.asm.encode", `{"bytes":"4c00"}`, map[string]string{"text": ""}},
		{"script.asm.encode", `{"bytes":"4c01aa"}`, map[string]string{"text": "aa"}},
		{"script.asm.decode", `{"text":"aa"}`, map[string]string{"bytes": "01aa"}},
		{"script.asm.decode", `{"text":""}`, map[string]string{"bytes": ""}},
		{"script.asm.decode", `{"text":"OP_PUSHDATA1"}`, map[string]string{"bytes": ""}},
	} {
		got, err := execute(testRequest(tc.op, tc.args), metadata{})
		if err != nil {
			t.Fatalf("%s %s: %v", tc.op, tc.args, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s %s: got %#v, want %#v", tc.op, tc.args, got, tc.want)
		}
	}

	for _, text := range []string{"not-an-opcode", "abc"} {
		_, err := execute(testRequest("script.asm.decode", `{"text":"`+text+`"}`), metadata{})
		if err == nil {
			t.Fatalf("expected decode error for %q", text)
		}
	}
}

func TestCompleteOperationRegistry(t *testing.T) {
	expected := []string{
		"base58.decode", "base58.encode", "base58check.decode", "base58check.encode",
		"base64.decode", "base64.encode", "big.umod", "brc42.private.derive", "brc42.public.derive", "brc94.generate", "brc94.verify", "bsm.recover", "bsm.sign", "bytes.reverse", "digest32.display",
		"digest32.parse", "drbg.generate", "ecies.bitcore.decrypt", "ecies.bitcore.encrypt", "ecies.electrum.decrypt", "ecies.electrum.encrypt", "hash.hash160", "hash.ripemd160", "hash.sha256", "hash.sha256d",
		"hash.sha512", "hex.decode", "hex.encode", "hmac.sha256", "hmac.sha512", "keyshares.recover", "keyshares.split", "metadata",
		"portable.encrypted.decrypt", "portable.encrypted.encrypt", "portable.signed.sign", "portable.signed.verify",
		"script.asm.decode", "script.asm.encode", "script.asm.names", "script.execute", "scriptnum.decode", "scriptnum.encode", "spv.verify", "symmetric.decrypt", "symmetric.encrypt", "transaction.beef.decode", "transaction.beef.merge", "transaction.beef.reencode", "transaction.beef.trim", "transaction.beef.txidonly", "transaction.beef.validate", "transaction.beef.verify", "transaction.decode", "transaction.fee", "transaction.merklepath.combine", "transaction.merklepath.decode", "transaction.merklepath.root", "transaction.p2pkh.sign", "transaction.sighash", "u16.decode", "u16.encode",
		"u32.decode", "u32.encode", "u64.decode", "u64.encode", "varbytes.decode", "varbytes.encode",
		"varint.decode", "varint.encode",
	}
	if !reflect.DeepEqual(operations, expected) {
		t.Fatalf("registry mismatch\n got: %v\nwant: %v", operations, expected)
	}
}

func TestKeySharesSplitRecoverAndSubsets(t *testing.T) {
	privateKey := strings.Repeat("00", 31) + "2a"
	for _, tc := range []struct {
		threshold, shareCount int
		subsets               [][]int
	}{
		{2, 3, [][]int{{0, 1}, {0, 2}, {1, 2}}},
		{3, 5, [][]int{{0, 1, 2}, {0, 2, 4}, {1, 3, 4}}},
	} {
		t.Run(fmt.Sprintf("%d-of-%d", tc.threshold, tc.shareCount), func(t *testing.T) {
			shares := splitSharesForTest(t, privateKey, tc.threshold, tc.shareCount)
			if len(shares) != tc.shareCount {
				t.Fatalf("got %d shares, want %d", len(shares), tc.shareCount)
			}
			for index, subsetIndexes := range tc.subsets {
				subset := make([]string, len(subsetIndexes))
				for i, shareIndex := range subsetIndexes {
					subset[i] = shares[shareIndex]
				}
				got := recoverSharesForTest(t, fmt.Sprintf("subset-%d", index), subset)
				if got != privateKey {
					t.Fatalf("recovered key got %s, want %s", got, privateKey)
				}
			}
		})
	}
}

func TestKeySharesStrictBoundsAndFailures(t *testing.T) {
	privateKey := strings.Repeat("00", 31) + "01"
	for _, tc := range []struct {
		name, operation, arguments, category string
	}{
		{"threshold below minimum", "keyshares.split", `{"privateKey":"` + privateKey + `","threshold":"1","shareCount":"2"}`, "invalidEncoding"},
		{"threshold above maximum", "keyshares.split", `{"privateKey":"` + privateKey + `","threshold":"21","shareCount":"21"}`, "invalidEncoding"},
		{"count below minimum", "keyshares.split", `{"privateKey":"` + privateKey + `","threshold":"2","shareCount":"1"}`, "invalidEncoding"},
		{"count above maximum", "keyshares.split", `{"privateKey":"` + privateKey + `","threshold":"2","shareCount":"21"}`, "invalidEncoding"},
		{"threshold exceeds count", "keyshares.split", `{"privateKey":"` + privateKey + `","threshold":"3","shareCount":"2"}`, "invalidEncoding"},
		{"noncanonical threshold", "keyshares.split", `{"privateKey":"` + privateKey + `","threshold":"02","shareCount":"3"}`, "invalidEncoding"},
		{"numeric threshold", "keyshares.split", `{"privateKey":"` + privateKey + `","threshold":2,"shareCount":"3"}`, "invalidEncoding"},
		{"unknown split argument", "keyshares.split", `{"privateKey":"` + privateKey + `","threshold":"2","shareCount":"3","extra":true}`, "invalidEncoding"},
		{"missing split argument", "keyshares.split", `{"privateKey":"` + privateKey + `","threshold":"2"}`, "invalidEncoding"},
		{"short private key", "keyshares.split", `{"privateKey":"01","threshold":"2","shareCount":"3"}`, "invalidLength"},
		{"uppercase private key", "keyshares.split", `{"privateKey":"` + strings.Repeat("00", 31) + `0A","threshold":"2","shareCount":"3"}`, "invalidEncoding"},
		{"zero private key", "keyshares.split", `{"privateKey":"` + strings.Repeat("00", 32) + `","threshold":"2","shareCount":"3"}`, "scalar"},
		{"insufficient shares", "keyshares.recover", `{"shares":["invalid"]}`, "invalidLength"},
		{"oversized share", "keyshares.recover", `{"shares":["` + strings.Repeat("z", 129) + `","invalid"]}`, "resourceLimit"},
		{"malformed shares", "keyshares.recover", `{"shares":["invalid","invalid-2"]}`, "invalidEncoding"},
		{"empty share field", "keyshares.recover", `{"shares":["2..2.00000000","3.3.2.00000000"]}`, "invalidEncoding"},
		{"extra share field", "keyshares.recover", `{"shares":["2.2.2.00000000.extra","3.3.2.00000000"]}`, "invalidEncoding"},
		{"unknown recover argument", "keyshares.recover", `{"shares":["invalid","invalid-2"],"extra":true}`, "invalidEncoding"},
		{"missing recover argument", "keyshares.recover", `{}`, "invalidEncoding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := execute(testRequest(tc.operation, tc.arguments), metadata{})
			if err == nil {
				t.Fatal("expected error")
			}
			got := normalizeError(err).Category
			if got != tc.category {
				t.Fatalf("got %s, want %s (%v)", got, tc.category, err)
			}
			if got == "oraclePanic" {
				t.Fatalf("malformed request panicked: %v", err)
			}
		})
	}

	shares := splitSharesForTest(t, privateKey, 2, 3)
	arguments, err := json.Marshal(map[string]any{"shares": []string{shares[0], shares[0]}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = execute(testRequest("keyshares.recover", string(arguments)), metadata{})
	if err == nil || normalizeError(err).Category != "invalidEncoding" {
		t.Fatalf("duplicate shares got %v, want invalidEncoding", err)
	}

	twentyOne := make([]string, 21)
	for index := range twentyOne {
		twentyOne[index] = fmt.Sprintf("invalid-%d", index)
	}
	arguments, err = json.Marshal(map[string]any{"shares": twentyOne})
	if err != nil {
		t.Fatal(err)
	}
	_, err = execute(testRequest("keyshares.recover", string(arguments)), metadata{})
	if err == nil || normalizeError(err).Category != "invalidLength" {
		t.Fatalf("excess shares got %v, want invalidLength", err)
	}
}

func splitSharesForTest(t *testing.T, privateKey string, threshold, shareCount int) []string {
	t.Helper()
	result, err := execute(testRequest(
		"keyshares.split",
		fmt.Sprintf(
			`{"privateKey":"%s","threshold":"%d","shareCount":"%d"}`,
			privateKey,
			threshold,
			shareCount,
		),
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	fields, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("split result has unexpected type %T", result)
	}
	shares, ok := fields["shares"].([]string)
	if !ok {
		t.Fatalf("split shares have unexpected type %T", fields["shares"])
	}
	return shares
}

func recoverSharesForTest(t *testing.T, name string, shares []string) string {
	t.Helper()
	arguments, err := json.Marshal(map[string]any{"shares": shares})
	if err != nil {
		t.Fatal(err)
	}
	result, err := execute(testRequest("keyshares.recover", string(arguments)), metadata{})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	fields, ok := result.(map[string]string)
	if !ok {
		t.Fatalf("recover result has unexpected type %T", result)
	}
	return fields["privateKey"]
}

func TestBitcoinSignedMessageDeterministicSignAndRecover(t *testing.T) {
	privateKey := strings.Repeat("00", 31) + "01"
	message := "6f7261636c652d62736d"
	publicKey := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	cases := []struct {
		name       string
		compressed bool
		signature  string
	}{
		{
			name:       "compressed",
			compressed: true,
			signature:  "20643e48c5d55f7ff53d73c8079b03ac226f1520abe523fa1a783aa77aef056f22405495163cd405dc68f4fd9f074450a79bcfb1b8e72b1b46f49bf0d2cd9d3c7f",
		},
		{
			name:       "uncompressed",
			compressed: false,
			signature:  "1c643e48c5d55f7ff53d73c8079b03ac226f1520abe523fa1a783aa77aef056f22405495163cd405dc68f4fd9f074450a79bcfb1b8e72b1b46f49bf0d2cd9d3c7f",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := fmt.Sprintf(
				`{"privateKey":"%s","message":"%s","compressed":%t}`,
				privateKey,
				message,
				tc.compressed,
			)
			wantSignature := map[string]string{"signature": tc.signature}
			for range 2 {
				got, err := execute(testRequest("bsm.sign", args), metadata{})
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, wantSignature) {
					t.Fatalf("got %#v, want %#v", got, wantSignature)
				}
			}

			got, err := execute(testRequest(
				"bsm.recover",
				fmt.Sprintf(`{"signature":"%s","message":"%s"}`, tc.signature, message),
			), metadata{})
			if err != nil {
				t.Fatal(err)
			}
			wantRecovery := map[string]any{
				"publicKey":  publicKey,
				"compressed": tc.compressed,
			}
			if !reflect.DeepEqual(got, wantRecovery) {
				t.Fatalf("got %#v, want %#v", got, wantRecovery)
			}
		})
	}
}

func TestBitcoinSignedMessageStrictArguments(t *testing.T) {
	privateKey := strings.Repeat("00", 31) + "01"
	validSignature := "20643e48c5d55f7ff53d73c8079b03ac226f1520abe523fa1a783aa77aef056f22405495163cd405dc68f4fd9f074450a79bcfb1b8e72b1b46f49bf0d2cd9d3c7f"
	cases := []struct {
		name, operation, arguments, category string
	}{
		{"sign unknown argument", "bsm.sign", fmt.Sprintf(`{"privateKey":"%s","message":"","compressed":true,"extra":false}`, privateKey), "invalidEncoding"},
		{"recover unknown argument", "bsm.recover", fmt.Sprintf(`{"signature":"%s","message":"","extra":""}`, validSignature), "invalidEncoding"},
		{"missing compression", "bsm.sign", fmt.Sprintf(`{"privateKey":"%s","message":""}`, privateKey), "invalidEncoding"},
		{"short private key", "bsm.sign", `{"privateKey":"01","message":"","compressed":true}`, "invalidLength"},
		{"zero private key", "bsm.sign", fmt.Sprintf(`{"privateKey":"%s","message":"","compressed":true}`, strings.Repeat("00", 32)), "scalar"},
		{"odd message hex", "bsm.sign", fmt.Sprintf(`{"privateKey":"%s","message":"0","compressed":true}`, privateKey), "invalidLength"},
		{"uppercase message hex", "bsm.sign", fmt.Sprintf(`{"privateKey":"%s","message":"AA","compressed":true}`, privateKey), "invalidEncoding"},
		{"short signature", "bsm.recover", fmt.Sprintf(`{"signature":"%s","message":""}`, strings.Repeat("00", 64)), "invalidLength"},
		{"long signature", "bsm.recover", fmt.Sprintf(`{"signature":"%s","message":""}`, strings.Repeat("00", 66)), "invalidLength"},
		{"odd signature hex", "bsm.recover", `{"signature":"0","message":""}`, "invalidLength"},
		{"invalid signature header", "bsm.recover", fmt.Sprintf(`{"signature":"00%s","message":""}`, validSignature[2:]), "signature"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := execute(testRequest(tc.operation, tc.arguments), metadata{})
			if err == nil {
				t.Fatal("expected error")
			}
			if got := normalizeError(err).Category; got != tc.category {
				t.Fatalf("got %s, want %s (%v)", got, tc.category, err)
			}
		})
	}
}

func TestECIESDeterministicFramingAndDecryptPaths(t *testing.T) {
	senderPrivate := strings.Repeat("00", 31) + "07"
	recipientPrivate := strings.Repeat("00", 31) + "0d"
	sender, err := protocolPrivateKey(senderPrivate)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := protocolPrivateKey(recipientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	senderPublic := hex.EncodeToString(sender.PubKey().Compressed())
	recipientPublic := hex.EncodeToString(recipient.PubKey().Compressed())
	initializationVector := "000102030405060708090a0b0c0d0e0f"

	for _, plaintextByteCount := range []int{0, 16, 17, 31, 80} {
		plaintextBytes := make([]byte, plaintextByteCount)
		for i := range plaintextBytes {
			plaintextBytes[i] = byte(i*29 + 7)
		}
		plaintext := hex.EncodeToString(plaintextBytes)
		paddedByteCount := (plaintextByteCount/16 + 1) * 16

		electrumLayouts := []bool{false}
		if plaintextByteCount <= 31 {
			electrumLayouts = append(electrumLayouts, true)
		}
		for _, omit := range electrumLayouts {
			args := fmt.Sprintf(
				`{"plaintext":"%s","recipientPublicKey":"%s","senderPrivateKey":"%s","omitSenderPublicKey":%t}`,
				plaintext,
				recipientPublic,
				senderPrivate,
				omit,
			)
			first, err := execute(testRequest("ecies.electrum.encrypt", args), metadata{})
			if err != nil {
				t.Fatal(err)
			}
			second, err := execute(testRequest("ecies.electrum.encrypt", args), metadata{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(first, second) {
				t.Fatalf("Electrum encryption is not deterministic: %#v != %#v", first, second)
			}
			envelopeHex := first.(map[string]string)["envelope"]
			envelope, err := hex.DecodeString(envelopeHex)
			if err != nil {
				t.Fatal(err)
			}
			wantLength := 4 + paddedByteCount + 32
			if !omit {
				wantLength += 33
			}
			if len(envelope) != wantLength {
				t.Fatalf("Electrum envelope length got %d, want %d", len(envelope), wantLength)
			}
			if !bytes.Equal(envelope[:4], []byte("BIE1")) {
				t.Fatalf("Electrum magic is wrong: %x", envelope[:4])
			}
			if !omit && !bytes.Equal(envelope[4:37], sender.PubKey().Compressed()) {
				t.Fatalf("Electrum embedded sender is wrong: %x", envelope[4:37])
			}
			decryptSender := senderPublic
			if !omit {
				decryptSender = ""
			}
			decrypted, err := execute(testRequest(
				"ecies.electrum.decrypt",
				fmt.Sprintf(
					`{"envelope":"%s","recipientPrivateKey":"%s","senderPublicKey":"%s"}`,
					envelopeHex,
					recipientPrivate,
					decryptSender,
				),
			), metadata{})
			if err != nil {
				t.Fatal(err)
			}
			if want := (map[string]string{"plaintext": plaintext}); !reflect.DeepEqual(decrypted, want) {
				t.Fatalf("Electrum decrypt got %#v, want %#v", decrypted, want)
			}
		}

		bitcoreArgs := fmt.Sprintf(
			`{"plaintext":"%s","recipientPublicKey":"%s","senderPrivateKey":"%s","initializationVector":"%s"}`,
			plaintext,
			recipientPublic,
			senderPrivate,
			initializationVector,
		)
		first, err := execute(testRequest("ecies.bitcore.encrypt", bitcoreArgs), metadata{})
		if err != nil {
			t.Fatal(err)
		}
		second, err := execute(testRequest("ecies.bitcore.encrypt", bitcoreArgs), metadata{})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("Bitcore encryption is not deterministic: %#v != %#v", first, second)
		}
		envelopeHex := first.(map[string]string)["envelope"]
		envelope, err := hex.DecodeString(envelopeHex)
		if err != nil {
			t.Fatal(err)
		}
		wantLength := 33 + 16 + paddedByteCount + 32
		if len(envelope) != wantLength {
			t.Fatalf("Bitcore envelope length got %d, want %d", len(envelope), wantLength)
		}
		if !bytes.Equal(envelope[:33], sender.PubKey().Compressed()) {
			t.Fatalf("Bitcore sender is wrong: %x", envelope[:33])
		}
		if got := hex.EncodeToString(envelope[33:49]); got != initializationVector {
			t.Fatalf("Bitcore IV got %s, want %s", got, initializationVector)
		}
		decrypted, err := execute(testRequest(
			"ecies.bitcore.decrypt",
			fmt.Sprintf(
				`{"envelope":"%s","recipientPrivateKey":"%s"}`,
				envelopeHex,
				recipientPrivate,
			),
		), metadata{})
		if err != nil {
			t.Fatal(err)
		}
		if want := (map[string]string{"plaintext": plaintext}); !reflect.DeepEqual(decrypted, want) {
			t.Fatalf("Bitcore decrypt got %#v, want %#v", decrypted, want)
		}
	}
}

func TestECIESOmittedLongPacketArtifactIsNontrapping(t *testing.T) {
	senderPrivate := strings.Repeat("00", 31) + "07"
	recipientPrivate := strings.Repeat("00", 31) + "0d"
	sender, err := protocolPrivateKey(senderPrivate)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := protocolPrivateKey(recipientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := hex.EncodeToString(bytes.Repeat([]byte{0x5a}, 33))
	encrypted, err := execute(testRequest(
		"ecies.electrum.encrypt",
		fmt.Sprintf(
			`{"plaintext":"%s","recipientPublicKey":"%s","senderPrivateKey":"%s","omitSenderPublicKey":true}`,
			plaintext,
			hex.EncodeToString(recipient.PubKey().Compressed()),
			senderPrivate,
		),
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	envelopeHex := encrypted.(map[string]string)["envelope"]
	_, err = execute(testRequest(
		"ecies.electrum.decrypt",
		fmt.Sprintf(
			`{"envelope":"%s","recipientPrivateKey":"%s","senderPublicKey":"%s"}`,
			envelopeHex,
			recipientPrivate,
			hex.EncodeToString(sender.PubKey().Compressed()),
		),
	), metadata{})
	if err == nil {
		t.Fatal("expected pinned Go omitted-layout heuristic failure")
	}
	if got := normalizeError(err).Category; got != "invalidLength" {
		t.Fatalf("got %s, want invalidLength (%v)", got, err)
	}
}

func TestECIESStrictArgumentsAndMalformedPackets(t *testing.T) {
	privateKey := strings.Repeat("00", 31) + "01"
	publicKey := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	embeddedBadKey := "42494531" + strings.Repeat("00", 33+16+32)
	bitcoreBadKey := strings.Repeat("00", 33+16+16+32)
	electrumEmbeddedNonBlock := "42494531" + publicKey + strings.Repeat("00", 17+32)
	electrumExternalNonBlock := "42494531" + strings.Repeat("00", 17+32)
	bitcoreNonBlock := publicKey + strings.Repeat("00", 16+17+32)
	cases := []struct {
		name, operation, arguments, category string
	}{
		{"Electrum encrypt unknown argument", "ecies.electrum.encrypt", fmt.Sprintf(`{"plaintext":"","recipientPublicKey":"%s","senderPrivateKey":"%s","omitSenderPublicKey":false,"extra":true}`, publicKey, privateKey), "invalidEncoding"},
		{"Electrum encrypt missing layout", "ecies.electrum.encrypt", fmt.Sprintf(`{"plaintext":"","recipientPublicKey":"%s","senderPrivateKey":"%s"}`, publicKey, privateKey), "invalidEncoding"},
		{"Electrum encrypt short public key", "ecies.electrum.encrypt", fmt.Sprintf(`{"plaintext":"","recipientPublicKey":"02","senderPrivateKey":"%s","omitSenderPublicKey":false}`, privateKey), "invalidLength"},
		{"Electrum encrypt zero private key", "ecies.electrum.encrypt", fmt.Sprintf(`{"plaintext":"","recipientPublicKey":"%s","senderPrivateKey":"%s","omitSenderPublicKey":false}`, publicKey, strings.Repeat("00", 32)), "scalar"},
		{"Electrum encrypt uppercase plaintext", "ecies.electrum.encrypt", fmt.Sprintf(`{"plaintext":"AA","recipientPublicKey":"%s","senderPrivateKey":"%s","omitSenderPublicKey":false}`, publicKey, privateKey), "invalidEncoding"},
		{"Electrum embedded short envelope", "ecies.electrum.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s","senderPublicKey":""}`, strings.Repeat("00", 84), privateKey), "invalidLength"},
		{"Electrum external short envelope", "ecies.electrum.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s","senderPublicKey":"%s"}`, strings.Repeat("00", 51), privateKey, publicKey), "invalidLength"},
		{"Electrum decrypt missing sender argument", "ecies.electrum.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s"}`, strings.Repeat("00", 85), privateKey), "invalidEncoding"},
		{"Electrum bad magic", "ecies.electrum.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s","senderPublicKey":""}`, strings.Repeat("00", 85), privateKey), "invalidEncoding"},
		{"Electrum bad embedded key", "ecies.electrum.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s","senderPublicKey":""}`, embeddedBadKey, privateKey), "key"},
		{"Electrum bad external key", "ecies.electrum.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s","senderPublicKey":"04%s"}`, strings.Repeat("00", 52), privateKey, strings.Repeat("00", 32)), "key"},
		{"Electrum embedded non-block ciphertext", "ecies.electrum.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s","senderPublicKey":""}`, electrumEmbeddedNonBlock, privateKey), "invalidLength"},
		{"Electrum external non-block ciphertext", "ecies.electrum.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s","senderPublicKey":"%s"}`, electrumExternalNonBlock, privateKey, publicKey), "invalidLength"},
		{"Bitcore encrypt unknown argument", "ecies.bitcore.encrypt", fmt.Sprintf(`{"plaintext":"","recipientPublicKey":"%s","senderPrivateKey":"%s","initializationVector":"%s","extra":true}`, publicKey, privateKey, strings.Repeat("00", 16)), "invalidEncoding"},
		{"Bitcore encrypt missing IV", "ecies.bitcore.encrypt", fmt.Sprintf(`{"plaintext":"","recipientPublicKey":"%s","senderPrivateKey":"%s"}`, publicKey, privateKey), "invalidEncoding"},
		{"Bitcore encrypt short IV", "ecies.bitcore.encrypt", fmt.Sprintf(`{"plaintext":"","recipientPublicKey":"%s","senderPrivateKey":"%s","initializationVector":"%s"}`, publicKey, privateKey, strings.Repeat("00", 15)), "invalidLength"},
		{"Bitcore encrypt long IV", "ecies.bitcore.encrypt", fmt.Sprintf(`{"plaintext":"","recipientPublicKey":"%s","senderPrivateKey":"%s","initializationVector":"%s"}`, publicKey, privateKey, strings.Repeat("00", 17)), "invalidLength"},
		{"Bitcore decrypt short envelope", "ecies.bitcore.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s"}`, strings.Repeat("00", 96), privateKey), "invalidLength"},
		{"Bitcore decrypt bad sender key", "ecies.bitcore.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s"}`, bitcoreBadKey, privateKey), "key"},
		{"Bitcore decrypt non-block ciphertext", "ecies.bitcore.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s"}`, bitcoreNonBlock, privateKey), "invalidLength"},
		{"Bitcore decrypt zero recipient", "ecies.bitcore.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s"}`, bitcoreNonBlock, strings.Repeat("00", 32)), "scalar"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := execute(testRequest(tc.operation, tc.arguments), metadata{})
			if err == nil {
				t.Fatal("expected error")
			}
			if got := normalizeError(err).Category; got != tc.category {
				t.Fatalf("got %s, want %s (%v)", got, tc.category, err)
			}
			if got := normalizeError(err).Category; got == "oraclePanic" {
				t.Fatalf("malformed request panicked: %v", err)
			}
		})
	}
}

func TestPortableMessagesRoundTripAndFrame(t *testing.T) {
	senderPrivate := strings.Repeat("00", 31) + "0f"
	recipientPrivate := strings.Repeat("00", 31) + "15"
	unrelatedPrivate := strings.Repeat("00", 31) + "16"
	sender, err := portablePrivateKey(senderPrivate)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := portablePrivateKey(recipientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	recipientPublic := hex.EncodeToString(recipient.PubKey().Compressed())

	anyResult, err := execute(testRequest(
		"portable.signed.sign",
		fmt.Sprintf(`{"message":"","senderPrivateKey":"%s"}`, senderPrivate),
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	anyEnvelopeHex := anyResult.(map[string]string)["envelope"]
	anyEnvelope, err := hex.DecodeString(anyEnvelopeHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(anyEnvelope[:4], portableSignedVersion) ||
		!bytes.Equal(anyEnvelope[4:37], sender.PubKey().Compressed()) ||
		anyEnvelope[37] != 0 {
		t.Fatal("anyone signed-message framing is incorrect")
	}
	for index, recipientArgument := range []string{"", `,"recipientPrivateKey":"` + unrelatedPrivate + `"`} {
		verified, err := execute(testRequest(
			"portable.signed.verify",
			fmt.Sprintf(`{"message":"","envelope":"%s"%s}`, anyEnvelopeHex, recipientArgument),
		), metadata{})
		if err != nil {
			t.Fatalf("anyone verification %d: %v", index, err)
		}
		if !verified.(map[string]bool)["valid"] {
			t.Fatalf("anyone verification %d returned false", index)
		}
	}

	messageHex := hex.EncodeToString([]byte("Grüße, 世界"))
	specificResult, err := execute(testRequest(
		"portable.signed.sign",
		fmt.Sprintf(
			`{"message":"%s","senderPrivateKey":"%s","recipientPublicKey":"%s"}`,
			messageHex, senderPrivate, recipientPublic,
		),
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	specificEnvelopeHex := specificResult.(map[string]string)["envelope"]
	specificEnvelope, err := hex.DecodeString(specificEnvelopeHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(specificEnvelope[37:70], recipient.PubKey().Compressed()) {
		t.Fatal("specific signed-message recipient framing is incorrect")
	}
	verified, err := execute(testRequest(
		"portable.signed.verify",
		fmt.Sprintf(
			`{"message":"%s","envelope":"%s","recipientPrivateKey":"%s"}`,
			messageHex, specificEnvelopeHex, recipientPrivate,
		),
	), metadata{})
	if err != nil || !verified.(map[string]bool)["valid"] {
		t.Fatalf("specific signed-message verification failed: %#v, %v", verified, err)
	}

	plaintext := hex.EncodeToString(bytes.Repeat([]byte{0x5a}, 65))
	encryptedResult, err := execute(testRequest(
		"portable.encrypted.encrypt",
		fmt.Sprintf(
			`{"plaintext":"%s","senderPrivateKey":"%s","recipientPublicKey":"%s"}`,
			plaintext, senderPrivate, recipientPublic,
		),
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	encryptedEnvelopeHex := encryptedResult.(map[string]string)["envelope"]
	encryptedEnvelope, err := hex.DecodeString(encryptedEnvelopeHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(encryptedEnvelope) != 150+65 ||
		!bytes.Equal(encryptedEnvelope[:4], portableEncryptedVersion) ||
		!bytes.Equal(encryptedEnvelope[4:37], sender.PubKey().Compressed()) ||
		!bytes.Equal(encryptedEnvelope[37:70], recipient.PubKey().Compressed()) {
		t.Fatal("encrypted-message framing is incorrect")
	}
	decrypted, err := execute(testRequest(
		"portable.encrypted.decrypt",
		fmt.Sprintf(
			`{"envelope":"%s","recipientPrivateKey":"%s"}`,
			encryptedEnvelopeHex, recipientPrivate,
		),
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	if got := decrypted.(map[string]string)["plaintext"]; got != plaintext {
		t.Fatalf("decrypted plaintext got %s, want %s", got, plaintext)
	}
}

func TestPortableMessagesStrictArgumentsAndPanicSafePreflights(t *testing.T) {
	senderPrivate := strings.Repeat("00", 31) + "0f"
	recipientPrivate := strings.Repeat("00", 31) + "15"
	wrongRecipientPrivate := strings.Repeat("00", 31) + "16"
	recipient, err := portablePrivateKey(recipientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	recipientPublic := hex.EncodeToString(recipient.PubKey().Compressed())

	signedResult, err := execute(testRequest(
		"portable.signed.sign",
		fmt.Sprintf(
			`{"message":"0102","senderPrivateKey":"%s","recipientPublicKey":"%s"}`,
			senderPrivate, recipientPublic,
		),
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	signedHex := signedResult.(map[string]string)["envelope"]
	signed, err := hex.DecodeString(signedHex)
	if err != nil {
		t.Fatal(err)
	}

	encryptedResult, err := execute(testRequest(
		"portable.encrypted.encrypt",
		fmt.Sprintf(
			`{"plaintext":"01020304","senderPrivateKey":"%s","recipientPublicKey":"%s"}`,
			senderPrivate, recipientPublic,
		),
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	encryptedHex := encryptedResult.(map[string]string)["envelope"]
	encrypted, err := hex.DecodeString(encryptedHex)
	if err != nil {
		t.Fatal(err)
	}

	wrongVersionSigned := append([]byte(nil), signed...)
	wrongVersionSigned[0] ^= 1
	malformedSenderSigned := append([]byte(nil), signed...)
	malformedSenderSigned[4] = 0x04
	malformedRecipientSigned := append([]byte(nil), signed...)
	malformedRecipientSigned[37] = 0x04
	trailingSigned := append(append([]byte(nil), signed...), 0)
	wrongVersionEncrypted := append([]byte(nil), encrypted...)
	wrongVersionEncrypted[0] ^= 1
	malformedSenderEncrypted := append([]byte(nil), encrypted...)
	malformedSenderEncrypted[4] = 0x04
	malformedRecipientEncrypted := append([]byte(nil), encrypted...)
	malformedRecipientEncrypted[37] = 0x04
	tamperedEncrypted := append([]byte(nil), encrypted...)
	tamperedEncrypted[70] ^= 1

	cases := []struct {
		name, operation, arguments, category string
	}{
		{"sign unknown field", "portable.signed.sign", fmt.Sprintf(`{"message":"","senderPrivateKey":"%s","extra":true}`, senderPrivate), "invalidEncoding"},
		{"sign missing message", "portable.signed.sign", fmt.Sprintf(`{"senderPrivateKey":"%s"}`, senderPrivate), "invalidEncoding"},
		{"sign null message", "portable.signed.sign", fmt.Sprintf(`{"message":null,"senderPrivateKey":"%s"}`, senderPrivate), "invalidEncoding"},
		{"sign odd hex", "portable.signed.sign", fmt.Sprintf(`{"message":"0","senderPrivateKey":"%s"}`, senderPrivate), "invalidHex"},
		{"sign uppercase hex", "portable.signed.sign", fmt.Sprintf(`{"message":"AA","senderPrivateKey":"%s"}`, senderPrivate), "invalidHex"},
		{"sign bad hex", "portable.signed.sign", fmt.Sprintf(`{"message":"zz","senderPrivateKey":"%s"}`, senderPrivate), "invalidHex"},
		{"sign short private key", "portable.signed.sign", `{"message":"","senderPrivateKey":"01"}`, "invalidLength"},
		{"sign zero private key", "portable.signed.sign", fmt.Sprintf(`{"message":"","senderPrivateKey":"%s"}`, strings.Repeat("00", 32)), "invalidPrivateKey"},
		{"sign uncompressed recipient", "portable.signed.sign", fmt.Sprintf(`{"message":"","senderPrivateKey":"%s","recipientPublicKey":"04%s"}`, senderPrivate, strings.Repeat("00", 32)), "invalidPublicKey"},
		{"verify wrong version", "portable.signed.verify", fmt.Sprintf(`{"message":"0102","envelope":"%s","recipientPrivateKey":"%s"}`, hex.EncodeToString(wrongVersionSigned), recipientPrivate), "unsupportedVersion"},
		{"verify unknown field", "portable.signed.verify", fmt.Sprintf(`{"message":"0102","envelope":"%s","recipientPrivateKey":"%s","extra":true}`, signedHex, recipientPrivate), "invalidEncoding"},
		{"verify missing envelope", "portable.signed.verify", `{"message":"0102"}`, "invalidEncoding"},
		{"verify malformed sender", "portable.signed.verify", fmt.Sprintf(`{"message":"0102","envelope":"%s","recipientPrivateKey":"%s"}`, hex.EncodeToString(malformedSenderSigned), recipientPrivate), "invalidPublicKey"},
		{"verify malformed recipient", "portable.signed.verify", fmt.Sprintf(`{"message":"0102","envelope":"%s","recipientPrivateKey":"%s"}`, hex.EncodeToString(malformedRecipientSigned), recipientPrivate), "invalidPublicKey"},
		{"verify trailing DER", "portable.signed.verify", fmt.Sprintf(`{"message":"0102","envelope":"%s","recipientPrivateKey":"%s"}`, hex.EncodeToString(trailingSigned), recipientPrivate), "invalidSignature"},
		{"verify wrong recipient", "portable.signed.verify", fmt.Sprintf(`{"message":"0102","envelope":"%s","recipientPrivateKey":"%s"}`, signedHex, wrongRecipientPrivate), "recipientMismatch"},
		{"encrypt unknown field", "portable.encrypted.encrypt", fmt.Sprintf(`{"plaintext":"","senderPrivateKey":"%s","recipientPublicKey":"%s","extra":true}`, senderPrivate, recipientPublic), "invalidEncoding"},
		{"encrypt missing recipient", "portable.encrypted.encrypt", fmt.Sprintf(`{"plaintext":"","senderPrivateKey":"%s"}`, senderPrivate), "invalidEncoding"},
		{"decrypt unknown field", "portable.encrypted.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s","extra":true}`, encryptedHex, recipientPrivate), "invalidEncoding"},
		{"decrypt missing recipient", "portable.encrypted.decrypt", fmt.Sprintf(`{"envelope":"%s"}`, encryptedHex), "invalidEncoding"},
		{"decrypt wrong version", "portable.encrypted.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s"}`, hex.EncodeToString(wrongVersionEncrypted), recipientPrivate), "unsupportedVersion"},
		{"decrypt malformed sender", "portable.encrypted.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s"}`, hex.EncodeToString(malformedSenderEncrypted), recipientPrivate), "invalidPublicKey"},
		{"decrypt malformed recipient", "portable.encrypted.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s"}`, hex.EncodeToString(malformedRecipientEncrypted), recipientPrivate), "invalidPublicKey"},
		{"decrypt wrong recipient", "portable.encrypted.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s"}`, encryptedHex, wrongRecipientPrivate), "recipientMismatch"},
		{"decrypt authentication", "portable.encrypted.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s"}`, hex.EncodeToString(tamperedEncrypted), recipientPrivate), "authenticationFailed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := execute(testRequest(tc.operation, tc.arguments), metadata{})
			if err == nil {
				t.Fatal("expected error")
			}
			normalized := normalizeError(err)
			if normalized.Category != tc.category {
				t.Fatalf("got %s, want %s (%v)", normalized.Category, tc.category, err)
			}
			if normalized.Category == "oraclePanic" {
				t.Fatal("malformed portable request reached panic recovery")
			}
			for _, secret := range []string{senderPrivate, recipientPrivate, signedHex, encryptedHex} {
				if strings.Contains(normalized.Message, secret) {
					t.Fatal("normalized error leaked request material")
				}
			}
		})
	}

	mismatch, err := execute(testRequest(
		"portable.signed.verify",
		fmt.Sprintf(
			`{"message":"ff","envelope":"%s","recipientPrivateKey":"%s"}`,
			signedHex, recipientPrivate,
		),
	), metadata{})
	if err != nil || mismatch.(map[string]bool)["valid"] {
		t.Fatalf("well-formed signature mismatch must be success/false: %#v, %v", mismatch, err)
	}

	for count := 0; count < len(signed); count++ {
		_, err := execute(testRequest(
			"portable.signed.verify",
			fmt.Sprintf(`{"message":"0102","envelope":"%s"}`, hex.EncodeToString(signed[:count])),
		), metadata{})
		if err == nil || normalizeError(err).Category == "oraclePanic" {
			t.Fatalf("signed truncation %d was not safely rejected: %v", count, err)
		}
	}
	for count := 0; count < 150; count++ {
		_, err := execute(testRequest(
			"portable.encrypted.decrypt",
			fmt.Sprintf(
				`{"envelope":"%s","recipientPrivateKey":"%s"}`,
				hex.EncodeToString(encrypted[:min(count, len(encrypted))]), recipientPrivate,
			),
		), metadata{})
		if err == nil || normalizeError(err).Category == "oraclePanic" {
			t.Fatalf("encrypted truncation %d was not safely rejected: %v", count, err)
		}
	}

	oversizedContent := strings.Repeat("00", portableContentMaximumByteCount+1)
	oversizedVerificationField := strings.Repeat("00", portableVerificationFieldMaximumByteCount+1)
	resourceCases := []request{
		testRequest("portable.signed.sign", fmt.Sprintf(`{"message":"%s","senderPrivateKey":"%s"}`, oversizedContent, senderPrivate)),
		testRequest("portable.signed.verify", fmt.Sprintf(`{"message":"%s","envelope":"%s"}`, oversizedVerificationField, signedHex)),
		testRequest("portable.encrypted.encrypt", fmt.Sprintf(`{"plaintext":"%s","senderPrivateKey":"%s","recipientPublicKey":"%s"}`, oversizedContent, senderPrivate, recipientPublic)),
		testRequest("portable.encrypted.decrypt", fmt.Sprintf(`{"envelope":"%s","recipientPrivateKey":"%s"}`, oversizedContent, recipientPrivate)),
	}
	for _, request := range resourceCases {
		_, err := execute(request, metadata{})
		if err == nil || normalizeError(err).Category != "resourceLimit" {
			t.Fatalf("%s oversized input was not resource-limited: %v", request.Op, err)
		}
	}
}

func TestBRC42BilateralDerivation(t *testing.T) {
	senderPrivate := strings.Repeat("00", 31) + "07"
	recipientPrivate := strings.Repeat("00", 31) + "13"
	sender, err := protocolPrivateKey(senderPrivate)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := protocolPrivateKey(recipientPrivate)
	if err != nil {
		t.Fatal(err)
	}

	privateResult, err := execute(testRequest(
		"brc42.private.derive",
		`{"recipientPrivateKey":"`+recipientPrivate+`","senderPublicKey":"`+
			hex.EncodeToString(sender.PubKey().Compressed())+`","invoiceNumber":"independent-1"}`,
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	publicResult, err := execute(testRequest(
		"brc42.public.derive",
		`{"recipientPublicKey":"`+hex.EncodeToString(recipient.PubKey().Compressed())+
			`","senderPrivateKey":"`+senderPrivate+`","invoiceNumber":"independent-1"}`,
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	childPrivate, err := protocolPrivateKey(privateResult.(map[string]string)["privateKey"])
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(childPrivate.PubKey().Compressed())
	want := publicResult.(map[string]string)["publicKey"]
	if got != want {
		t.Fatalf("private/public BRC-42 mismatch: got %s want %s", got, want)
	}
}

func TestBRC94GeneratedProofVerifies(t *testing.T) {
	proverPrivate := strings.Repeat("00", 31) + "0b"
	counterpartyPrivate, err := protocolPrivateKey(strings.Repeat("00", 31) + "11")
	if err != nil {
		t.Fatal(err)
	}
	counterpartyPublic := hex.EncodeToString(counterpartyPrivate.PubKey().Compressed())
	generated, err := execute(testRequest(
		"brc94.generate",
		`{"proverPrivateKey":"`+proverPrivate+`","counterpartyPublicKey":"`+
			counterpartyPublic+`"}`,
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	proof := generated.(map[string]string)
	verified, err := execute(testRequest(
		"brc94.verify",
		`{"proverPublicKey":"`+proof["proverPublicKey"]+`","counterpartyPublicKey":"`+
			counterpartyPublic+`","sharedSecret":"`+proof["sharedSecret"]+
			`","noncePublicKey":"`+proof["noncePublicKey"]+`","nonceSharedSecret":"`+
			proof["nonceSharedSecret"]+`","response":"`+proof["response"]+`"}`,
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.(map[string]bool)["valid"] {
		t.Fatal("generated BRC-94 proof did not verify")
	}
}

func TestSymmetricEnvelopeComposition(t *testing.T) {
	shortKey := "01"
	paddedKey := strings.Repeat("00", 31) + "01"
	nonce := strings.Repeat("a5", 32)
	plaintext := "000102ff"

	encryptedShort, err := execute(testRequest(
		"symmetric.encrypt",
		`{"key":"`+shortKey+`","plaintext":"`+plaintext+`","nonce":"`+nonce+`"}`,
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	encryptedPadded, err := execute(testRequest(
		"symmetric.encrypt",
		`{"key":"`+paddedKey+`","plaintext":"`+plaintext+`","nonce":"`+nonce+`"}`,
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(encryptedShort, encryptedPadded) {
		t.Fatal("left-zero-padded key did not match exact 32-byte key")
	}
	envelope := encryptedShort.(map[string]string)["envelope"]
	if len(envelope) != (32+4+16)*2 || !strings.HasPrefix(envelope, nonce) {
		t.Fatalf("unexpected symmetric envelope: %s", envelope)
	}
	decrypted, err := execute(testRequest(
		"symmetric.decrypt",
		`{"key":"`+shortKey+`","envelope":"`+envelope+`"}`,
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	if got := decrypted.(map[string]string)["plaintext"]; got != plaintext {
		t.Fatalf("got plaintext %s, want %s", got, plaintext)
	}
}

func TestScriptExecuteFoundation(t *testing.T) {
	tests := []struct {
		name string
		args string
		want any
	}{
		{
			"stack equality",
			`{"unlockingScript":"012a","lockingScript":"7687","era":"legacy"}`,
			map[string]any{"stack": []string{"01"}, "valid": true},
		},
		{
			"conditional branch",
			`{"unlockingScript":"","lockingScript":"006300675168","era":"genesis"}`,
			map[string]any{"stack": []string{"01"}, "valid": true},
		},
		{
			"return ignores malformed tail",
			`{"unlockingScript":"516a4c","lockingScript":"51","era":"genesis"}`,
			map[string]any{"stack": []string{"01", "01"}, "valid": true},
		},
		{
			"early return preserves alt stack across scripts",
			`{"unlockingScript":"516b6a","lockingScript":"6c","era":"genesis"}`,
			map[string]any{"stack": []string{"01"}, "valid": true},
		},
		{
			"hidden genesis version conditional is a no-op",
			`{"unlockingScript":"","lockingScript":"0063656851","era":"genesis"}`,
			map[string]any{"stack": []string{"01"}, "valid": true},
		},
		{
			"returned genesis version conditional is a no-op",
			`{"unlockingScript":"51","lockingScript":"51636a6568","era":"genesis"}`,
			map[string]any{"stack": []string{"01"}, "valid": true},
		},
		{
			"chronicle transaction version",
			`{"unlockingScript":"","lockingScript":"6204020000008804020000006551675068","era":"chronicle","transactionVersion":"2"}`,
			map[string]any{"stack": []string{"01"}, "valid": true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := execute(testRequest("script.execute", tc.args), metadata{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}

	_, err := execute(testRequest(
		"script.execute",
		`{"unlockingScript":"","lockingScript":"00","era":"legacy"}`,
	), metadata{})
	if err == nil || normalizeError(err).Category != "evaluatedFalse" {
		t.Fatalf("expected evaluatedFalse, got %v", err)
	}

	for _, opcode := range []string{"ba", "bc", "bd", "fe", "ff"} {
		_, err = execute(testRequest(
			"script.execute",
			`{"unlockingScript":"","lockingScript":"`+opcode+`","era":"chronicle"}`,
		), metadata{})
		if err == nil || normalizeError(err).Category != "reservedOpcode" {
			t.Fatalf("opcode %s: expected reservedOpcode, got %v", opcode, err)
		}
	}
}

func TestBEEFGraphTransformValues(t *testing.T) {
	zeroID := strings.Repeat("00", 32)
	minimal := "0200beef000102" + zeroID
	wantOne := map[string]any{
		"bumps": "0",
		"transactions": []map[string]string{{
			"format":        "0",
			"transactionID": zeroID,
		}},
		"version": "4022206466",
	}

	for _, tc := range []struct {
		name string
		op   string
		args string
		want any
	}{
		{
			name: "merge",
			op:   "transaction.beef.merge",
			args: `{"left":"` + minimal + `","right":"` + minimal + `"}`,
			want: wantOne,
		},
		{
			name: "txidonly",
			op:   "transaction.beef.txidonly",
			args: `{"bytes":"` + minimal + `"}`,
			want: map[string]any{
				"bumps": "0",
				"transactions": []map[string]string{{
					"format":        "2",
					"transactionID": zeroID,
				}},
				"version": "4022206466",
			},
		},
		{
			name: "trim",
			op:   "transaction.beef.trim",
			args: `{"bytes":"` + minimal + `","knownTransactionIDs":["` + zeroID + `"]}`,
			want: map[string]any{
				"bumps":        "0",
				"transactions": []map[string]string{},
				"version":      "4022206466",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
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

func TestTransactionSighashRejectsNoncanonicalFlags(t *testing.T) {
	transactionBytes := `0100000001` + strings.Repeat("00", 32) + `0000000000ffffffff0100000000000000000000000000`
	for _, flag := range []string{"0", "4", "64", "68", "97", "255"} {
		_, err := execute(testRequest("transaction.sighash", `{"bytes":"`+transactionBytes+`","inputIndex":"0","sourceSatoshis":"0","sourceScript":"","signatureHash":"`+flag+`"}`), metadata{})
		if err == nil {
			t.Fatalf("expected flag %s to be rejected", flag)
		}
		if got := normalizeError(err).Category; got != "invalidEncoding" {
			t.Fatalf("flag %s: got %s, want invalidEncoding", flag, got)
		}
	}
}

func TestTransactionFeeUsesActualScriptsAndExplicitEstimates(t *testing.T) {
	emptyInputTransaction := `0100000001` + strings.Repeat("00", 32) + `0000000000ffffffff0000000000`
	for _, tc := range []struct {
		name string
		args string
		want string
	}{
		{
			"projected P2PKH input",
			`{"bytes":"` + emptyInputTransaction + `","satoshisPerKilobyte":"1000","unlockingByteCounts":["106"]}`,
			"157",
		},
		{
			"zero rate",
			`{"bytes":"` + emptyInputTransaction + `","satoshisPerKilobyte":"0","unlockingByteCounts":["106"]}`,
			"0",
		},
		{
			"empty transaction rounds up",
			`{"bytes":"01000000000000000000","satoshisPerKilobyte":"1","unlockingByteCounts":[]}`,
			"1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := execute(testRequest("transaction.fee", tc.args), metadata{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, map[string]string{"fee": tc.want}) {
				t.Fatalf("got %#v, want fee %s", got, tc.want)
			}
		})
	}

	for _, args := range []string{
		`{"bytes":"` + emptyInputTransaction + `","satoshisPerKilobyte":"1000","unlockingByteCounts":[]}`,
		`{"bytes":"` + emptyInputTransaction + `","satoshisPerKilobyte":"1000","unlockingByteCounts":[null]}`,
	} {
		if _, err := execute(testRequest("transaction.fee", args), metadata{}); err == nil {
			t.Fatalf("expected fee operation failure for %s", args)
		}
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
		testRequest("script.asm.decode", `{"text":"OP_DUP OP_HASH160 0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG"}`),
		testRequest("script.asm.encode", `{"bytes":"0051b3ff"}`),
		testRequest("script.asm.names", `{}`),
		testRequest("transaction.decode", `{"bytes":"01000000000000000000"}`),
		testRequest("transaction.fee", `{"bytes":"01000000000000000000","satoshisPerKilobyte":"100","unlockingByteCounts":[]}`),
		testRequest("transaction.p2pkh.sign", `{"bytes":"0100000001`+strings.Repeat("00", 32)+`0000000000ffffffff0100000000000000000000000000","inputIndex":"0","sourceSatoshis":"0","sourceScript":"","signatureHash":"65","privateKey":"`+strings.Repeat("00", 31)+`01"}`),
		testRequest("transaction.sighash", `{"bytes":"0100000001`+strings.Repeat("00", 32)+`0000000000ffffffff0100000000000000000000000000","inputIndex":"0","sourceSatoshis":"0","sourceScript":"","signatureHash":"65"}`),
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

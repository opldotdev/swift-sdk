package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestCompatibilityTailBIP276Operations(t *testing.T) {
	encoded, err := execute(testRequest(
		"script.bip276.encode",
		`{"prefix":"bitcoin-script","version":"1","network":"2","data":"006a"}`,
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	text := encoded.(map[string]string)["text"]
	decoded, err := execute(testRequest(
		"script.bip276.decode",
		`{"text":`+string(mustCompatibilityTailJSON(t, text))+`}`,
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"prefix": "bitcoin-script", "version": "1", "network": "2", "data": "006a",
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("got %#v, want %#v", decoded, want)
	}
}

func TestCompatibilityTailBIP276Preflight(t *testing.T) {
	cases := []string{
		`{"prefix":"bitcoin-script","version":"0","network":"1","data":""}`,
		`{"prefix":"bad:prefix","version":"1","network":"1","data":""}`,
		`{"prefix":"` + strings.Repeat("x", 129) + `","version":"1","network":"1","data":""}`,
	}
	for _, args := range cases {
		if _, err := execute(testRequest("script.bip276.encode", args), metadata{}); err == nil {
			t.Fatalf("expected preflight failure for %s", args)
		}
	}
	if _, err := execute(testRequest("script.bip276.decode", `{"text":"bitcoin-script:01"}`), metadata{}); err == nil {
		t.Fatal("expected malformed decode failure")
	}
}

func TestCompatibilityTailBIP276StableZeroCategories(t *testing.T) {
	for _, tc := range []struct {
		name, operation, args, category string
	}{
		{"encode zero version", "script.bip276.encode", `{"prefix":"x","version":"0","network":"1","data":""}`, "unsupportedVersion"},
		{"encode zero network", "script.bip276.encode", `{"prefix":"x","version":"1","network":"0","data":""}`, "unsupportedNetwork"},
		{"decode zero version", "script.bip276.decode", `{"text":"x:0001ab1056ef"}`, "unsupportedVersion"},
		{"decode zero network", "script.bip276.decode", `{"text":"x:0100d68783ad"}`, "unsupportedNetwork"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := execute(testRequest(tc.operation, tc.args), metadata{})
			if err == nil {
				t.Fatal("expected failure")
			}
			if got := normalizeError(err).Category; got != tc.category {
				t.Fatalf("got category %q, want %q", got, tc.category)
			}
		})
	}
}

func TestCompatibilityTailBIP276DataBoundary(t *testing.T) {
	data := strings.Repeat("a5", compatibilityTailMaximumBIP276DataBytes)
	encoded, err := execute(testRequest(
		"script.bip276.encode",
		`{"prefix":"x","version":"1","network":"2","data":"`+data+`"}`,
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	text := encoded.(map[string]string)["text"]
	decoded, err := execute(testRequest(
		"script.bip276.decode",
		`{"text":`+string(mustCompatibilityTailJSON(t, text))+`}`,
	), metadata{})
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.(map[string]string)["data"]; got != data {
		t.Fatalf("decoded data length %d, want %d", len(got)/2, compatibilityTailMaximumBIP276DataBytes)
	}

	tooLarge := strings.Repeat("a5", compatibilityTailMaximumBIP276DataBytes+1)
	for _, tc := range []struct {
		operation, args string
	}{
		{"script.bip276.encode", `{"prefix":"x","version":"1","network":"2","data":"` + tooLarge + `"}`},
		{"script.bip276.decode", `{"text":"x:0102` + tooLarge + `00000000"}`},
	} {
		_, err := execute(testRequest(tc.operation, tc.args), metadata{})
		if err == nil {
			t.Fatalf("expected %s resource-limit failure", tc.operation)
		}
		if got := normalizeError(err).Category; got != "resourceLimit" {
			t.Fatalf("got category %q, want resourceLimit", got)
		}
	}
}

func TestCompatibilityTailBIP276PreservesPinnedPrefixDomain(t *testing.T) {
	for _, prefix := range []string{"A", "a_b", "a.b"} {
		args := `{"prefix":` + string(mustCompatibilityTailJSON(t, prefix)) + `,"version":"1","network":"1","data":"af"}`
		encoded, err := execute(testRequest("script.bip276.encode", args), metadata{})
		if err != nil {
			t.Fatalf("prefix %q encode: %v", prefix, err)
		}
		text := encoded.(map[string]string)["text"]
		decoded, err := execute(testRequest(
			"script.bip276.decode",
			`{"text":`+string(mustCompatibilityTailJSON(t, text))+`}`,
		), metadata{})
		if err != nil {
			t.Fatalf("prefix %q decode: %v", prefix, err)
		}
		if got := decoded.(map[string]string)["prefix"]; got != prefix {
			t.Fatalf("got prefix %q, want %q", got, prefix)
		}
	}
}

func mustCompatibilityTailJSON(t *testing.T, value string) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

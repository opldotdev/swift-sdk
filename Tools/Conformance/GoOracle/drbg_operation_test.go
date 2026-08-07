package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestDRBGGenerateSequence(t *testing.T) {
	request := testRequest(
		"drbg.generate",
		`{"entropy":"`+strings.Repeat("00", 32)+`","nonce":"0102","actions":[`+
			`{"type":"generate","count":"16"},`+
			`{"type":"generate","count":"0"},`+
			`{"type":"reseed","entropy":"`+strings.Repeat("11", 32)+`"},`+
			`{"type":"generate","count":"16"}]}`,
	)
	first, err := execute(request, metadata{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := execute(request, metadata{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("equal DRBG action sequences were not deterministic")
	}
	result := first.(map[string]any)
	outputs := result["outputs"].([]string)
	if len(outputs) != 3 || len(outputs[0]) != 32 || outputs[1] != "" || len(outputs[2]) != 32 {
		t.Fatalf("unexpected outputs: %#v", outputs)
	}
	if outputs[0] == outputs[2] {
		t.Fatal("reseed did not change generated output")
	}
	if result["reseedCounter"] != "2" {
		t.Fatalf("unexpected final counter: %v", result["reseedCounter"])
	}
}

func TestDRBGGenerateStrictErrors(t *testing.T) {
	entropy := strings.Repeat("00", 32)
	cases := []struct {
		name, arguments, category string
	}{
		{"short initialization", `{"entropy":"00","nonce":"","actions":[]}`, "insufficientEntropy"},
		{"negative count", `{"entropy":"` + entropy + `","nonce":"","actions":[{"type":"generate","count":"-1"}]}`, "invalidRequestedByteCount"},
		{"oversized count", `{"entropy":"` + entropy + `","nonce":"","actions":[{"type":"generate","count":"938"}]}`, "requestTooLarge"},
		{"short reseed", `{"entropy":"` + entropy + `","nonce":"","actions":[{"type":"reseed","entropy":"00"}]}`, "insufficientEntropy"},
		{"unknown nested field", `{"entropy":"` + entropy + `","nonce":"","actions":[{"type":"generate","count":"0","extra":true}]}`, "invalidEncoding"},
		{"wrong action fields", `{"entropy":"` + entropy + `","nonce":"","actions":[{"type":"generate","count":"0","entropy":"` + entropy + `"}]}`, "invalidEncoding"},
		{"null actions", `{"entropy":"` + entropy + `","nonce":"","actions":null}`, "invalidEncoding"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := execute(testRequest("drbg.generate", tc.arguments), metadata{})
			if err == nil {
				t.Fatal("expected error")
			}
			if got := normalizeError(err).Category; got != tc.category {
				t.Fatalf("got %s, want %s (%v)", got, tc.category, err)
			}
		})
	}
}

func TestDRBGGenerateReseedLimit(t *testing.T) {
	zero := "0"
	actions := make([]drbgAction, 10_001)
	for index := range actions {
		actions[index] = drbgAction{Type: "generate", Count: &zero}
	}
	arguments, err := json.Marshal(drbgGenerateArgs{
		Entropy: strings.Repeat("00", 32),
		Nonce:   "",
		Actions: actions,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = execute(request{
		Schema: protocolSchema,
		ID:     "case",
		Op:     "drbg.generate",
		Args:   arguments,
	}, metadata{})
	if err == nil {
		t.Fatal("expected reseed-required error")
	}
	if got := normalizeError(err).Category; got != "reseedRequired" {
		t.Fatalf("got %s, want reseedRequired (%v)", got, err)
	}
}

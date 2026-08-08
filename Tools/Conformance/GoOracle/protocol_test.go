package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestServeOrderedResponsesAndDuplicateID(t *testing.T) {
	input := strings.NewReader("{\"schema\":\"bsv-conformance/1\",\"id\":\"a\",\"op\":\"bytes.reverse\",\"args\":{\"hex\":\"0102\"}}\n" +
		"{\"schema\":\"bsv-conformance/1\",\"id\":\"a\",\"op\":\"bytes.reverse\",\"args\":{\"hex\":\"00\"}}\n")
	var output bytes.Buffer
	if err := serve(input, json.NewEncoder(&output), metadata{}); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(&output)
	var responses []response
	for scanner.Scan() {
		var res response
		if err := json.Unmarshal(scanner.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		responses = append(responses, res)
	}
	if len(responses) != 2 || !responses[0].OK || responses[1].OK || responses[1].Error.Category != "invalidEncoding" {
		t.Fatalf("unexpected responses: %#v", responses)
	}
}

func TestServeRejectsStreamCorruption(t *testing.T) {
	cases := []string{"{}", "{not json}\n", "{\"schema\":\"bsv-conformance/1\",\"id\":\"x\",\"op\":\"metadata\",\"args\":{},\"extra\":1}\n", "\xff\n"}
	for _, input := range cases {
		var output bytes.Buffer
		if err := serve(strings.NewReader(input), json.NewEncoder(&output), metadata{}); err == nil {
			t.Fatalf("expected stream error for %q", input)
		}
	}
}

func TestServeRejectsOverlongInput(t *testing.T) {
	line := strings.Repeat("x", maxLineBytes+1) + "\n"
	if err := serve(strings.NewReader(line), json.NewEncoder(&bytes.Buffer{}), metadata{}); err == nil {
		t.Fatal("expected overlong error")
	}
}

func TestServeDoesNotEchoOversizedRequestID(t *testing.T) {
	requestID := strings.Repeat("x", maxLineBytes-1024)
	requestBytes, err := json.Marshal(request{
		Schema: protocolSchema,
		ID:     requestID,
		Op:     "metadata",
		Args:   json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(requestBytes)+1 > maxLineBytes {
		t.Fatalf("test request unexpectedly exceeds line bound: %d", len(requestBytes)+1)
	}

	var output bytes.Buffer
	if err := serve(
		strings.NewReader(string(requestBytes)+"\n"),
		json.NewEncoder(&output),
		metadata{},
	); err != nil {
		t.Fatal(err)
	}
	if output.Len() >= 1024 {
		t.Fatalf("oversized ID was reflected into response: %d bytes", output.Len())
	}
	var res response
	if err := json.Unmarshal(output.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.OK || res.ID != "" || res.Error == nil || res.Error.Category != "resourceLimit" {
		t.Fatalf("unexpected oversized-ID response: %#v", res)
	}
}

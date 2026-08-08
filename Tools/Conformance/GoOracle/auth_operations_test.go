package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestAuthPayloadRequestEncode(t *testing.T) {
	requestID := strings.Repeat("06", 32)
	result, err := executeAuthOperation("auth.payload.request.encode", json.RawMessage(`{
		"requestID":"`+requestID+`",
		"method":"POST",
		"path":"/v1/items",
		"query":"a=b",
		"body":"",
		"headers":{"content-type":"application/json; charset=utf-8","x-bsv-trace":"one"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	fields, ok := result.(map[string]string)
	if !ok {
		t.Fatalf("unexpected result type %T", result)
	}
	payload, err := hex.DecodeString(fields["bytes"])
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) <= 32 || !bytes.Equal(payload[:32], bytes.Repeat([]byte{6}, 32)) {
		t.Fatal("request payload does not start with the supplied request ID")
	}
	if !strings.HasSuffix(fields["bytes"], "027b7d") {
		t.Fatal("empty JSON request body was not normalized to an empty object")
	}
}

func TestAuthOperationsRejectInvalidArguments(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		arguments string
	}{
		{"missing request field", "auth.payload.request.encode", `{"requestID":"00"}`},
		{"unknown response field", "auth.payload.response.encode", `{"requestID":"` + strings.Repeat("00", 32) + `","status":"200","body":"","headers":{},"extra":0}`},
		{"short request ID", "auth.payload.request.encode", `{"requestID":"00","method":"GET","path":"/","query":"","body":"","headers":{}}`},
		{"uppercase body hex", "auth.payload.response.encode", `{"requestID":"` + strings.Repeat("00", 32) + `","status":"200","body":"AA","headers":{}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := executeAuthOperation(test.operation, json.RawMessage(test.arguments)); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

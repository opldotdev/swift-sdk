package main

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

const transactionJSONTestHex = "0100000001abad53d72f342dd3f338e5e3346b492440f8ea821f8b8800e318f461cc5ea5a20100000000ffffffff02000000000000000008006a0548656c6c6f7f030000000000001976a914b85524abf8202a961b847a3bd0bc89d3d4d41cc588ac00000000"

func TestTransactionJSONOperationsRoundTripPinnedMethods(t *testing.T) {
	marshalResult, err := executeTransactionJSONOperation(
		"transaction.json.marshal",
		json.RawMessage(`{"bytes":"`+transactionJSONTestHex+`"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	documentHex := marshalResult.(map[string]string)["json"]
	document, err := hex.DecodeString(documentHex)
	if err != nil {
		t.Fatal(err)
	}
	expectedPrefix := `{"txid":"c39e5ae1cdcb234302dd3d553b99a2a30d541c94744289e37ef6d316b5c38b7d","hex":"` + transactionJSONTestHex + `","inputs":[{"unlockingScript":"","txid":"a2a55ecc61f418e300888b1f82eaf84024496b34e3e538f3d32d342fd753adab","vout":1,"sequence":4294967295}],"outputs":[{"satoshis":0,"lockingScript":"006a0548656c6c6f"},{"satoshis":895,"lockingScript":"76a914b85524abf8202a961b847a3bd0bc89d3d4d41cc588ac"}],"version":1,"lockTime":0}`
	if string(document) != expectedPrefix {
		t.Fatalf("unexpected pinned JSON: %s", document)
	}

	unmarshalResult, err := executeTransactionJSONOperation(
		"transaction.json.unmarshal",
		json.RawMessage(`{"json":"`+documentHex+`"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := unmarshalResult.(map[string]string)["bytes"]; got != transactionJSONTestHex {
		t.Fatalf("round trip = %s", got)
	}

	emptyResult, err := executeTransactionJSONOperation(
		"transaction.json.marshal",
		json.RawMessage("{\"bytes\":\"01000000000000000000\"}"),
	)
	if err != nil {
		t.Fatal(err)
	}
	emptyDocument, err := hex.DecodeString(emptyResult.(map[string]string)["json"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(emptyDocument), `"inputs":null,"outputs":null`) {
		t.Fatalf("empty pinned JSON = %s", emptyDocument)
	}
}

func TestTransactionJSONComponentOperations(t *testing.T) {
	inputResult, err := executeTransactionJSONOperation(
		"transaction.input.json.marshal",
		json.RawMessage(`{"unlockingScript":"51","txid":"a2a55ecc61f418e300888b1f82eaf84024496b34e3e538f3d32d342fd753adab","vout":"1","sequence":"4294967295"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	inputDocument := inputResult.(map[string]string)["json"]
	inputDecoded, err := executeTransactionJSONOperation(
		"transaction.input.json.unmarshal",
		json.RawMessage(`{"json":"`+inputDocument+`"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	input := inputDecoded.(map[string]string)
	if input["txid"] != "a2a55ecc61f418e300888b1f82eaf84024496b34e3e538f3d32d342fd753adab" ||
		input["vout"] != "1" || input["sequence"] != "4294967295" || input["unlockingScript"] != "51" {
		t.Fatalf("unexpected input result: %#v", input)
	}

	outputResult, err := executeTransactionJSONOperation(
		"transaction.output.json.marshal",
		json.RawMessage(`{"satoshis":"9007199254740991","lockingScript":"51"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	outputDocument := outputResult.(map[string]string)["json"]
	outputDecoded, err := executeTransactionJSONOperation(
		"transaction.output.json.unmarshal",
		json.RawMessage(`{"json":"`+outputDocument+`"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	output := outputDecoded.(map[string]string)
	if output["satoshis"] != "9007199254740991" || output["lockingScript"] != "51" {
		t.Fatalf("unexpected output result: %#v", output)
	}
}

func TestTransactionJSONOperationsExposePinnedLossyArtifacts(t *testing.T) {
	partial := hex.EncodeToString([]byte(`{"version":2,"lockTime":3,"inputs":[{"vout":7}]}`))
	result, err := executeTransactionJSONOperation(
		"transaction.json.unmarshal",
		json.RawMessage(`{"json":"`+partial+`"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := result.(map[string]string)["bytes"]; got != "02000000000003000000" {
		t.Fatalf("pinned partial decode = %s", got)
	}

	inconsistent := `{"hex":"` + transactionJSONTestHex + `","version":9,"lockTime":8,"unknown":true}`
	result, err = executeTransactionJSONOperation(
		"transaction.json.unmarshal",
		json.RawMessage(`{"json":"`+hex.EncodeToString([]byte(inconsistent))+`"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := result.(map[string]string)["bytes"]; got != transactionJSONTestHex {
		t.Fatalf("pinned hex precedence = %s", got)
	}
}

func TestTransactionJSONOperationBounds(t *testing.T) {
	_, err := executeTransactionJSONOperation(
		"transaction.json.marshal",
		json.RawMessage(`{"bytes":"`+strings.Repeat("00", transactionJSONMaximumTransactionBytes+1)+`"}`),
	)
	if category := normalizeError(err).Category; category != "resourceLimit" {
		t.Fatalf("oversized transaction category = %s", category)
	}
	_, err = executeTransactionJSONOperation(
		"transaction.json.unmarshal",
		json.RawMessage(`{"json":"`+strings.Repeat("00", transactionJSONMaximumDocumentBytes+1)+`"}`),
	)
	if category := normalizeError(err).Category; category != "resourceLimit" {
		t.Fatalf("oversized document category = %s", category)
	}
}

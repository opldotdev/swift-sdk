package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
)

// executeAuthOperation deliberately covers only the shared, non-transport BRC-103/104 domain.
func executeAuthOperation(operation string, raw json.RawMessage) (any, error) {
	switch operation {
	case "auth.message.reencode":
		var args struct {
			JSON string `json:"json"`
		}
		if err := decodeArgs(raw, &args); err != nil {
			return nil, err
		}
		data, err := protocolHex(args.JSON)
		if err != nil {
			return nil, err
		}
		var message auth.AuthMessage
		if err := json.Unmarshal(data, &message); err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(&message)
		if err != nil {
			return nil, err
		}
		return map[string]string{"json": hex.EncodeToString(encoded)}, nil
	case "auth.payload.request.encode":
		var args struct {
			RequestID string            `json:"requestID"`
			Method    string            `json:"method"`
			Path      string            `json:"path"`
			Query     string            `json:"query"`
			Body      string            `json:"body"`
			Headers   map[string]string `json:"headers"`
		}
		if err := decodeArgs(raw, &args); err != nil {
			return nil, err
		}
		id, err := protocolHex(args.RequestID)
		if err != nil {
			return nil, err
		}
		body, err := protocolHex(args.Body)
		if err != nil {
			return nil, err
		}
		req := &http.Request{Method: args.Method, URL: &url.URL{Path: args.Path, RawQuery: args.Query}, Header: make(http.Header), Body: http.NoBody}
		for name, value := range args.Headers {
			req.Header.Set(name, value)
		}
		if len(body) > 0 {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
		payload, err := authpayload.FromHTTPRequest(id, req)
		if err != nil {
			return nil, err
		}
		return map[string]string{"bytes": hex.EncodeToString(payload)}, nil
	case "auth.payload.response.encode":
		var args struct {
			RequestID string            `json:"requestID"`
			Status    string            `json:"status"`
			Body      string            `json:"body"`
			Headers   map[string]string `json:"headers"`
		}
		if err := decodeArgs(raw, &args); err != nil {
			return nil, err
		}
		id, err := protocolHex(args.RequestID)
		if err != nil {
			return nil, err
		}
		status, err := decimalUint(args.Status, 16)
		if err != nil {
			return nil, err
		}
		body, err := protocolHex(args.Body)
		if err != nil {
			return nil, err
		}
		headers := make(http.Header)
		for name, value := range args.Headers {
			headers.Set(name, value)
		}
		payload, err := authpayload.FromResponse(id, authpayload.SimplifiedHttpResponse{StatusCode: int(status), Header: headers, Body: body})
		if err != nil {
			return nil, err
		}
		return map[string]string{"bytes": hex.EncodeToString(payload)}, nil
	default:
		return nil, categorizedError{"invalidOperation", "unsupported auth operation"}
	}
}

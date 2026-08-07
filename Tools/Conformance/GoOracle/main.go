package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf8"
)

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "metadata" && os.Args[1] != "serve") {
		fmt.Fprintln(os.Stderr, "usage: go-oracle metadata|serve")
		os.Exit(2)
	}
	meta, err := validatePin()
	if err != nil {
		fmt.Fprintln(os.Stderr, "oracle pin validation failed:", err)
		os.Exit(3)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if os.Args[1] == "metadata" {
		if err := encoder.Encode(meta); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(4)
		}
		return
	}
	if err := serve(os.Stdin, encoder, meta); err != nil {
		fmt.Fprintln(os.Stderr, "oracle stream failed:", err)
		os.Exit(5)
	}
}

func serve(input io.Reader, encoder *json.Encoder, meta metadata) error {
	reader := bufio.NewReaderSize(input, maxLineBytes+1)
	seen := make(map[string]struct{})
	for {
		line, err := reader.ReadSlice('\n')
		if len(line) > maxLineBytes {
			return errors.New("request line exceeds 1 MiB")
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			return errors.New("request line exceeds 1 MiB")
		}
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return nil
		}
		if err != nil {
			return errors.New("request stream ended without newline")
		}
		line = bytes.TrimSuffix(line, []byte{'\n'})
		if len(line) > 0 && line[len(line)-1] == '\r' {
			return errors.New("CRLF is not accepted")
		}
		if !utf8.Valid(line) {
			return errors.New("request is not UTF-8")
		}
		var req request
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			return fmt.Errorf("invalid request JSON: %w", err)
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return errors.New("trailing JSON data")
		}
		var res response
		switch {
		case req.Schema != protocolSchema:
			res = failure(req.ID, "invalidEncoding", "unsupported schema")
		case req.ID == "":
			res = failure(req.ID, "invalidEncoding", "id must be a non-empty string")
		case len(req.ID) > 256:
			res = failure(req.ID, "resourceLimit", "id exceeds 256 bytes")
		case req.Op == "":
			res = failure(req.ID, "invalidEncoding", "op must be a non-empty string")
		default:
			if _, duplicate := seen[req.ID]; duplicate {
				res = failure(req.ID, "invalidEncoding", "duplicate request id")
			} else {
				seen[req.ID] = struct{}{}
				result, err := execute(req, meta)
				if err != nil {
					normalized := normalizeError(err)
					res = response{Schema: protocolSchema, ID: req.ID, OK: false, Error: &normalized}
				} else {
					res = success(req.ID, result)
				}
			}
		}
		encoded, err := json.Marshal(res)
		if err != nil {
			return err
		}
		if len(encoded)+1 > maxLineBytes {
			return errors.New("response line exceeds 1 MiB")
		}
		if err := encoder.Encode(res); err != nil {
			return err
		}
	}
}

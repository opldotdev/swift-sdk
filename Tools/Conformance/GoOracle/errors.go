package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	interpretererrors "github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
)

func normalizeError(err error) oracleError {
	if err == nil {
		return oracleError{Category: "internal", Message: "missing error"}
	}
	var categorized categorizedError
	if errors.As(err, &categorized) {
		return oracleError{Category: categorized.category, Message: categorized.message}
	}
	var scriptError interpretererrors.Error
	if errors.As(err, &scriptError) {
		switch scriptError.ErrorCode {
		case interpretererrors.ErrNumberTooBig, interpretererrors.ErrNumberTooSmall:
			return oracleError{Category: "numberTooLarge", Message: err.Error()}
		case interpretererrors.ErrMinimalData:
			return oracleError{Category: "nonminimal", Message: err.Error()}
		case interpretererrors.ErrDivideByZero:
			return oracleError{Category: "divisionByZero", Message: err.Error()}
		}
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return oracleError{Category: "truncated", Message: err.Error()}
	}
	var corruptInput hex.InvalidByteError
	if errors.As(err, &corruptInput) {
		return oracleError{Category: "invalidCharacter", Message: err.Error()}
	}
	var base64Corrupt base64.CorruptInputError
	if errors.As(err, &base64Corrupt) {
		return oracleError{Category: "invalidEncoding", Message: err.Error()}
	}
	return mapPinnedMessage(err.Error())
}

// mapPinnedMessage is the only fallback string mapping. Its inputs are locked to v1.3.3 by pin validation.
func mapPinnedMessage(message string) oracleError {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "bad character"):
		return oracleError{Category: "invalidCharacter", Message: message}
	case strings.Contains(lower, "checksum"):
		return oracleError{Category: "checksum", Message: message}
	case strings.Contains(lower, "unexpected eof"), strings.Contains(lower, "read past end"):
		return oracleError{Category: "truncated", Message: message}
	case strings.Contains(lower, "too large"), strings.Contains(lower, "resource limit"):
		return oracleError{Category: "resourceLimit", Message: message}
	default:
		return oracleError{Category: "internal", Message: message}
	}
}

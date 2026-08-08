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
		case interpretererrors.ErrEvalFalse:
			return oracleError{Category: "evaluatedFalse", Message: err.Error()}
		case interpretererrors.ErrEmptyStack:
			return oracleError{Category: "emptyStack", Message: err.Error()}
		case interpretererrors.ErrEarlyReturn:
			return oracleError{Category: "earlyReturn", Message: err.Error()}
		case interpretererrors.ErrInvalidStackOperation:
			return oracleError{Category: "invalidStackOperation", Message: err.Error()}
		case interpretererrors.ErrVerify:
			return oracleError{Category: "verifyFailed", Message: err.Error()}
		case interpretererrors.ErrEqualVerify:
			return oracleError{Category: "equalVerifyFailed", Message: err.Error()}
		case interpretererrors.ErrNumEqualVerify:
			return oracleError{Category: "numericEqualVerifyFailed", Message: err.Error()}
		case interpretererrors.ErrCheckSigVerify:
			return oracleError{Category: "checkSignatureVerifyFailed", Message: err.Error()}
		case interpretererrors.ErrCheckMultiSigVerify:
			return oracleError{Category: "checkMultiSignatureVerifyFailed", Message: err.Error()}
		case interpretererrors.ErrUnbalancedConditional:
			return oracleError{Category: "unbalancedConditional", Message: err.Error()}
		case interpretererrors.ErrReservedOpcode:
			return oracleError{Category: "reservedOpcode", Message: err.Error()}
		case interpretererrors.ErrDisabledOpcode:
			return oracleError{Category: "disabledOpcode", Message: err.Error()}
		case interpretererrors.ErrScriptTooBig, interpretererrors.ErrElementTooBig,
			interpretererrors.ErrTooManyOperations, interpretererrors.ErrStackOverflow:
			return oracleError{Category: "consensusLimit", Message: err.Error()}
		case interpretererrors.ErrInvalidPubKeyCount:
			return oracleError{Category: "invalidPublicKeyCount", Message: err.Error()}
		case interpretererrors.ErrInvalidSignatureCount:
			return oracleError{Category: "invalidSignatureCount", Message: err.Error()}
		case interpretererrors.ErrNotPushOnly:
			return oracleError{Category: "notPushOnly", Message: err.Error()}
		case interpretererrors.ErrCleanStack:
			return oracleError{Category: "cleanStack", Message: err.Error()}
		case interpretererrors.ErrNumberTooBig, interpretererrors.ErrNumberTooSmall:
			return oracleError{Category: "numberTooLarge", Message: err.Error()}
		case interpretererrors.ErrMinimalData:
			return oracleError{Category: "nonminimal", Message: err.Error()}
		case interpretererrors.ErrInvalidSigHashType:
			return oracleError{Category: "invalidSignatureHashType", Message: err.Error()}
		case interpretererrors.ErrSigTooShort, interpretererrors.ErrSigTooLong,
			interpretererrors.ErrSigInvalidSeqID, interpretererrors.ErrSigInvalidDataLen,
			interpretererrors.ErrSigMissingSTypeID, interpretererrors.ErrSigMissingSLen,
			interpretererrors.ErrSigInvalidSLen, interpretererrors.ErrSigInvalidRIntID,
			interpretererrors.ErrSigZeroRLen, interpretererrors.ErrSigNegativeR,
			interpretererrors.ErrSigTooMuchRPadding, interpretererrors.ErrSigInvalidSIntID,
			interpretererrors.ErrSigZeroSLen, interpretererrors.ErrSigNegativeS,
			interpretererrors.ErrSigTooMuchSPadding, interpretererrors.ErrSigHighS:
			return oracleError{Category: "invalidSignatureEncoding", Message: err.Error()}
		case interpretererrors.ErrPubKeyType:
			return oracleError{Category: "invalidPublicKeyEncoding", Message: err.Error()}
		case interpretererrors.ErrSigNullDummy:
			return oracleError{Category: "nullDummy", Message: err.Error()}
		case interpretererrors.ErrNullFail:
			return oracleError{Category: "nullFail", Message: err.Error()}
		case interpretererrors.ErrIllegalForkID:
			return oracleError{Category: "illegalForkID", Message: err.Error()}
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

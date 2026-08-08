package main

import "encoding/json"

const (
	protocolSchema = "bsv-conformance/1"
	maxLineBytes   = 1 << 20
)

var operations = []string{
	"base58.decode", "base58.encode", "base58check.decode", "base58check.encode",
	"base64.decode", "base64.encode", "big.umod", "brc42.private.derive", "brc42.public.derive", "brc94.generate", "brc94.verify", "bsm.recover", "bsm.sign", "bytes.reverse", "digest32.display",
	"digest32.parse", "drbg.generate", "ecies.bitcore.decrypt", "ecies.bitcore.encrypt", "ecies.electrum.decrypt", "ecies.electrum.encrypt", "hash.hash160", "hash.ripemd160", "hash.sha256", "hash.sha256d",
	"hash.sha512", "hex.decode", "hex.encode", "hmac.sha256", "hmac.sha512", "keyshares.recover", "keyshares.split", "metadata",
	"script.asm.decode", "script.asm.encode", "script.asm.names", "script.execute", "scriptnum.decode", "scriptnum.encode", "spv.verify", "symmetric.decrypt", "symmetric.encrypt", "transaction.beef.decode", "transaction.beef.merge", "transaction.beef.reencode", "transaction.beef.trim", "transaction.beef.txidonly", "transaction.beef.validate", "transaction.beef.verify", "transaction.decode", "transaction.fee", "transaction.merklepath.combine", "transaction.merklepath.decode", "transaction.merklepath.root", "transaction.p2pkh.sign", "transaction.sighash", "u16.decode", "u16.encode",
	"u32.decode", "u32.encode", "u64.decode", "u64.encode", "varbytes.decode", "varbytes.encode",
	"varint.decode", "varint.encode",
}

type drbgAction struct {
	Type    string  `json:"type"`
	Count   *string `json:"count,omitempty"`
	Entropy *string `json:"entropy,omitempty"`
}

type drbgGenerateArgs struct {
	Entropy string       `json:"entropy"`
	Nonce   string       `json:"nonce"`
	Actions []drbgAction `json:"actions"`
}

type request struct {
	Schema string          `json:"schema"`
	ID     string          `json:"id"`
	Op     string          `json:"op"`
	Args   json.RawMessage `json:"args"`
}

type oracleError struct {
	Category string `json:"category"`
	Message  string `json:"message"`
}

type response struct {
	Schema string       `json:"schema"`
	ID     string       `json:"id"`
	OK     bool         `json:"ok"`
	Result any          `json:"result,omitempty"`
	Error  *oracleError `json:"error,omitempty"`
}

type metadata struct {
	Schema           string            `json:"schema"`
	Module           string            `json:"module"`
	Tag              string            `json:"tag"`
	Commit           string            `json:"commit"`
	SourceMode       string            `json:"sourceMode"`
	SourceTreeSHA256 string            `json:"sourceTreeSHA256"`
	Dirty            bool              `json:"dirty"`
	GoVersion        string            `json:"goVersion"`
	DependencySHA256 string            `json:"dependencyGraphSHA256"`
	Hashes           map[string]string `json:"hashes"`
	Operations       []string          `json:"operations"`
}

type lockFile struct {
	Schema                   string `json:"schema"`
	Repository               string `json:"repository"`
	Module                   string `json:"module"`
	Tag                      string `json:"tag"`
	Commit                   string `json:"commit"`
	GoVersion                string `json:"goVersion"`
	DependencyGraphAlgorithm string `json:"dependencyGraphAlgorithm"`
	DependencyGraphSHA256    string `json:"dependencyGraphSHA256"`
	TreeAlgorithm            string `json:"treeAlgorithm"`
	ArchiveTreeSHA256        string `json:"archiveTreeSHA256"`
	GitTreeSHA256            string `json:"gitTreeSHA256"`
	Hashes                   struct {
		License string `json:"license"`
		GoMod   string `json:"goMod"`
		GoSum   string `json:"goSum"`
	} `json:"hashes"`
}

type categorizedError struct {
	category string
	message  string
}

func (e categorizedError) Error() string { return e.message }

func failure(id, category, message string) response {
	return response{Schema: protocolSchema, ID: id, OK: false, Error: &oracleError{Category: category, Message: message}}
}

func success(id string, result any) response {
	return response{Schema: protocolSchema, ID: id, OK: true, Result: result}
}

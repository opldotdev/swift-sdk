package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	dependencyAlgorithm = "sha256(go.mod || NUL || go.sum)"
	treeAlgorithm       = "sha256(sorted(sha256(content) SP SP slash-relative-path LF)); excludes .git; rejects symlinks/non-regular entries"
)

func validatePin() (metadata, error) {
	lockPath := os.Getenv("BSV_ORACLE_LOCK_PATH")
	sourcePath := os.Getenv("BSV_GO_SDK_PATH")
	repositoryPath := os.Getenv("BSV_SWIFT_REPOSITORY_PATH")
	if lockPath == "" || sourcePath == "" || repositoryPath == "" {
		return metadata{}, errors.New("BSV_ORACLE_LOCK_PATH, BSV_GO_SDK_PATH, and BSV_SWIFT_REPOSITORY_PATH are required")
	}

	lockBytes, err := os.ReadFile(lockPath)
	if err != nil {
		return metadata{}, fmt.Errorf("read lock: %w", err)
	}
	var lock lockFile
	decoder := json.NewDecoder(bytes.NewReader(lockBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&lock); err != nil {
		return metadata{}, fmt.Errorf("decode lock: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return metadata{}, errors.New("lock contains trailing JSON data")
	}
	if lock.Schema != protocolSchema || lock.Repository != "https://github.com/bsv-blockchain/go-sdk" ||
		lock.Module != "github.com/bsv-blockchain/go-sdk" ||
		lock.Tag != "v1.3.3" || lock.Commit != "de26fdec57a945ddc06de5d5617f6c32374f3929" {
		return metadata{}, errors.New("lock identity does not match the compiled oracle baseline")
	}
	if lock.GoVersion != "go1.25.0" || runtime.Version() != lock.GoVersion {
		return metadata{}, fmt.Errorf("Go toolchain mismatch: got %s, require %s", runtime.Version(), lock.GoVersion)
	}
	if lock.DependencyGraphAlgorithm != dependencyAlgorithm || lock.TreeAlgorithm != treeAlgorithm {
		return metadata{}, errors.New("unsupported lock hashing algorithm")
	}

	sourceReal, err := filepath.EvalSymlinks(sourcePath)
	if err != nil {
		return metadata{}, fmt.Errorf("resolve source: %w", err)
	}
	sourceReal, err = filepath.Abs(sourceReal)
	if err != nil {
		return metadata{}, fmt.Errorf("absolute source: %w", err)
	}
	repositoryReal, err := filepath.EvalSymlinks(repositoryPath)
	if err != nil {
		return metadata{}, fmt.Errorf("resolve Swift repository: %w", err)
	}
	repositoryReal, err = filepath.Abs(repositoryReal)
	if err != nil {
		return metadata{}, fmt.Errorf("absolute Swift repository: %w", err)
	}
	if pathContains(repositoryReal, sourceReal) {
		return metadata{}, errors.New("Go SDK source must be outside the Swift repository")
	}

	licenseHash, err := hashFile(filepath.Join(sourceReal, "LICENSE"))
	if err != nil {
		return metadata{}, err
	}
	goModHash, err := hashFile(filepath.Join(sourceReal, "go.mod"))
	if err != nil {
		return metadata{}, err
	}
	goSumHash, err := hashFile(filepath.Join(sourceReal, "go.sum"))
	if err != nil {
		return metadata{}, err
	}
	if licenseHash != lock.Hashes.License || goModHash != lock.Hashes.GoMod || goSumHash != lock.Hashes.GoSum {
		return metadata{}, errors.New("pinned file hash mismatch")
	}
	module, err := moduleName(filepath.Join(sourceReal, "go.mod"))
	if err != nil || module != lock.Module {
		return metadata{}, fmt.Errorf("module mismatch: got %q, require %q", module, lock.Module)
	}
	dependencyHash, err := dependencyHash(sourceReal)
	if err != nil {
		return metadata{}, err
	}
	if dependencyHash != lock.DependencyGraphSHA256 {
		return metadata{}, errors.New("dependency graph hash mismatch")
	}

	mode := "archive"
	dirty := false
	var treeHash string
	if _, err := os.Stat(filepath.Join(sourceReal, ".git")); err == nil {
		mode = "git"
		treeHash, dirty, err = validateGit(sourceReal, lock)
		if err != nil {
			return metadata{}, err
		}
	} else {
		if lock.ArchiveTreeSHA256 == "" {
			return metadata{}, errors.New("archive mode requires a trusted complete-tree hash")
		}
		treeHash, err = completeTreeHash(sourceReal)
		if err != nil {
			return metadata{}, err
		}
		if treeHash != lock.ArchiveTreeSHA256 {
			return metadata{}, fmt.Errorf("archive complete-tree hash mismatch: got %s, require %s", treeHash, lock.ArchiveTreeSHA256)
		}
	}

	return metadata{
		Schema: protocolSchema, Module: lock.Module, Tag: lock.Tag, Commit: lock.Commit,
		SourceMode: mode, SourceTreeSHA256: treeHash, Dirty: dirty, GoVersion: runtime.Version(),
		DependencySHA256: dependencyHash,
		Hashes:           map[string]string{"license": licenseHash, "goMod": goModHash, "goSum": goSumHash},
		Operations:       append([]string(nil), operations...),
	}, nil
}

func pathContains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func moduleName(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) == 2 && fields[0] == "module" {
			return fields[1], nil
		}
	}
	return "", errors.New("go.mod has no module directive")
}

func dependencyHash(root string) (string, error) {
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	sum, err := os.ReadFile(filepath.Join(root, "go.sum"))
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(mod)
	h.Write([]byte{0})
	h.Write(sum)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func completeTreeHash(root string) (string, error) {
	type entry struct{ path, hash string }
	var entries []entry
	err := filepath.WalkDir(root, func(path string, item os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == ".git" {
			if item.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if item.IsDir() {
			return nil
		}
		if item.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("complete tree contains forbidden symlink %s", filepath.ToSlash(rel))
		}
		if !item.Type().IsRegular() {
			return fmt.Errorf("unsupported tree entry %s", rel)
		}
		hash, err := hashFile(path)
		if err != nil {
			return err
		}
		entries = append(entries, entry{filepath.ToSlash(rel), hash})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	h := sha256.New()
	for _, item := range entries {
		fmt.Fprintf(h, "%s  %s\n", item.hash, item.path)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func validateGit(root string, lock lockFile) (string, bool, error) {
	run := func(args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		out, err := cmd.Output()
		return strings.TrimSpace(string(out)), err
	}
	head, err := run("rev-parse", "HEAD")
	if err != nil || head != lock.Commit {
		return "", false, errors.New("git HEAD does not match pinned commit")
	}
	tagCommit, err := run("rev-list", "-n", "1", lock.Tag)
	if err != nil || tagCommit != lock.Commit {
		return "", false, errors.New("git tag does not resolve to pinned commit")
	}
	status, err := run("status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return "", false, errors.New("cannot inspect git status")
	}
	if status != "" {
		return "", true, errors.New("git checkout is dirty")
	}
	tree, err := completeTreeHash(root)
	if err != nil {
		return "", false, errors.New("cannot hash git tree")
	}
	if err := requireTrustedTree(tree, lock.GitTreeSHA256, "git"); err != nil {
		return "", false, err
	}
	return tree, false, nil
}

func requireTrustedTree(actual, trusted, mode string) error {
	if trusted == "" {
		return fmt.Errorf("%s mode requires a trusted complete-tree hash", mode)
	}
	if actual != trusted {
		return fmt.Errorf("%s complete-tree hash mismatch: got %s, require %s", mode, actual, trusted)
	}
	return nil
}

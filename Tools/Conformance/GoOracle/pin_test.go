package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDependencyAndTreeHashAlgorithms(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.sum"), []byte("sum\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := dependencyHash(root)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write([]byte("module example.test\n"))
	h.Write([]byte{0})
	h.Write([]byte("sum\n"))
	if want := hex.EncodeToString(h.Sum(nil)); got != want {
		t.Fatalf("dependency hash got %s want %s", got, want)
	}
	first, err := completeTreeHash(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.sum"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := completeTreeHash(root)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("tree hash did not cover file content")
	}
}

func TestPathContainsUsesPathComponents(t *testing.T) {
	if !pathContains("/repo", "/repo/child") {
		t.Fatal("child not detected")
	}
	if pathContains("/repo", "/repository") {
		t.Fatal("prefix-only path incorrectly detected")
	}
}

func TestCompleteTreeHashRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := completeTreeHash(root); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestTrustedGitTreeComparisonRejectsDifferentCleanTree(t *testing.T) {
	const pinned = "2d2b2012877f208b46a295dbc1cada9fabcb8416a85bcf35ad3c55afeb3ce367"
	if err := requireTrustedTree(pinned, pinned, "git"); err != nil {
		t.Fatalf("matching tree rejected: %v", err)
	}
	if err := requireTrustedTree(strings.Repeat("0", 64), pinned, "git"); err == nil {
		t.Fatal("different clean-looking tree accepted")
	}
	if err := requireTrustedTree(pinned, "", "git"); err == nil {
		t.Fatal("missing trusted git tree accepted")
	}
}

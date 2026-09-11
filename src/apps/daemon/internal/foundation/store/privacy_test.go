package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenDBEnforcesPrivateFilesystemPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not an authoritative Windows ACL assertion")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "luminet")
	path := filepath.Join(dir, "state.db")

	db, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("directory mode=%#o want 0700", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("database mode=%#o want 0600", got)
	}
}

func TestNodeStoreEnforcesPrivateFilesystemPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not an authoritative Windows ACL assertion")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "nodes")
	path := filepath.Join(dir, "nodes.db")

	store, err := NewNodeStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("directory mode=%#o want 0700", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("database mode=%#o want 0600", got)
	}
}

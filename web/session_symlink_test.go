package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Tightening the mode of the secret file must not follow a symlink: a link at
// that path would otherwise get the mode of its target changed.
func TestBrowserSessionsDoNotChmodThroughSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks and POSIX modes")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "web-session.key")
	newBrowserSessions(dir, "tok") // writes a valid secret
	target := filepath.Join(dir, "elsewhere.key")
	if err := os.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	a := newBrowserSessions(dir, "tok")
	b := newBrowserSessions(dir, "tok")
	if id := a.newID(); a.key(id) != b.key(id) {
		t.Error("the secret behind the symlink was not used consistently")
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("symlink target mode = %v, want it left at 0644", fi.Mode().Perm())
	}
}

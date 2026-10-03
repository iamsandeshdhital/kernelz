package image

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type member struct {
	name   string
	body   string
	mode   int64
	typ    byte
	link   string
	isDir  bool
	isLink bool
}

func tarOf(ms ...member) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range ms {
		typ := m.typ
		if typ == 0 {
			switch {
			case m.isDir:
				typ = tar.TypeDir
			case m.isLink:
				typ = tar.TypeSymlink
			default:
				typ = tar.TypeReg
			}
		}
		mode := m.mode
		if mode == 0 {
			if typ == tar.TypeDir {
				mode = 0o755
			} else {
				mode = 0o644
			}
		}
		hdr := &tar.Header{
			Name:     m.name,
			Mode:     mode,
			Size:     int64(len(m.body)),
			Typeflag: typ,
			Linkname: m.link,
		}
		if typ == tar.TypeDir || typ == tar.TypeSymlink {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			panic(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(m.body)); err != nil {
				panic(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func apply(t *testing.T, ms ...member) string {
	t.Helper()
	dest := t.TempDir()
	if err := ApplyLayer(dest, bytes.NewReader(tarOf(ms...)), 0); err != nil {
		t.Fatalf("ApplyLayer: %v", err)
	}
	return dest
}

func TestApplyRegularFiles(t *testing.T) {
	dest := apply(t,
		member{name: "etc/", isDir: true},
		member{name: "etc/hostname", body: "web\n"},
	)
	got, err := os.ReadFile(filepath.Join(dest, "etc/hostname"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "web\n" {
		t.Errorf("content = %q", got)
	}
}

func TestApplyCreatesMissingParents(t *testing.T) {
	// A layer that adds a deep file without listing any of its parent
	// directories is legal and common.
	dest := apply(t, member{name: "a/b/c/deep.txt", body: "x"})
	if _, err := os.Stat(filepath.Join(dest, "a/b/c/deep.txt")); err != nil {
		t.Errorf("deep file not created: %v", err)
	}
}

func TestWhiteoutHidesLowerLayerFile(t *testing.T) {
	dest := apply(t,
		member{name: "etc/passwd", body: "root:x:0:0"},
		member{name: "etc/.wh.passwd"}, // whiteout for etc/passwd
	)
	if _, err := os.Lstat(filepath.Join(dest, "etc/passwd")); !os.IsNotExist(err) {
		t.Errorf("whiteout failed, passwd still present (err=%v)", err)
	}
	// The marker itself must never survive into the final filesystem.
	if _, err := os.Lstat(filepath.Join(dest, "etc/.wh.passwd")); !os.IsNotExist(err) {
		t.Error("whiteout marker leaked into the rootfs")
	}
}

func TestOpaqueWhiteoutClearsDirectory(t *testing.T) {
	// This is the case that is easy to get wrong. An opaque marker means the
	// directory's *entire* lower-layer contents must disappear.
	dest := apply(t,
		member{name: "opt/", isDir: true},
		member{name: "opt/secret.key", body: "lower"},
		member{name: "opt/keep", body: "lower"},
		member{name: "opt/.wh..wh..opq"},
		member{name: "opt/new.txt", body: "upper"},
	)
	for _, gone := range []string{"opt/secret.key", "opt/keep"} {
		if _, err := os.Lstat(filepath.Join(dest, filepath.FromSlash(gone))); !os.IsNotExist(err) {
			t.Errorf("opaque whiteout did not remove %s", gone)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, "opt/new.txt")); err != nil {
		t.Errorf("upper-layer file lost: %v", err)
	}
}

func TestAUFSOpaqueMarkerAlsoHonoured(t *testing.T) {
	dest := apply(t,
		member{name: "opt/", isDir: true},
		member{name: "opt/old", body: "x"},
		member{name: "opt/.wh..wh.aufs"},
	)
	if _, err := os.Lstat(filepath.Join(dest, "opt/old")); !os.IsNotExist(err) {
		t.Error(".wh..wh.aufs opaque marker not honoured")
	}
}

func TestWhiteoutIsIdempotent(t *testing.T) {
	// Whiteouts routinely reference paths that no lower layer ever created, and
	// images in the wild depend on that being harmless rather than fatal.
	dest := t.TempDir()
	if err := ApplyLayer(dest, bytes.NewReader(tarOf(
		member{name: "etc/.wh.neverexisted"},
		member{name: "nowhere/.wh.alsomissing"},
	)), 0); err != nil {
		t.Errorf("absent whiteouts must be no-ops, got: %v", err)
	}
}

func TestWhiteoutTargetingDirectoryRejected(t *testing.T) {
	// A .wh.<name> where <name> is a directory in a lower layer is a malformed
	// image: directories are removed with .wh..wh..opq, not with a plain
	// whiteout. Silently ignoring it would hide a real inconsistency.
	dest := apply(t,
		member{name: "etc/", isDir: true},
		member{name: "etc/conf/", isDir: true},
		member{name: "etc/conf/f", body: "x"},
	)
	err := ApplyLayer(dest, bytes.NewReader(tarOf(member{name: "etc/.wh.conf"})), 0)
	if err == nil {
		t.Error("expected an error for a whiteout targeting a directory")
	} else if !strings.Contains(err.Error(), "opq") {
		t.Errorf("error should point at the correct marker, got: %v", err)
	}
}

func TestPathTraversalRejected(t *testing.T) {
	// The core image-level escape: a tar entry that walks out of the rootfs.
	for _, bad := range []string{
		"../escape",
		"a/../../escape",
		"./../../etc/shadow",
		"..",
	} {
		err := ApplyLayer(t.TempDir(), bytes.NewReader(tarOf(member{name: bad, body: "pwn"})), 0)
		if err == nil {
			t.Errorf("path traversal %q was accepted", bad)
			continue
		}
		if !strings.Contains(err.Error(), "escapes") && !strings.Contains(err.Error(), "resolves") {
			t.Errorf("traversal %q rejected with unexpected message: %v", bad, err)
		}
	}
}

func TestAbsolutePathRejected(t *testing.T) {
	// filepath.Clean strips a leading slash, so this needs an explicit check --
	// without it "/etc/shadow" would land on the host root.
	err := ApplyLayer(t.TempDir(), bytes.NewReader(tarOf(member{name: "/etc/shadow", body: "pwn"})), 0)
	if err == nil {
		t.Fatal("absolute path in a layer was accepted")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBackslashTraversalRejected(t *testing.T) {
	// Windows-style separators must not sneak past the traversal check.
	err := ApplyLayer(t.TempDir(), bytes.NewReader(tarOf(member{name: `..\..\escape`, body: "pwn"})), 0)
	if err == nil {
		t.Error("backslash traversal was accepted")
	}
}

func TestTraversalNeverWritesOutsideRoot(t *testing.T) {
	// Defence in depth: confirm no file appears next to the rootfs.
	base := t.TempDir()
	root := filepath.Join(base, "rootfs")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	err := ApplyLayer(root, bytes.NewReader(tarOf(member{name: "../canary", body: "pwn"})), 0)
	if err == nil {
		t.Fatal("expected rejection")
	}
	if _, err := os.Lstat(filepath.Join(base, "canary")); !os.IsNotExist(err) {
		t.Error("traversal wrote outside the rootfs")
	}
}

func TestSetuidBitsStripped(t *testing.T) {
	// A setuid-root binary from an image is a standing escalation primitive.
	dest := apply(t, member{name: "bin/evil", body: "#!/bin/sh", mode: 0o4755})
	fi, err := os.Stat(filepath.Join(dest, "bin/evil"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&0o4000 != 0 {
		t.Errorf("setuid bit survived layer extraction: %v", fi.Mode())
	}
}

func TestSymlinkCannotRedirectLaterWrite(t *testing.T) {
	requireSymlinkSupport(t)
	// Layer 1 plants a symlink; layer 2 writes through it. If the write
	// followed the link, layer 2 would clobber a file outside the rootfs.
	base := t.TempDir()
	root := filepath.Join(base, "rootfs")
	outside := filepath.Join(base, "hostfile")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("important"), 0o644); err != nil {
		t.Fatal(err)
	}
	l1 := tarOf(member{name: "link", isLink: true, link: "../hostfile"})
	if err := ApplyLayer(root, bytes.NewReader(l1), 0); err != nil {
		t.Fatal(err)
	}
	l2 := tarOf(member{name: "link", body: "overwritten"})
	if err := ApplyLayer(root, bytes.NewReader(l2), 0); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "important" {
		t.Errorf("symlink redirection overwrote a file outside the rootfs: %q", b)
	}
}

func TestSymlinkRelativeTargetResolvesAgainstItsOwnDir(t *testing.T) {
	requireSymlinkSupport(t)
	dest := apply(t, member{name: "bin/tool", isLink: true, link: "../lib/tool"})
	raw, err := os.Readlink(filepath.Join(dest, "bin/tool"))
	if err != nil {
		t.Fatal(err)
	}
	if raw != filepath.FromSlash("../lib/tool") {
		t.Errorf("symlink target = %q, want ../lib/tool", raw)
	}
}

func TestSizeLimitEnforced(t *testing.T) {
	big := strings.Repeat("a", 4096)
	err := ApplyLayer(t.TempDir(), bytes.NewReader(tarOf(
		member{name: "a", body: big},
		member{name: "b", body: big},
	)), 5000)
	if err == nil {
		t.Error("size limit not enforced")
	}
}

func TestDecodeClassifiesWithoutWriting(t *testing.T) {
	entries, err := DecodeLayer(bytes.NewReader(tarOf(
		member{name: "etc/", isDir: true},
		member{name: "etc/f", body: "x"},
		member{name: "etc/.wh.g"},
		member{name: "opt/.wh..wh..opq"},
		member{name: "l", isLink: true, link: "t"},
	)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("got %d entries, want 5", len(entries))
	}
	if !entries[0].IsDir {
		t.Error("entry 0 should be a directory")
	}
	if !entries[2].IsWhiteout || entries[2].Name != "etc/g" {
		t.Errorf("whiteout misparsed: name=%q whiteout=%v", entries[2].Name, entries[2].IsWhiteout)
	}
	if !entries[3].Opaque || entries[3].Name != "opt" {
		t.Errorf("opaque marker misparsed: name=%q opaque=%v", entries[3].Name, entries[3].Opaque)
	}
	if !entries[4].IsLink || entries[4].Target != "t" {
		t.Errorf("symlink misparsed: %+v", entries[4])
	}
}

func TestLayeredStackProducesFinalState(t *testing.T) {
	// End-to-end shape of a real image: base layer, then a diff layer.
	root := t.TempDir()

	base := tarOf(
		member{name: "bin/", isDir: true},
		member{name: "bin/sh", body: "old-shell"},
		member{name: "bin/obsolete", body: "gone"},
		member{name: "etc/", isDir: true},
		member{name: "etc/config", body: "v1"},
	)
	if err := ApplyLayer(root, bytes.NewReader(base), 0); err != nil {
		t.Fatal(err)
	}

	diff := tarOf(
		member{name: "bin/sh", body: "new-shell"}, // overwrite
		member{name: "bin/.wh.obsolete"},          // delete
		member{name: "etc/config", body: "v2"},    // overwrite
		member{name: "etc/extra", body: "added"},
	)
	if err := ApplyLayer(root, bytes.NewReader(diff), 0); err != nil {
		t.Fatal(err)
	}

	checks := map[string]string{
		"bin/sh":     "new-shell",
		"etc/config": "v2",
		"etc/extra":  "added",
	}
	for p, want := range checks {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if string(b) != want {
			t.Errorf("%s = %q, want %q", p, b, want)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "bin/obsolete")); !os.IsNotExist(err) {
		t.Error("whiteout did not delete bin/obsolete from the lower layer")
	}
}

func TestCorruptTarRejected(t *testing.T) {
	garbage := []byte("this is definitely not a tar archive")
	err := ApplyLayer(t.TempDir(), bytes.NewReader(garbage), 0)
	if err == nil {
		t.Error("corrupt layer accepted")
	}
}

func TestNULByteInPathRejected(t *testing.T) {
	// Go's tar.Writer refuses to encode a NUL in a path, so this input cannot be
	// produced by the stdlib encoder. That makes it untestable through a real
	// tar stream, but sanitizePath still has to reject it: a different tar
	// implementation on the read path could emit one.
	got, err := sanitizePath("bad\x00name")
	if err == nil {
		t.Errorf("NUL byte accepted, got %q", got)
	}
}

func TestSanitizePathUnit(t *testing.T) {
	ok := map[string]string{
		"etc/passwd":   "etc/passwd",
		"./etc/passwd": "etc/passwd",
		"a//b///c":     "a/b/c",
		"a/./b":        "a/b",
		"a/b/../c":     "a/c",
		`a\b`:          "a/b",
		"..hidden":     "..hidden", // a legitimate dotfile, not traversal
		"a/.hidden":    "a/.hidden",
		"./.wh.foo":    ".wh.foo",
	}
	for in, want := range ok {
		got, err := sanitizePath(in)
		if err != nil {
			t.Errorf("sanitizePath(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("sanitizePath(%q) = %q, want %q", in, got, want)
		}
	}

	bad := []string{"", "/abs", "..", "../x", "a/../../x", ".", "/", "./..", "a\x00b", "a\x01b"}
	for _, in := range bad {
		if got, err := sanitizePath(in); err == nil {
			t.Errorf("sanitizePath(%q) accepted, got %q", in, got)
		}
	}
}

// requireSymlinkSupport skips tests that create symlinks.
//
// Windows requires the SeCreateSymbolicLinkPrivilege privilege to create one,
// which an unprivileged process does not hold. These tests are meaningful on
// Linux -- which is the only platform this runtime actually runs on -- so they
// are skipped rather than weakened here.
func requireSymlinkSupport(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks on Windows requires SeCreateSymbolicLinkPrivilege")
	}
}

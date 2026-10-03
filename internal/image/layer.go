// Package image handles pulling apart a layered container image and materialising
// it as a flat directory.
//
// OCI images are a stack of tar archives. Each layer is a *diff* against the
// layer below it, and "deleting" a file is expressed through the OverlayFS
// whiteout convention rather than by actually removing anything:
//
//	.wh..wh..opq   opaque  -- this directory hides all sibling entries from lower layers
//	.wh.<name>     whiteout -- <name> from lower layers must appear deleted
//
// Getting whiteouts wrong is the classic way a hand-rolled image store produces
// a filesystem that looks right and behaves like a security hole: a stale
// /etc/shadow or an old setuid binary from a lower layer simply stays reachable.
package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Whiteout markers defined by the OverlayFS specification and used by Docker's
// AUFS back-compatibility shims.
const (
	// WhiteoutPrefix marks a single hidden entry: .wh.foo hides ./foo.
	WhiteoutPrefix = ".wh."
	// WhiteoutMeta is the per-directory "this whole directory is replaced"
	// marker: .wh..wh..opq.
	WhiteoutMeta = WhiteoutPrefix + ".wh..opq"
	// WhiteoutOpaqueDir is the same thing under AUFS's older name.
	WhiteoutOpaqueDir = WhiteoutPrefix + ".wh.aufs"
)

// ErrUnsupportedArchive reports a layer that is not a POSIX tar stream.
var ErrUnsupportedArchive = errors.New("not a tar archive")

// Entry is one member of a layer, decoded but not yet applied.
//
// Entries carry metadata only. File bodies are *not* buffered: a layer is
// applied by streaming (see ApplyLayer), because a 2 GiB single-file layer would
// otherwise be read entirely into memory before being written to disk.
type Entry struct {
	// Name is the cleaned, absolute, slash-separated path.
	Name string
	// Header is the original tar header, retained for mode/uid/gid/mtime.
	Header *tar.Header
	// IsDir, IsLink and IsWhiteout are mutually exclusive classifications.
	IsDir      bool
	IsLink     bool
	IsWhiteout bool
	// Opaque marks a .wh..wh..opq entry, which means "forget the directory
	// contents from all lower layers", not just "hide one name".
	Opaque bool
	// Target is the destination for a hardlink/symlink.
	Target string
}

// classify converts a raw tar header into a classified Entry. It is shared by
// the streaming and metadata-only paths so the two can never disagree about
// what a layer contains.
func classify(hdr *tar.Header) (Entry, error) {
	name, err := sanitizePath(hdr.Name)
	if err != nil {
		return Entry{}, fmt.Errorf("layer entry %q: %w", hdr.Name, err)
	}

	e := Entry{Name: name, Header: hdr}
	// Container paths are *always* slash-separated, even when the runtime
	// itself is built for Windows. Using the `path` package rather than
	// `filepath` keeps these names OS-independent -- with filepath, a whiteout
	// for etc/group would be classified as "etc\group" on Windows and fail to
	// match the "etc/group" written by an earlier layer.
	base := path.Base(name)
	dir := path.Dir(name)

	switch {
	case base == WhiteoutMeta || base == WhiteoutOpaqueDir:
		e.IsWhiteout = true
		e.Opaque = true
		e.Name = dir // applies to the containing directory

	case strings.HasPrefix(base, WhiteoutPrefix):
		e.IsWhiteout = true
		e.Name = path.Join(dir, strings.TrimPrefix(base, WhiteoutPrefix))

	default:
		switch hdr.Typeflag {
		case tar.TypeDir:
			e.IsDir = true
		case tar.TypeSymlink, tar.TypeLink:
			e.IsLink = true
			e.Target = sanitizeLinkTarget(name, hdr.Linkname)
		}
	}
	return e, nil
}

// DecodeLayer reads a tar stream and returns metadata for every entry,
// discarding file contents.
//
// This exists for inspection and testing. To actually build a filesystem use
// ApplyLayer, which streams instead of buffering.
func DecodeLayer(r io.Reader, sizeLimit int64) ([]Entry, error) {
	tr := tar.NewReader(r)
	var out []Entry
	var total int64

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read layer tar: %w", err)
		}

		e, err := classify(hdr)
		if err != nil {
			return nil, err
		}
		if hdr.Size > 0 {
			total += hdr.Size
			if sizeLimit > 0 && total > sizeLimit {
				return nil, fmt.Errorf("layer exceeds size limit of %d bytes", sizeLimit)
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// sanitizePath cleans a tar member name and refuses anything that escapes the
// destination root.
//
// Two distinct attacks are covered here:
//
//	absolute paths       "/etc/shadow"  -> resolved against the host root
//	relative traversal   "../../shadow" -> resolved above the destination
//
// A tar stream is just bytes; there is nothing stopping either. Normalising
// afterwards is too late, so it happens before the name is ever used.
//
// Uses `path`, not `filepath`: these are container paths and must be normalised
// identically no matter which OS the runtime was built for.
func sanitizePath(name string) (string, error) {
	if name == "" {
		return "", errors.New("empty path")
	}
	// Reject NUL and other control characters outright; tar implementations
	// have historically disagreed about how to treat them.
	for _, r := range name {
		if r == 0 {
			return "", errors.New("path contains NUL")
		}
		if r < 0x20 && r != '\t' {
			return "", fmt.Errorf("path contains control character %#x", r)
		}
	}

	// Images built on Windows use backslash separators. Convert before checking
	// for traversal so "..\\.." is caught too.
	name = strings.ReplaceAll(name, `\`, "/")

	// path.Clean resolves a leading "/" away, so the absolute check must be
	// done against the raw input, before cleaning.
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("absolute path in layer: %q", name)
	}

	clean := path.Clean(name)
	if clean == "." || clean == "/" {
		return "", errors.New("path resolves to the destination root")
	}
	// Reject rather than silently strip: an image that tries to escape is a
	// bug or an attack, and either way the operator should hear about it.
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("path escapes the rootfs: %q", name)
	}
	return clean, nil
}

// sanitizeLinkTarget validates a symlink/hardlink destination. A symlink
// pointing at an absolute host path is useless at best and an escape at worst,
// but it is legal in images, so it is normalised rather than rejected.
func sanitizeLinkTarget(from, target string) string {
	target = strings.ReplaceAll(target, `\`, "/")
	if path.IsAbs(target) {
		return path.Clean(target)
	}
	return path.Join(path.Dir(from), path.Clean(target))
}

// ApplyLayer streams a tar layer directly into dest, honouring whiteouts.
//
// Layers are applied in order, each on top of the last, which is exactly how the
// image format defines stacking. Directories are created on demand so that a
// layer which adds "a/b/c.txt" without listing "a" or "a/b" still works.
//
// The layer is processed in a single pass: file bodies are copied straight from
// the tar reader to disk and never held in memory, so a layer containing a
// multi-gigabyte file costs a buffer rather than a heap.
func ApplyLayer(dest string, r io.Reader, sizeLimit int64) error {
	tr := tar.NewReader(r)
	var total int64

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read layer tar: %w", err)
		}

		e, err := classify(hdr)
		if err != nil {
			return err
		}
		if hdr.Size > 0 {
			total += hdr.Size
			if sizeLimit > 0 && total > sizeLimit {
				return fmt.Errorf("layer exceeds size limit of %d bytes", sizeLimit)
			}
		}
		if err := applyEntry(dest, e, tr); err != nil {
			return err
		}
	}
}

func applyEntry(dest string, e Entry, body io.Reader) error {
	target := filepath.Join(dest, filepath.FromSlash(e.Name))

	if e.IsWhiteout {
		return applyWhiteout(dest, e)
	}

	if e.IsDir {
		if err := os.MkdirAll(target, dirMode(e)); err != nil {
			return fmt.Errorf("mkdir %s: %w", target, err)
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("mkdir parent of %s: %w", target, err)
	}

	if e.IsLink {
		if err := os.RemoveAll(target); err != nil {
			return fmt.Errorf("replace %s: %w", target, err)
		}
		if err := os.Symlink(filepath.FromSlash(e.Target), target); err != nil {
			return fmt.Errorf("symlink %s -> %s: %w", target, e.Target, err)
		}
		return nil
	}

	return writeFile(target, e, body)
}

// applyWhiteout removes whatever a lower layer put at this path.
func applyWhiteout(dest string, e Entry) error {
	target := filepath.Join(dest, filepath.FromSlash(e.Name))

	if e.Opaque {
		// Opaque: delete the *entire* directory, so lower layers contribute
		// nothing to it. This is the one that is easy to get wrong -- treating
		// it as an ordinary whiteout leaves stale lower-layer files behind.
		if err := os.RemoveAll(target); err != nil {
			return fmt.Errorf("opaque whiteout %s: %w", target, err)
		}
		return nil
	}

	// A whiteout for a *directory* must be a problem: a file cannot have been
	// deleted by a lower layer's whiteout marker, so something is inconsistent.
	info, err := os.Lstat(target)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // already absent; whiteouts are idempotent
		}
		return fmt.Errorf("whiteout %s: %w", target, err)
	}
	if info.IsDir() {
		return fmt.Errorf("whiteout %s targets a directory; expected .wh..wh..opq", e.Name)
	}
	if err := os.Remove(target); err != nil {
		return fmt.Errorf("whiteout %s: %w", target, err)
	}
	return nil
}

// writeFile copies one regular file body from the tar reader to disk.
func writeFile(target string, e Entry, body io.Reader) error {
	// A symlink from a lower layer must not be followed: writing through it
	// would place the new contents at the link's destination, which may be
	// outside the rootfs entirely.
	if fi, err := os.Lstat(target); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(target); err != nil {
			return fmt.Errorf("replace symlink %s: %w", target, err)
		}
	}

	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fileMode(e))
	if err != nil {
		return fmt.Errorf("create %s: %w", target, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, body); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	if err := f.Chmod(safeMode(fileMode(e))); err != nil {
		return fmt.Errorf("chmod %s: %w", target, err)
	}
	return nil
}

// allowSetuid is deliberately false. A setuid binary in an image is a
// privilege-escalation primitive waiting for a bug elsewhere; refusing to
// materialise one means a whole class of image-based escapes does not exist.
const allowSetuid = false

// safeMode strips setuid, setgid and sticky bits from an image-supplied mode.
func safeMode(m os.FileMode) os.FileMode {
	perms := m.Perm()
	if !allowSetuid {
		perms &^= 0o6000 // S_ISUID | S_ISGID
	}
	return perms
}

func dirMode(e Entry) os.FileMode {
	m := e.Header.Mode
	if m == 0 {
		return 0o755
	}
	return os.FileMode(m).Perm()
}

func fileMode(e Entry) os.FileMode {
	m := e.Header.Mode
	if m == 0 {
		return 0o644
	}
	return os.FileMode(m).Perm()
}

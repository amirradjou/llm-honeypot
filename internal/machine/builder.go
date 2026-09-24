package machine

import (
	"fmt"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

// builder is a tiny DSL over vfs for writing the seed tree tersely. The
// first error stops everything and is reported by seed().
type builder struct {
	m      *Machine
	fs     *vfs.FS
	err    error
	stamps map[string]time.Time
}

func (b *builder) fail(err error) {
	if b.err == nil && err != nil {
		b.err = err
	}
}

// failp is fail with the offending path attached, for debugging seeds.
func (b *builder) failp(p string, err error) {
	if b.err == nil && err != nil {
		b.err = fmt.Errorf("%s: %w", p, err)
	}
}

// dir creates a directory and any parents it needs.
func (b *builder) dir(p string, mode fs.FileMode, uid, gid int, a age) {
	if b.err != nil {
		return
	}
	b.failp(p, b.fs.MkdirAll(p, vfs.WriteOptions{Mode: mode, UID: uid, GID: gid}))
	b.stamp(p, a)
}

// file writes a regular file; the parent must already exist.
func (b *builder) file(p, content string, mode fs.FileMode, uid, gid int, a age) {
	if b.err != nil {
		return
	}
	b.failp(p, b.fs.WriteFile(p, []byte(content), vfs.WriteOptions{Mode: mode, UID: uid, GID: gid}))
	b.stamp(p, a)
}

// text is file() with the common root:root 0644 settings.
func (b *builder) text(p, content string, a age) { b.file(p, content, 0o644, 0, 0, a) }

// link creates a symlink.
func (b *builder) link(target, p string, a age) {
	if b.err != nil {
		return
	}
	b.failp(p, b.fs.Symlink(target, p, vfs.WriteOptions{}))
	b.stamp(p, a)
}

// placeholder registers a file whose content a model will write later.
func (b *builder) placeholder(p string, size int64, hint string, mode fs.FileMode, uid, gid int, a age) {
	if b.err != nil {
		return
	}
	b.failp(p, b.fs.WritePlaceholder(p, size, hint, vfs.WriteOptions{Mode: mode, UID: uid, GID: gid}))
	b.stamp(p, a)
}

var elfHeader = []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0x3e, 0}

// bin creates a fake ELF executable. size 0 picks a stable size from the
// path hash in the 15–350 KiB range that most /usr/bin tools fall in.
func (b *builder) bin(p string, size int64) {
	if b.err != nil {
		return
	}
	h := seedHash(p)
	if size == 0 {
		size = 15_000 + int64(h%335_000)
	}
	b.failp(p, b.fs.WriteOpaque(p, size, elfHeader, h, vfs.WriteOptions{Mode: 0o755}))
	b.stamp(p, ageInstall)
}

// dev creates a device node.
func (b *builder) dev(p string, char bool, mode fs.FileMode, gid int, gen vfs.Dynamic) {
	if b.err != nil {
		return
	}
	typ := fs.ModeDevice
	if char {
		typ |= fs.ModeCharDevice
	}
	b.failp(p, b.fs.Mknod(p, typ, gen, vfs.WriteOptions{Mode: mode, GID: gid}))
	b.stamp(p, ageBoot)
}

// dynamic registers a file computed on every read.
func (b *builder) dynamic(p string, gen vfs.Dynamic, mode fs.FileMode) {
	if b.err != nil {
		return
	}
	b.failp(p, b.fs.WriteDynamic(p, gen, vfs.WriteOptions{Mode: mode}))
	b.stamp(p, ageBoot)
}

// stamp records the believable mtime for p. Creating children re-bumps a
// directory's mtime to "now", so the recorded times are replayed once the
// whole tree exists (see replay). vfs.Chtimes does not touch parents, so a
// final pass sticks.
func (b *builder) stamp(p string, a age) {
	if b.err != nil {
		return
	}
	if b.stamps == nil {
		b.stamps = map[string]time.Time{}
	}
	b.stamps[p] = b.m.mtime(p, a)
}

// replay applies every recorded stamp. Called after the tree is built.
func (b *builder) replay() {
	for p, t := range b.stamps {
		b.failp(p, b.fs.Chtimes(p, t))
	}
}

// lines joins with newlines and adds a trailing one, for file bodies.
func lines(ss ...string) string { return strings.Join(ss, "\n") + "\n" }

// under joins a base directory and a name.
func under(base, name string) string { return path.Join(base, name) }

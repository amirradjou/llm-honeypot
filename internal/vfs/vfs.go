// Package vfs is the in-memory filesystem of the fake machine. It is the
// single source of truth for what the attacker sees: every emulated
// command reads and writes it, and anything a model invents is written
// back so that later commands agree with earlier ones.
//
// Paths are POSIX-style. Callers pass absolute paths; use Resolve to turn
// a relative path plus a working directory into one.
package vfs

import (
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

// Errors mirror the errno values a real libc would report, so commands
// can print the exact messages bash users are used to. Use Strerror.
var (
	ErrNotExist   = errors.New("no such file or directory")
	ErrNotDir     = errors.New("not a directory")
	ErrIsDir      = errors.New("is a directory")
	ErrExist      = errors.New("file exists")
	ErrNotEmpty   = errors.New("directory not empty")
	ErrPermission = errors.New("permission denied")
	ErrLoop       = errors.New("too many levels of symbolic links")
	ErrInvalid    = errors.New("invalid argument")
)

// Strerror renders an error the way coreutils would print it.
func Strerror(err error) string {
	switch {
	case errors.Is(err, ErrNotExist):
		return "No such file or directory"
	case errors.Is(err, ErrNotDir):
		return "Not a directory"
	case errors.Is(err, ErrIsDir):
		return "Is a directory"
	case errors.Is(err, ErrExist):
		return "File exists"
	case errors.Is(err, ErrNotEmpty):
		return "Directory not empty"
	case errors.Is(err, ErrPermission):
		return "Permission denied"
	case errors.Is(err, ErrLoop):
		return "Too many levels of symbolic links"
	case err == nil:
		return "Success"
	}
	return err.Error()
}

// Info is a snapshot of one node. It is a value, so callers cannot mutate
// the filesystem behind its back.
type Info struct {
	Name    string
	Mode    fs.FileMode // type bits plus permissions
	UID     int
	GID     int
	Size    int64
	ModTime time.Time
	// Target is the link target for symlinks.
	Target string
	// Placeholder marks a file whose content has not been authored yet;
	// the shell asks a generator for it on first read. Hint describes
	// what the file is for the generator.
	Placeholder bool
	Hint        string
}

// IsDir reports whether the node is a directory.
func (i Info) IsDir() bool { return i.Mode.IsDir() }

// IsSymlink reports whether the node is a symbolic link.
func (i Info) IsSymlink() bool { return i.Mode&fs.ModeSymlink != 0 }

// Dynamic files compute their content on every read, e.g. /proc/uptime.
type Dynamic func() []byte

type node struct {
	name        string
	mode        fs.FileMode
	uid, gid    int
	modTime     time.Time
	content     []byte
	size        int64 // authoritative for placeholders; len(content) otherwise
	target      string
	dynamic     Dynamic
	placeholder bool
	hint        string
	children    map[string]*node
	parent      *node
}

func (n *node) isDir() bool     { return n.mode.IsDir() }
func (n *node) isSymlink() bool { return n.mode&fs.ModeSymlink != 0 }

func (n *node) info() Info {
	size := n.size
	if !n.placeholder && n.dynamic == nil && !n.isDir() {
		size = int64(len(n.content))
	}
	if n.isDir() {
		size = 4096
	}
	if n.mode&fs.ModeDevice != 0 {
		size = 0
	}
	return Info{
		Name:        n.name,
		Mode:        n.mode,
		UID:         n.uid,
		GID:         n.gid,
		Size:        size,
		ModTime:     n.modTime,
		Target:      n.target,
		Placeholder: n.placeholder,
		Hint:        n.hint,
	}
}

// FS is a virtual filesystem. It is safe for concurrent use.
type FS struct {
	mu   sync.RWMutex
	root *node
	// Now is the clock used for mtimes; tests replace it.
	Now func() time.Time
}

// New returns an empty filesystem with a root directory owned by root.
func New() *FS {
	f := &FS{Now: time.Now}
	f.root = &node{name: "/", mode: fs.ModeDir | 0o755, modTime: f.Now(), children: map[string]*node{}}
	return f
}

// Resolve joins a possibly relative path onto cwd and cleans it. It does
// not touch the filesystem or follow symlinks.
func Resolve(cwd, p string) string {
	if p == "" {
		return path.Clean(cwd)
	}
	if !path.IsAbs(p) {
		p = path.Join(cwd, p)
	}
	return path.Clean(p)
}

const maxSymlinkDepth = 40

// lookup walks to p. With follow, a trailing symlink is resolved too.
// It must be called with the lock held.
func (f *FS) lookup(p string, follow bool) (*node, error) {
	n, _, err := f.walk(p, follow, 0)
	return n, err
}

// walk returns the node and its parent. parent is nil for the root.
func (f *FS) walk(p string, follow bool, depth int) (*node, *node, error) {
	if depth > maxSymlinkDepth {
		return nil, nil, ErrLoop
	}
	p = path.Clean(p)
	if !path.IsAbs(p) {
		return nil, nil, ErrInvalid
	}
	cur := f.root
	var parent *node
	if p == "/" {
		return cur, nil, nil
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, part := range parts {
		if !cur.isDir() {
			return nil, nil, ErrNotDir
		}
		child, ok := cur.children[part]
		if !ok {
			return nil, nil, ErrNotExist
		}
		last := i == len(parts)-1
		if child.isSymlink() && (!last || follow) {
			target := child.target
			if !path.IsAbs(target) {
				target = path.Join(nodePath(cur), target)
			}
			resolved, _, err := f.walk(target, true, depth+1)
			if err != nil {
				return nil, nil, err
			}
			child = resolved
		}
		parent, cur = cur, child
	}
	return cur, parent, nil
}

func nodePath(n *node) string {
	if n.parent == nil {
		return "/"
	}
	parts := []string{}
	for c := n; c.parent != nil; c = c.parent {
		parts = append([]string{c.name}, parts...)
	}
	return "/" + strings.Join(parts, "/")
}

// Stat describes the node at p, following symlinks.
func (f *FS) Stat(p string) (Info, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	n, err := f.lookup(p, true)
	if err != nil {
		return Info{}, err
	}
	return n.info(), nil
}

// Lstat describes the node at p without following a trailing symlink.
func (f *FS) Lstat(p string) (Info, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	n, err := f.lookup(p, false)
	if err != nil {
		return Info{}, err
	}
	return n.info(), nil
}

// Exists reports whether p names anything.
func (f *FS) Exists(p string) bool {
	_, err := f.Lstat(p)
	return err == nil
}

// RealPath resolves every symlink in p and returns the canonical path.
func (f *FS) RealPath(p string) (string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	n, err := f.lookup(p, true)
	if err != nil {
		return "", err
	}
	return nodePath(n), nil
}

// ReadDir lists a directory sorted by name.
func (f *FS) ReadDir(p string) ([]Info, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	n, err := f.lookup(p, true)
	if err != nil {
		return nil, err
	}
	if !n.isDir() {
		return nil, ErrNotDir
	}
	out := make([]Info, 0, len(n.children))
	for _, c := range n.children {
		out = append(out, c.info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ReadFile returns a file's content. Placeholders return their Info with
// Placeholder set and nil content; the caller decides how to fill them.
func (f *FS) ReadFile(p string) ([]byte, Info, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	n, err := f.lookup(p, true)
	if err != nil {
		return nil, Info{}, err
	}
	if n.isDir() {
		return nil, n.info(), ErrIsDir
	}
	if n.dynamic != nil {
		return n.dynamic(), n.info(), nil
	}
	if n.placeholder {
		return nil, n.info(), nil
	}
	return append([]byte(nil), n.content...), n.info(), nil
}

// WriteOptions control how a file is created.
type WriteOptions struct {
	Mode fs.FileMode // permission bits; 0 means 0644
	UID  int
	GID  int
}

// WriteFile creates or truncates a regular file. The parent must exist.
// Writing to a placeholder materialises it.
func (f *FS) WriteFile(p string, data []byte, opts WriteOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.create(p, opts)
	if err != nil {
		return err
	}
	if n.mode&fs.ModeDevice != 0 {
		return nil // writes to /dev/null and friends vanish
	}
	n.content = append([]byte(nil), data...)
	n.size = int64(len(data))
	n.placeholder = false
	n.dynamic = nil
	n.modTime = f.Now()
	return nil
}

// AppendFile appends to a file, creating it if needed.
func (f *FS) AppendFile(p string, data []byte, opts WriteOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.create(p, opts)
	if err != nil {
		return err
	}
	if n.mode&fs.ModeDevice != 0 {
		return nil
	}
	if n.placeholder || n.dynamic != nil {
		// Appending to something we never authored: the best we can do
		// is start from empty rather than invent the prefix here.
		n.placeholder, n.dynamic, n.content = false, nil, nil
	}
	n.content = append(n.content, data...)
	n.size = int64(len(n.content))
	n.modTime = f.Now()
	return nil
}

// WritePlaceholder registers a file whose content will be generated on
// first read. size is what ls reports meanwhile.
func (f *FS) WritePlaceholder(p string, size int64, hint string, opts WriteOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.create(p, opts)
	if err != nil {
		return err
	}
	n.placeholder = true
	n.hint = hint
	n.size = size
	n.content = nil
	return nil
}

// WriteDynamic registers a file whose content is computed on every read.
func (f *FS) WriteDynamic(p string, gen Dynamic, opts WriteOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.create(p, opts)
	if err != nil {
		return err
	}
	n.dynamic = gen
	n.placeholder = false
	return nil
}

// create returns the regular file at p, making it if absent.
func (f *FS) create(p string, opts WriteOptions) (*node, error) {
	p = path.Clean(p)
	if existing, err := f.lookup(p, true); err == nil {
		if existing.isDir() {
			return nil, ErrIsDir
		}
		return existing, nil
	} else if !errors.Is(err, ErrNotExist) {
		return nil, err
	}
	dir, err := f.lookup(path.Dir(p), true)
	if err != nil {
		return nil, err
	}
	if !dir.isDir() {
		return nil, ErrNotDir
	}
	mode := opts.Mode &^ fs.ModeType
	if mode == 0 {
		mode = 0o644
	}
	n := &node{name: path.Base(p), mode: mode, uid: opts.UID, gid: opts.GID, modTime: f.Now(), parent: dir}
	dir.children[n.name] = n
	dir.modTime = n.modTime
	return n, nil
}

// Mkdir creates one directory; the parent must exist.
func (f *FS) Mkdir(p string, opts WriteOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mkdir(p, opts)
}

func (f *FS) mkdir(p string, opts WriteOptions) error {
	p = path.Clean(p)
	if _, err := f.lookup(p, false); err == nil {
		return ErrExist
	}
	dir, err := f.lookup(path.Dir(p), true)
	if err != nil {
		return err
	}
	if !dir.isDir() {
		return ErrNotDir
	}
	mode := opts.Mode &^ fs.ModeType
	if mode == 0 {
		mode = 0o755
	}
	n := &node{name: path.Base(p), mode: fs.ModeDir | mode, uid: opts.UID, gid: opts.GID, modTime: f.Now(), children: map[string]*node{}, parent: dir}
	dir.children[n.name] = n
	dir.modTime = n.modTime
	return nil
}

// MkdirAll creates p and any missing parents, like mkdir -p.
func (f *FS) MkdirAll(p string, opts WriteOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p = path.Clean(p)
	if n, err := f.lookup(p, true); err == nil {
		if n.isDir() {
			return nil
		}
		return ErrNotDir
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	cur := "/"
	for _, part := range parts {
		cur = path.Join(cur, part)
		if n, err := f.lookup(cur, true); err == nil {
			if !n.isDir() {
				return ErrNotDir
			}
			continue
		}
		if err := f.mkdir(cur, opts); err != nil {
			return err
		}
	}
	return nil
}

// Symlink creates a symbolic link at p pointing to target.
func (f *FS) Symlink(target, p string, opts WriteOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p = path.Clean(p)
	if _, err := f.lookup(p, false); err == nil {
		return ErrExist
	}
	dir, err := f.lookup(path.Dir(p), true)
	if err != nil {
		return err
	}
	if !dir.isDir() {
		return ErrNotDir
	}
	n := &node{name: path.Base(p), mode: fs.ModeSymlink | 0o777, uid: opts.UID, gid: opts.GID, modTime: f.Now(), target: target, parent: dir}
	dir.children[n.name] = n
	return nil
}

// Remove deletes a file, symlink or empty directory.
func (f *FS) Remove(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, parent, err := f.walk(p, false, 0)
	if err != nil {
		return err
	}
	if parent == nil {
		return ErrPermission
	}
	if n.isDir() && len(n.children) > 0 {
		return ErrNotEmpty
	}
	delete(parent.children, n.name)
	parent.modTime = f.Now()
	return nil
}

// RemoveAll deletes p and everything under it. A missing p is not an error.
func (f *FS) RemoveAll(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, parent, err := f.walk(p, false, 0)
	if errors.Is(err, ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if parent == nil {
		return ErrPermission
	}
	delete(parent.children, n.name)
	parent.modTime = f.Now()
	return nil
}

// Rename moves p to newp, replacing a non-directory target.
func (f *FS) Rename(p, newp string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, parent, err := f.walk(p, false, 0)
	if err != nil {
		return err
	}
	if parent == nil {
		return ErrPermission
	}
	newp = path.Clean(newp)
	if existing, err := f.lookup(newp, false); err == nil {
		if existing.isDir() {
			// mv file dir → dir/file
			newp = path.Join(newp, n.name)
			if _, err := f.lookup(newp, false); err == nil {
				return ErrExist
			}
		}
	}
	dest, err := f.lookup(path.Dir(newp), true)
	if err != nil {
		return err
	}
	if !dest.isDir() {
		return ErrNotDir
	}
	delete(parent.children, n.name)
	n.name = path.Base(newp)
	n.parent = dest
	dest.children[n.name] = n
	now := f.Now()
	parent.modTime, dest.modTime = now, now
	return nil
}

// Chmod sets permission bits, keeping the type bits.
func (f *FS) Chmod(p string, mode fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.lookup(p, true)
	if err != nil {
		return err
	}
	n.mode = (n.mode & fs.ModeType) | (mode & fs.ModePerm)
	return nil
}

// Chown sets the owner and group.
func (f *FS) Chown(p string, uid, gid int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.lookup(p, true)
	if err != nil {
		return err
	}
	n.uid, n.gid = uid, gid
	return nil
}

// Touch updates the mtime, creating an empty file if needed.
func (f *FS) Touch(p string, opts WriteOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.lookup(p, true)
	if errors.Is(err, ErrNotExist) {
		_, err = f.create(p, opts)
		return err
	}
	if err != nil {
		return err
	}
	n.modTime = f.Now()
	return nil
}

// Clone returns an independent deep copy. Sessions start from a clone of
// the seeded machine so that one attacker's mess never leaks to another.
func (f *FS) Clone() *FS {
	f.mu.RLock()
	defer f.mu.RUnlock()
	c := &FS{Now: f.Now}
	c.root = cloneNode(f.root, nil)
	return c
}

func cloneNode(n *node, parent *node) *node {
	c := *n
	c.parent = parent
	c.content = append([]byte(nil), n.content...)
	if n.children != nil {
		c.children = make(map[string]*node, len(n.children))
		for name, child := range n.children {
			c.children[name] = cloneNode(child, &c)
		}
	}
	return &c
}

// Walk calls fn for every node under root in lexical order, like
// fs.WalkDir. Returning fs.SkipDir from fn skips a directory's children.
func (f *FS) Walk(root string, fn func(p string, info Info) error) error {
	f.mu.RLock()
	defer f.mu.RUnlock()
	n, err := f.lookup(root, true)
	if err != nil {
		return err
	}
	return walkNode(path.Clean(root), n, fn)
}

func walkNode(p string, n *node, fn func(string, Info) error) error {
	err := fn(p, n.info())
	if err == fs.SkipDir {
		return nil
	}
	if err != nil {
		return err
	}
	if !n.isDir() {
		return nil
	}
	names := make([]string, 0, len(n.children))
	for name := range n.children {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := walkNode(path.Join(p, name), n.children[name], fn); err != nil {
			return err
		}
	}
	return nil
}

// Mknod creates a device node. typ must be fs.ModeDevice (block) or
// fs.ModeDevice|fs.ModeCharDevice (character). Reads return content, or
// the dynamic generator when set; writes are accepted and discarded.
func (f *FS) Mknod(p string, typ fs.FileMode, gen Dynamic, opts WriteOptions) error {
	if typ&fs.ModeDevice == 0 {
		return ErrInvalid
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.create(p, opts)
	if err != nil {
		return err
	}
	n.mode = (typ & fs.ModeType) | (n.mode & fs.ModePerm)
	n.dynamic = gen
	n.size = 0
	return nil
}

// IsDevice reports whether the node is a block or character device.
func (i Info) IsDevice() bool { return i.Mode&fs.ModeDevice != 0 }

// MaxOpaqueRead caps how much of an opaque file a single read produces;
// an attacker cat-ing a 200 MB payload must not cost 200 MB of memory.
const MaxOpaqueRead = 4 << 20

// WriteOpaque registers a file that reports size bytes and reads back as
// deterministic junk (prefix followed by seeded pseudo-random bytes).
// It stands in for binaries and downloaded payloads without storing them.
func (f *FS) WriteOpaque(p string, size int64, prefix []byte, seed uint64, opts WriteOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.create(p, opts)
	if err != nil {
		return err
	}
	prefix = append([]byte(nil), prefix...)
	n.dynamic = func() []byte {
		want := min(size, MaxOpaqueRead)
		out := make([]byte, want)
		copy(out, prefix)
		// splitmix64 spreads nearby seeds apart before xorshift takes over
		x := seed + 0x9E3779B97F4A7C15
		x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
		x = (x ^ (x >> 27)) * 0x94D049BB133111EB
		x ^= x >> 31
		if x == 0 {
			x = 1
		}
		for i := int64(len(prefix)); i < want; i++ {
			// xorshift64*: cheap, deterministic, good enough for junk
			x ^= x >> 12
			x ^= x << 25
			x ^= x >> 27
			out[i] = byte((x * 2685821657736338717) >> 56)
		}
		return out
	}
	n.size = size
	n.placeholder = false
	n.content = nil
	return nil
}

// Chtimes sets the modification time of p itself (a symlink is not
// followed), for seeding believable listings.
func (f *FS) Chtimes(p string, mtime time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.lookup(p, false)
	if err != nil {
		return err
	}
	n.modTime = mtime
	return nil
}

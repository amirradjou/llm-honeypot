package vfs

import (
	"errors"
	"io/fs"
	"testing"
	"time"
)

func TestResolve(t *testing.T) {
	cases := []struct{ cwd, p, want string }{
		{"/root", "", "/root"},
		{"/root", ".", "/root"},
		{"/root", "..", "/"},
		{"/root", "../etc/../etc/passwd", "/etc/passwd"},
		{"/home/deploy", "/tmp/x", "/tmp/x"},
		{"/", "../../..", "/"},
		{"/var/log", "nginx//access.log", "/var/log/nginx/access.log"},
	}
	for _, c := range cases {
		if got := Resolve(c.cwd, c.p); got != c.want {
			t.Errorf("Resolve(%q, %q) = %q, want %q", c.cwd, c.p, got, c.want)
		}
	}
}

func newTestFS(t *testing.T) *FS {
	t.Helper()
	f := New()
	f.Now = func() time.Time { return time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC) }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(f.MkdirAll("/etc/nginx", WriteOptions{}))
	must(f.MkdirAll("/home/deploy", WriteOptions{UID: 1000, GID: 1000}))
	must(f.MkdirAll("/tmp", WriteOptions{Mode: 0o1777}))
	must(f.WriteFile("/etc/hostname", []byte("box\n"), WriteOptions{}))
	must(f.WriteFile("/etc/shadow", []byte("root:*:1::::::\n"), WriteOptions{Mode: 0o640, GID: 42}))
	must(f.Symlink("/etc/hostname", "/tmp/hn", WriteOptions{}))
	must(f.Symlink("nginx", "/etc/ngx", WriteOptions{}))
	return f
}

func TestReadWriteAndListing(t *testing.T) {
	f := newTestFS(t)

	data, info, err := f.ReadFile("/etc/hostname")
	if err != nil || string(data) != "box\n" || info.Size != 4 || info.Mode != 0o644 {
		t.Fatalf("ReadFile = %q, %+v, %v", data, info, err)
	}

	entries, err := f.ReadDir("/etc")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name)
	}
	if got := len(names); got != 4 || names[0] != "hostname" || names[3] != "shadow" {
		t.Fatalf("ReadDir(/etc) = %v", names)
	}

	if err := f.AppendFile("/etc/hostname", []byte("more\n"), WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	data, _, _ = f.ReadFile("/etc/hostname")
	if string(data) != "box\nmore\n" {
		t.Fatalf("after append = %q", data)
	}

	if err := f.WriteFile("/nope/file", nil, WriteOptions{}); !errors.Is(err, ErrNotExist) {
		t.Fatalf("write into missing dir: %v", err)
	}
	if err := f.WriteFile("/etc", nil, WriteOptions{}); !errors.Is(err, ErrIsDir) {
		t.Fatalf("write over dir: %v", err)
	}
	if _, _, err := f.ReadFile("/etc/hostname/x"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("path through file: %v", err)
	}
	if _, _, err := f.ReadFile("/etc"); !errors.Is(err, ErrIsDir) {
		t.Fatalf("read dir: %v", err)
	}
}

func TestSymlinks(t *testing.T) {
	f := newTestFS(t)

	data, _, err := f.ReadFile("/tmp/hn")
	if err != nil || string(data) != "box\n" {
		t.Fatalf("read through symlink: %q %v", data, err)
	}
	li, _ := f.Lstat("/tmp/hn")
	si, _ := f.Stat("/tmp/hn")
	if !li.IsSymlink() || li.Target != "/etc/hostname" || si.IsSymlink() {
		t.Fatalf("Lstat/Stat = %+v / %+v", li, si)
	}
	// Relative symlink to a directory, used mid-path.
	if _, err := f.Stat("/etc/ngx/../hostname"); err != nil {
		// path.Clean removes the ".." lexically, which is what bash does too.
		t.Fatal(err)
	}
	if err := f.WriteFile("/etc/ngx/site.conf", []byte("server {}"), WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Stat("/etc/nginx/site.conf"); err != nil {
		t.Fatalf("write through dir symlink: %v", err)
	}
	real, err := f.RealPath("/etc/ngx/site.conf")
	if err != nil || real != "/etc/nginx/site.conf" {
		t.Fatalf("RealPath = %q, %v", real, err)
	}

	_ = f.Symlink("/tmp/b", "/tmp/a", WriteOptions{})
	_ = f.Symlink("/tmp/a", "/tmp/b", WriteOptions{})
	if _, err := f.Stat("/tmp/a"); !errors.Is(err, ErrLoop) {
		t.Fatalf("loop: %v", err)
	}
	if _, err := f.Stat("/tmp/dangling"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
}

func TestRemoveRenameMkdir(t *testing.T) {
	f := newTestFS(t)

	if err := f.Remove("/etc"); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("remove non-empty dir: %v", err)
	}
	if err := f.Remove("/"); !errors.Is(err, ErrPermission) {
		t.Fatalf("remove root: %v", err)
	}
	if err := f.Remove("/tmp/hn"); err != nil || f.Exists("/tmp/hn") || !f.Exists("/etc/hostname") {
		t.Fatalf("removing a symlink must not follow it: %v", err)
	}
	if err := f.RemoveAll("/etc"); err != nil || f.Exists("/etc") {
		t.Fatalf("RemoveAll: %v", err)
	}
	if err := f.RemoveAll("/etc"); err != nil {
		t.Fatalf("RemoveAll of missing path should be nil: %v", err)
	}

	if err := f.Mkdir("/home/deploy", WriteOptions{}); !errors.Is(err, ErrExist) {
		t.Fatalf("mkdir existing: %v", err)
	}
	if err := f.Mkdir("/a/b", WriteOptions{}); !errors.Is(err, ErrNotExist) {
		t.Fatalf("mkdir without parent: %v", err)
	}
	if err := f.MkdirAll("/home/deploy/.ssh/x", WriteOptions{UID: 1000, GID: 1000}); err != nil {
		t.Fatal(err)
	}
	info, _ := f.Stat("/home/deploy/.ssh")
	if !info.IsDir() || info.UID != 1000 || info.Mode.Perm() != 0o755 {
		t.Fatalf(".ssh = %+v", info)
	}

	_ = f.WriteFile("/tmp/x.sh", []byte("#!/bin/sh"), WriteOptions{})
	if err := f.Rename("/tmp/x.sh", "/tmp/y.sh"); err != nil || f.Exists("/tmp/x.sh") || !f.Exists("/tmp/y.sh") {
		t.Fatalf("rename: %v", err)
	}
	if err := f.Rename("/tmp/y.sh", "/home/deploy"); err != nil || !f.Exists("/home/deploy/y.sh") {
		t.Fatalf("rename into dir: %v", err)
	}
	if err := f.Rename("/home/deploy/y.sh", "/nowhere/z"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("rename to missing dir: %v", err)
	}
}

func TestPlaceholderAndDynamic(t *testing.T) {
	f := newTestFS(t)

	if err := f.WritePlaceholder("/etc/nginx/mime.types", 3957, "nginx mime.types", WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	data, info, err := f.ReadFile("/etc/nginx/mime.types")
	if err != nil || data != nil || !info.Placeholder || info.Size != 3957 || info.Hint != "nginx mime.types" {
		t.Fatalf("placeholder read = %q %+v %v", data, info, err)
	}
	if err := f.WriteFile("/etc/nginx/mime.types", []byte("types {}\n"), WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	data, info, _ = f.ReadFile("/etc/nginx/mime.types")
	if info.Placeholder || string(data) != "types {}\n" || info.Size != 9 {
		t.Fatalf("materialised = %q %+v", data, info)
	}

	n := 0
	if err := f.WriteDynamic("/proc/uptime", func() []byte { n++; return []byte("1 2") }, WriteOptions{}); !errors.Is(err, ErrNotExist) {
		t.Fatalf("dynamic needs parent: %v", err)
	}
	_ = f.Mkdir("/proc", WriteOptions{})
	_ = f.WriteDynamic("/proc/uptime", func() []byte { n++; return []byte("1 2") }, WriteOptions{})
	_, _, _ = f.ReadFile("/proc/uptime")
	_, _, _ = f.ReadFile("/proc/uptime")
	if n != 2 {
		t.Fatalf("dynamic generator called %d times, want 2", n)
	}
}

func TestCloneIsIndependent(t *testing.T) {
	f := newTestFS(t)
	c := f.Clone()

	if err := c.WriteFile("/tmp/evil", []byte("x"), WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	_ = c.RemoveAll("/etc")
	if f.Exists("/tmp/evil") || !f.Exists("/etc/hostname") {
		t.Fatal("clone leaked into the original")
	}
	if err := f.AppendFile("/etc/hostname", []byte("!"), WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	// The clone's copy of /etc is gone; but it must not see the original's append either.
	if _, err := c.Stat("/etc/hostname"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("clone should not see /etc: %v", err)
	}
	real, err := c.RealPath("/tmp/hn")
	if err != nil {
		// /tmp/hn points at /etc/hostname, gone in the clone
		if !errors.Is(err, ErrNotExist) {
			t.Fatal(err)
		}
	} else {
		t.Fatalf("RealPath = %q, expected dangling", real)
	}
}

func TestAccess(t *testing.T) {
	f := newTestFS(t)
	root := Cred{UID: 0, GIDs: []int{0}}
	deploy := Cred{UID: 1000, GIDs: []int{1000}}
	shadowGroup := Cred{UID: 1001, GIDs: []int{42}}

	if err := f.Access("/etc/shadow", root, R); err != nil {
		t.Errorf("root read shadow: %v", err)
	}
	if err := f.Access("/etc/shadow", deploy, R); !errors.Is(err, ErrPermission) {
		t.Errorf("deploy read shadow: %v", err)
	}
	if err := f.Access("/etc/shadow", shadowGroup, R); err != nil {
		t.Errorf("group read shadow: %v", err)
	}
	if err := f.Access("/etc/shadow", shadowGroup, W); !errors.Is(err, ErrPermission) {
		t.Errorf("group write shadow: %v", err)
	}
	if err := f.Access("/home/deploy", deploy, W); err != nil {
		t.Errorf("owner write home: %v", err)
	}
	if err := f.Access("/etc", deploy, W); !errors.Is(err, ErrPermission) {
		t.Errorf("other write /etc: %v", err)
	}
	if err := f.Access("/etc/hostname", root, X); !errors.Is(err, ErrPermission) {
		t.Errorf("root exec non-executable: %v", err)
	}
	_ = f.Chmod("/etc/hostname", 0o755)
	if err := f.Access("/etc/hostname", root, X); err != nil {
		t.Errorf("root exec after chmod: %v", err)
	}
	if err := f.Access("/missing", root, R); !errors.Is(err, ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
}

func TestWalkAndStrerror(t *testing.T) {
	f := newTestFS(t)
	var seen []string
	err := f.Walk("/", func(p string, info Info) error {
		seen = append(seen, p)
		if p == "/home" {
			return fs.SkipDir
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/", "/etc", "/etc/hostname", "/etc/nginx", "/etc/ngx", "/etc/shadow", "/home", "/tmp", "/tmp/hn"}
	if len(seen) != len(want) {
		t.Fatalf("walk = %v", seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("walk[%d] = %q, want %q", i, seen[i], want[i])
		}
	}

	if s := Strerror(ErrNotExist); s != "No such file or directory" {
		t.Fatalf("Strerror = %q", s)
	}
	if s := Strerror(nil); s != "Success" {
		t.Fatalf("Strerror(nil) = %q", s)
	}
}

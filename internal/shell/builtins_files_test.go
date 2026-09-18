package shell

import (
	"strings"
	"testing"
)

func TestLsLongFormat(t *testing.T) {
	in, s := testSession(t)
	out, _, st := run(t, in, s, "ls -la /etc/nginx")
	if st != 0 {
		t.Fatalf("status %d", st)
	}
	if !strings.Contains(out, "total ") {
		t.Errorf("no total line:\n%s", out)
	}
	// The sites-enabled symlink shows an arrow.
	if !strings.Contains(out, "sites-enabled") {
		t.Errorf("missing sites-enabled:\n%s", out)
	}
	// nginx.conf owned by root, drwx for dirs.
	if !strings.Contains(out, "root") {
		t.Errorf("no root owner:\n%s", out)
	}
	// Long line for a known file has a 10-char mode and a size.
	out, _, _ = run(t, in, s, "ls -l /etc/hostname")
	if !strings.HasPrefix(out, "-rw-r--r-- 1 root root") {
		t.Errorf("hostname long line = %q", out)
	}

	// A symlink in long form shows -> target.
	out, _, _ = run(t, in, s, "ls -l /bin")
	if !strings.Contains(out, "-> usr/bin") && !strings.Contains(out, "-> /usr/bin") {
		t.Errorf("/bin symlink not shown: %q", out)
	}

	// -a includes dotfiles and . / ..
	out, _, _ = run(t, in, s, "ls -a /root")
	if !strings.Contains(out, ".bashrc") || !strings.Contains(out, ".bash_history") {
		t.Errorf("ls -a /root missing dotfiles:\n%s", out)
	}
}

func TestLsAndCatUnprivileged(t *testing.T) {
	in, s := testSession(t)
	// A non-root user cannot cat /etc/shadow.
	m := s.Machine
	as := NewSession(m, "martin", 3)
	_, errb, st := run(t, in, as, "cat /etc/shadow")
	if st == 0 || !strings.Contains(errb, "Permission denied") {
		t.Errorf("martin cat shadow: %q %d", errb, st)
	}
	// But root can.
	out, _, st := run(t, in, s, "cat /etc/hostname")
	if st != 0 || out != "srv-web01\n" {
		t.Errorf("cat hostname = %q %d", out, st)
	}
	// cat a directory errors.
	_, errb, st = run(t, in, s, "cat /etc")
	if st == 0 || !strings.Contains(errb, "Is a directory") {
		t.Errorf("cat dir: %q %d", errb, st)
	}
}

func TestHeadTail(t *testing.T) {
	in, s := testSession(t)
	run(t, in, s, "cd /tmp")
	run(t, in, s, "printf ''")
	// Build a numbered file via a loop of echoes.
	for i := 1; i <= 20; i++ {
		run(t, in, s, "echo line"+itoa(i)+" >> nums.txt")
	}
	out, _, _ := run(t, in, s, "head -n 3 nums.txt")
	if out != "line1\nline2\nline3\n" {
		t.Errorf("head = %q", out)
	}
	out, _, _ = run(t, in, s, "tail -n 2 nums.txt")
	if out != "line19\nline20\n" {
		t.Errorf("tail = %q", out)
	}
	out, _, _ = run(t, in, s, "head -5 nums.txt | tail -1")
	if out != "line5\n" {
		t.Errorf("head|tail = %q", out)
	}
}

func TestMkdirRmCpMv(t *testing.T) {
	in, s := testSession(t)
	run(t, in, s, "cd /tmp")
	run(t, in, s, "mkdir -p a/b/c")
	if !s.FS.Exists("/tmp/a/b/c") {
		t.Fatal("mkdir -p failed")
	}
	run(t, in, s, "echo hi > a/b/f.txt")
	run(t, in, s, "cp a/b/f.txt a/b/g.txt")
	data, _, _ := s.FS.ReadFile("/tmp/a/b/g.txt")
	if string(data) != "hi\n" {
		t.Errorf("cp = %q", data)
	}
	run(t, in, s, "cp -r a a2")
	if !s.FS.Exists("/tmp/a2/b/f.txt") {
		t.Error("cp -r failed")
	}
	run(t, in, s, "mv a2/b/f.txt a2/moved.txt")
	if s.FS.Exists("/tmp/a2/b/f.txt") || !s.FS.Exists("/tmp/a2/moved.txt") {
		t.Error("mv failed")
	}
	_, errb, st := run(t, in, s, "rm a")
	if st == 0 || !strings.Contains(errb, "Is a directory") {
		t.Errorf("rm dir without -r: %q %d", errb, st)
	}
	run(t, in, s, "rm -rf a a2")
	if s.FS.Exists("/tmp/a") || s.FS.Exists("/tmp/a2") {
		t.Error("rm -rf failed")
	}
	// rm -f on a missing file is silent and succeeds.
	if _, errb, st := run(t, in, s, "rm -f /tmp/does-not-exist"); st != 0 || errb != "" {
		t.Errorf("rm -f missing: %q %d", errb, st)
	}
}

func TestChmodChown(t *testing.T) {
	in, s := testSession(t)
	run(t, in, s, "cd /tmp")
	run(t, in, s, "echo x > f")
	run(t, in, s, "chmod 600 f")
	info, _ := s.FS.Stat("/tmp/f")
	if info.Mode.Perm() != 0o600 {
		t.Errorf("chmod 600 -> %o", info.Mode.Perm())
	}
	run(t, in, s, "chmod +x f")
	info, _ = s.FS.Stat("/tmp/f")
	if info.Mode.Perm() != 0o711 {
		t.Errorf("chmod +x -> %o", info.Mode.Perm())
	}
	run(t, in, s, "chmod u=rw,go= f")
	info, _ = s.FS.Stat("/tmp/f")
	if info.Mode.Perm() != 0o600 {
		t.Errorf("chmod symbolic -> %o", info.Mode.Perm())
	}
	// chown as root.
	run(t, in, s, "chown www-data:www-data f")
	info, _ = s.FS.Stat("/tmp/f")
	if info.UID != 33 || info.GID != 33 {
		t.Errorf("chown -> %d:%d", info.UID, info.GID)
	}
	// chown as non-root fails.
	as := NewSession(s.Machine, "martin", 4)
	run(t, in, as, "echo y > /home/martin/z")
	_, errb, st := run(t, in, as, "chown root /home/martin/z")
	if st == 0 || !strings.Contains(errb, "Operation not permitted") {
		t.Errorf("non-root chown: %q %d", errb, st)
	}
}

func TestWcGrepFindWhich(t *testing.T) {
	in, s := testSession(t)
	out, _, _ := run(t, in, s, "wc -l /etc/passwd")
	if !strings.Contains(out, "/etc/passwd") {
		t.Errorf("wc = %q", out)
	}
	// grep root in passwd finds the root line.
	out, _, st := run(t, in, s, "grep root /etc/passwd")
	if st != 0 || !strings.Contains(out, "root:x:0:0:") {
		t.Errorf("grep = %q %d", out, st)
	}
	// grep -c counts.
	out, _, _ = run(t, in, s, "grep -c bash /etc/passwd")
	if strings.TrimSpace(out) == "0" {
		t.Errorf("grep -c = %q", out)
	}
	// grep with no match exits 1.
	_, _, st = run(t, in, s, "grep zzzznotthere /etc/passwd")
	if st != 1 {
		t.Errorf("grep no-match status = %d", st)
	}
	// grep through a pipe.
	out, _, _ = run(t, in, s, "cat /etc/passwd | grep -c :/bin/bash")
	if strings.TrimSpace(out) == "0" {
		t.Errorf("piped grep -c = %q", out)
	}
	// which resolves a PATH binary.
	out, _, st = run(t, in, s, "which ls")
	if st != 0 || strings.TrimSpace(out) != "/usr/bin/ls" {
		t.Errorf("which ls = %q %d", out, st)
	}
	_, _, st = run(t, in, s, "which nonexistentcmd")
	if st != 1 {
		t.Errorf("which missing status = %d", st)
	}
	// find by name.
	out, _, _ = run(t, in, s, "find /etc/nginx -name '*.conf'")
	if !strings.Contains(out, "nginx.conf") {
		t.Errorf("find = %q", out)
	}
	// find -type d.
	out, _, _ = run(t, in, s, "find /etc/nginx -type d")
	if !strings.Contains(out, "/etc/nginx/sites-available") {
		t.Errorf("find -type d = %q", out)
	}
}

func TestStatAndChecksums(t *testing.T) {
	in, s := testSession(t)
	out, _, _ := run(t, in, s, "stat /etc/hostname")
	if !strings.Contains(out, "File: /etc/hostname") || !strings.Contains(out, "Uid: (    0/    root)") {
		t.Errorf("stat = %q", out)
	}
	// sha256sum of a known small file is stable.
	out, _, _ = run(t, in, s, "echo -n abc | sha256sum")
	if !strings.HasPrefix(out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") {
		t.Errorf("sha256 = %q", out)
	}
	out, _, _ = run(t, in, s, "echo -n '' | md5sum")
	if !strings.HasPrefix(out, "d41d8cd98f00b204e9800998ecf8427e") {
		t.Errorf("md5 = %q", out)
	}
}

func TestSortUniqCutTr(t *testing.T) {
	in, s := testSession(t)
	out, _, _ := run(t, in, s, "echo -e 'b\\na\\nc\\na' | sort")
	if out != "a\na\nb\nc\n" {
		t.Errorf("sort = %q", out)
	}
	out, _, _ = run(t, in, s, "echo -e 'b\\na\\nc\\na' | sort -u")
	if out != "a\nb\nc\n" {
		t.Errorf("sort -u = %q", out)
	}
	out, _, _ = run(t, in, s, "echo -e 'a\\na\\nb' | uniq -c")
	if !strings.Contains(out, "2 a") || !strings.Contains(out, "1 b") {
		t.Errorf("uniq -c = %q", out)
	}
	out, _, _ = run(t, in, s, "echo 'root:x:0:0' | cut -d: -f1,3")
	if out != "root:0\n" {
		t.Errorf("cut = %q", out)
	}
	out, _, _ = run(t, in, s, "echo hello | tr a-z A-Z")
	if out != "HELLO\n" {
		t.Errorf("tr = %q", out)
	}
}

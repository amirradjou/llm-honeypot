package shell

import (
	"strings"
	"testing"
)

// Expected outputs recorded from the Ubuntu 22.04 reference container.
func TestMoreToolsMatchUbuntu(t *testing.T) {
	cases := []struct{ line, want string }{
		{`echo abcdefghijkl | cut -c1-10`, "abcdefghij\n"},
		{`echo abcdef | cut -c2,4-`, "bdef\n"},
		{`echo a:b:c:d | cut -d: -f2-`, "b:c:d\n"},
		{`echo a:b:c:d | cut -d: -f-2`, "a:b\n"},
		{`printf 'x\na:b\n' | cut -d: -f2`, "x\nb\n"},
		{`printf 'x\na:b\n' | cut -s -d: -f2`, "b\n"},
		{`echo 'a b c' | cut -d' ' -f1,3 --output-delimiter=,`, "a,c\n"},
		{`getconf LONG_BIT`, "64\n"},
		{`getconf PAGESIZE`, "4096\n"},
		{`echo hello | od -c`, "0000000   h   e   l   l   o  \\n\n0000006\n"},
		{`echo hello | od -An -tx1`, " 68 65 6c 6c 6f 0a\n"},
		{`printf 'AB' | od -x`, "0000000 4241\n0000002\n"},
		{`printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' | od -An -c`, "   A   B   C   D   E   F   G   H   I   J   K   L   M   N   O   P\n   Q   R   S   T   U   V   W   X   Y   Z\n"},
		{`echo hi | od`, "0000000 064550 000012\n0000003\n"},
		{`printf 'a b c\n' | xargs -n1 | wc -l`, "3\n"},
	}
	for _, c := range cases {
		in, s := testSession(t)
		out, errb, _ := run(t, in, s, c.line)
		if out != c.want {
			t.Errorf("%s\n got %q (stderr %q)\nwant %q", c.line, out, errb, c.want)
		}
	}
}

func TestSysctlGetconfWhereisStat(t *testing.T) {
	in, s := testSession(t)
	cases := []struct {
		line, out, err string
		code           int
	}{
		{"sysctl -n vm.nr_hugepages", "0\n", "", 0},
		{"sysctl vm.swappiness", "vm.swappiness = 60\n", "", 0},
		{"sysctl -n nope.key", "", "sysctl: cannot stat /proc/sys/nope/key: No such file or directory\n", 255},
		{"sysctl -w vm.nr_hugepages=128", "vm.nr_hugepages = 128\n", "", 0},
		{"sysctl -n vm.nr_hugepages", "128\n", "", 0},
		{"getconf NOPE", "", "getconf: Unrecognized variable `NOPE'\n", 2},
		{"whereis nosuchcmd", "nosuchcmd:\n", "", 0},
		{"whereis bash", "bash: /usr/bin/bash /usr/share/man/man1/bash.1.gz\n", "", 0},
		{`stat -c "%n %F %a %U" /etc/passwd /tmp`, "/etc/passwd regular file 644 root\n/tmp directory 1777 root\n", "", 0},
	}
	for _, c := range cases {
		out, errb, code := run(t, in, s, c.line)
		if out != c.out || errb != c.err || code != c.code {
			t.Errorf("%s = %d %q %q, want %d %q %q", c.line, code, out, errb, c.code, c.out, c.err)
		}
	}
}

// Off the terminal (an exec session or a pipe), ls prints one name per line.
func TestLsOnePerLineOffTerminal(t *testing.T) {
	in, s := testSession(t)
	out, _, _ := run(t, in, s, "ls -d /etc/pass*")
	if !strings.Contains(out, "/etc/passwd\n") || strings.Contains(out, "  ") {
		t.Errorf("ls off terminal = %q", out)
	}
}

package shell

import (
	"strings"
	"testing"
)

func TestUnameAndHost(t *testing.T) {
	in, s := testSession(t)
	if out, _, _ := run(t, in, s, "uname"); out != "Linux\n" {
		t.Errorf("uname = %q", out)
	}
	if out, _, _ := run(t, in, s, "uname -r"); out != "5.15.0-113-generic\n" {
		t.Errorf("uname -r = %q", out)
	}
	out, _, _ := run(t, in, s, "uname -a")
	if !strings.HasPrefix(out, "Linux srv-web01 5.15.0-113-generic") || !strings.Contains(out, "x86_64 GNU/Linux") {
		t.Errorf("uname -a = %q", out)
	}
	if out, _, _ := run(t, in, s, "hostname"); out != "srv-web01\n" {
		t.Errorf("hostname = %q", out)
	}
	if out, _, _ := run(t, in, s, "whoami"); out != "root\n" {
		t.Errorf("whoami = %q", out)
	}
}

func TestIDAndGroups(t *testing.T) {
	in, s := testSession(t)
	out, _, _ := run(t, in, s, "id")
	if !strings.HasPrefix(out, "uid=0(root) gid=0(root)") {
		t.Errorf("id = %q", out)
	}
	if out, _, _ := run(t, in, s, "id -u"); out != "0\n" {
		t.Errorf("id -u = %q", out)
	}
	// A non-root user reports their uid.
	as := NewSession(s.Machine, "martin", 5)
	out, _, _ = run(t, in, as, "id")
	if !strings.HasPrefix(out, "uid=1001(martin) gid=1001(martin)") {
		t.Errorf("martin id = %q", out)
	}
	if !strings.Contains(out, "sudo") {
		t.Errorf("martin should be in sudo group: %q", out)
	}
	if out, _, _ := run(t, in, as, "id -u"); out != "1001\n" {
		t.Errorf("martin id -u = %q", out)
	}
}

func TestPsAndUptime(t *testing.T) {
	in, s := testSession(t)
	out, _, _ := run(t, in, s, "ps aux")
	if !strings.Contains(out, "USER") || !strings.Contains(out, "nginx: master process") || !strings.Contains(out, "/sbin/init") {
		t.Errorf("ps aux missing rows:\n%s", out[:min2(len(out), 400)])
	}
	if !strings.Contains(out, "-bash") {
		t.Errorf("ps aux missing the session shell")
	}
	out, _, _ = run(t, in, s, "ps -ef")
	if !strings.Contains(out, "PPID") || !strings.Contains(out, "postgres") {
		t.Errorf("ps -ef = %q", out[:min2(len(out), 200)])
	}
	out, _, _ = run(t, in, s, "uptime")
	if !strings.Contains(out, "load average:") || !strings.Contains(out, "up ") {
		t.Errorf("uptime = %q", out)
	}
}

func TestFreeDfNprocLscpu(t *testing.T) {
	in, s := testSession(t)
	out, _, _ := run(t, in, s, "free -m")
	if !strings.Contains(out, "Mem:") || !strings.Contains(out, "Swap:") {
		t.Errorf("free = %q", out)
	}
	out, _, _ = run(t, in, s, "df -h")
	if !strings.Contains(out, "/dev/sda1") || !strings.Contains(out, "/boot/efi") {
		t.Errorf("df -h = %q", out)
	}
	if out, _, _ := run(t, in, s, "nproc"); out != "2\n" {
		t.Errorf("nproc = %q", out)
	}
	out, _, _ = run(t, in, s, "lscpu")
	if !strings.Contains(out, "Architecture:") || !strings.Contains(out, "CPU(s):") || !strings.Contains(out, "Xeon") {
		t.Errorf("lscpu = %q", out)
	}
}

func TestDateSleepSeq(t *testing.T) {
	in, s := testSession(t)
	out, _, _ := run(t, in, s, "date +%Y-%m-%d")
	if out != "2026-09-17\n" {
		t.Errorf("date = %q", out)
	}
	out, _, _ = run(t, in, s, "date +%s")
	if strings.TrimSpace(out) == "" {
		t.Errorf("date +%%s = %q", out)
	}
	// sleep is capped; this must return quickly.
	_, _, st := run(t, in, s, "sleep 9999")
	if st != 0 {
		t.Errorf("sleep status = %d", st)
	}
	out, _, _ = run(t, in, s, "seq 1 3")
	if out != "1\n2\n3\n" {
		t.Errorf("seq = %q", out)
	}
}

func TestSudoSu(t *testing.T) {
	in, s := testSession(t)
	// martin uses sudo to read shadow, which they cannot read directly.
	as := NewSession(s.Machine, "martin", 6)
	_, _, st := run(t, in, as, "cat /etc/shadow")
	if st == 0 {
		t.Fatal("martin should not read shadow directly")
	}
	out, _, st := run(t, in, as, "sudo cat /etc/shadow")
	if st != 0 || !strings.Contains(out, "root:$6$") {
		t.Errorf("sudo cat shadow = %q %d", out[:min2(len(out), 60)], st)
	}
	// After sudo, the session drops back to martin.
	if out, _, _ := run(t, in, as, "whoami"); out != "martin\n" {
		t.Errorf("post-sudo whoami = %q", out)
	}
	// su - switches the session user.
	run(t, in, as, "su -")
	if as.User != "root" || !as.Cred.IsRoot() {
		t.Errorf("su - did not switch to root: user=%s", as.User)
	}
	out, _, st = run(t, in, as, "sudo -u postgres whoami")
	if st != 0 || out != "postgres\n" {
		t.Errorf("sudo -u postgres whoami = %q %d", out, st)
	}
}

func TestBusyboxAndShellC(t *testing.T) {
	in, s := testSession(t)
	// Mirai probe.
	_, errb, st := run(t, in, s, "busybox ECCHI")
	if st != 127 || !strings.Contains(errb, "ECCHI: applet not found") {
		t.Errorf("busybox ECCHI = %q %d", errb, st)
	}
	// A real applet works.
	out, _, _ := run(t, in, s, "busybox echo hi")
	if out != "hi\n" {
		t.Errorf("busybox echo = %q", out)
	}
	// sh -c runs a command.
	out, _, _ = run(t, in, s, `sh -c "echo nested; echo again"`)
	if out != "nested\nagain\n" {
		t.Errorf("sh -c = %q", out)
	}
	// bash -c with a pipeline.
	out, _, _ = run(t, in, s, `bash -c "echo -e 'a\nb' | wc -l"`)
	if strings.TrimSpace(out) != "2" {
		t.Errorf("bash -c pipe = %q", out)
	}
}

func TestDpkgApt(t *testing.T) {
	in, s := testSession(t)
	out, _, _ := run(t, in, s, "dpkg -l")
	if !strings.Contains(out, "nginx") || !strings.Contains(out, "ii  ") {
		t.Errorf("dpkg -l = %q", out[:min2(len(out), 200)])
	}
	out, _, _ = run(t, in, s, "apt update")
	if !strings.Contains(out, "Hit:1") {
		t.Errorf("apt update = %q", out)
	}
	// Non-root install is refused.
	as := NewSession(s.Machine, "martin", 7)
	_, out2, st := runBoth(t, in, as, "apt install curl")
	_ = out2
	if st == 0 {
		t.Errorf("non-root apt install should fail, status %d", st)
	}
}

func runBoth(t *testing.T, in *Interp, s *Session, line string) (string, string, int) {
	return run(t, in, s, line)
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}

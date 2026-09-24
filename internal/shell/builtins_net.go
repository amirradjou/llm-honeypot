package shell

import (
	"fmt"
	"path"
	"strings"
)

func (in *Interp) registerNet() {
	in.Register("wget", cmdWget)
	in.Register("curl", cmdCurl)
	in.Register("tftp", cmdTftp)
	in.Register("ftpget", cmdFtpget)
	in.Register("ifconfig", cmdIfconfig)
	in.Register("ip", cmdIP)
	in.Register("netstat", cmdNetstat)
	in.Register("ss", cmdSs)
	in.Register("route", cmdRoute)
	in.Register("arp", cmdArp)
	in.Register("ping", cmdPing)
	in.Register("wget", cmdWget)
}

// recordDownload notes an attempted fetch and, if a save path is given,
// drops an opaque payload file there so later commands (ls, cat, chmod,
// ./x) behave as if the download succeeded — without ever fetching it.
func (c *Context) recordDownload(tool, url, method, saveAs string) {
	d := Download{Tool: tool, URL: url, Method: method}
	if saveAs != "" {
		abs := c.Sess.abs(saveAs)
		// Payloads are small opaque blobs; size is stable per URL.
		size := int64(24_000 + seedInode(url)%180_000)
		_ = c.FS().WriteOpaque(abs, size, []byte{0x7f, 'E', 'L', 'F'}, seedInode(url), c.writeOptsMode(0o644))
		d.SavedAs = abs
	}
	if c.Interp.OnDownload != nil {
		c.Interp.OnDownload(c, d)
	}
}

// urlBasename picks the filename a download would land in, like wget does.
func urlBasename(url string) string {
	u := url
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	u = strings.TrimRight(u, "/")
	base := path.Base(u)
	if base == "" || base == "." || base == "/" || !strings.Contains(base, ".") && base == u {
		return "index.html"
	}
	if base == "" {
		return "index.html"
	}
	return base
}

func hostOf(url string) string {
	u := url
	for _, p := range []string{"http://", "https://", "ftp://", "tftp://"} {
		u = strings.TrimPrefix(u, p)
	}
	if i := strings.IndexAny(u, "/:"); i >= 0 {
		u = u[:i]
	}
	return u
}

func cmdWget(c *Context) int {
	var url, output string
	quiet := false
	args := c.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-O" && i+1 < len(args):
			output = args[i+1]
			i++
		case strings.HasPrefix(a, "-O"):
			output = a[2:]
		case a == "-q" || a == "--quiet":
			quiet = true
		case a == "-P" && i+1 < len(args):
			output = path.Join(args[i+1], "")
			i++
		case a == "--no-check-certificate" || a == "-c" || a == "--no-check-cert" || strings.HasPrefix(a, "--"):
		case strings.HasPrefix(a, "-"):
		default:
			if url == "" {
				url = a
			}
		}
	}
	if url == "" {
		c.Print("wget: missing URL\n")
		return 1
	}
	saveAs := output
	if saveAs == "" || strings.HasSuffix(saveAs, "/") {
		saveAs = path.Join(strings.TrimSuffix(output, "/"), urlBasename(url))
	}
	host := hostOf(url)
	ip := fakeResolve(host)
	size := int64(24_000 + seedInode(url)%180_000)
	if !quiet {
		now := c.Sess.Machine.Now().Format("2006-01-02 15:04:05")
		c.Printf("--%s--  %s\n", now, url)
		c.Printf("Resolving %s (%s)... %s\n", host, host, ip)
		c.Printf("Connecting to %s (%s)|%s|:%s... connected.\n", host, host, ip, portFor(url))
		c.Print("HTTP request sent, awaiting response... 200 OK\n")
		c.Printf("Length: %d (%s) [application/octet-stream]\n", size, humanSize(size, true))
		c.Printf("Saving to: '%s'\n\n", saveAs)
		c.Printf("%-28s 100%%[===================>] %s  --.-KB/s    in 0.1s\n\n", path.Base(saveAs), humanSize(size, true))
		c.Printf("%s (2.13 MB/s) - '%s' saved [%d/%d]\n\n", now, saveAs, size, size)
	}
	c.recordDownload("wget", url, "GET", saveAs)
	return 0
}

func cmdCurl(c *Context) int {
	var url, output string
	toFile, silent := false, false
	method := "GET"
	args := c.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-o" && i+1 < len(args):
			output = args[i+1]
			toFile = true
			i++
		case a == "-O":
			toFile = true
		case a == "-s" || a == "--silent":
			silent = true
		case a == "-X" && i+1 < len(args):
			method = args[i+1]
			i++
		case a == "-d" || a == "--data":
			method = "POST"
			i++
		case a == "-I" || a == "--head":
			method = "HEAD"
		case a == "-L" || a == "-k" || a == "-f" || a == "-S" || strings.HasPrefix(a, "-"):
		default:
			if url == "" {
				url = a
			}
		}
	}
	if url == "" {
		c.Print("curl: try 'curl --help' for more information\n")
		return 2
	}
	saveAs := ""
	if toFile {
		if output != "" {
			saveAs = output
		} else {
			saveAs = urlBasename(url)
		}
	}
	if method == "HEAD" {
		c.Print("HTTP/1.1 200 OK\r\n")
		c.Print("Server: nginx\r\n")
		c.Printf("Date: %s\r\n", c.Sess.Machine.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
		c.Print("Content-Type: application/octet-stream\r\n")
		c.Print("Content-Length: 51242\r\n\r\n")
		c.recordDownload("curl", url, method, "")
		return 0
	}
	c.recordDownload("curl", url, method, saveAs)
	if !toFile && !silent {
		// Piping to a shell (curl ... | sh) is the classic; emit a short
		// shell-looking payload so the pipe has something, but never run it.
		c.Print("#!/bin/sh\n# (content not retrieved by honeypot)\n")
	}
	return 0
}

func fakeResolve(host string) string {
	h := seedInode(host)
	return fmt.Sprintf("%d.%d.%d.%d", 45+h%180, h%256, (h>>8)%256, 1+(h>>16)%254)
}

func portFor(url string) string {
	if strings.HasPrefix(url, "https://") {
		return "443"
	}
	if strings.HasPrefix(url, "ftp://") {
		return "21"
	}
	return "80"
}

func cmdTftp(c *Context) int {
	// tftp -g -r file host  or  tftp host then get. Bots use the -g form.
	var host, remote string
	args := c.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-g", "-l", "-p":
		case "-r":
			if i+1 < len(args) {
				remote = args[i+1]
				i++
			}
		default:
			host = args[i]
		}
	}
	if remote != "" {
		url := "tftp://" + host + "/" + remote
		c.recordDownload("tftp", url, "GET", remote)
	}
	return 0
}

func cmdFtpget(c *Context) int {
	// ftpget -v -u user -p pass host localfile remotefile
	nonflag := []string{}
	for i := 1; i < len(c.Args); i++ {
		a := c.Args[i]
		if strings.HasPrefix(a, "-") {
			if a == "-u" || a == "-p" {
				i++
			}
			continue
		}
		nonflag = append(nonflag, a)
	}
	if len(nonflag) >= 3 {
		host, local, remote := nonflag[0], nonflag[1], nonflag[2]
		c.recordDownload("ftpget", "ftp://"+host+"/"+remote, "GET", local)
	}
	return 0
}

func cmdIfconfig(c *Context) int {
	p := c.Sess.Machine.Profile
	rx, tx := 9182377, 12928311
	c.Printf("%s: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n", p.Interface)
	c.Printf("        inet %s  netmask %s  broadcast %s\n", p.IPv4, p.Netmask, broadcast(p.IPv4))
	c.Printf("        inet6 %s  prefixlen 64  scopeid 0x20<link>\n", linkLocal(p.MAC))
	c.Printf("        ether %s  txqueuelen 1000  (Ethernet)\n", p.MAC)
	c.Printf("        RX packets %d  bytes 9318472113 (9.3 GB)\n", rx)
	c.Print("        RX errors 0  dropped 0  overruns 0  frame 0\n")
	c.Printf("        TX packets %d  bytes 21873341922 (21.8 GB)\n", tx)
	c.Print("        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\n")
	c.Print("lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n")
	c.Print("        inet 127.0.0.1  netmask 255.0.0.0\n")
	c.Print("        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n")
	c.Print("        loop  txqueuelen 1000  (Local Loopback)\n")
	c.Print("        RX packets 261402  bytes 48211932 (48.2 MB)\n")
	c.Print("        RX errors 0  dropped 0  overruns 0  frame 0\n")
	c.Print("        TX packets 261402  bytes 48211932 (48.2 MB)\n")
	c.Print("        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\n")
	return 0
}

func cmdIP(c *Context) int {
	p := c.Sess.Machine.Profile
	if len(c.Args) < 2 {
		c.Print("Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n")
		return 1
	}
	obj := c.Args[1]
	switch {
	case strings.HasPrefix("addr", obj) || obj == "a" || obj == "address":
		c.Print("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n")
		c.Print("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n")
		c.Print("    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever\n")
		c.Print("    inet6 ::1/128 scope host\n       valid_lft forever preferred_lft forever\n")
		c.Printf("2: %s: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n", p.Interface)
		c.Printf("    link/ether %s brd ff:ff:ff:ff:ff:ff\n", p.MAC)
		c.Printf("    inet %s/24 brd %s scope global %s\n       valid_lft forever preferred_lft forever\n", p.IPv4, broadcast(p.IPv4), p.Interface)
		c.Printf("    inet6 %s/64 scope link\n       valid_lft forever preferred_lft forever\n", linkLocal(p.MAC))
	case strings.HasPrefix("route", obj) || obj == "r":
		c.Printf("default via %s dev %s proto static\n", p.Gateway, p.Interface)
		c.Printf("%s.0/24 dev %s proto kernel scope link src %s\n", netOf(p.IPv4), p.Interface, p.IPv4)
	case strings.HasPrefix("link", obj) || obj == "l":
		c.Print("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n")
		c.Print("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n")
		c.Printf("2: %s: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n", p.Interface)
		c.Printf("    link/ether %s brd ff:ff:ff:ff:ff:ff\n", p.MAC)
	}
	return 0
}

func cmdNetstat(c *Context) int {
	p := c.Sess.Machine.Profile
	c.Print("Active Internet connections (only servers)\n")
	c.Printf("%-6s %-6s %-6s %-23s %-23s %s\n", "Proto", "Recv-Q", "Send-Q", "Local Address", "Foreign Address", "State")
	listeners := []struct {
		proto, laddr, prog string
	}{
		{"tcp", "0.0.0.0:22", "672/sshd: /usr/sbin"},
		{"tcp", "0.0.0.0:80", "733/nginx: master"},
		{"tcp", "0.0.0.0:443", "733/nginx: master"},
		{"tcp", "127.0.0.1:5432", "801/postgres"},
		{"tcp", "127.0.0.1:3000", "912/node"},
		{"tcp6", ":::22", "672/sshd: /usr/sbin"},
	}
	wantProg := false
	for _, a := range c.Args[1:] {
		if strings.Contains(a, "p") {
			wantProg = true
		}
	}
	for _, l := range listeners {
		prog := ""
		if wantProg {
			prog = "  " + l.prog
		}
		c.Printf("%-6s %6d %6d %-23s %-23s %s%s\n", l.proto, 0, 0, l.laddr, "0.0.0.0:*", "LISTEN", prog)
	}
	c.Printf("tcp        0      0 %s:22          %s:52014       ESTABLISHED%s\n", p.IPv4, clientIP(c), progIf(wantProg, "672/sshd: root@pts/"))
	return 0
}

func progIf(want bool, s string) string {
	if want {
		return "  " + s
	}
	return ""
}

func cmdSs(c *Context) int {
	c.Printf("%-6s %-7s %-6s %-6s %-22s %-22s\n", "Netid", "State", "Recv-Q", "Send-Q", "Local Address:Port", "Peer Address:Port")
	rows := []struct{ state, laddr string }{
		{"LISTEN", "0.0.0.0:22"}, {"LISTEN", "0.0.0.0:80"}, {"LISTEN", "0.0.0.0:443"},
		{"LISTEN", "127.0.0.1:5432"}, {"LISTEN", "127.0.0.1:3000"},
	}
	for _, r := range rows {
		c.Printf("%-6s %-7s %-6d %-6d %-22s %-22s\n", "tcp", r.state, 0, 128, r.laddr, "0.0.0.0:*")
	}
	return 0
}

func cmdRoute(c *Context) int {
	p := c.Sess.Machine.Profile
	c.Print("Kernel IP routing table\n")
	c.Printf("%-15s %-15s %-15s %-5s %s %s %s %s\n", "Destination", "Gateway", "Genmask", "Flags", "Metric", "Ref", "Use", "Iface")
	c.Printf("%-15s %-15s %-15s %-5s %-6d %-3d %-3d %s\n", "0.0.0.0", p.Gateway, "0.0.0.0", "UG", 0, 0, 0, p.Interface)
	c.Printf("%-15s %-15s %-15s %-5s %-6d %-3d %-3d %s\n", netOf(p.IPv4)+".0", "0.0.0.0", "255.255.255.0", "U", 0, 0, 0, p.Interface)
	return 0
}

func cmdArp(c *Context) int {
	p := c.Sess.Machine.Profile
	c.Printf("%-22s %-8s %-19s %-6s %s\n", "Address", "HWtype", "HWaddress", "Flags", "Iface")
	c.Printf("%-22s %-8s %-19s %-6s %s\n", p.Gateway, "ether", "52:54:00:12:34:56", "C", p.Interface)
	return 0
}

func cmdPing(c *Context) int {
	_, hosts := splitFlags(c.Args[1:])
	if len(hosts) == 0 {
		c.Errorf("usage error: Destination address required")
		return 1
	}
	host := hosts[len(hosts)-1]
	ip := fakeResolve(host)
	c.Printf("PING %s (%s) 56(84) bytes of data.\n", host, ip)
	for i := 1; i <= 4; i++ {
		c.Printf("64 bytes from %s: icmp_seq=%d ttl=54 time=%d.%d ms\n", ip, i, 10+i, seedInode(host+itoa(i))%99)
	}
	c.Printf("\n--- %s ping statistics ---\n", host)
	c.Print("4 packets transmitted, 4 received, 0% packet loss, time 3005ms\n")
	c.Print("rtt min/avg/max/mdev = 10.112/12.500/14.203/1.520 ms\n")
	return 0
}

// --- small network formatting helpers ---

func broadcast(ip string) string {
	f := strings.Split(ip, ".")
	if len(f) != 4 {
		return ip
	}
	return f[0] + "." + f[1] + "." + f[2] + ".255"
}

func netOf(ip string) string {
	f := strings.Split(ip, ".")
	if len(f) != 4 {
		return ip
	}
	return f[0] + "." + f[1] + "." + f[2]
}

func linkLocal(mac string) string {
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return "fe80::1"
	}
	return fmt.Sprintf("fe80::%s%s:%sff:fe%s:%s%s", parts[0], parts[1], parts[2], parts[3], parts[4], parts[5])
}

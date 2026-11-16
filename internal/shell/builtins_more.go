package shell

import (
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

// More tools a stock Ubuntu 22.04 server answers and bots ask: getconf for
// the word size, sysctl for hugepages before a miner starts, whereis to
// find interpreters, od to look at a binary's header.
func (in *Interp) registerMore() {
	in.Register("getconf", cmdGetconf)
	in.Register("whereis", cmdWhereis)
	in.Register("sysctl", cmdSysctl)
	in.Register("od", cmdOd)
}

func cmdGetconf(c *Context) int {
	_, args := splitFlags(c.Args[1:])
	if len(args) == 0 {
		fmt.Fprint(c.Stderr, "Usage: getconf [-v specification] variable_name [pathname]\n       getconf -a [pathname]\n")
		return 1
	}
	cores := strconv.Itoa(c.Sess.Machine.Profile.CPUCores)
	vals := map[string]string{
		"LONG_BIT": "64", "WORD_BIT": "32", "PAGESIZE": "4096", "PAGE_SIZE": "4096",
		"_NPROCESSORS_ONLN": cores, "_NPROCESSORS_CONF": cores, "CLK_TCK": "100",
		"ARG_MAX": "2097152", "OPEN_MAX": "1024", "CHILD_MAX": "15541", "HOST_NAME_MAX": "64",
		"LOGIN_NAME_MAX": "256", "PATH_MAX": "4096", "NAME_MAX": "255", "LINE_MAX": "2048",
		"GNU_LIBC_VERSION": "glibc 2.35", "GNU_LIBPTHREAD_VERSION": "NPTL 2.35",
		"PATH": "/bin:/usr/bin", "INT_MAX": "2147483647",
	}
	v, ok := vals[args[0]]
	if !ok {
		fmt.Fprintf(c.Stderr, "getconf: Unrecognized variable `%s'\n", args[0])
		return 2
	}
	c.Print(v + "\n")
	return 0
}

func cmdWhereis(c *Context) int {
	_, names := splitFlags(c.Args[1:])
	if len(names) == 0 {
		fmt.Fprint(c.Stderr, "whereis: not enough arguments\nTry 'whereis --help' for more information.\n")
		return 1
	}
	dirs := []string{"/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/usr/lib", "/usr/libexec", "/etc", "/usr/share"}
	for _, n := range names {
		n = path.Base(n)
		var hits []string
		for _, d := range dirs {
			if _, err := c.FS().Stat(path.Join(d, n)); err == nil {
				hits = append(hits, path.Join(d, n))
			}
		}
		// Every packaged binary on a server ships a man page.
		if len(hits) > 0 && strings.HasPrefix(hits[0], "/usr/bin/") {
			hits = append(hits, "/usr/share/man/man1/"+n+".1.gz")
		} else if len(hits) > 0 && strings.HasPrefix(hits[0], "/usr/sbin/") {
			hits = append(hits, "/usr/share/man/man8/"+n+".8.gz")
		}
		if len(hits) == 0 {
			c.Print(n + ":\n")
			continue
		}
		c.Print(n + ": " + strings.Join(hits, " ") + "\n")
	}
	return 0
}

// sysctlDefaults are what a small 22.04 VPS reports for the keys bots read.
var sysctlDefaults = map[string]string{
	"vm.nr_hugepages": "0", "vm.swappiness": "60", "vm.overcommit_memory": "0",
	"vm.max_map_count": "65530", "vm.dirty_ratio": "20", "kernel.pid_max": "4194304",
	"kernel.randomize_va_space": "2", "kernel.panic": "0", "kernel.threads-max": "31083",
	"kernel.yama.ptrace_scope": "1", "kernel.kptr_restrict": "1", "kernel.dmesg_restrict": "1",
	"net.ipv4.ip_forward": "0", "net.ipv4.tcp_syncookies": "1", "net.core.somaxconn": "4096",
	"net.ipv4.ip_local_port_range": "32768\t60999", "fs.file-max": "9223372036854775807",
	"fs.inotify.max_user_watches": "61606",
}

func cmdSysctl(c *Context) int {
	quiet, valueOnly, all, write := false, false, false, false
	var keys []string
	for _, a := range c.Args[1:] {
		switch {
		case a == "-a" || a == "-A" || a == "-X" || a == "--all":
			all = true
		case a == "-n" || a == "--values":
			valueOnly = true
		case a == "-q" || a == "--quiet":
			quiet = true
		case a == "-w" || a == "--write":
			write = true
		case a == "-p" || a == "--load" || a == "--system":
			return 0
		case strings.HasPrefix(a, "-"):
		default:
			keys = append(keys, a)
		}
	}
	if all {
		names := make([]string, 0, len(sysctlDefaults))
		for k := range sysctlDefaults {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			c.Printf("%s = %s\n", k, c.sysctlGet(k))
		}
		return 0
	}
	status := 0
	for _, k := range keys {
		key, val, isSet := strings.Cut(k, "=")
		key = strings.ReplaceAll(strings.TrimSpace(key), "/", ".")
		procPath := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
		if isSet || write {
			if !isSet {
				fmt.Fprintf(c.Stderr, "sysctl: \"%s\" must be of the form name=value\n", k)
				status = 255
				continue
			}
			if _, known := sysctlDefaults[key]; !known && !c.FS().Exists(procPath) {
				fmt.Fprintf(c.Stderr, "sysctl: cannot stat %s: No such file or directory\n", procPath)
				status = 255
				continue
			}
			if !c.Sess.Cred.IsRoot() {
				fmt.Fprintf(c.Stderr, "sysctl: permission denied on key \"%s\"\n", key)
				status = 255
				continue
			}
			val = strings.TrimSpace(val)
			_ = c.FS().MkdirAll(path.Dir(procPath), vfs.WriteOptions{Mode: 0o555})
			_ = c.FS().WriteFile(procPath, []byte(val+"\n"), vfs.WriteOptions{Mode: 0o644})
			if !quiet {
				c.Printf("%s = %s\n", key, val)
			}
			continue
		}
		v := c.sysctlGet(key)
		if v == "" {
			fmt.Fprintf(c.Stderr, "sysctl: cannot stat %s: No such file or directory\n", procPath)
			status = 255
			continue
		}
		if valueOnly {
			c.Print(v + "\n")
		} else {
			c.Printf("%s = %s\n", key, v)
		}
	}
	return status
}

// sysctlGet reads a key from the session's /proc/sys first (so a value an
// attacker set sticks), then the defaults.
func (c *Context) sysctlGet(key string) string {
	if data, _, err := c.FS().ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/")); err == nil {
		return strings.TrimRight(string(data), "\n")
	}
	return sysctlDefaults[key]
}

// odMax bounds how much one od call dumps.
const odMax = 1 << 20

func cmdOd(c *Context) int {
	radix := "o"
	type spec struct {
		kind byte // o x d u c a
		size int
	}
	var specs []spec
	limit, skip := -1, 0
	verbose := false
	var files []string
	args := c.Args[1:]
	addType := func(t string) bool {
		for len(t) > 0 {
			k := t[0]
			t = t[1:]
			size := 1
			switch k {
			case 'c', 'a':
			case 'o', 'x', 'd', 'u':
				size = 4
				if len(t) > 0 && t[0] >= '1' && t[0] <= '8' {
					size = int(t[0] - '0')
					t = t[1:]
				}
			default:
				return false
			}
			specs = append(specs, spec{k, size})
		}
		return true
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		val := func(flag string) string {
			if a == flag && i+1 < len(args) {
				i++
				return args[i]
			}
			return strings.TrimPrefix(a, flag)
		}
		switch {
		case strings.HasPrefix(a, "-A"):
			radix = val("-A")
		case strings.HasPrefix(a, "-t"):
			if !addType(val("-t")) {
				fmt.Fprintf(c.Stderr, "od: invalid type string '%s'\n", a)
				return 1
			}
		case strings.HasPrefix(a, "-N"):
			limit, _ = strconv.Atoi(val("-N"))
		case strings.HasPrefix(a, "-j"):
			skip, _ = strconv.Atoi(val("-j"))
		case a == "-v":
			verbose = true
		case a == "-c":
			specs = append(specs, spec{'c', 1})
		case a == "-b":
			specs = append(specs, spec{'o', 1})
		case a == "-x":
			specs = append(specs, spec{'x', 2})
		case a == "-d":
			specs = append(specs, spec{'u', 2})
		case a == "-o":
			specs = append(specs, spec{'o', 2})
		case strings.HasPrefix(a, "-") && a != "-":
			fmt.Fprintf(c.Stderr, "od: invalid option -- '%s'\nTry 'od --help' for more information.\n", strings.TrimLeft(a, "-"))
			return 1
		default:
			files = append(files, a)
		}
	}
	if len(specs) == 0 {
		specs = []spec{{'o', 2}}
	}
	var data []byte
	if len(files) == 0 {
		data, _ = io.ReadAll(io.LimitReader(c.Stdin, odMax))
	}
	for _, f := range files {
		d, err := c.readTarget(f)
		if err != nil {
			fmt.Fprintf(c.Stderr, "od: %s: No such file or directory\n", f)
			return 1
		}
		data = append(data, d...)
	}
	if skip > 0 {
		data = data[min(skip, len(data)):]
	}
	if limit >= 0 && limit < len(data) {
		data = data[:limit]
	}
	if len(data) > odMax {
		data = data[:odMax]
	}
	offset := func(n int) string {
		switch radix {
		case "n":
			return ""
		case "d":
			return fmt.Sprintf("%07d", n+skip)
		case "x":
			return fmt.Sprintf("%06x", n+skip)
		}
		return fmt.Sprintf("%07o", n+skip)
	}
	var prev []byte
	starred := false
	for at := 0; at < len(data); at += 16 {
		row := data[at:min(at+16, len(data))]
		if !verbose && prev != nil && len(row) == 16 && string(row) == string(prev) {
			if !starred {
				c.Print("*\n")
				starred = true
			}
			continue
		}
		starred = false
		prev = row
		for k, sp := range specs {
			lead := offset(at)
			if k > 0 {
				lead = strings.Repeat(" ", len(lead))
			}
			c.Print(lead + odRow(row, sp.kind, sp.size) + "\n")
		}
	}
	if radix != "n" {
		c.Print(offset(len(data)) + "\n")
	}
	return 0
}

// odRow formats one 16-byte row in GNU od's column widths.
func odRow(row []byte, kind byte, size int) string {
	var b strings.Builder
	if kind == 'c' || kind == 'a' {
		for _, ch := range row {
			b.WriteString(fmt.Sprintf("%4s", odChar(ch)))
		}
		return b.String()
	}
	widths := map[byte]map[int]int{
		'o': {1: 3, 2: 6, 4: 11, 8: 22},
		'x': {1: 2, 2: 4, 4: 8, 8: 16},
		'd': {1: 4, 2: 6, 4: 11, 8: 20},
		'u': {1: 3, 2: 5, 4: 10, 8: 20},
	}
	w := widths[kind][size]
	if w == 0 {
		size, w = 4, widths[kind][4]
	}
	for i := 0; i < len(row); i += size {
		chunk := make([]byte, 8)
		copy(chunk, row[i:min(i+size, len(row))])
		v := binary.LittleEndian.Uint64(chunk)
		switch kind {
		case 'o':
			fmt.Fprintf(&b, " %0*o", w, v)
		case 'x':
			fmt.Fprintf(&b, " %0*x", w, v)
		case 'u':
			fmt.Fprintf(&b, " %*d", w, v)
		case 'd':
			var sv int64
			switch size {
			case 1:
				sv = int64(int8(v))
			case 2:
				sv = int64(int16(v))
			case 4:
				sv = int64(int32(v))
			default:
				sv = int64(v)
			}
			fmt.Fprintf(&b, " %*d", w, sv)
		}
	}
	return b.String()
}

func odChar(ch byte) string {
	switch ch {
	case 0:
		return `\0`
	case '\a':
		return `\a`
	case '\b':
		return `\b`
	case '\f':
		return `\f`
	case '\n':
		return `\n`
	case '\r':
		return `\r`
	case '\t':
		return `\t`
	case '\v':
		return `\v`
	}
	if ch >= 32 && ch < 127 {
		return string(ch)
	}
	return fmt.Sprintf("%03o", ch)
}

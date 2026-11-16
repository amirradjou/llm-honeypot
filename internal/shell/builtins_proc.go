package shell

import (
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

// registerProcTools adds process lookup and low-level file tools that ship
// with every Ubuntu server (procps, coreutils, e2fsprogs, file) and that
// bot scripts use to find competitors, read ELF headers and lock files.
func (in *Interp) registerProcTools() {
	in.Register("pgrep", cmdPgrep)
	in.Register("pidof", cmdPidof)
	in.Register("dd", cmdDd)
	in.Register("chattr", cmdChattr)
	in.Register("lsattr", cmdLsattr)
	in.Register("file", cmdFile)
}

// procEntry is one process as pgrep/pidof see it.
type procEntry struct {
	pid  int
	user string
	name string // comm: base name of the program
	cmd  string // full command line
}

func (c *Context) processes() []procEntry {
	var out []procEntry
	for _, p := range c.Sess.Machine.Profile.Processes {
		cmd := p.Command
		name := strings.Trim(strings.Fields(cmd + " x")[0], "[]")
		if !strings.HasPrefix(cmd, "[") {
			name = path.Base(name)
		}
		name = strings.TrimSuffix(name, ":")
		if len(name) > 15 {
			name = name[:15]
		}
		out = append(out, procEntry{pid: p.PID, user: p.User, name: name, cmd: cmd})
	}
	out = append(out, procEntry{pid: c.Sess.PID, user: c.Sess.User, name: "bash", cmd: "-bash"})
	return out
}

func cmdPgrep(c *Context) int {
	full, exact, list, listFull, count, newest, oldest := false, false, false, false, false, false, false
	user := ""
	var pattern string
	havePat := false
	args := c.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-u" && i+1 < len(args):
			user = args[i+1]
			i++
		case a == "-V" || a == "--version":
			c.Print("pgrep from procps-ng 3.3.17\n")
			return 0
		case strings.HasPrefix(a, "-") && len(a) > 1 && !havePat:
			for _, r := range a[1:] {
				switch r {
				case 'f':
					full = true
				case 'x':
					exact = true
				case 'l':
					list = true
				case 'a':
					listFull = true
				case 'c':
					count = true
				case 'n':
					newest = true
				case 'o':
					oldest = true
				case '9', 'i':
				}
			}
		default:
			if !havePat {
				pattern, havePat = a, true
			}
		}
	}
	if !havePat && user == "" {
		fmt.Fprint(c.Stderr, "pgrep: no matching criteria specified\nTry `pgrep --help' for more information.\n")
		return 2
	}
	var re *regexp.Regexp
	if havePat {
		expr := pattern
		if exact {
			expr = "^(?:" + expr + ")$"
		}
		var err error
		if re, err = compileRegex(expr, true, false); err != nil {
			fmt.Fprint(c.Stderr, "pgrep: invalid regular expression\n")
			return 2
		}
	}
	var hits []procEntry
	for _, p := range c.processes() {
		if user != "" && p.user != user {
			continue
		}
		subject := p.name
		if full {
			subject = p.cmd
		}
		if re != nil && !re.MatchString(subject) {
			continue
		}
		hits = append(hits, p)
	}
	if (newest || oldest) && len(hits) > 1 {
		if newest {
			hits = hits[len(hits)-1:]
		} else {
			hits = hits[:1]
		}
	}
	if count {
		c.Printf("%d\n", len(hits))
	} else {
		for _, p := range hits {
			switch {
			case listFull:
				c.Printf("%d %s\n", p.pid, p.cmd)
			case list:
				c.Printf("%d %s\n", p.pid, p.name)
			default:
				c.Printf("%d\n", p.pid)
			}
		}
	}
	if len(hits) == 0 {
		return 1
	}
	return 0
}

func cmdPidof(c *Context) int {
	_, names := splitFlags(c.Args[1:])
	var pids []int
	for _, p := range c.processes() {
		for _, n := range names {
			if p.name == path.Base(n) {
				pids = append(pids, p.pid)
			}
		}
	}
	if len(pids) == 0 {
		return 1
	}
	sort.Sort(sort.Reverse(sort.IntSlice(pids)))
	strs := make([]string, len(pids))
	for i, p := range pids {
		strs[i] = strconv.Itoa(p)
	}
	c.Print(strings.Join(strs, " ") + "\n")
	return 0
}

// ddMaxCopy bounds how many real bytes one dd stores; larger copies from
// /dev/zero or /dev/urandom become opaque files that only report a size.
const ddMaxCopy = 8 << 20

func cmdDd(c *Context) int {
	ifile, ofile := "", ""
	bs, count, skip := int64(512), int64(-1), int64(0)
	quiet := false
	for _, a := range c.Args[1:] {
		if a == "--version" {
			c.Print("dd (coreutils) 8.32\n")
			return 0
		}
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			fmt.Fprintf(c.Stderr, "dd: unrecognized operand '%s'\nTry 'dd --help' for more information.\n", a)
			return 1
		}
		switch k {
		case "if":
			ifile = v
		case "of":
			ofile = v
		case "bs", "ibs":
			n, err := ddSize(v)
			if err != nil || n <= 0 {
				fmt.Fprintf(c.Stderr, "dd: invalid number: '%s'\n", v)
				return 1
			}
			bs = n
		case "count":
			n, err := ddSize(v)
			if err != nil {
				fmt.Fprintf(c.Stderr, "dd: invalid number: '%s'\n", v)
				return 1
			}
			count = n
		case "skip":
			n, _ := ddSize(v)
			skip = n
		case "status":
			quiet = v == "none"
		case "obs", "seek", "conv", "iflag", "oflag":
		default:
			fmt.Fprintf(c.Stderr, "dd: unrecognized operand '%s'\nTry 'dd --help' for more information.\n", a)
			return 1
		}
	}
	want := int64(-1)
	if count >= 0 {
		want = count * bs
	}

	var data []byte
	synthetic := false // /dev/zero and friends: any length is available
	switch ifile {
	case "/dev/zero", "/dev/urandom", "/dev/random":
		synthetic = true
		if want < 0 {
			// An unbounded read from /dev/zero would run until the disk is
			// full; say so the way dd does on a small box.
			want = ddMaxCopy
		}
	case "", "-":
		data, _ = io.ReadAll(c.Stdin)
	case "/dev/null":
	default:
		abs := c.Sess.abs(ifile)
		if info, err := c.FS().Stat(abs); err == nil && info.IsDir() {
			fmt.Fprintf(c.Stderr, "dd: error reading '%s': Is a directory\n", ifile)
			return 1
		}
		d, err := c.readTarget(ifile)
		if err != nil {
			fmt.Fprintf(c.Stderr, "dd: failed to open '%s': No such file or directory\n", ifile)
			return 1
		}
		data = d
	}

	var n int64
	if synthetic {
		n = want
	} else {
		if skip*bs < int64(len(data)) {
			data = data[skip*bs:]
		} else {
			data = nil
		}
		if want >= 0 && want < int64(len(data)) {
			data = data[:want]
		}
		n = int64(len(data))
	}

	if ofile == "" || ofile == "-" || ofile == "/dev/stdout" {
		if synthetic {
			data = make([]byte, min(n, ddMaxCopy))
		}
		c.Stdout.Write(data)
	} else if ofile != "/dev/null" {
		abs := c.Sess.abs(ofile)
		var err error
		if synthetic && n > ddMaxCopy {
			err = c.FS().WriteOpaque(abs, n, nil, seedInode(abs), c.writeOpts())
		} else {
			if synthetic {
				data = make([]byte, n)
			}
			err = c.FS().WriteFile(abs, data, c.writeOpts())
		}
		if err != nil {
			fmt.Fprintf(c.Stderr, "dd: failed to open '%s': %s\n", ofile, vfs.Strerror(err))
			return 1
		}
	}
	if !quiet {
		full, partial := n/bs, int64(0)
		if n%bs != 0 {
			partial = 1
		}
		secs := 0.000041 + float64(n)/1.4e9
		fmt.Fprintf(c.Stderr, "%d+%d records in\n%d+%d records out\n", full, partial, full, partial)
		if n >= 1000 {
			fmt.Fprintf(c.Stderr, "%d bytes (%s, %s) copied, %s s, %s/s\n", n, siSize(float64(n)), iecSize(float64(n)), shortFloat(secs), ddSpeed(float64(n)/secs))
		} else {
			fmt.Fprintf(c.Stderr, "%d bytes copied, %s s, %s/s\n", n, shortFloat(secs), ddSpeed(float64(n)/secs))
		}
	}
	return 0
}

func ddSize(s string) (int64, error) {
	mult := int64(1)
	for _, suf := range []struct {
		s string
		m int64
	}{{"kB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000}, {"K", 1024}, {"k", 1024}, {"M", 1 << 20}, {"G", 1 << 30}, {"c", 1}, {"w", 2}, {"b", 512}} {
		if strings.HasSuffix(s, suf.s) {
			s, mult = strings.TrimSuffix(s, suf.s), suf.m
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n * mult, err
}

func shortFloat(f float64) string {
	return strconv.FormatFloat(f, 'g', 6, 64)
}

// ddSpeed prints a rate with three significant digits, as dd does
// ("96.8 kB/s", "11.5 GB/s").
func ddSpeed(n float64) string {
	units := []string{"B", "kB", "MB", "GB", "TB"}
	i := 0
	for n >= 1000 && i < len(units)-1 {
		n /= 1000
		i++
	}
	switch {
	case n < 10:
		return fmt.Sprintf("%.2f %s", n, units[i])
	case n < 100:
		return fmt.Sprintf("%.1f %s", n, units[i])
	}
	return fmt.Sprintf("%.0f %s", n, units[i])
}

func siSize(n float64) string  { return humanUnits(n, 1000, []string{"B", "kB", "MB", "GB", "TB"}) }
func iecSize(n float64) string { return humanUnits(n, 1024, []string{"B", "KiB", "MiB", "GiB", "TiB"}) }

func humanUnits(n, base float64, units []string) string {
	i := 0
	for n >= base && i < len(units)-1 {
		n /= base
		i++
	}
	if n < 10 && i > 0 {
		return fmt.Sprintf("%.1f %s", n, units[i])
	}
	return fmt.Sprintf("%.0f %s", n, units[i])
}

func cmdChattr(c *Context) int {
	var files []string
	haveMode := false
	for _, a := range c.Args[1:] {
		switch {
		case a == "-R" || a == "-V" || a == "-f":
		case strings.HasPrefix(a, "+") || strings.HasPrefix(a, "-") || strings.HasPrefix(a, "="):
			haveMode = true
		default:
			files = append(files, a)
		}
	}
	if !haveMode || len(files) == 0 {
		fmt.Fprint(c.Stderr, "Usage: chattr [-pRVf] [-+=aAcCdDeijPsStTuFx] [-v version] files...\n")
		return 1
	}
	status := 0
	for _, f := range files {
		if _, err := c.FS().Lstat(c.Sess.abs(f)); err != nil {
			fmt.Fprintf(c.Stderr, "chattr: No such file or directory while trying to stat %s\n", f)
			status = 1
		}
	}
	return status
}

func cmdLsattr(c *Context) int {
	_, files := splitFlags(c.Args[1:])
	const attrs = "--------------e-------"
	if len(files) == 0 {
		entries, err := c.FS().ReadDir(c.Sess.Cwd)
		if err != nil {
			return 1
		}
		for _, e := range entries {
			if !strings.HasPrefix(e.Name, ".") {
				c.Printf("%s ./%s\n", attrs, e.Name)
			}
		}
		return 0
	}
	status := 0
	for _, f := range files {
		if _, err := c.FS().Stat(c.Sess.abs(f)); err != nil {
			fmt.Fprintf(c.Stderr, "lsattr: No such file or directory while trying to stat %s\n", f)
			status = 1
			continue
		}
		c.Printf("%s %s\n", attrs, f)
	}
	return status
}

func cmdFile(c *Context) int {
	brief := false
	var names []string
	for _, a := range c.Args[1:] {
		switch {
		case a == "--version" || a == "-v":
			c.Print("file-5.41\nmagic file from /etc/magic:/usr/share/misc/magic\n")
			return 0
		case a == "-b" || a == "--brief":
			brief = true
		case strings.HasPrefix(a, "-"):
		default:
			names = append(names, a)
		}
	}
	if len(names) == 0 {
		fmt.Fprint(c.Stderr, "Usage: file [-bcCdEhikLlNnprsSvzZ0] [--apple] [--extension] [--mime-encoding]\n            [--mime-type] [-e <testname>] [-F <separator>]  [-f <namefile>]\n            [-m <magicfiles>] [-P <parameter=value>] [--exclude-quiet]\n            <file> ...\n       file -C [-m <magicfiles>]\n       file [--help]\n")
		return 1
	}
	width := 0
	if len(names) > 1 {
		for _, n := range names {
			width = max(width, len(n)+1)
		}
	}
	for _, n := range names {
		desc := c.describeFile(n)
		if brief {
			c.Print(desc + "\n")
		} else {
			c.Printf("%-*s %s\n", width, n+":", desc)
		}
	}
	return 0
}

func (c *Context) describeFile(name string) string {
	abs := c.Sess.abs(name)
	info, err := c.FS().Lstat(abs)
	if err != nil {
		return fmt.Sprintf("cannot open `%s' (No such file or directory)", name)
	}
	switch {
	case info.Mode&fs.ModeSymlink != 0:
		return "symbolic link to " + info.Target
	case info.IsDir() && info.Mode&fs.ModeSticky != 0:
		return "sticky, directory"
	case info.IsDir():
		return "directory"
	case info.Mode&fs.ModeCharDevice != 0:
		if dev, ok := map[string]string{"/dev/null": "1/3", "/dev/zero": "1/5", "/dev/full": "1/7", "/dev/random": "1/8", "/dev/urandom": "1/9", "/dev/tty": "5/0", "/dev/ptmx": "5/2"}[abs]; ok {
			return "character special (" + dev + ")"
		}
		return "character special"
	case info.Mode&fs.ModeDevice != 0:
		return "block special"
	}
	data, _, err := c.FS().ReadFile(abs)
	if err != nil {
		return "regular file, no read permission"
	}
	if len(data) == 0 {
		return "empty"
	}
	// Seeded system binaries carry a full x86-64 ELF identification;
	// downloaded payloads only claim the magic bytes.
	if len(data) >= 20 && string(data[:4]) == "\x7fELF" && data[4] == 2 && data[5] == 1 && data[18] == 0x3e {
		return "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=" +
			fmt.Sprintf("%016x%016x%08x", seedInode(abs), seedInode(abs+"1"), uint32(seedInode(abs+"2"))) + ", for GNU/Linux 3.2.0, stripped"
	}
	head := data[:min(len(data), 4096)]
	if !utf8.Valid(head) || strings.ContainsRune(string(head), 0) {
		return "data"
	}
	text := string(head)
	kind := "ASCII text"
	for _, r := range text {
		if r > 127 {
			kind = "Unicode text, UTF-8 text"
			break
		}
	}
	switch {
	case strings.HasPrefix(text, "#!/bin/bash") || strings.HasPrefix(text, "#!/usr/bin/env bash"):
		return "Bourne-Again shell script, " + kind + " executable"
	case strings.HasPrefix(text, "#!/bin/sh"):
		return "POSIX shell script, " + kind + " executable"
	case strings.HasPrefix(text, "#!/usr/bin/env python") || strings.HasPrefix(text, "#!/usr/bin/python"):
		return "Python script, " + kind + " executable"
	}
	for _, line := range strings.Split(text, "\n") {
		if len(line) > 300 {
			return kind + ", with very long lines (" + strconv.Itoa(len(line)) + ")"
		}
	}
	return kind
}

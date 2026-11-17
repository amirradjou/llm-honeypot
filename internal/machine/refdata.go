package machine

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"embed"
	"io"
	"path"
	"strconv"
	"strings"
	"sync"
)

// refdata/ is recorded from a real Ubuntu 22.04 VPS with the default
// profile's packages (scripts/record-refdata.sh, tools/refdata/Dockerfile):
// the package database, the contents of /usr/bin and /usr/sbin, stock config
// files and the install logs. Re-record it; never edit it by hand.
//
//go:embed refdata
var refFS embed.FS

// refFile returns a recorded file, inflating the .gz copy if that is how it
// is stored. The result is shared between callers and must not be modified.
// A missing file is a build mistake, so it panics.
func refFile(name string) []byte {
	if data, ok := refCache.Load(name); ok {
		return data.([]byte)
	}
	data := readRef(name)
	refCache.Store(name, data)
	return data
}

var refCache sync.Map

func readRef(name string) []byte {
	if data, err := refFS.ReadFile("refdata/" + name); err == nil {
		return data
	}
	gz, err := refFS.ReadFile("refdata/" + name + ".gz")
	if err != nil {
		panic("machine: missing reference file " + name)
	}
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		panic("machine: bad reference file " + name + ": " + err.Error())
	}
	data, err := io.ReadAll(r)
	if err != nil {
		panic("machine: bad reference file " + name + ": " + err.Error())
	}
	return data
}

// refString is a one-line recorded value without its newline.
func refString(name string) string { return strings.TrimSpace(string(refFile(name))) }

// Package is one installed package as dpkg -l lists it.
type Package struct {
	Name    string // without the :arch suffix
	Version string
	Arch    string
	// Line is the package's row in `dpkg -l`, exactly as recorded.
	Line string
}

// refBin is one entry of /usr/bin, /usr/sbin or /etc/alternatives.
type refBin struct {
	link   bool
	mode   uint32
	size   int64
	group  string
	path   string
	target string
}

// refSet is everything recorded, parsed once.
type refSet struct {
	dpkgHeader string // the five header lines of dpkg -l
	packages   []Package
	byName     map[string]int // name -> index in packages
	status     map[string]string
	bins       []refBin
	sizes      map[string]int64
}

var reference = sync.OnceValue(func() *refSet {
	r := &refSet{byName: map[string]int{}, status: map[string]string{}, sizes: map[string]int64{}}

	sc := bufio.NewScanner(bytes.NewReader(refFile("dpkg-l.txt")))
	var hdr strings.Builder
	for n := 0; sc.Scan(); n++ {
		line := sc.Text()
		if n < 5 {
			hdr.WriteString(line + "\n")
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		name, _, _ := strings.Cut(f[1], ":")
		r.byName[name] = len(r.packages)
		r.packages = append(r.packages, Package{Name: name, Version: f[2], Arch: f[3], Line: line})
	}
	r.dpkgHeader = hdr.String()

	for _, stanza := range strings.Split(strings.TrimSpace(string(refFile("status"))), "\n\n") {
		if name, ok := strings.CutPrefix(stanza, "Package: "); ok {
			name, _, _ = strings.Cut(name, "\n")
			r.status[name] = stanza + "\n"
		}
	}

	sc = bufio.NewScanner(bytes.NewReader(refFile("bins.tsv")))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 7 {
			continue
		}
		mode, _ := strconv.ParseUint(f[1], 8, 32)
		size, _ := strconv.ParseInt(f[2], 10, 64)
		r.bins = append(r.bins, refBin{link: f[0] == "l", mode: uint32(mode), size: size, group: f[4], path: f[5], target: f[6]})
	}

	for _, line := range strings.Split(strings.TrimSpace(string(refFile("sizes.txt"))), "\n") {
		if n, p, ok := strings.Cut(line, " "); ok {
			size, _ := strconv.ParseInt(n, 10, 64)
			r.sizes[path.Base(p)] = size
		}
	}
	return r
})

// Packages lists every installed package, in dpkg -l order.
func (m *Machine) Packages() []Package { return reference().packages }

// Package finds an installed package by name.
func (m *Machine) Package(name string) (Package, bool) {
	r := reference()
	i, ok := r.byName[name]
	if !ok {
		return Package{}, false
	}
	return r.packages[i], true
}

// DpkgHeader is the header dpkg -l prints above the package rows.
func (m *Machine) DpkgHeader() string { return reference().dpkgHeader }

// PackageStatus is the package's stanza in /var/lib/dpkg/status, for
// dpkg -s, or "" when it is not installed.
func (m *Machine) PackageStatus(name string) string { return reference().status[name] }

// AptListInstalled is `apt list --installed` without the warning apt
// prints to stderr.
func (m *Machine) AptListInstalled() []byte { return refFile("apt-list-installed.txt") }

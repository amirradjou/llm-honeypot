// Package profile describes the machine the honeypot pretends to be. One
// profile seeds the virtual filesystem and feeds every command that
// reports on the system, so that uname, /etc/os-release, ps and the
// model-generated output all describe the same box.
package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// User is an account on the fake machine.
type User struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Gecos string `json:"gecos"`
	Home  string `json:"home"`
	Shell string `json:"shell"`
}

// Process is a row in the fake process table.
type Process struct {
	PID     int     `json:"pid"`
	User    string  `json:"user"`
	CPU     float64 `json:"cpu"`
	Mem     float64 `json:"mem"`
	VSZ     int     `json:"vsz"`
	RSS     int     `json:"rss"`
	TTY     string  `json:"tty"`
	Stat    string  `json:"stat"`
	Start   string  `json:"start"`
	Time    string  `json:"time"`
	Command string  `json:"command"`
}

// Profile is everything static about the fake machine.
type Profile struct {
	Hostname string `json:"hostname"`
	Domain   string `json:"domain"`
	// OSName / OSVersion / OSCodename fill /etc/os-release and lsb_release.
	OSName     string `json:"os_name"`
	OSVersion  string `json:"os_version"`
	OSCodename string `json:"os_codename"`
	OSPretty   string `json:"os_pretty"`
	// Kernel is the uname -r string; KernelVersion the uname -v string.
	Kernel        string `json:"kernel"`
	KernelVersion string `json:"kernel_version"`
	Arch          string `json:"arch"`
	CPUModel      string `json:"cpu_model"`
	CPUCores      int    `json:"cpu_cores"`
	MemMB         int    `json:"mem_mb"`
	SwapMB        int    `json:"swap_mb"`
	DiskGB        int    `json:"disk_gb"`
	DiskUsedPct   int    `json:"disk_used_pct"`
	Interface     string `json:"interface"`
	IPv4          string `json:"ipv4"`
	Netmask       string `json:"netmask"`
	Gateway       string `json:"gateway"`
	MAC           string `json:"mac"`
	Timezone      string `json:"timezone"`
	// BootedAgo is how long the box claims to have been up when the
	// honeypot starts; uptime grows from there.
	BootedAgo time.Duration `json:"booted_ago"`
	// Role is a one-line description used in the model prompt, e.g.
	// "small Ubuntu VPS running nginx and a Node.js app for a bakery".
	Role      string    `json:"role"`
	Users     []User    `json:"users"`
	Processes []Process `json:"processes"`
	// Packages is a sample of installed packages for dpkg -l and the prompt.
	Packages []string `json:"packages"`
}

// Load reads a JSON profile from path. Fields left out keep the Default
// values, so a profile file only needs to list what differs.
func Load(path string) (*Profile, error) {
	p := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	if err := json.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("parse profile %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("profile %s: %w", path, err)
	}
	return p, nil
}

// Validate checks the profile is complete enough to seed a machine.
func (p *Profile) Validate() error {
	if p.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}
	if len(p.Users) == 0 {
		return fmt.Errorf("at least one user is required")
	}
	if p.User("root") == nil {
		return fmt.Errorf("a root user is required")
	}
	if p.CPUCores <= 0 || p.MemMB <= 0 || p.DiskGB <= 0 {
		return fmt.Errorf("cpu_cores, mem_mb and disk_gb must be positive")
	}
	return nil
}

// User finds an account by name, or returns nil.
func (p *Profile) User(name string) *User {
	for i := range p.Users {
		if p.Users[i].Name == name {
			return &p.Users[i]
		}
	}
	return nil
}

// FQDN is hostname.domain, or just the hostname when there is no domain.
func (p *Profile) FQDN() string {
	if p.Domain == "" {
		return p.Hostname
	}
	return p.Hostname + "." + p.Domain
}

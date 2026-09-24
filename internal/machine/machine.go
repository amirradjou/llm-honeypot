// Package machine turns a profile into a fully populated template
// filesystem plus the little bit of dynamic state (clock, load) that the
// fake box needs. Sessions take a clone of the template so nothing an
// attacker does leaks into the next session.
package machine

import (
	"fmt"
	"hash/fnv"
	"math"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/profile"
	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

// Machine is the fake box: its profile, the seeded template filesystem
// and the clock that uptime and load are derived from.
type Machine struct {
	Profile  *profile.Profile
	FS       *vfs.FS
	BootTime time.Time
	// Now is the clock; tests replace it.
	Now func() time.Time
}

// New seeds a machine from p. now is used for the boot time and for the
// "seeded on" reference point of every generated timestamp.
func New(p *profile.Profile, now func() time.Time) (*Machine, error) {
	if now == nil {
		now = time.Now
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("machine: %w", err)
	}
	m := &Machine{Profile: p, Now: now, BootTime: now().Add(-p.BootedAgo)}
	m.FS = vfs.New()
	m.FS.Now = now
	if err := m.seed(); err != nil {
		return nil, fmt.Errorf("machine: seed: %w", err)
	}
	return m, nil
}

// Uptime is how long the box claims to have been running.
func (m *Machine) Uptime() time.Duration {
	return m.Now().Sub(m.BootTime)
}

// LoadAvg returns plausible 1/5/15 minute load averages for a mostly idle
// server. They drift slowly with time so repeated calls differ a little,
// and they are a pure function of the clock so they never jump.
func (m *Machine) LoadAvg() (l1, l5, l15 float64) {
	t := float64(m.Now().Unix())
	base := 0.04 + 0.02*float64(m.Profile.CPUCores)
	l1 = base + 0.06*math.Abs(math.Sin(t/97)) + 0.03*math.Abs(math.Sin(t/13))
	l5 = base + 0.04*math.Abs(math.Sin(t/311))
	l15 = base + 0.02*math.Abs(math.Sin(t/907))
	return round2(l1), round2(l5), round2(l15)
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

// NewSessionFS returns an independent copy of the template filesystem.
func (m *Machine) NewSessionFS() *vfs.FS {
	return m.FS.Clone()
}

// Age classes give seeded files believable modification times: system
// files date from the install, configs from the last few months, logs
// from today. Each path's exact offset is a stable hash so listings do
// not change between restarts.
type age int

const (
	ageInstall age = iota // 400–500 days ago
	ageConfig             // 20–200 days ago
	ageHome               // 2–90 days ago
	ageRecent             // within the last day
	ageBoot               // at boot time
)

func (m *Machine) mtime(path string, a age) time.Time {
	h := fnv.New64a()
	_, _ = h.Write([]byte(path))
	r := h.Sum64()
	minutes := func(lo, hi int64) time.Duration {
		return time.Duration(lo+int64(r%uint64(hi-lo))) * time.Minute
	}
	now := m.Now()
	switch a {
	case ageInstall:
		return now.Add(-minutes(400*1440, 500*1440))
	case ageConfig:
		return now.Add(-minutes(20*1440, 200*1440))
	case ageHome:
		return now.Add(-minutes(2*1440, 90*1440))
	case ageRecent:
		return now.Add(-minutes(1, 1440))
	case ageBoot:
		return m.BootTime
	}
	return now
}

// seedHash gives each path a stable number for sizes and opaque content.
func seedHash(path string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(path))
	return h.Sum64()
}

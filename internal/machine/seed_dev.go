package machine

import (
	"crypto/rand"

	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

func (m *Machine) seedDev(b *builder) {
	for _, d := range []string{"/dev/pts", "/dev/shm", "/dev/net", "/dev/disk", "/dev/disk/by-uuid", "/dev/disk/by-id", "/dev/mapper", "/dev/block", "/dev/char"} {
		b.dir(d, 0o755, 0, 0, ageBoot)
	}
	zero := func() []byte { return make([]byte, vfs.MaxOpaqueRead) }
	random := func() []byte { buf := make([]byte, 4096); _, _ = rand.Read(buf); return buf }
	b.dev("/dev/null", true, 0o666, 0, nil)
	b.dev("/dev/zero", true, 0o666, 0, zero)
	b.dev("/dev/full", true, 0o666, 0, nil)
	b.dev("/dev/tty", true, 0o666, 5, nil)
	b.dev("/dev/console", true, 0o600, 0, nil)
	b.dev("/dev/ptmx", true, 0o666, 5, nil)
	b.dev("/dev/random", true, 0o666, 0, random)
	b.dev("/dev/urandom", true, 0o666, 0, random)
	b.dev("/dev/kmsg", true, 0o644, 0, nil)
	b.dev("/dev/sda", false, 0o660, 6, nil)
	b.dev("/dev/sda1", false, 0o660, 6, nil)
	b.dev("/dev/sda14", false, 0o660, 6, nil)
	b.dev("/dev/sda15", false, 0o660, 6, nil)
	b.dev("/dev/loop0", false, 0o660, 6, nil)
	b.dev("/dev/loop1", false, 0o660, 6, nil)
	b.dev("/dev/loop2", false, 0o660, 6, nil)
	b.link("/proc/self/fd", "/dev/fd", ageBoot)
	b.link("/proc/self/fd/0", "/dev/stdin", ageBoot)
	b.link("/proc/self/fd/1", "/dev/stdout", ageBoot)
	b.link("/proc/self/fd/2", "/dev/stderr", ageBoot)
	b.link("../sda1", "/dev/disk/by-uuid/"+uuidFrom(m.Profile.Hostname+"root"), ageBoot)
	b.link("/dev/null", "/dev/net/tun", ageBoot)
}

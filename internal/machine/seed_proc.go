package machine

import (
	"fmt"
	"io/fs"
	"strings"
)

func (m *Machine) seedProc(b *builder) {
	p := m.Profile
	for _, d := range []string{"/proc/sys", "/proc/sys/kernel", "/proc/sys/net", "/proc/sys/net/ipv4", "/proc/net", "/proc/self", "/proc/1", "/proc/driver", "/proc/bus", "/proc/fs", "/proc/irq", "/proc/scsi", "/proc/tty"} {
		b.dir(d, 0o555, 0, 0, ageBoot)
	}
	b.dynamic("/proc/uptime", func() []byte {
		up := m.Uptime().Seconds()
		return []byte(fmt.Sprintf("%.2f %.2f\n", up, up*float64(p.CPUCores)*0.97))
	}, 0o444)
	b.dynamic("/proc/loadavg", func() []byte {
		l1, l5, l15 := m.LoadAvg()
		return []byte(fmt.Sprintf("%.2f %.2f %.2f 1/%d %d\n", l1, l5, l15, 150+len(p.Processes), 20000+int(m.Uptime().Minutes())%40000))
	}, 0o444)
	b.file("/proc/version", fmt.Sprintf("Linux version %s (buildd@lcy02-amd64-041) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) %s\n", p.Kernel, p.KernelVersion), 0o444, 0, 0, ageBoot)
	b.file("/proc/cpuinfo", cpuinfoFor(p.CPUModel, p.CPUCores), 0o444, 0, 0, ageBoot)
	b.file("/proc/meminfo", meminfoFor(p.MemMB, p.SwapMB), 0o444, 0, 0, ageBoot)
	b.file("/proc/cmdline", "BOOT_IMAGE=/boot/vmlinuz-"+p.Kernel+" root=UUID="+uuidFrom(p.Hostname+"root")+" ro console=tty1 console=ttyS0\n", 0o444, 0, 0, ageBoot)
	b.file("/proc/mounts", lines(
		"sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0",
		"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0",
		"udev /dev devtmpfs rw,nosuid,relatime,size=1973016k,nr_inodes=493254,mode=755,inode64 0 0",
		"devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0",
		"tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size=403016k,mode=755,inode64 0 0",
		"/dev/sda1 / ext4 rw,relatime,discard,errors=remount-ro 0 0",
		"securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0",
		"tmpfs /dev/shm tmpfs rw,nosuid,nodev,inode64 0 0",
		"tmpfs /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k,inode64 0 0",
		"cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot 0 0",
		"/dev/sda15 /boot/efi vfat rw,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=iso8859-1,shortname=mixed,errors=remount-ro 0 0",
		"/dev/loop0 /snap/core20/2318 squashfs ro,nodev,relatime,errors=continue,threads=single 0 0",
		"/dev/loop1 /snap/lxd/29351 squashfs ro,nodev,relatime,errors=continue,threads=single 0 0",
		"/dev/loop2 /snap/snapd/21759 squashfs ro,nodev,relatime,errors=continue,threads=single 0 0",
		"tmpfs /run/user/0 tmpfs rw,nosuid,nodev,relatime,size=403012k,nr_inodes=100753,mode=700,inode64 0 0",
	), 0o444, 0, 0, ageBoot)
	b.file("/proc/sys/kernel/hostname", p.Hostname+"\n", 0o644, 0, 0, ageBoot)
	b.file("/proc/sys/kernel/ostype", "Linux\n", 0o444, 0, 0, ageBoot)
	b.file("/proc/sys/kernel/osrelease", p.Kernel+"\n", 0o444, 0, 0, ageBoot)
	b.file("/proc/sys/kernel/version", p.KernelVersion+"\n", 0o444, 0, 0, ageBoot)
	b.file("/proc/sys/kernel/random", "", 0o444, 0, 0, ageBoot)
	b.file("/proc/sys/net/ipv4/ip_forward", "0\n", 0o644, 0, 0, ageBoot)
	b.file("/proc/net/dev", lines(
		"Inter-|   Receive                                                |  Transmit",
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed",
		fmt.Sprintf("    lo: %d %d    0    0    0     0          0         0 %d %d    0    0    0     0       0          0", 48211932, 261402, 48211932, 261402),
		fmt.Sprintf("  %s: %d %d    0    0    0     0          0         0 %d %d    0    0    0     0       0          0", p.Interface, 9318472113, 9182377, 21873341922, 12928311),
	), 0o444, 0, 0, ageBoot)
	b.placeholder("/proc/net/tcp", 1800, "/proc/net/tcp listing listeners on :0016 (ssh), :0050 (http), :01BB (https), :0BB8 bound to 0100007F (node), :1538 bound to 0100007F (postgres), plus one established ssh connection", 0o444, 0, 0, ageBoot)
	b.placeholder("/proc/net/route", 384, "/proc/net/route with a default route via "+p.Gateway+" on "+p.Interface, 0o444, 0, 0, ageBoot)
	b.placeholder("/proc/net/arp", 240, "/proc/net/arp with the gateway "+p.Gateway, 0o444, 0, 0, ageBoot)
	b.placeholder("/proc/stat", 1200, "/proc/stat for a "+fmt.Sprint(p.CPUCores)+"-core mostly idle box up for "+m.Uptime().Round(1e9).String(), 0o444, 0, 0, ageBoot)
	b.placeholder("/proc/self/status", 1300, "/proc/self/status of a bash process", 0o444, 0, 0, ageBoot)
	b.placeholder("/proc/1/status", 1300, "/proc/1/status of systemd", 0o444, 0, 0, ageBoot)
	b.file("/proc/1/cmdline", "/sbin/init\x00", 0o444, 0, 0, ageBoot)
	b.link("/", "/proc/1/root", ageBoot)
	b.link("/usr/lib/systemd/systemd", "/proc/1/exe", ageBoot)
	b.link("/", "/proc/self/root", ageBoot)
	b.link("/usr/bin/bash", "/proc/self/exe", ageBoot)
	b.file("/proc/self/cmdline", "-bash\x00", 0o444, 0, 0, ageBoot)
	b.file("/proc/filesystems", lines("nodev\tsysfs", "nodev\ttmpfs", "nodev\tbdev", "nodev\tproc", "nodev\tcgroup", "nodev\tcgroup2", "nodev\tcpuset", "nodev\tdevtmpfs", "nodev\tconfigfs", "nodev\tdebugfs", "nodev\ttracefs", "nodev\tsecurityfs", "nodev\tsockfs", "nodev\tbpf", "nodev\tpipefs", "nodev\tramfs", "nodev\thugetlbfs", "nodev\tdevpts", "\text3", "\text2", "\text4", "\tsquashfs", "\tvfat", "nodev\tecryptfs", "\tfuseblk", "nodev\tfuse", "nodev\tfusectl", "nodev\tmqueue", "nodev\tpstore", "nodev\tautofs", "nodev\tbinfmt_misc"), 0o444, 0, 0, ageBoot)
	b.file("/proc/swaps", "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n", 0o444, 0, 0, ageBoot)
	b.file("/proc/partitions", lines("major minor  #blocks  name", "", fmt.Sprintf("   8        0   %d sda", p.DiskGB*1024*1024), fmt.Sprintf("   8        1   %d sda1", p.DiskGB*1024*1024-118784-1024), "   8       14       4096 sda14", "   8       15     111616 sda15", "   7        0      65536 loop0", "   7        1     102400 loop1", "   7        2      40448 loop2"), 0o444, 0, 0, ageBoot)
	b.file("/proc/devices", lines("Character devices:", "  1 mem", "  4 /dev/vc/0", "  4 tty", "  4 ttyS", "  5 /dev/tty", "  5 /dev/console", "  5 /dev/ptmx", "  7 vcs", " 10 misc", " 13 input", " 29 fb", "128 ptm", "136 pts", "180 usb", "189 usb_device", "226 drm", "", "Block devices:", "  7 loop", "  8 sd", "  9 md", " 11 sr", " 65 sd", "252 device-mapper", "253 virtblk", "259 blkext"), 0o444, 0, 0, ageBoot)
	b.file("/proc/modules", lines("tls 114688 0 - Live 0x0000000000000000", "xt_conntrack 16384 1 - Live 0x0000000000000000", "nft_chain_nat 16384 3 - Live 0x0000000000000000", "xt_MASQUERADE 20480 1 - Live 0x0000000000000000", "nf_nat 49152 2 nft_chain_nat,xt_MASQUERADE, Live 0x0000000000000000", "nf_conntrack 172032 3 xt_conntrack,xt_MASQUERADE,nf_nat, Live 0x0000000000000000", "nf_defrag_ipv6 24576 1 nf_conntrack, Live 0x0000000000000000", "nf_defrag_ipv4 16384 1 nf_conntrack, Live 0x0000000000000000", "nft_compat 20480 2 - Live 0x0000000000000000", "nf_tables 249856 4 nft_chain_nat,nft_compat, Live 0x0000000000000000", "nfnetlink 20480 2 nft_compat,nf_tables, Live 0x0000000000000000", "br_netfilter 32768 0 - Live 0x0000000000000000", "bridge 311296 1 br_netfilter, Live 0x0000000000000000", "stp 16384 1 bridge, Live 0x0000000000000000", "llc 16384 2 bridge,stp, Live 0x0000000000000000", "overlay 151552 0 - Live 0x0000000000000000", "binfmt_misc 24576 1 - Live 0x0000000000000000", "nls_iso8859_1 16384 1 - Live 0x0000000000000000", "virtio_net 61440 0 - Live 0x0000000000000000", "net_failover 20480 1 virtio_net, Live 0x0000000000000000", "failover 16384 1 net_failover, Live 0x0000000000000000", "virtio_blk 20480 1 - Live 0x0000000000000000", "crc32_pclmul 16384 0 - Live 0x0000000000000000", "psmouse 176128 0 - Live 0x0000000000000000", "i2c_piix4 28672 0 - Live 0x0000000000000000"), 0o444, 0, 0, ageBoot)
	_ = fs.ModeDir
}

func cpuinfoFor(model string, cores int) string {
	var sb strings.Builder
	for i := 0; i < cores; i++ {
		fmt.Fprintf(&sb, "processor\t: %d\n", i)
		sb.WriteString("vendor_id\t: GenuineIntel\n")
		sb.WriteString("cpu family\t: 6\n")
		sb.WriteString("model\t\t: 79\n")
		fmt.Fprintf(&sb, "model name\t: %s\n", model)
		sb.WriteString("stepping\t: 1\n")
		sb.WriteString("microcode\t: 0xb000040\n")
		sb.WriteString("cpu MHz\t\t: 2394.454\n")
		sb.WriteString("cache size\t: 35840 KB\n")
		sb.WriteString("physical id\t: 0\n")
		fmt.Fprintf(&sb, "siblings\t: %d\n", cores)
		fmt.Fprintf(&sb, "core id\t\t: %d\n", i)
		fmt.Fprintf(&sb, "cpu cores\t: %d\n", cores)
		fmt.Fprintf(&sb, "apicid\t\t: %d\n", i)
		fmt.Fprintf(&sb, "initial apicid\t: %d\n", i)
		sb.WriteString("fpu\t\t: yes\n")
		sb.WriteString("fpu_exception\t: yes\n")
		sb.WriteString("cpuid level\t: 13\n")
		sb.WriteString("wp\t\t: yes\n")
		sb.WriteString("flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon rep_good nopl xtopology cpuid tsc_known_freq pni pclmulqdq vmx ssse3 fma cx16 pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch cpuid_fault invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm rdseed adx smap xsaveopt arat umip md_clear arch_capabilities\n")
		sb.WriteString("bugs\t\t: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs taa itlb_multihit mmio_stale_data\n")
		sb.WriteString("bogomips\t: 4788.90\n")
		sb.WriteString("clflush size\t: 64\n")
		sb.WriteString("cache_alignment\t: 64\n")
		sb.WriteString("address sizes\t: 46 bits physical, 48 bits virtual\n")
		sb.WriteString("power management:\n\n")
	}
	return sb.String()
}

func meminfoFor(memMB, swapMB int) string {
	total := memMB * 1024
	free := total * 22 / 100
	buffers := total * 3 / 100
	cached := total * 41 / 100
	available := free + buffers + cached - total*4/100
	swap := swapMB * 1024
	rows := []struct {
		k string
		v int
	}{
		{"MemTotal", total}, {"MemFree", free}, {"MemAvailable", available}, {"Buffers", buffers}, {"Cached", cached},
		{"SwapCached", 0}, {"Active", total * 45 / 100}, {"Inactive", total * 25 / 100}, {"Active(anon)", total * 28 / 100},
		{"Inactive(anon)", total * 1 / 100}, {"Active(file)", total * 17 / 100}, {"Inactive(file)", total * 24 / 100},
		{"Unevictable", 27856}, {"Mlocked", 27856}, {"SwapTotal", swap}, {"SwapFree", swap}, {"Dirty", 124}, {"Writeback", 0},
		{"AnonPages", total * 29 / 100}, {"Mapped", total * 6 / 100}, {"Shmem", total * 1 / 100}, {"KReclaimable", total * 4 / 100},
		{"Slab", total * 5 / 100}, {"SReclaimable", total * 4 / 100}, {"SUnreclaim", total * 1 / 100}, {"KernelStack", 4256},
		{"PageTables", 9880}, {"NFS_Unstable", 0}, {"Bounce", 0}, {"WritebackTmp", 0}, {"CommitLimit", total/2 + swap},
		{"Committed_AS", total * 62 / 100}, {"VmallocTotal", 34359738367}, {"VmallocUsed", 21648}, {"VmallocChunk", 0},
		{"Percpu", 3024}, {"HardwareCorrupted", 0}, {"AnonHugePages", 0}, {"ShmemHugePages", 0}, {"ShmemPmdMapped", 0},
		{"FileHugePages", 0}, {"FilePmdMapped", 0}, {"HugePages_Total", 0}, {"HugePages_Free", 0}, {"HugePages_Rsvd", 0},
		{"HugePages_Surp", 0}, {"Hugepagesize", 2048}, {"Hugetlb", 0}, {"DirectMap4k", 190364}, {"DirectMap2M", total - 190364},
	}
	var sb strings.Builder
	for _, r := range rows {
		unit := " kB"
		if strings.HasPrefix(r.k, "HugePages_") {
			unit = ""
		}
		fmt.Fprintf(&sb, "%-15s %8d%s\n", r.k+":", r.v, unit)
	}
	return sb.String()
}

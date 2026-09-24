package machine

// seedBins fills /usr/bin and /usr/sbin with fake ELF binaries so that
// which, ls -l and file all agree the tools exist. The shell emulates
// their behaviour; these are just so the filesystem is not empty.
func (m *Machine) seedBins(b *builder) {
	// coreutils and friends in /usr/bin
	usrBin := []string{
		"bash", "dash", "ls", "cat", "echo", "pwd", "cd", "cp", "mv", "rm", "mkdir", "rmdir", "touch", "ln", "chmod",
		"chown", "chgrp", "ln", "readlink", "realpath", "basename", "dirname", "head", "tail", "less", "more", "grep",
		"egrep", "fgrep", "sed", "awk", "gawk", "cut", "sort", "uniq", "wc", "tr", "tee", "find", "xargs", "which",
		"whereis", "file", "stat", "du", "df", "free", "ps", "top", "htop", "kill", "pkill", "pgrep", "sleep", "date",
		"whoami", "who", "w", "id", "groups", "users", "last", "uptime", "uname", "hostname", "hostnamectl", "env",
		"printenv", "export", "set", "unset", "history", "clear", "reset", "tput", "stty", "tty", "man", "info",
		"apropos", "vim.basic", "nano", "emacs", "ed", "tar", "gzip", "gunzip", "zcat", "bzip2", "xz",
		"zip", "unzip", "curl", "wget", "scp", "sftp", "ssh", "ssh-keygen", "ssh-copy-id", "rsync", "nc", "ncat",
		"netcat", "telnet", "ftp", "tftp", "socat", "nmap", "dig", "host", "nslookup", "ping", "ping6", "traceroute",
		"mtr", "python3.10", "perl", "ruby", "node", "npm", "npx", "git", "gcc", "cc", "g++",
		"make", "cmake", "gdb", "strace", "ltrace", "lsof", "ss", "netstat", "ip", "ifconfig", "route", "arp",
		"iptables", "psql", "mysql", "redis-cli", "mongo", "docker", "kubectl", "screen", "tmux", "sudo", "su",
		"passwd", "chsh", "chfn", "crontab", "at", "systemctl", "journalctl", "service", "dpkg", "dpkg-query",
		"apt", "apt-get", "apt-cache", "snap", "pip", "pip3", "openssl", "base64", "md5sum", "sha1sum", "sha256sum",
		"sha512sum", "cksum", "od", "hexdump", "xxd", "strings", "diff", "cmp", "patch", "watch", "timeout", "nohup",
		"nice", "renice", "ionice", "flock", "seq", "yes", "true", "false", "test", "expr", "bc", "jq", "column",
		"fmt", "fold", "paste", "join", "comm", "shuf", "factor", "sync", "dd", "mktemp", "mkfifo", "getent", "locale",
		"lsb_release", "wall", "write", "mesg", "logger", "dmesg", "lspci", "lsusb", "lsblk", "lscpu", "lsmod",
		"vmstat", "iostat", "mpstat", "sar", "fuser", "killall", "busybox", "wget", "gpg", "gpgv", "tac", "nl", "rev",
	}
	for _, name := range usrBin {
		b.bin("/usr/bin/"+name, 0)
	}
	usrSbin := []string{
		"sshd", "nginx", "cron", "atd", "rsyslogd", "agetty", "getty", "useradd", "userdel", "usermod",
		"groupadd", "groupdel", "groupmod", "chpasswd", "newusers", "vipw", "visudo", "adduser", "deluser",
		"addgroup", "delgroup", "iptables", "ip6tables", "nft", "ufw", "fail2ban-server", "fail2ban-client",
		"modprobe", "insmod", "rmmod", "depmod", "sysctl", "reboot", "shutdown", "halt", "poweroff", "swapon",
		"swapoff", "mkfs", "mkfs.ext4", "fsck", "e2fsck", "tune2fs", "blkid", "mount", "umount", "losetup",
		"update-grub", "grub-install", "dpkg-reconfigure", "invoke-rc.d", "update-rc.d", "logrotate", "cron",
		"pg_ctlcluster", "pg_lsclusters", "postgres", "unattended-upgrade", "faillog", "runuser", "nologin",
	}
	for _, name := range usrSbin {
		b.bin("/usr/sbin/"+name, 0)
	}
	// A couple of these binaries are famously large; give them realistic sizes.
	b.bin("/usr/bin/vim.basic", 3524384)
	b.bin("/usr/bin/perl", 2093216)
	b.bin("/usr/bin/python3.10", 5904936)
	b.link("python3.10", "/usr/bin/python3", ageInstall)
	b.link("python3", "/usr/bin/python", ageInstall)
	b.link("/etc/alternatives/vi", "/usr/bin/vi", ageInstall)
	b.link("/usr/bin/vim.basic", "/etc/alternatives/vi", ageInstall)
	b.link("/usr/bin/vim.basic", "/usr/bin/vim", ageInstall)
	b.link("bash", "/usr/bin/rbash", ageInstall)
	b.link("dash", "/usr/bin/sh", ageInstall)

	b.dir("/usr/lib/openssh", 0o755, 0, 0, ageInstall)
	b.bin("/usr/lib/openssh/sftp-server", 154344)
	b.dir("/usr/lib/systemd", 0o755, 0, 0, ageInstall)
	b.bin("/usr/lib/systemd/systemd", 1620224)
	b.link("../lib/systemd/systemd", "/usr/sbin/init", ageInstall)

	// A little bit of /usr/share so man and docs are not conspicuously empty.
	for _, d := range []string{"/usr/share/man", "/usr/share/man/man1", "/usr/share/doc", "/usr/share/bash-completion",
		"/usr/share/bash-completion/completions", "/usr/share/vim", "/usr/share/zoneinfo", "/usr/share/keyrings",
		"/usr/share/ca-certificates", "/usr/share/misc"} {
		b.dir(d, 0o755, 0, 0, ageInstall)
	}
	b.placeholder("/usr/share/misc/magic.mgc", 8438272, "compiled libmagic database", 0o644, 0, 0, ageInstall)
}

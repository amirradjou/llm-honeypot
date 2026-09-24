package machine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/amirradjou/llm-honeypot/internal/profile"
)

const gidShadow = 42

func (m *Machine) seedEtc(b *builder) {
	p := m.Profile
	for _, d := range []string{"/etc/default", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly",
		"/etc/cron.monthly", "/etc/ssh", "/etc/ssl", "/etc/ssl/certs", "/etc/ssl/private", "/etc/systemd", "/etc/systemd/system",
		"/etc/network", "/etc/netplan", "/etc/apt", "/etc/apt/sources.list.d", "/etc/pam.d", "/etc/security", "/etc/skel",
		"/etc/logrotate.d", "/etc/init.d", "/etc/update-motd.d", "/etc/ufw", "/etc/fail2ban", "/etc/letsencrypt",
		"/etc/nginx", "/etc/nginx/sites-available", "/etc/nginx/sites-enabled", "/etc/nginx/conf.d", "/etc/nginx/snippets",
		"/etc/postgresql", "/etc/postgresql/14", "/etc/postgresql/14/main", "/etc/sudoers.d", "/etc/alternatives",
		"/etc/X11", "/etc/dpkg", "/etc/ld.so.conf.d", "/etc/profile.d", "/etc/rsyslog.d", "/etc/vim", "/etc/python3"} {
		b.dir(d, 0o755, 0, 0, ageInstall)
	}
	b.dir("/etc/ssl/private", 0o710, 0, gidShadow, ageInstall)
	b.dir("/etc/letsencrypt/live", 0o700, 0, 0, ageConfig)
	b.dir("/etc/letsencrypt/archive", 0o700, 0, 0, ageConfig)

	b.text("/etc/passwd", passwdFile(p), ageConfig)
	b.text("/etc/group", groupFile(p), ageConfig)
	b.file("/etc/shadow", shadowFile(p, m), 0o640, 0, gidShadow, ageConfig)
	b.file("/etc/gshadow", gshadowFile(p), 0o640, 0, gidShadow, ageConfig)
	b.text("/etc/passwd-", passwdFile(p), ageConfig)
	b.file("/etc/shadow-", shadowFile(p, m), 0o640, 0, gidShadow, ageConfig)
	b.text("/etc/hostname", p.Hostname+"\n", ageInstall)
	b.text("/etc/hosts", lines(
		"127.0.0.1 localhost",
		"127.0.1.1 "+p.FQDN()+" "+p.Hostname,
		"",
		"# The following lines are desirable for IPv6 capable hosts",
		"::1     ip6-localhost ip6-loopback",
		"fe00::0 ip6-localnet",
		"ff00::0 ip6-mcastprefix",
		"ff02::1 ip6-allnodes",
		"ff02::2 ip6-allrouters",
	), ageInstall)
	b.text("/usr/lib/os-release", lines(
		`PRETTY_NAME="`+p.OSPretty+`"`,
		`NAME="`+p.OSName+`"`,
		`VERSION_ID="`+strings.Fields(p.OSVersion)[0]+`"`,
		`VERSION="`+p.OSVersion+" ("+capitalize(p.OSCodename)+" Jellyfish)"+`"`,
		`VERSION_CODENAME=`+p.OSCodename,
		`ID=`+strings.ToLower(p.OSName),
		`ID_LIKE=debian`,
		`HOME_URL="https://www.ubuntu.com/"`,
		`SUPPORT_URL="https://help.ubuntu.com/"`,
		`BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"`,
		`PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"`,
		`UBUNTU_CODENAME=`+p.OSCodename,
	), ageInstall)
	b.link("../usr/lib/os-release", "/etc/os-release", ageInstall)
	b.text("/etc/lsb-release", lines(
		"DISTRIB_ID="+p.OSName,
		"DISTRIB_RELEASE="+strings.Fields(p.OSVersion)[0],
		"DISTRIB_CODENAME="+p.OSCodename,
		`DISTRIB_DESCRIPTION="`+p.OSPretty+`"`,
	), ageInstall)
	b.text("/etc/debian_version", "bookworm/sid\n", ageInstall)
	b.text("/etc/issue", p.OSPretty+" \\n \\l\n\n", ageInstall)
	b.text("/etc/issue.net", p.OSPretty+"\n", ageInstall)
	b.text("/etc/machine-id", fmt.Sprintf("%016x%016x\n", seedHash(p.Hostname+"mid1"), seedHash(p.Hostname+"mid2")), ageInstall)
	b.text("/etc/timezone", p.Timezone+"\n", ageInstall)
	b.link("/usr/share/zoneinfo/"+p.Timezone, "/etc/localtime", ageInstall)
	b.link("../run/systemd/resolve/stub-resolv.conf", "/etc/resolv.conf", ageInstall)
	b.text("/etc/fstab", lines(
		"# /etc/fstab: static file system information.",
		"#",
		"# Use 'blkid' to print the universally unique identifier for a",
		"# device; this may be used with UUID= as a more robust way to name devices",
		"# that works even if disks are added and removed. See fstab(5).",
		"#",
		"# <file system> <mount point>   <type>  <options>       <dump>  <pass>",
		"# / was on /dev/sda1 during curtin installation",
		fmt.Sprintf("/dev/disk/by-uuid/%s / ext4 defaults 0 1", uuidFrom(p.Hostname+"root")),
		fmt.Sprintf("/dev/disk/by-uuid/%s /boot/efi vfat defaults 0 1", strings.ToUpper(uuidFrom(p.Hostname + "efi")[:9])),
		"/swap.img\tnone\tswap\tsw\t0\t0",
	), ageInstall)
	b.text("/etc/crontab", lines(
		"# /etc/crontab: system-wide crontab",
		"# Unlike any other crontab you don't have to run the `crontab'",
		"# command to install the new version when you edit this file",
		"# and files in /etc/cron.d. These files also have username fields,",
		"# that none of the other crontabs do.",
		"",
		"SHELL=/bin/sh",
		"# You can also override PATH, but by default, newer versions inherit it from the environment",
		"#PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"",
		"# Example of job definition:",
		"# .---------------- minute (0 - 59)",
		"# |  .------------- hour (0 - 23)",
		"# |  |  .---------- day of month (1 - 31)",
		"# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...",
		"# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat",
		"# |  |  |  |  |",
		"# *  *  *  *  * user-name command to be executed",
		"17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly",
		"25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )",
		"47 6\t* * 7\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )",
		"52 6\t1 * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )",
		"#",
	), ageInstall)
	b.text("/etc/cron.d/e2scrub_all", lines(
		"30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron",
		"10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r",
	), ageInstall)
	b.text("/etc/cron.d/certbot", lines(
		"# /etc/cron.d/certbot: crontab entries for the certbot package",
		"#",
		"# Upstream recommends attempting renewal twice a day",
		"#",
		"# Eventually, this will be an opportunity to validate certificates",
		"# haven't been revoked, etc.  Renewal will only occur if expiration",
		"# is within 30 days.",
		"#",
		"# Important Note!  This cronjob will NOT be executed if you are",
		"# running systemd as your init system.  If you are running systemd,",
		"# the cronjob.timer function takes precedence over this cronjob.  For",
		"# more details, see the systemd.timer manpage, or use systemctl show",
		"# certbot.timer.",
		"SHELL=/bin/sh",
		"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin",
		"",
		"0 */12 * * * root test -x /usr/bin/certbot -a \\! -d /run/systemd/system && perl -e 'sleep int(rand(43200))' && certbot -q renew",
	), ageConfig)
	b.text("/etc/cron.d/bakery-backup", lines(
		"# nightly database dump, see /root/scripts/backup.sh",
		"MAILTO=martin@localhost",
		"15 2 * * * root /root/scripts/backup.sh >> /var/log/bakery-backup.log 2>&1",
	), ageConfig)
	b.file("/etc/sudoers", lines(
		"#",
		"# This file MUST be edited with the 'visudo' command as root.",
		"#",
		"# Please consider adding local content in /etc/sudoers.d/ instead of",
		"# directly modifying this file.",
		"#",
		"# See the man page for details on how to write a sudoers file.",
		"#",
		`Defaults	env_reset`,
		`Defaults	mail_badpass`,
		`Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"`,
		`Defaults	use_pty`,
		"",
		"# Host alias specification",
		"",
		"# User alias specification",
		"",
		"# Cmnd alias specification",
		"",
		"# User privilege specification",
		"root\tALL=(ALL:ALL) ALL",
		"",
		"# Members of the admin group may gain root privileges",
		"%admin ALL=(ALL) ALL",
		"",
		"# Allow members of group sudo to execute any command",
		"%sudo\tALL=(ALL:ALL) ALL",
		"",
		"# See sudoers(5) for more information on \"@include\" directives:",
		"",
		"@includedir /etc/sudoers.d",
	), 0o440, 0, 0, ageInstall)
	b.file("/etc/sudoers.d/README", lines(
		"#",
		"# As of Debian version 1.7.2p1-1, the default /etc/sudoers file created on",
		"# installation of the package now includes the directive:",
		"# ",
		"# 	#includedir /etc/sudoers.d",
		"# ",
		"# This will cause sudo to read and parse any files in the /etc/sudoers.d ",
		"# directory that do not end in '~' or contain a '.' character.",
	), 0o440, 0, 0, ageInstall)
	b.file("/etc/sudoers.d/90-deploy", "deploy ALL=(ALL) NOPASSWD: /bin/systemctl restart bakery, /bin/systemctl reload nginx\n", 0o440, 0, 0, ageConfig)
	b.text("/etc/motd", "", ageInstall)
	b.text("/etc/environment", `PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"`+"\n", ageInstall)
	b.text("/etc/shells", lines("# /etc/shells: valid login shells", "/bin/sh", "/bin/bash", "/usr/bin/bash", "/bin/rbash", "/usr/bin/rbash", "/usr/bin/sh", "/bin/dash", "/usr/bin/dash", "/usr/bin/tmux", "/usr/bin/screen"), ageInstall)
	b.text("/etc/profile", lines(
		"# /etc/profile: system-wide .profile file for the Bourne shell (sh(1))",
		"# and Bourne compatible shells (bash(1), ksh(1), ash(1), ...).",
		"",
		`if [ "${PS1-}" ]; then`,
		`  if [ "${BASH-}" ] && [ "$BASH" != "/bin/sh" ]; then`,
		"    # The file bash.bashrc already sets the default PS1.",
		`    # PS1='\h:\w\$ '`,
		"    if [ -f /etc/bash.bashrc ]; then",
		"      . /etc/bash.bashrc",
		"    fi",
		"  else",
		`    if [ "$(id -u)" -eq 0 ]; then`,
		"      PS1='# '",
		"    else",
		"      PS1='$ '",
		"    fi",
		"  fi",
		"fi",
		"",
		"if [ -d /etc/profile.d ]; then",
		"  for i in /etc/profile.d/*.sh; do",
		`    if [ -r $i ]; then`,
		"      . $i",
		"    fi",
		"  done",
		"  unset i",
		"fi",
	), ageInstall)
	b.placeholder("/etc/bash.bashrc", 2319, "Ubuntu's default system-wide /etc/bash.bashrc", 0o644, 0, 0, ageInstall)
	b.placeholder("/etc/services", 12813, "standard /etc/services from the netbase package", 0o644, 0, 0, ageInstall)
	b.placeholder("/etc/protocols", 2932, "standard /etc/protocols from the netbase package", 0o644, 0, 0, ageInstall)
	b.placeholder("/etc/login.defs", 10734, "Ubuntu default /etc/login.defs", 0o644, 0, 0, ageInstall)
	b.placeholder("/etc/adduser.conf", 3028, "Ubuntu default adduser.conf", 0o644, 0, 0, ageInstall)
	b.placeholder("/etc/nsswitch.conf", 510, "Ubuntu default nsswitch.conf", 0o644, 0, 0, ageInstall)
	b.placeholder("/etc/ld.so.conf", 34, "Debian ld.so.conf: include /etc/ld.so.conf.d/*.conf", 0o644, 0, 0, ageInstall)
	b.placeholder("/etc/ld.so.cache", 27412, "binary ld.so cache", 0o644, 0, 0, ageConfig)
	b.text("/etc/apt/sources.list", lines(
		"# See http://help.ubuntu.com/community/UpgradeNotes for how to upgrade to",
		"# newer versions of the distribution.",
		"deb http://archive.ubuntu.com/ubuntu "+p.OSCodename+" main restricted",
		"deb http://archive.ubuntu.com/ubuntu "+p.OSCodename+"-updates main restricted",
		"deb http://archive.ubuntu.com/ubuntu "+p.OSCodename+" universe",
		"deb http://archive.ubuntu.com/ubuntu "+p.OSCodename+"-updates universe",
		"deb http://archive.ubuntu.com/ubuntu "+p.OSCodename+" multiverse",
		"deb http://archive.ubuntu.com/ubuntu "+p.OSCodename+"-updates multiverse",
		"deb http://archive.ubuntu.com/ubuntu "+p.OSCodename+"-backports main restricted universe multiverse",
		"deb http://security.ubuntu.com/ubuntu "+p.OSCodename+"-security main restricted",
		"deb http://security.ubuntu.com/ubuntu "+p.OSCodename+"-security universe",
		"deb http://security.ubuntu.com/ubuntu "+p.OSCodename+"-security multiverse",
	), ageInstall)
	b.text("/etc/apt/sources.list.d/nodesource.list", "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main\n", ageConfig)
	b.text("/etc/apt/sources.list.d/pgdg.list", "deb http://apt.postgresql.org/pub/repos/apt "+p.OSCodename+"-pgdg main\n", ageConfig)
	b.text("/etc/netplan/50-cloud-init.yaml", lines(
		"# This file is generated from information provided by the datasource.  Changes",
		"# to it will not persist across an instance reboot.  To disable cloud-init's",
		"# network configuration capabilities, write a file",
		"# /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg with the following:",
		"# network: {config: disabled}",
		"network:",
		"    ethernets:",
		"        "+p.Interface+":",
		"            addresses:",
		"            - "+p.IPv4+"/24",
		"            match:",
		"                macaddress: "+p.MAC,
		"            nameservers:",
		"                addresses:",
		"                - 1.1.1.1",
		"                - 8.8.8.8",
		"            routes:",
		"            -   to: default",
		"                via: "+p.Gateway,
		"            set-name: "+p.Interface,
		"    version: 2",
	), ageInstall)
	b.text("/etc/ssh/sshd_config", sshdConfig, ageConfig)
	b.placeholder("/etc/ssh/ssh_config", 1650, "OpenSSH client ssh_config with Ubuntu defaults", 0o644, 0, 0, ageInstall)
	b.placeholder("/etc/ssh/moduli", 613029, "OpenSSH moduli file", 0o644, 0, 0, ageInstall)
	b.text("/etc/ssh/ssh_host_ed25519_key.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN"+base64ish(p.Hostname+"hostkey", 37)+" root@"+p.Hostname+"\n", ageInstall)
	b.file("/etc/ssh/ssh_host_ed25519_key", lines(
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
		"QyNTUxOQAAACD"+base64ish(p.Hostname+"hk1", 57),
		"AAAAIA"+base64ish(p.Hostname+"hk2", 64),
		base64ish(p.Hostname+"hk3", 70),
		base64ish(p.Hostname+"hk4", 70),
		base64ish(p.Hostname+"hk5", 23)+"=",
		"-----END OPENSSH PRIVATE KEY-----",
	), 0o600, 0, 0, ageInstall)
	b.text("/etc/ssh/ssh_host_rsa_key.pub", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ"+base64ish(p.Hostname+"rsa", 372)+" root@"+p.Hostname+"\n", ageInstall)
	b.placeholder("/etc/ssh/ssh_host_rsa_key", 2602, "OpenSSH RSA private host key (PEM, unreadable garbage is fine)", 0o600, 0, 0, ageInstall)
	b.placeholder("/etc/ssh/ssh_host_ecdsa_key", 505, "OpenSSH ECDSA private host key", 0o600, 0, 0, ageInstall)
	b.text("/etc/ssh/ssh_host_ecdsa_key.pub", "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB"+base64ish(p.Hostname+"ecdsa", 111)+"= root@"+p.Hostname+"\n", ageInstall)

	b.text("/etc/nginx/nginx.conf", nginxConf, ageConfig)
	b.text("/etc/nginx/sites-available/default", nginxDefaultSite, ageInstall)
	b.text("/etc/nginx/sites-available/bakery", nginxBakerySite, ageConfig)
	b.link("/etc/nginx/sites-available/bakery", "/etc/nginx/sites-enabled/bakery", ageConfig)
	b.placeholder("/etc/nginx/mime.types", 5349, "stock nginx mime.types", 0o644, 0, 0, ageInstall)
	b.placeholder("/etc/nginx/fastcgi_params", 1077, "stock nginx fastcgi_params", 0o644, 0, 0, ageInstall)
	b.placeholder("/etc/nginx/proxy_params", 180, "stock nginx proxy_params", 0o644, 0, 0, ageInstall)
	b.placeholder("/etc/nginx/snippets/fastcgi-php.conf", 423, "stock nginx fastcgi-php snippet", 0o644, 0, 0, ageInstall)
	b.placeholder("/etc/nginx/snippets/snakeoil.conf", 217, "stock nginx snakeoil snippet", 0o644, 0, 0, ageInstall)
	b.dir("/etc/letsencrypt/live/shop.hazelbakery.example", 0o700, 0, 0, ageConfig)
	b.placeholder("/etc/letsencrypt/live/shop.hazelbakery.example/README", 692, "certbot live README", 0o644, 0, 0, ageConfig)
	b.link("../../archive/shop.hazelbakery.example/fullchain3.pem", "/etc/letsencrypt/live/shop.hazelbakery.example/fullchain.pem", ageConfig)
	b.link("../../archive/shop.hazelbakery.example/privkey3.pem", "/etc/letsencrypt/live/shop.hazelbakery.example/privkey.pem", ageConfig)
	b.dir("/etc/letsencrypt/archive/shop.hazelbakery.example", 0o700, 0, 0, ageConfig)
	b.placeholder("/etc/letsencrypt/archive/shop.hazelbakery.example/fullchain3.pem", 5616, "PEM certificate chain for shop.hazelbakery.example issued by Let's Encrypt R3", 0o644, 0, 0, ageConfig)
	b.placeholder("/etc/letsencrypt/archive/shop.hazelbakery.example/privkey3.pem", 241, "PEM EC private key", 0o600, 0, 0, ageConfig)

	b.placeholder("/etc/postgresql/14/main/postgresql.conf", 29734, "PostgreSQL 14 postgresql.conf with listen_addresses = 'localhost', shared_buffers = 512MB, max_connections = 100", 0o644, 110, 116, ageConfig)
	b.file("/etc/postgresql/14/main/pg_hba.conf", pgHba, 0o640, 110, 116, ageConfig)
	b.placeholder("/etc/postgresql/14/main/pg_ident.conf", 1636, "stock pg_ident.conf", 0o640, 110, 116, ageInstall)
	b.file("/etc/postgresql/14/main/postgresql.auto.conf", "# Do not edit this file manually!\n# It will be overwritten by the ALTER SYSTEM command.\n", 0o600, 110, 116, ageInstall)

	b.text("/etc/fail2ban/jail.local", lines(
		"[DEFAULT]",
		"bantime  = 1h",
		"findtime = 10m",
		"maxretry = 5",
		"",
		"[sshd]",
		"enabled = true",
		"port    = ssh",
		"logpath = %(sshd_log)s",
		"backend = %(sshd_backend)s",
		"",
		"[nginx-http-auth]",
		"enabled = true",
	), ageConfig)
	b.text("/etc/ufw/ufw.conf", lines("# /etc/ufw/ufw.conf", "#", "", "# Set to yes to start on boot. If setting this remotely, be sure to add a rule", "# to allow your remote connection before starting ufw. Eg: 'ufw allow 22/tcp'", "ENABLED=yes", "", "# Please use the 'ufw' command to set the loglevel. Eg: 'ufw logging medium'.", "# See 'man ufw' for details.", "LOGLEVEL=low"), ageConfig)
	b.file("/etc/ufw/user.rules", ufwUserRules, 0o640, 0, 0, ageConfig)
	b.text("/etc/default/grub", lines(
		"# If you change this file, run 'update-grub' afterwards to update",
		"# /boot/grub/grub.cfg.",
		"# For full documentation of the options in this file, see:",
		"#   info -f grub -n 'Simple configuration'",
		"",
		"GRUB_DEFAULT=0",
		"GRUB_TIMEOUT_STYLE=hidden",
		"GRUB_TIMEOUT=0",
		"GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`",
		`GRUB_CMDLINE_LINUX_DEFAULT=""`,
		`GRUB_CMDLINE_LINUX="console=tty1 console=ttyS0"`,
	), ageInstall)
	b.text("/etc/default/useradd", lines("# Default values for useradd(8)", "#", "# The SHELL variable specifies the default login shell on your", "# system.", "# Similar to DHSELL in adduser. However, we use \"sh\" here because", "# useradd is a low level utility and should be as general", "# as possible", "SHELL=/bin/sh", "#", "# The default group for users", "# 100=users on Debian systems", "# Same as USERS_GID in adduser", "# This argument is used when the -n flag is specified.", "# The default behavior (when -n and -g are not specified) is to create a", "# primary user group with the same name as the user being added to the", "# system.", "# GROUP=100", "#", "# The default home directory. Same as DHOME for adduser", "# HOME=/home", "#", "# The number of days after a password expires until the account", "# is permanently disabled", "# INACTIVE=-1", "#", "# The default expire date", "# EXPIRE=", "#", "# The SKEL variable specifies the directory containing \"skeletal\" user", "# files; in other words, files such as a sample .profile that will be", "# copied to the new user's home directory when it is created.", "# SKEL=/etc/skel", "#", "# Defines whether the mail spool should be created while", "# creating the account", "# CREATE_MAIL_SPOOL=yes"), ageInstall)
	b.text("/etc/systemd/system/bakery.service", lines(
		"[Unit]",
		"Description=Hazel Bakery shop (Node.js)",
		"After=network.target postgresql.service",
		"",
		"[Service]",
		"Type=simple",
		"User=deploy",
		"WorkingDirectory=/srv/bakery",
		"EnvironmentFile=/srv/bakery/.env",
		"ExecStart=/usr/bin/node /srv/bakery/dist/server.js",
		"Restart=on-failure",
		"RestartSec=5",
		"",
		"[Install]",
		"WantedBy=multi-user.target",
	), ageConfig)
	b.text("/etc/logrotate.d/nginx", lines("/var/log/nginx/*.log {", "\tdaily", "\tmissingok", "\trotate 14", "\tcompress", "\tdelaycompress", "\tnotifempty", "\tcreate 0640 www-data adm", "\tsharedscripts", "\tprerotate", "\t\tif [ -d /etc/logrotate.d/httpd-prerotate ]; then \\", "\t\t\trun-parts /etc/logrotate.d/httpd-prerotate; \\", "\t\tfi \\", "\tendscript", "\tpostrotate", "\t\tinvoke-rc.d nginx rotate >/dev/null 2>&1", "\tendscript", "}"), ageInstall)
	b.text("/etc/skel/.bashrc", bashrc, ageInstall)
	b.text("/etc/skel/.profile", profileRc, ageInstall)
	b.text("/etc/skel/.bash_logout", bashLogout, ageInstall)
	b.text("/etc/vim/vimrc", lines("\" All system-wide defaults are set in $VIMRUNTIME/debian.vim and sourced by", "\" the call to :runtime you can find below.  If you wish to change any of those", "\" settings, you should do it in this file (/etc/vim/vimrc), since debian.vim", "\" will be overwritten everytime an upgrade of the vim packages is performed.", "", "runtime! debian.vim", "", "\" Vim will load $VIMRUNTIME/defaults.vim if the user does not have a vimrc.", "if filereadable(\"/etc/vim/vimrc.local\")", "  source /etc/vim/vimrc.local", "endif"), ageInstall)
	b.placeholder("/etc/pam.d/sshd", 2133, "Ubuntu /etc/pam.d/sshd", 0o644, 0, 0, ageInstall)
	b.placeholder("/etc/pam.d/common-auth", 1332, "Ubuntu /etc/pam.d/common-auth", 0o644, 0, 0, ageInstall)
	b.placeholder("/etc/pam.d/common-password", 1642, "Ubuntu /etc/pam.d/common-password", 0o644, 0, 0, ageInstall)
	b.text("/etc/rsyslog.d/50-default.conf", lines("#  Default rules for rsyslog.", "#", "#\t\t\tFor more information see rsyslog.conf(5) and /etc/rsyslog.conf", "", "#", "# First some standard log files.  Log by facility.", "#", "auth,authpriv.*\t\t\t/var/log/auth.log", "*.*;auth,authpriv.none\t\t-/var/log/syslog", "#cron.*\t\t\t\t/var/log/cron.log", "#daemon.*\t\t\t-/var/log/daemon.log", "kern.*\t\t\t\t-/var/log/kern.log", "#lpr.*\t\t\t\t-/var/log/lpr.log", "mail.*\t\t\t\t-/var/log/mail.log", "#user.*\t\t\t\t-/var/log/user.log"), ageInstall)
	b.text("/etc/update-motd.d/00-header", lines("#!/bin/sh", "#", "#    00-header - create the header of the MOTD", "#    Copyright (C) 2009-2010 Canonical Ltd.", "", "[ -r /etc/lsb-release ] && . /etc/lsb-release", "", `if [ -z "$DISTRIB_DESCRIPTION" ] && [ -x /usr/bin/lsb_release ]; then`, "\t# Fall back to using the very slow lsb_release utility", "\tDISTRIB_DESCRIPTION=$(lsb_release -s -d)", "fi", "", `printf "Welcome to %s (%s %s %s)\n" "$DISTRIB_DESCRIPTION" "$(uname -o)" "$(uname -r)" "$(uname -m)"`), ageInstall)
}

// passwdFile renders /etc/passwd from the profile's users, sorted by uid.
func passwdFile(p *profile.Profile) string {
	users := sortedUsers(p)
	var sb strings.Builder
	for _, u := range users {
		fmt.Fprintf(&sb, "%s:x:%d:%d:%s:%s:%s\n", u.Name, u.UID, u.GID, u.Gecos, u.Home, u.Shell)
	}
	return sb.String()
}

// shadowFile renders /etc/shadow: real-looking hashes for real users,
// locked entries for system accounts. Nothing here matches any password
// the honeypot accepts, of course.
func shadowFile(p *profile.Profile, m *Machine) string {
	users := sortedUsers(p)
	days := m.Now().Unix() / 86400
	var sb strings.Builder
	for _, u := range users {
		var hash string
		switch {
		case u.Name == "root" || u.Name == "martin":
			hash = "$6$" + base64ish(u.Name+"salt", 16) + "$" + base64ish(u.Name+"hash", 86)
		case u.Name == "postgres" || u.Name == "deploy":
			hash = "!" // locked: key-only accounts
		default:
			hash = "*"
		}
		last := days - int64(seedHash(u.Name+"pw")%400)
		fmt.Fprintf(&sb, "%s:%s:%d:0:99999:7:::\n", u.Name, hash, last)
	}
	return sb.String()
}

// groupFile renders /etc/group with the standard Debian groups plus one
// per real user.
func groupFile(p *profile.Profile) string {
	type g struct {
		name string
		gid  int
		mem  string
	}
	base := []g{{"root", 0, ""}, {"daemon", 1, ""}, {"bin", 2, ""}, {"sys", 3, ""}, {"adm", 4, "syslog,martin"}, {"tty", 5, ""}, {"disk", 6, ""}, {"lp", 7, ""}, {"mail", 8, ""}, {"news", 9, ""}, {"uucp", 10, ""}, {"man", 12, ""}, {"proxy", 13, ""}, {"kmem", 15, ""}, {"dialout", 20, ""}, {"fax", 21, ""}, {"voice", 22, ""}, {"cdrom", 24, "martin"}, {"floppy", 25, ""}, {"tape", 26, ""}, {"sudo", 27, "martin"}, {"audio", 29, ""}, {"dip", 30, "martin"}, {"www-data", 33, ""}, {"backup", 34, ""}, {"operator", 37, ""}, {"list", 38, ""}, {"irc", 39, ""}, {"src", 40, ""}, {"gnats", 41, ""}, {"shadow", 42, ""}, {"utmp", 43, ""}, {"video", 44, ""}, {"sasl", 45, ""}, {"plugdev", 46, "martin"}, {"staff", 50, ""}, {"games", 60, ""}, {"users", 100, ""}, {"nogroup", 65534, ""}, {"systemd-journal", 101, ""}, {"systemd-network", 102, ""}, {"systemd-resolve", 103, ""}, {"messagebus", 105, ""}, {"systemd-timesync", 106, ""}, {"input", 107, ""}, {"sgx", 108, ""}, {"kvm", 109, ""}, {"render", 110, ""}, {"lxd", 111, "martin"}, {"_ssh", 112, ""}, {"crontab", 113, ""}, {"syslog", 114, ""}, {"uuidd", 115, ""}, {"postgres", 116, ""}, {"ssl-cert", 117, "postgres"}, {"netdev", 118, ""}}
	seen := map[int]bool{}
	for _, x := range base {
		seen[x.gid] = true
	}
	for _, u := range p.Users {
		if u.UID >= 1000 && !seen[u.GID] {
			base = append(base, g{u.Name, u.GID, ""})
			seen[u.GID] = true
		}
	}
	sort.SliceStable(base, func(i, j int) bool { return base[i].gid < base[j].gid })
	var sb strings.Builder
	for _, x := range base {
		fmt.Fprintf(&sb, "%s:x:%d:%s\n", x.name, x.gid, x.mem)
	}
	return sb.String()
}

func gshadowFile(p *profile.Profile) string {
	return strings.ReplaceAll(groupFile(p), ":x:", ":*:")
}

func sortedUsers(p *profile.Profile) []profile.User {
	users := append([]profile.User(nil), p.Users...)
	sort.SliceStable(users, func(i, j int) bool { return users[i].UID < users[j].UID })
	return users
}

// base64ish makes n stable base64-alphabet characters from a seed, for
// fake keys and hashes that must look right and never change.
func base64ish(seed string, n int) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := make([]byte, n)
	x := seedHash(seed)
	for i := range out {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		out[i] = alpha[x%64]
	}
	return string(out)
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func uuidFrom(seed string) string {
	h := fmt.Sprintf("%016x%016x", seedHash(seed+"a"), seedHash(seed+"b"))
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:32]
}

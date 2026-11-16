package shell

import (
	"io"
	"io/fs"
	"maps"
	"math/rand"
	"strings"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/machine"
	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

// Session is one attacker's shell state: where they are, who they are,
// their environment and history, on top of a private clone of the machine.
type Session struct {
	Machine *machine.Machine
	FS      *vfs.FS
	Cred    vfs.Cred
	User    string
	Group   string
	Cwd     string
	Env     map[string]string
	Umask   fs.FileMode
	History []string
	// Status is the exit code of the last command ($?).
	Status int
	// PID is the shell's fake process id, used for $$.
	PID int
	// Cols and Rows come from the pty; 0 means unknown (default 80x24).
	Cols, Rows int
	// Rand seeds any per-session randomness (fake pids, etc.).
	Rand *rand.Rand
	// Interactive marks an interactive login shell (a PTY session): $0 is
	// -bash, errors read "-bash: ...", a syntax error does not echo the
	// line and expansion errors abandon the line instead of exiting. Exec
	// and piped sessions leave it false and get bash -c's wording
	// ("bash: line 1: ...").
	Interactive bool

	// Terminal is the writer that is the attacker's terminal in a PTY
	// session (nil otherwise). Commands whose stdout is exactly this writer
	// behave as if isatty(1) were true; anything piped or redirected does
	// not, so `ls | cat` prints one name per line, as on a real box.
	Terminal io.Writer

	// prevPID is $!, the last background job's fake pid.
	prevPID int
	// elevated notes a `sudo -i`/`sudo -s` in this session (cosmetic).
	elevated bool

	started time.Time
	funcs   map[string]*funcDecl
	hashed  map[string]string // bash's command hash table, for type/hash
	ulimits map[string]string // values set with ulimit
	jobs    int               // background jobs started (for "[1] 1234")
	lines   int               // lines read by non-interactive runs ("line N")
	// active is the shell currently running a line for this session, so
	// builtins that re-enter the interpreter (sudo, nohup, timeout) share
	// its limits and wording.
	active *shell
}

// NewSession builds a session for user on a fresh clone of m's filesystem.
func NewSession(m *machine.Machine, user string, seed int64) *Session {
	u := m.Profile.User(user)
	home := "/root"
	gid := 0
	if u != nil {
		home = u.Home
		gid = u.GID
	} else if user != "root" {
		home = "/home/" + user
	}
	uid := 0
	if u != nil {
		uid = u.UID
	}
	r := rand.New(rand.NewSource(seed))
	s := &Session{
		Machine: m,
		FS:      m.NewSessionFS(),
		Cred:    vfs.Cred{UID: uid, GIDs: []int{gid}},
		User:    user,
		Group:   user,
		Cwd:     home,
		Umask:   0o022,
		PID:     10000 + r.Intn(22000),
		Rand:    r,
		started: m.Now(),
	}
	if s.FS.Exists(home) {
		s.Cwd = home
	} else {
		s.Cwd = "/"
	}
	s.Env = defaultEnv(user, home, m)
	return s
}

func defaultEnv(user, home string, m *machine.Machine) map[string]string {
	path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"
	shell := "/bin/bash"
	logname := user
	env := map[string]string{
		"SHELL":    shell,
		"PWD":      home,
		"LOGNAME":  logname,
		"HOME":     home,
		"LANG":     "en_US.UTF-8",
		"USER":     user,
		"PATH":     path,
		"MAIL":     "/var/mail/" + user,
		"TERM":     "xterm-256color",
		"HOSTNAME": m.Profile.Hostname,
		"_":        "/usr/bin/env",
	}
	if user == "root" {
		env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"
	}
	return env
}

// Getenv returns an environment variable, or "".
func (s *Session) Getenv(name string) string { return s.Env[name] }

// Prompt renders the bash PS1 the attacker sees, e.g. "root@srv-web01:~# ".
func (s *Session) Prompt() string {
	sym := "$"
	if s.Cred.IsRoot() {
		sym = "#"
	}
	return s.User + "@" + s.Machine.Profile.Hostname + ":" + s.tildeCwd() + sym + " "
}

func (s *Session) tildeCwd() string {
	home := s.Env["HOME"]
	if home != "" && (s.Cwd == home || strings.HasPrefix(s.Cwd, home+"/")) {
		return "~" + strings.TrimPrefix(s.Cwd, home)
	}
	return s.Cwd
}

// abs resolves p against the session's cwd.
func (s *Session) abs(p string) string { return vfs.Resolve(s.Cwd, p) }

// fork copies the session for a subshell: cwd, variables, functions and
// the rest are the child's own from here on; the filesystem is shared, as
// in bash.
func (s *Session) fork() *Session {
	c := *s
	c.Env = maps.Clone(s.Env)
	c.funcs = maps.Clone(s.funcs)
	c.hashed = maps.Clone(s.hashed)
	c.ulimits = maps.Clone(s.ulimits)
	c.History = s.History[:len(s.History):len(s.History)]
	return &c
}

// nextPID hands out a fake pid for a background job.
func (s *Session) nextPID() int {
	if s.prevPID < s.PID {
		s.prevPID = s.PID
	}
	s.prevPID += 1 + s.Rand.Intn(40)
	return s.prevPID
}

// homeOf returns user's home directory from the machine profile.
func (s *Session) homeOf(user string) (string, bool) {
	if u := s.Machine.Profile.User(user); u != nil {
		return u.Home, true
	}
	return "", false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

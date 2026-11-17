package shell

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

// maxFd is the highest file descriptor a redirection may name.
const maxFd = 9

// fdTable is a command's open file descriptors. Copying the struct gives
// the child its own table; the readers and writers themselves are shared,
// so a loop's redirected stdin is consumed line by line across iterations.
type fdTable struct {
	r    [maxFd + 1]io.Reader
	w    [maxFd + 1]io.Writer
	open [maxFd + 1]bool
}

func newFdTable(stdin io.Reader, stdout, stderr io.Writer) *fdTable {
	t := &fdTable{}
	t.setReader(0, stdin)
	t.setWriter(1, stdout)
	t.setWriter(2, stderr)
	return t
}

func (t *fdTable) setReader(fd int, r io.Reader) {
	t.r[fd], t.w[fd], t.open[fd] = r, nil, true
}

func (t *fdTable) setWriter(fd int, w io.Writer) {
	t.r[fd], t.w[fd], t.open[fd] = nil, w, true
}

func (t *fdTable) close(fd int) { t.r[fd], t.w[fd], t.open[fd] = nil, nil, false }

// in is stdin; a closed or write-only fd 0 reads as empty.
func (t *fdTable) in() io.Reader {
	if t.r[0] != nil {
		return t.r[0]
	}
	return strings.NewReader("")
}

// out is an output fd; a closed one swallows writes.
func (t *fdTable) out(fd int) io.Writer {
	if t.w[fd] != nil {
		return t.w[fd]
	}
	return io.Discard
}

// fileSink appends a command's output to a file in the virtual filesystem
// as it is written. The per-line write budget stops a loop from filling
// the honeypot's memory with one huge file.
type fileSink struct {
	fs   *vfs.FS
	path string
	opts vfs.WriteOptions
	lim  *limits
}

func (w *fileSink) Write(p []byte) (int, error) {
	n := len(p)
	if w.lim != nil {
		w.lim.move(len(p))
		room := maxFileWrite - w.lim.written
		if room <= 0 {
			return n, nil
		}
		if len(p) > room {
			p = p[:room]
		}
		w.lim.written += len(p)
	}
	_ = w.fs.AppendFile(w.path, p, w.opts)
	return n, nil
}

// cappedBuffer collects output up to a limit and silently drops the rest.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
	lim *limits
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.lim != nil {
		b.lim.move(len(p))
	}
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

// redirError is a failed redirection; the command does not run.
type redirError struct{ msg string }

func (e *redirError) Error() string { return e.msg }

// applyRedirs returns the fd table for a command with redirs applied in
// order on top of fds, so ">f 2>&1" and "2>&1 >f" differ as in bash.
func (sh *shell) applyRedirs(redirs []*redir, fds *fdTable) (*fdTable, error) {
	if len(redirs) == 0 {
		return fds, nil
	}
	nt := *fds
	for _, r := range redirs {
		if err := sh.applyRedir(&nt, r); err != nil {
			return nil, err
		}
	}
	return &nt, nil
}

func (sh *shell) applyRedir(t *fdTable, r *redir) error {
	fd := r.fd
	if fd < 0 {
		fd = defaultFd(r.op)
	}
	if fd > maxFd {
		return &redirError{msg: strconv.Itoa(fd) + ": Bad file descriptor"}
	}
	x := sh.expander(t)
	switch r.op {
	case "<<", "<<-":
		body, err := x.str(r.body)
		if err != nil {
			return err
		}
		t.setReader(fd, strings.NewReader(body))
		return nil
	case "<<<":
		s, err := x.str(r.target)
		if err != nil {
			return err
		}
		t.setReader(fd, strings.NewReader(s+"\n"))
		return nil
	}
	fields, err := x.fields(r.target, true)
	if err != nil {
		return err
	}
	if len(fields) != 1 {
		return &redirError{msg: r.target.src + ": ambiguous redirect"}
	}
	target := fields[0]
	switch r.op {
	case ">&", "<&":
		if target == "-" {
			t.close(fd)
			return nil
		}
		if isDigits(target) {
			src, _ := strconv.Atoi(target)
			if src > maxFd || !t.open[src] {
				return &redirError{msg: target + ": Bad file descriptor"}
			}
			t.r[fd], t.w[fd], t.open[fd] = t.r[src], t.w[src], true
			return nil
		}
		if r.op == "<&" || r.fd >= 0 {
			return &redirError{msg: r.target.src + ": ambiguous redirect"}
		}
		// >&word is &>word.
		w, err := sh.openWrite(t, target, false)
		if err != nil {
			return err
		}
		t.setWriter(1, w)
		t.setWriter(2, w)
		return nil
	case "&>", "&>>":
		w, err := sh.openWrite(t, target, r.op == "&>>")
		if err != nil {
			return err
		}
		t.setWriter(1, w)
		t.setWriter(2, w)
		return nil
	case ">", ">|", ">>":
		w, err := sh.openWrite(t, target, r.op == ">>")
		if err != nil {
			return err
		}
		t.setWriter(fd, w)
		return nil
	case "<", "<>":
		rd, err := sh.openRead(t, target, r.op == "<>")
		if err != nil {
			return err
		}
		t.setReader(fd, rd)
		return nil
	}
	return &redirError{msg: "syntax error near unexpected token `" + r.op + "'"}
}

// netRedirect reports a /dev/tcp or /dev/udp path. bash would connect;
// the honeypot never opens a socket, so the connection is refused.
func netRedirect(p string) bool {
	return strings.HasPrefix(p, "/dev/tcp/") || strings.HasPrefix(p, "/dev/udp/")
}

// devStream maps the /dev names bash and the kernel treat specially to an
// fd, or -1.
func devStream(p string) int {
	switch p {
	case "/dev/stdin", "/proc/self/fd/0":
		return 0
	case "/dev/stdout", "/proc/self/fd/1":
		return 1
	case "/dev/stderr", "/proc/self/fd/2":
		return 2
	}
	if n, ok := strings.CutPrefix(p, "/dev/fd/"); ok && isDigits(n) && len(n) == 1 {
		return int(n[0] - '0')
	}
	return -1
}

// openWrite opens target for output: truncating it (or appending) in the
// virtual filesystem after the same checks the kernel would make.
func (sh *shell) openWrite(t *fdTable, target string, appendMode bool) (io.Writer, error) {
	s := sh.s
	abs := s.abs(target)
	if fd := devStream(abs); fd >= 0 {
		if !t.open[fd] {
			return nil, &redirError{msg: target + ": Bad file descriptor"}
		}
		return t.out(fd), nil
	}
	if abs == "/dev/tty" {
		if sh.lim.tty != nil {
			return sh.lim.tty, nil
		}
		return io.Discard, nil
	}
	if netRedirect(abs) {
		return nil, sh.refuseNet(target)
	}
	info, err := s.FS.Stat(abs)
	switch {
	case err == nil && info.IsDir():
		return nil, &redirError{msg: target + ": Is a directory"}
	case err == nil && info.IsDevice():
		return io.Discard, nil
	case err == nil:
		if !permit(s, abs, 'w') {
			return nil, &redirError{msg: target + ": Permission denied"}
		}
	case errors.Is(err, vfs.ErrNotExist):
		if err := sh.checkCreatable(target, abs); err != nil {
			return nil, err
		}
	default:
		return nil, &redirError{msg: target + ": " + vfs.Strerror(err)}
	}
	opts := vfs.WriteOptions{Mode: 0o666 &^ s.Umask, UID: s.Cred.UID}
	if len(s.Cred.GIDs) > 0 {
		opts.GID = s.Cred.GIDs[0]
	}
	if appendMode {
		err = s.FS.AppendFile(abs, nil, opts)
	} else {
		err = s.FS.WriteFile(abs, nil, opts)
	}
	if err != nil {
		return nil, &redirError{msg: target + ": " + vfs.Strerror(err)}
	}
	return &fileSink{fs: s.FS, path: abs, opts: opts, lim: sh.lim}, nil
}

// checkCreatable verifies a new file's directory exists and is writable.
func (sh *shell) checkCreatable(target, abs string) error {
	dir := parentOf(abs)
	info, err := sh.s.FS.Stat(dir)
	if err != nil {
		return &redirError{msg: target + ": No such file or directory"}
	}
	if !info.IsDir() {
		return &redirError{msg: target + ": Not a directory"}
	}
	if !vfs.Allowed(info, sh.s.Cred, vfs.W) {
		return &redirError{msg: target + ": Permission denied"}
	}
	return nil
}

// openRead opens target for input. A placeholder file is generated first,
// as any other read of it would be.
func (sh *shell) openRead(t *fdTable, target string, rw bool) (io.Reader, error) {
	s := sh.s
	abs := s.abs(target)
	if fd := devStream(abs); fd >= 0 {
		if !t.open[fd] {
			return nil, &redirError{msg: target + ": Bad file descriptor"}
		}
		return t.r[fd], nil
	}
	if abs == "/dev/null" {
		return strings.NewReader(""), nil
	}
	if netRedirect(abs) {
		return nil, sh.refuseNet(target)
	}
	info, err := s.FS.Stat(abs)
	if err != nil {
		if rw && errors.Is(err, vfs.ErrNotExist) {
			if _, err := sh.openWrite(t, target, true); err != nil {
				return nil, err
			}
			return strings.NewReader(""), nil
		}
		return nil, &redirError{msg: target + ": " + vfs.Strerror(err)}
	}
	if info.IsDir() {
		return nil, &redirError{msg: target + ": Is a directory"}
	}
	if !permit(s, abs, 'r') {
		return nil, &redirError{msg: target + ": Permission denied"}
	}
	data, dinfo, err := s.FS.ReadFile(abs)
	if err != nil {
		return nil, &redirError{msg: target + ": " + vfs.Strerror(err)}
	}
	if dinfo.Placeholder {
		if gen := sh.in.FileContent; gen != nil {
			ctx := &Context{Sess: s, Interp: sh.in, Args: []string{"bash"}, Stdin: t.in(), Stdout: t.out(1), Stderr: t.out(2), sh: sh, fds: t}
			if filled, ok := gen(ctx, abs, dinfo); ok {
				data = filled
			}
		}
	}
	return bytes.NewReader(data), nil
}

// refuseNet answers a /dev/tcp redirection the way bash does when the
// connection fails.
func (sh *shell) refuseNet(target string) error {
	return &redirError{msg: "connect: Connection refused\n" + sh.prefix() + target + ": Connection refused"}
}

func parentOf(p string) string {
	for i := len(p) - 1; i > 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "/"
}

// redirFailed reports a failed redirection or expansion and returns the
// status the command gets.
func (sh *shell) redirFailed(err error, stderr io.Writer) int {
	var xe *expandError
	if errors.As(err, &xe) {
		return sh.expansionFailed(xe, stderr)
	}
	fmt.Fprintf(stderr, "%s%s\n", sh.prefix(), err)
	return 1
}

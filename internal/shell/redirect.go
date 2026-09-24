package shell

import (
	"bytes"
	"fmt"
	"io"

	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

// vfsSink buffers a command's output and writes it to the virtual
// filesystem when the command finishes. Whole-file writes keep the VFS
// simple and are indistinguishable from the attacker's point of view.
type vfsSink struct {
	fs     *vfs.FS
	path   string
	append bool
	opts   vfs.WriteOptions
	buf    bytes.Buffer
}

func (w *vfsSink) Write(p []byte) (int, error) { return w.buf.Write(p) }

func (w *vfsSink) flush() error {
	if w.append {
		return w.fs.AppendFile(w.path, w.buf.Bytes(), w.opts)
	}
	return w.fs.WriteFile(w.path, w.buf.Bytes(), w.opts)
}

// applyRedirects rewires stdout/stderr/stdin per the command's redirects.
// It returns the possibly-replaced writers, a cleanup that flushes file
// sinks, and an error (e.g. input file missing). stdinp is updated in
// place for input redirections.
func (in *Interp) applyRedirects(s *Session, c *SimpleCommand, stdout, stderr io.Writer, stdinp *io.Reader) (io.Writer, io.Writer, func(), error) {
	var sinks []*vfsSink
	cleanup := func() {
		for _, snk := range sinks {
			_ = snk.flush()
		}
	}
	opts := vfs.WriteOptions{Mode: 0o644 &^ s.Umask, UID: s.Cred.UID}
	if len(s.Cred.GIDs) > 0 {
		opts.GID = s.Cred.GIDs[0]
	}

	for _, r := range c.Redirects {
		target := s.abs(r.Target)
		switch r.Op {
		case ">", ">>", "&>":
			// The parent directory must exist and be writable.
			if err := in.checkWritable(s, target); err != nil {
				cleanup()
				return stdout, stderr, func() {}, err
			}
			snk := &vfsSink{fs: s.FS, path: target, append: r.Op == ">>", opts: opts}
			sinks = append(sinks, snk)
			stdout = snk
			if r.Op == "&>" {
				stderr = snk
			}
		case "2>", "2>>":
			if err := in.checkWritable(s, target); err != nil {
				cleanup()
				return stdout, stderr, func() {}, err
			}
			snk := &vfsSink{fs: s.FS, path: target, append: r.Op == "2>>", opts: opts}
			sinks = append(sinks, snk)
			stderr = snk
		case "<":
			data, info, err := s.FS.ReadFile(target)
			if err != nil {
				cleanup()
				return stdout, stderr, func() {}, fmt.Errorf("%s: %s", r.Target, vfs.Strerror(err))
			}
			if info.IsDir() {
				cleanup()
				return stdout, stderr, func() {}, fmt.Errorf("%s: Is a directory", r.Target)
			}
			if info.Placeholder {
				// Not yet materialised: reads see empty for now.
				data = nil
			}
			*stdinp = bytes.NewReader(data)
		}
	}
	return stdout, stderr, cleanup, nil
}

// checkWritable verifies target's directory exists and is writable and
// that target itself is not a directory.
func (in *Interp) checkWritable(s *Session, target string) error {
	if info, err := s.FS.Lstat(target); err == nil && info.IsDir() {
		return fmt.Errorf("%s: Is a directory", target)
	}
	dir := parentOf(target)
	info, err := s.FS.Stat(dir)
	if err != nil {
		return fmt.Errorf("%s: No such file or directory", target)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s: Not a directory", target)
	}
	if !vfs.Allowed(info, s.Cred, vfs.W) {
		return fmt.Errorf("%s: Permission denied", target)
	}
	return nil
}

func parentOf(p string) string {
	for i := len(p) - 1; i > 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "/"
}

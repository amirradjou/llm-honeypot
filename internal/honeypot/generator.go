package honeypot

import (
	"context"
	"fmt"
	"strings"

	"github.com/amirradjou/llm-honeypot/internal/llm"
	"github.com/amirradjou/llm-honeypot/internal/machine"
	"github.com/amirradjou/llm-honeypot/internal/shell"
	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

// UseGenerator wires a model backend into the interpreter: unknown commands
// and placeholder file contents are produced by g (already wrapped in a
// cache). Call before serving. With a Null generator this is a no-op and
// the honeypot behaves exactly as without a model.
func (h *Handler) UseGenerator(g llm.Generator) {
	if g == nil {
		return
	}
	h.gen = g
	facts := machineFacts(h.machine)

	// Unknown commands: ask the model for their output.
	h.interp.Fallback = func(ctx *shell.Context) (int, bool) {
		line := strings.Join(ctx.Args, " ")
		// A command line addressed at the model is not a real command.
		// Declining here means bash answers it the way it really would,
		// which is both safer and more convincing than a generated reply.
		if llm.SuspectInjection(line) {
			if sink := h.sinkFor(ctx.Sess); sink != nil {
				sink.ModelCall("declined-injection:"+ctx.Args[0], g.Model(), 0)
			}
			return 0, false
		}
		out, tokens, err := g.Generate(context.Background(), llm.Request{
			Kind:    llm.KindCommand,
			Machine: facts,
			Cwd:     ctx.Sess.Cwd,
			User:    ctx.Sess.User,
			Recent:  recent(ctx.Sess),
			Input:   line,
		})
		if err != nil {
			return 0, false // fall back to "command not found"
		}
		if sink := h.sinkFor(ctx.Sess); sink != nil {
			sink.ModelCall("command:"+ctx.Args[0], g.Model(), tokens)
		}
		ctx.Print(out)
		return 0, true
	}

	// Placeholder files: ask the model for their contents, then write the
	// result back into the session filesystem so later reads agree.
	h.interp.FileContent = func(ctx *shell.Context, path string, info vfs.Info) ([]byte, bool) {
		out, tokens, err := g.Generate(context.Background(), llm.Request{
			Kind:    llm.KindFile,
			Machine: facts,
			Cwd:     ctx.Sess.Cwd,
			User:    ctx.Sess.User,
			Recent:  recent(ctx.Sess),
			Input:   path,
			Hint:    info.Hint,
		})
		if err != nil {
			return nil, false
		}
		data := []byte(out)
		// Materialise the placeholder so ls sizes and repeat reads are
		// consistent, preserving the original owner/mode.
		_ = ctx.FS().WriteFile(path, data, vfs.WriteOptions{Mode: info.Mode.Perm(), UID: info.UID, GID: info.GID})
		if sink := h.sinkFor(ctx.Sess); sink != nil {
			sink.ModelCall("file:"+path, g.Model(), tokens)
		}
		return data, true
	}
}

// recent returns the last few command lines for model continuity.
func recent(s *shell.Session) []string {
	const n = 8
	if len(s.History) <= n {
		return s.History
	}
	return s.History[len(s.History)-n:]
}

// machineFacts renders the profile into the compact factual block the model
// is grounded on. It is built once per machine and reused for every call.
func machineFacts(m *machine.Machine) string {
	p := m.Profile
	var b strings.Builder
	fmt.Fprintf(&b, "hostname: %s\n", p.Hostname)
	fmt.Fprintf(&b, "os: %s\n", p.OSPretty)
	fmt.Fprintf(&b, "kernel: %s (%s)\n", p.Kernel, p.Arch)
	fmt.Fprintf(&b, "cpu: %s x%d\n", p.CPUModel, p.CPUCores)
	fmt.Fprintf(&b, "memory: %d MB, swap %d MB\n", p.MemMB, p.SwapMB)
	fmt.Fprintf(&b, "disk: %d GB (%d%% used)\n", p.DiskGB, p.DiskUsedPct)
	fmt.Fprintf(&b, "network: %s on %s, gateway %s\n", p.IPv4, p.Interface, p.Gateway)
	fmt.Fprintf(&b, "role: %s\n", p.Role)
	// A few human users so invented output names real accounts.
	var users []string
	for _, u := range p.Users {
		if u.UID == 0 || u.UID >= 1000 && u.Shell != "/usr/sbin/nologin" {
			users = append(users, u.Name)
		}
	}
	fmt.Fprintf(&b, "notable users: %s\n", strings.Join(users, ", "))
	fmt.Fprintf(&b, "installed packages include: %s\n", strings.Join(p.Packages, ", "))
	return b.String()
}

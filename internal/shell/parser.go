// Package shell parses and interprets the small subset of bash that
// attackers actually type: quoting, variable expansion, pipelines,
// sequences (;, &&, ||), redirections and background (&). It never runs
// anything real; commands are Go functions over the virtual machine.
package shell

import (
	"fmt"
	"strings"
)

// Redirect is one I/O redirection on a command.
type Redirect struct {
	// Op is one of ">", ">>", "<", "2>", "2>>", "&>".
	Op string
	// Target is the file path (already expanded).
	Target string
}

// SimpleCommand is a single command with its arguments and redirections.
// Assignments that precede the command (FOO=bar cmd) are captured too.
type SimpleCommand struct {
	Assigns   []string // "FOO=bar" prefixes
	Args      []string // argv; Args[0] is the command name
	Redirects []Redirect
}

// Pipeline is one or more SimpleCommands joined by "|".
type Pipeline struct {
	Cmds []*SimpleCommand
}

// AndOr is a sequence of pipelines joined by && / || / ; operators.
type AndOr struct {
	// Pipelines[i] runs; Ops[i] ("&&", "||", ";", "&") joins to Pipelines[i+1].
	Pipelines []*Pipeline
	Ops       []string
	// Background is true when the whole list ended with '&'.
	Background bool
}

// Expander resolves variables and ~ during parsing. The interpreter
// supplies one backed by the session's environment.
type Expander interface {
	// Var returns the value of name and whether it was set.
	Var(name string) (string, bool)
	// Home returns the home directory for ~ (empty user = current user).
	Home(user string) (string, bool)
}

// Parse turns a command line into an AndOr. It returns an error for
// genuinely malformed input (unterminated quotes, dangling operators);
// bots occasionally send those and a real bash would complain too.
func Parse(line string, exp Expander) (*AndOr, error) {
	toks, err := tokenize(line, exp)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return &AndOr{}, nil
	}
	return parseTokens(toks)
}

// token kinds
type tokKind int

const (
	tWord tokKind = iota
	tPipe
	tAnd   // &&
	tOr    // ||
	tSemi  // ;
	tBg    // &
	tRedir // >, >>, <, 2>, 2>>, &>
)

type token struct {
	kind tokKind
	val  string // word text (expanded) or redirection operator
	// quoted marks a word that was entirely quoted, so an empty string
	// still counts as an argument (e.g. cmd "").
	quoted bool
}

func parseTokens(toks []token) (*AndOr, error) {
	ao := &AndOr{}
	pl := &Pipeline{}
	cmd := &SimpleCommand{}
	expectMore := false // a |, && or || needs a command after it

	flushCmd := func() error {
		if len(cmd.Args) == 0 && len(cmd.Assigns) == 0 && len(cmd.Redirects) == 0 {
			return fmt.Errorf("syntax error near unexpected token")
		}
		pl.Cmds = append(pl.Cmds, cmd)
		cmd = &SimpleCommand{}
		return nil
	}
	flushPipe := func(op string) error {
		if err := flushCmd(); err != nil {
			return err
		}
		ao.Pipelines = append(ao.Pipelines, pl)
		if op != "" {
			ao.Ops = append(ao.Ops, op)
		}
		pl = &Pipeline{}
		return nil
	}

	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch t.kind {
		case tWord:
			expectMore = false
			if len(cmd.Args) == 0 && !t.quoted && isAssignment(t.val) {
				cmd.Assigns = append(cmd.Assigns, t.val)
			} else {
				cmd.Args = append(cmd.Args, t.val)
			}
		case tRedir:
			expectMore = false
			if i+1 >= len(toks) || toks[i+1].kind != tWord {
				return nil, fmt.Errorf("syntax error near unexpected token `newline'")
			}
			cmd.Redirects = append(cmd.Redirects, Redirect{Op: t.val, Target: toks[i+1].val})
			i++
		case tPipe:
			if len(cmd.Args) == 0 {
				return nil, fmt.Errorf("syntax error near unexpected token `|'")
			}
			if err := flushCmd(); err != nil {
				return nil, err
			}
			expectMore = true
		case tAnd, tOr, tSemi:
			op := map[tokKind]string{tAnd: "&&", tOr: "||", tSemi: ";"}[t.kind]
			if err := flushPipe(op); err != nil {
				return nil, err
			}
			expectMore = t.kind != tSemi
		case tBg:
			if err := flushPipe(";"); err != nil {
				return nil, err
			}
			ao.Background = true
		}
	}
	if expectMore && len(cmd.Args) == 0 && len(cmd.Assigns) == 0 && len(cmd.Redirects) == 0 {
		return nil, fmt.Errorf("syntax error near unexpected token `newline'")
	}
	// Trailing command / pipeline.
	if len(cmd.Args) > 0 || len(cmd.Assigns) > 0 || len(cmd.Redirects) > 0 {
		if err := flushCmd(); err != nil {
			return nil, err
		}
		ao.Pipelines = append(ao.Pipelines, pl)
	} else if len(pl.Cmds) > 0 {
		ao.Pipelines = append(ao.Pipelines, pl)
	} else if len(ao.Ops) > 0 && strings.HasSuffix(lastOp(ao), "&&") {
		return nil, fmt.Errorf("syntax error near unexpected token `newline'")
	}
	// A dangling && or || with nothing after is an error; a dangling ; is fine.
	if n := len(ao.Ops); n > 0 && len(ao.Pipelines) <= n {
		if ao.Ops[n-1] == "&&" || ao.Ops[n-1] == "||" {
			return nil, fmt.Errorf("syntax error near unexpected token `newline'")
		}
		ao.Ops = ao.Ops[:len(ao.Pipelines)-1]
	}
	return ao, nil
}

func lastOp(ao *AndOr) string {
	if len(ao.Ops) == 0 {
		return ""
	}
	return ao.Ops[len(ao.Ops)-1]
}

// isAssignment reports whether s looks like NAME=value with a valid name.
func isAssignment(s string) bool {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return false
	}
	name := s[:eq]
	for i, r := range name {
		if r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

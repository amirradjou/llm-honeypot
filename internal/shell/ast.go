package shell

// The parser turns a command line or script into this tree, and the
// interpreter walks it. Words keep their quoting structure so expansion can
// happen when each command runs, the way bash does it: X=1; echo $X works,
// and so do cd /tmp; echo $PWD and X=$(uname -m); echo "arch:$X".

// word is one shell word before expansion.
type word struct {
	parts []wpart
	src   string // the word as typed
	// alts holds the result of brace expansion: when set, the word stands
	// for each of these words in turn ({a,b} and {1..3}).
	alts []*word
}

type wpart interface{ isPart() }

type (
	// wLit is unquoted literal text: subject to pathname expansion.
	wLit struct{ s string }
	// wQuoted is text that came from quotes or a backslash escape.
	wQuoted struct{ s string }
	// wDouble is a double-quoted section: expansions inside it are not
	// split into fields and not globbed.
	wDouble struct{ parts []wpart }
	// wTilde is a leading ~ or ~user.
	wTilde struct{ user string }
	// wParam is $name, ${name} or ${name<op>arg}.
	wParam struct {
		name string
		op   string // "" or one of the ${...} operators, "len", "bad"
		ind  bool   // ${!name}
		arg  *word  // default, pattern, offset ...
		arg2 *word  // replacement for ${x/p/r}, length for ${x:o:l}
		src  string
	}
	// wCmdSub is $(...) or `...`.
	wCmdSub struct {
		body *list
		src  string
	}
	// wArith is $((...)).
	wArith struct {
		expr *word
		src  string
	}
)

func (*wLit) isPart()    {}
func (*wQuoted) isPart() {}
func (*wDouble) isPart() {}
func (*wTilde) isPart()  {}
func (*wParam) isPart()  {}
func (*wCmdSub) isPart() {}
func (*wArith) isPart()  {}

// list is a sequence of and-or lists separated by ; & or newlines.
type list struct{ items []*andOr }

// andOr is pipelines joined by && and ||; bg marks a trailing &.
type andOr struct {
	pipes []*pipeline
	ops   []string // ops[i] joins pipes[i] and pipes[i+1]
	bg    bool
	line  int
}

type pipeline struct {
	cmds  []command
	amp   []bool // amp[i]: cmds[i] is joined to the next with |& (stderr too)
	bang  bool   // ! pipeline
	timed bool   // time pipeline
}

// command is a simple command, a compound command or a function definition.
type command interface{ isCommand() }

type simpleCmd struct {
	assigns []*assign
	words   []*word
	redirs  []*redir
	line    int
}

type assign struct {
	name  string
	value *word
	add   bool // NAME+=value
}

// redir is one redirection. fd is -1 when the operator's default applies.
type redir struct {
	fd     int
	op     string // < > >> >| <> >& <& &> &>> << <<- <<<
	target *word
	// Here-documents: the delimiter, whether it was quoted (no expansion
	// in the body), and the body once the parser has read it.
	delim  string
	quoted bool
	body   *word
	line   int
}

type (
	braceGroup struct {
		body   *list
		redirs []*redir
	}
	subshellCmd struct {
		body   *list
		redirs []*redir
	}
	ifClause struct {
		conds, bodies []*list
		elseBody      *list
		redirs        []*redir
	}
	forClause struct {
		name   string
		items  []*word
		hasIn  bool
		body   *list
		redirs []*redir
		line   int
	}
	arithFor struct {
		init, cond, step *word
		body             *list
		redirs           []*redir
		line             int
	}
	whileClause struct {
		cond, body *list
		until      bool
		redirs     []*redir
	}
	caseClause struct {
		subject *word
		items   []*caseItem
		redirs  []*redir
		line    int
	}
	arithCmd struct {
		expr   *word
		redirs []*redir
		line   int
	}
	// condCmd is [[ ... ]]: operands are words, operators are kept as text.
	condCmd struct {
		items  []condItem
		redirs []*redir
		line   int
	}
	funcDecl struct {
		name string
		body command
		src  string // the body as typed, for `type`
		line int
	}
)

type caseItem struct {
	patterns []*word
	body     *list
	term     string // ;; ;& ;;&
}

type condItem struct {
	w  *word
	op string // set for && || ( ) < > (operators the lexer splits off)
}

func (*simpleCmd) isCommand()   {}
func (*braceGroup) isCommand()  {}
func (*subshellCmd) isCommand() {}
func (*ifClause) isCommand()    {}
func (*forClause) isCommand()   {}
func (*arithFor) isCommand()    {}
func (*whileClause) isCommand() {}
func (*caseClause) isCommand()  {}
func (*arithCmd) isCommand()    {}
func (*condCmd) isCommand()     {}
func (*funcDecl) isCommand()    {}

// redirsOf returns a compound command's own redirections.
func redirsOf(c command) []*redir {
	switch c := c.(type) {
	case *braceGroup:
		return c.redirs
	case *subshellCmd:
		return c.redirs
	case *ifClause:
		return c.redirs
	case *forClause:
		return c.redirs
	case *arithFor:
		return c.redirs
	case *whileClause:
		return c.redirs
	case *caseClause:
		return c.redirs
	case *arithCmd:
		return c.redirs
	case *condCmd:
		return c.redirs
	}
	return nil
}

// setRedirs attaches trailing redirections to a compound command.
func setRedirs(c command, r []*redir) {
	switch c := c.(type) {
	case *braceGroup:
		c.redirs = r
	case *subshellCmd:
		c.redirs = r
	case *ifClause:
		c.redirs = r
	case *forClause:
		c.redirs = r
	case *arithFor:
		c.redirs = r
	case *whileClause:
		c.redirs = r
	case *caseClause:
		c.redirs = r
	case *arithCmd:
		c.redirs = r
	case *condCmd:
		c.redirs = r
	}
}

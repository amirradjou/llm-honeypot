package analysis

import (
	"strings"

	"github.com/amirradjou/llm-honeypot/internal/shell"
)

// nullExpander resolves nothing: when splitting a recorded line we only
// care about its structure, not what the variables were worth.
type nullExpander struct{}

func (nullExpander) Var(string) (string, bool)  { return "", false }
func (nullExpander) Home(string) (string, bool) { return "", false }

// splitLine breaks one recorded command line into the individual commands
// it ran. Attackers almost always arrive with a single line chaining
// several commands ("cd /tmp; wget ...; chmod +x x; ./x"), and the
// recording faithfully stores what they typed — so the analysis has to do
// the splitting.
//
// It reuses the honeypot's own shell parser, which means quoting is
// handled correctly: a semicolon inside quotes does not split a command.
// A line the parser rejects falls back to being treated as one command.
func splitLine(line string) []string {
	ao, err := shell.Parse(line, nullExpander{})
	if err != nil || ao == nil || len(ao.Pipelines) == 0 {
		if strings.TrimSpace(line) == "" {
			return nil
		}
		return []string{line}
	}
	var out []string
	for _, pl := range ao.Pipelines {
		for _, cmd := range pl.Cmds {
			if len(cmd.Args) == 0 {
				continue
			}
			out = append(out, strings.Join(cmd.Args, " "))
		}
	}
	if len(out) == 0 {
		return []string{line}
	}
	return out
}

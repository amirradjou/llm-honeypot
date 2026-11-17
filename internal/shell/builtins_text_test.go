package shell

import "testing"

// Every expected output below was recorded from a real Ubuntu 22.04
// container (tools/fidelity/Dockerfile) running the same line under bash.
func TestTextToolsMatchUbuntu(t *testing.T) {
	cases := []struct{ line, want string }{
		{`echo "a b c" | awk '{print $2}'`, "b\n"},
		{`echo "a:b:c" | awk -F: '{print $3}'`, "c\n"},
		{`printf '1 x\n2 y\n3 z\n' | awk 'NR==2 {print $2}'`, "y\n"},
		{`printf '1 x\n2 y\n3 z\n' | awk '{s+=$1} END {print s}'`, "6\n"},
		{`printf 'root:x:0\nbin:x:1\n' | awk -F: '$3==0 {print $1}'`, "root\n"},
		{`printf 'a\nbb\nccc\n' | awk 'length($0) > 1'`, "bb\nccc\n"},
		{`printf 'x 1\ny 2\n' | awk '/y/ {print $1, $2*10}'`, "y 20\n"},
		{`echo "Model name: Intel Xeon" | awk -F': ' '{print $2}'`, "Intel Xeon\n"},
		{`printf 'a b\n' | awk '{printf "%s-%s\n", $2, $1}'`, "b-a\n"},
		{`echo "hello world" | awk '{print toupper(substr($1,1,1)) substr($1,2)}'`, "Hello\n"},
		{`echo "a b c" | awk '{print $NF; print NF}'`, "c\n3\n"},
		{`echo "3 4" | awk '{print ($1 > $2) ? "big" : "small"}'`, "small\n"},
		{`echo "a,b" | awk 'BEGIN{FS=","} {print $2}'`, "b\n"},
		{`awk 'BEGIN {print 1/3}'`, "0.333333\n"},
		{`echo "x" | awk '{gsub(/x/,"y"); print}'`, "y\n"},
		{`awk 'BEGIN { x = 10; x += 5; print x }'`, "15\n"},
		{`printf 'h1 h2\nv1 v2\n' | awk 'FNR == 2 {print $2;}'`, "v2\n"},
		{`echo "  lead  trail  " | awk '{print $1 "|" $2}'`, "lead|trail\n"},
		{`printf 'a 1\nb 2\n' | awk '$2 > 1 {print $1}'`, "b\n"},
		{`echo "10 3" | awk '{print $1 % $2, $1 / $2, int($1/$2)}'`, "1 3.33333 3\n"},
		{`echo "a b" | awk '{$2 = "X"; print}'`, "a X\n"},
		{`echo "x" | awk '{ if ($1 == "x") print "yes"; else print "no" }'`, "yes\n"},
		{`echo hello world | sed 's/world/there/'`, "hello there\n"},
		{`printf 'a\nb\nc\n' | sed -n 2p`, "b\n"},
		{`printf 'a\nb\nc\n' | sed '2d'`, "a\nc\n"},
		{`printf 'a\nb\nc\n' | sed '$d'`, "a\nb\n"},
		{`echo aaa | sed 's/a/b/g'`, "bbb\n"},
		{`echo aaa | sed 's/a/b/2'`, "aba\n"},
		{`echo 'foo bar' | sed -E 's/(\w+) (\w+)/\2 \1/'`, "bar foo\n"},
		{`echo 'foo bar' | sed 's/\(foo\) \(bar\)/\2 \1/'`, "bar foo\n"},
		{`printf 'x\nkeep\nx\n' | sed '/x/d'`, "keep\n"},
		{`printf '1\n2\n3\n4\n' | sed -n '2,3p'`, "2\n3\n"},
		{`echo abc | sed 'y/abc/xyz/'`, "xyz\n"},
		{`printf 'a\nb\n' | sed '1a inserted'`, "a\ninserted\nb\n"},
		{`echo hi | sed -e 's/h/H/' -e 's/i/I/'`, "HI\n"},
		{`echo 'a.b' | sed 's/./X/'`, "X.b\n"},
		{`echo 'a+b' | sed 's/a+b/ok/'`, "ok\n"},
		{`printf 'a\nb\n' | sed -n '$='`, "2\n"},
		{`printf '1\n2\n3\n' | sed 2q`, "1\n2\n"},
		{`printf 'no newline' | sed 's/no/a/'`, "a newline"},
		{`echo 'path/to/x' | sed 's|/|:|g'`, "path:to:x\n"},
		{`echo hello | base64`, "aGVsbG8K\n"},
		{`echo aGVsbG8K | base64 -d`, "hello\n"},
		{`printf '' | base64`, ""},
		{`printf '%0100d' 0 | base64 | wc -l`, "2\n"},
		{`echo -n abc | base64 -w0`, "YWJj"},
		{`seq 1 3 | xargs echo`, "1 2 3\n"},
		{`printf 'a b\nc\n' | xargs -n 1 echo`, "a\nb\nc\n"},
		{`printf '' | xargs -r echo hi`, ""},
		{`printf '' | xargs echo hi`, "hi\n"},
		{`printf 'x\ny\n' | xargs -I{} echo item-{}`, "item-x\nitem-y\n"},
		{`echo a | xargs`, "a\n"},
		{`printf 'abcdef' | dd bs=2 count=2 2>/dev/null`, "abcd"},
		{`printf 'a\nb\n' | wc -l`, "2\n"},
		{`printf 'a\n' | wc`, "      1       1       2\n"},
		{`printf 'a b\n' | wc -l -w`, "      1       2\n"},
		{`echo a:b:c | tr ':' '\n'`, "a\nb\nc\n"},
		{`echo hello | tr a-z A-Z`, "HELLO\n"},
		{`echo hello | tr -d l`, "heo\n"},
		{`echo 'aaabbb' | tr -s a`, "abbb\n"},
		{`echo abc123 | tr -cd '0-9'`, "123"},
		{`echo hi | tr '[:lower:]' '[:upper:]'`, "HI\n"},
		{`printf 'CPU(s): 2\nCPUs\n' | grep "^CPU(s)"`, "CPU(s): 2\n"},
		{`printf 'aa\nab\nb\n' | grep 'a\+b'`, "ab\n"},
		{`printf 'foo\nbar\n' | grep -E 'foo|bar' | wc -l`, "2\n"},
		{`printf 'x{2}\nxx\n' | grep 'x{2}'`, "x{2}\n"},
		{`printf 'a|b\nab\n' | grep 'a|b'`, "a|b\n"},
		{`printf 'word\nwordy\n' | grep '\<word\>'`, "word\n"},
	}
	for _, c := range cases {
		in, s := testSession(t)
		out, errb, _ := run(t, in, s, c.line)
		if out != c.want {
			t.Errorf("%s\n got %q (stderr %q)\nwant %q", c.line, out, errb, c.want)
		}
	}
}

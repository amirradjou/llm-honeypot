package shell

import "strconv"

// cmdTest implements test / [ for the common one-argument and binary
// forms droppers use: -e, -f, -d, -r, -w, -x, -s, -z, -n, string/number
// comparisons. Unknown expressions are treated as false.
func cmdTest(c *Context) int {
	args := c.Args[1:]
	if c.Args[0] == "[" {
		if len(args) == 0 || args[len(args)-1] != "]" {
			c.Errorf("missing `]'")
			return 2
		}
		args = args[:len(args)-1]
	}
	if boolToStatus(evalTest(c, args)) == 0 {
		return 0
	}
	return 1
}

func evalTest(c *Context, args []string) bool {
	switch len(args) {
	case 0:
		return false
	case 1:
		return args[0] != ""
	case 2:
		return evalUnary(c, args[0], args[1])
	case 3:
		return evalBinary(args[0], args[1], args[2])
	}
	// Longer expressions (with -a/-o): evaluate leftmost triple, ignore rest.
	return evalBinary(args[0], args[1], args[2])
}

func evalUnary(c *Context, op, arg string) bool {
	if op == "!" {
		return arg == ""
	}
	if op == "-z" {
		return arg == ""
	}
	if op == "-n" {
		return arg != ""
	}
	info, err := c.FS().Stat(c.Sess.abs(arg))
	exists := err == nil
	switch op {
	case "-e", "-a":
		return exists
	case "-f":
		return exists && !info.IsDir() && !info.IsDevice()
	case "-d":
		return exists && info.IsDir()
	case "-s":
		return exists && info.Size > 0
	case "-r":
		return exists && permit(c.Sess, c.Sess.abs(arg), 'r')
	case "-w":
		return exists && permit(c.Sess, c.Sess.abs(arg), 'w')
	case "-x":
		return exists && permit(c.Sess, c.Sess.abs(arg), 'x')
	case "-L", "-h":
		li, err := c.FS().Lstat(c.Sess.abs(arg))
		return err == nil && li.IsSymlink()
	case "-b":
		return exists && info.IsDevice()
	}
	return false
}

func evalBinary(a, op, b string) bool {
	switch op {
	case "=", "==":
		return a == b
	case "!=":
		return a != b
	case "-eq", "-ne", "-lt", "-le", "-gt", "-ge":
		x, err1 := strconv.Atoi(a)
		y, err2 := strconv.Atoi(b)
		if err1 != nil || err2 != nil {
			return false
		}
		switch op {
		case "-eq":
			return x == y
		case "-ne":
			return x != y
		case "-lt":
			return x < y
		case "-le":
			return x <= y
		case "-gt":
			return x > y
		case "-ge":
			return x >= y
		}
	}
	return false
}

func boolToStatus(b bool) int {
	if b {
		return 0
	}
	return 1
}

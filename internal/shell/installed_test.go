package shell

import (
	"sort"
	"testing"
)

// Every program the shell emulates must exist on the box's $PATH, or `which
// x` and running x disagree. busybox-only applets are the exception: run by
// name they report "command not found" (see busyboxOnly).
func TestEveryEmulatedProgramIsInstalled(t *testing.T) {
	in, s := testSession(t)
	busyboxOnlyTools := map[string]bool{"tftp": true, "ftpget": true}
	var missing []string
	for name := range in.cmds {
		if isBashBuiltin(name) || busyboxOnlyTools[name] {
			continue
		}
		if !s.FS.Exists("/usr/bin/"+name) && !s.FS.Exists("/usr/sbin/"+name) {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("emulated but not installed: %v", missing)
	}
	for name := range busyboxOnlyTools {
		if s.FS.Exists("/usr/bin/"+name) || s.FS.Exists("/usr/sbin/"+name) {
			t.Errorf("%s is installed, so it should not be busybox-only", name)
		}
	}
}

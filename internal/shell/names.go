package shell

import (
	"strconv"
	"strings"
)

// idNames resolves uid/gid to names by reading the session's own
// /etc/passwd and /etc/group, exactly as the real tools do. Unknown ids
// render as their number, like coreutils.
type idNames struct {
	users  map[int]string
	groups map[int]string
}

func newIDNames(c *Context) *idNames {
	n := &idNames{users: map[int]string{}, groups: map[int]string{}}
	if data, _, err := c.FS().ReadFile("/etc/passwd"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Split(line, ":")
			if len(f) >= 3 {
				if uid, err := strconv.Atoi(f[2]); err == nil {
					n.users[uid] = f[0]
				}
			}
		}
	}
	if data, _, err := c.FS().ReadFile("/etc/group"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Split(line, ":")
			if len(f) >= 3 {
				if gid, err := strconv.Atoi(f[2]); err == nil {
					n.groups[gid] = f[0]
				}
			}
		}
	}
	return n
}

func (n *idNames) user(uid int) string {
	if s, ok := n.users[uid]; ok {
		return s
	}
	return strconv.Itoa(uid)
}

func (n *idNames) group(gid int) string {
	if s, ok := n.groups[gid]; ok {
		return s
	}
	return strconv.Itoa(gid)
}

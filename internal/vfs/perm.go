package vfs

import "io/fs"

// Perm is a requested access, as in access(2).
type Perm int

const (
	// R is read access.
	R Perm = 4
	// W is write access.
	W Perm = 2
	// X is execute (files) or search (directories) access.
	X Perm = 1
)

// Cred identifies who is asking.
type Cred struct {
	UID  int
	GIDs []int
}

// IsRoot reports whether the credential is uid 0.
func (c Cred) IsRoot() bool { return c.UID == 0 }

func (c Cred) inGroup(gid int) bool {
	for _, g := range c.GIDs {
		if g == gid {
			return true
		}
	}
	return false
}

// Access checks whether cred may use the node at p as perm asks, following
// symlinks. Directories along the way are not checked; that is what real
// systems do too for a caller that already got the path from somewhere.
func (f *FS) Access(p string, cred Cred, perm Perm) error {
	info, err := f.Stat(p)
	if err != nil {
		return err
	}
	if Allowed(info, cred, perm) {
		return nil
	}
	return ErrPermission
}

// Allowed applies the classic owner/group/other check to an Info. Root
// passes everything except execute, which needs at least one x bit.
func Allowed(info Info, cred Cred, perm Perm) bool {
	mode := info.Mode.Perm()
	if cred.IsRoot() {
		if perm == X && !info.IsDir() {
			return mode&0o111 != 0
		}
		return true
	}
	var bits fs.FileMode
	switch {
	case cred.UID == info.UID:
		bits = mode >> 6
	case cred.inGroup(info.GID):
		bits = mode >> 3
	default:
		bits = mode
	}
	return bits&fs.FileMode(perm) != 0
}

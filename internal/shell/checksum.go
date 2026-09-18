package shell

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"io"
)

// sumCmd implements md5sum/sha1sum/sha256sum over files or stdin.
func sumCmd(c *Context, algo string) int {
	_, files := splitFlags(c.Args[1:])
	hashOf := func(data []byte) string {
		switch algo {
		case "md5":
			return fmt.Sprintf("%x", md5.Sum(data))
		case "sha1":
			return fmt.Sprintf("%x", sha1.Sum(data))
		default:
			return fmt.Sprintf("%x", sha256.Sum256(data))
		}
	}
	if len(files) == 0 {
		data, _ := io.ReadAll(c.Stdin)
		c.Printf("%s  -\n", hashOf(data))
		return 0
	}
	status := 0
	for _, f := range files {
		data, err := c.readTarget(f)
		if err != nil {
			c.Errorf("%s", err)
			status = 1
			continue
		}
		c.Printf("%s  %s\n", hashOf(data), f)
	}
	return status
}

// readEachOrStdin applies fn to each file's data (or stdin), printing the
// result. Used by cksum.
func readEachOrStdin(c *Context, fn func(*Context, []byte, string)) int {
	_, files := splitFlags(c.Args[1:])
	if len(files) == 0 {
		data, _ := io.ReadAll(c.Stdin)
		fn(c, data, "")
		return 0
	}
	status := 0
	for _, f := range files {
		data, err := c.readTarget(f)
		if err != nil {
			c.Errorf("%s", err)
			status = 1
			continue
		}
		fn(c, data, f)
	}
	return status
}

func cksumOne(c *Context, data []byte, name string) {
	crc := crc32.ChecksumIEEE(data)
	if name == "" {
		c.Printf("%d %d\n", crc, len(data))
	} else {
		c.Printf("%d %d %s\n", crc, len(data), name)
	}
}

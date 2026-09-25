package analysis

import "os"

// osWriteFile is a tiny helper so tests can drop stray files next to the
// recordings and prove the loader tolerates them.
func osWriteFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

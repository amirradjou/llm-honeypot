package analysis

import (
	"os"
	"time"
)

// osWriteFile is a tiny helper so tests can drop stray files next to the
// recordings and prove the loader tolerates them.
func osWriteFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// nowForTest is a fixed instant for table-driven tests.
func nowForTest() time.Time { return time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC) }

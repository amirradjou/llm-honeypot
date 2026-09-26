// Package capture stores payloads an attacker tried to download.
//
// Nothing here runs anything. Files are written without an execute bit,
// content-addressed by SHA-256, and kept in a quarantine directory whose
// only purpose is later analysis. Fetching is never automatic — the
// honeypot only ever records URLs; an operator has to ask for them, which
// is a deliberate act with consequences (see Fetcher).
package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Meta describes one captured payload.
type Meta struct {
	SHA256      string    `json:"sha256"`
	Size        int64     `json:"size"`
	ContentType string    `json:"content_type,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	// URLs are every address this exact payload was served from, which is
	// how one binary spread across many hosts becomes visible.
	URLs []string `json:"urls"`
	// Truncated marks a payload that hit the size cap; the bytes on disk
	// are a prefix, so the hash is of the prefix, not the real file.
	Truncated bool `json:"truncated,omitempty"`
}

// Store is a quarantine directory of captured payloads.
type Store struct {
	dir string
	now func() time.Time
}

// NewStore returns a store writing under dir, creating it if needed. The
// directory is owner-only: it holds live malware.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("capture: create %s: %w", dir, err)
	}
	return &Store{dir: dir, now: time.Now}, nil
}

// Dir is the quarantine directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) blobPath(sum string) string { return filepath.Join(s.dir, sum+".bin") }
func (s *Store) metaPath(sum string) string { return filepath.Join(s.dir, sum+".json") }

// Put stores data as the payload fetched from url. If the same bytes are
// already stored, the URL is recorded against the existing entry rather
// than writing a second copy. It reports whether this was new.
func (s *Store) Put(data []byte, url, contentType string, truncated bool) (Meta, bool, error) {
	sum := sha256.Sum256(data)
	hexSum := hex.EncodeToString(sum[:])
	now := s.now().UTC()

	meta, err := s.load(hexSum)
	isNew := false
	if errors.Is(err, fs.ErrNotExist) {
		isNew = true
		meta = Meta{
			SHA256: hexSum, Size: int64(len(data)), ContentType: contentType,
			FirstSeen: now, Truncated: truncated,
		}
		// 0600 and no execute bit, deliberately: this is live malware.
		if err := os.WriteFile(s.blobPath(hexSum), data, 0o600); err != nil {
			return Meta{}, false, fmt.Errorf("capture: write payload: %w", err)
		}
	} else if err != nil {
		return Meta{}, false, err
	}

	meta.LastSeen = now
	if url != "" && !contains(meta.URLs, url) {
		meta.URLs = append(meta.URLs, url)
		sort.Strings(meta.URLs)
	}
	if err := s.save(meta); err != nil {
		return Meta{}, false, err
	}
	return meta, isNew, nil
}

// Has reports whether a payload with this hash is already stored.
func (s *Store) Has(sha string) bool {
	_, err := os.Stat(s.blobPath(sha))
	return err == nil
}

// List returns every stored payload, newest first.
func (s *Store) List() ([]Meta, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []Meta
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		m, err := s.load(trimExt(e.Name()))
		if err != nil {
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out, nil
}

func (s *Store) load(sum string) (Meta, error) {
	b, err := os.ReadFile(s.metaPath(sum))
	if err != nil {
		return Meta{}, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return Meta{}, fmt.Errorf("capture: parse metadata for %s: %w", sum, err)
	}
	return m, nil
}

func (s *Store) save(m Meta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.metaPath(m.SHA256), append(b, '\n'), 0o600)
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func trimExt(name string) string {
	return name[:len(name)-len(filepath.Ext(name))]
}

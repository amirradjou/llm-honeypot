package llm

import (
	"context"
	"sync"
)

// Cache wraps a Generator so identical requests return identical output.
// Two attackers who both run `lscpu` must see the same CPU, and cat-ing
// the same file twice must agree — consistency is what keeps the illusion.
// It also collapses duplicate concurrent work and bounds memory.
type Cache struct {
	inner Generator
	max   int

	mu       sync.Mutex
	entries  map[string]string
	order    []string
	inflight map[string]*call
}

type call struct {
	wg     sync.WaitGroup
	out    string
	tokens int
	err    error
}

// NewCache wraps g, keeping at most max entries (0 → 4096).
func NewCache(g Generator, max int) *Cache {
	if max <= 0 {
		max = 4096
	}
	return &Cache{inner: g, max: max, entries: map[string]string{}, inflight: map[string]*call{}}
}

func (c *Cache) Model() string { return c.inner.Model() }

// key identifies a request for caching. Session-specific state (cwd, user,
// recent commands) is deliberately excluded for KindCommand outputs like
// lscpu/uname that are machine-global, but included implicitly for files
// via the path. We key on kind+machine+input+hint; recent/cwd/user are not
// part of the key so the same command caches across sessions.
func key(req Request) string {
	return string(req.Kind) + "\x00" + req.Machine + "\x00" + req.Input + "\x00" + req.Hint
}

// Generate returns a cached result, joins an in-flight identical request,
// or computes and stores a new one.
func (c *Cache) Generate(ctx context.Context, req Request) (string, int, error) {
	k := key(req)

	c.mu.Lock()
	if out, ok := c.entries[k]; ok {
		c.mu.Unlock()
		return out, 0, nil
	}
	if cl, ok := c.inflight[k]; ok {
		c.mu.Unlock()
		cl.wg.Wait()
		return cl.out, cl.tokens, cl.err
	}
	cl := &call{}
	cl.wg.Add(1)
	c.inflight[k] = cl
	c.mu.Unlock()

	cl.out, cl.tokens, cl.err = c.inner.Generate(ctx, req)
	cl.wg.Done()

	c.mu.Lock()
	delete(c.inflight, k)
	if cl.err == nil {
		c.store(k, cl.out)
	}
	c.mu.Unlock()
	return cl.out, cl.tokens, cl.err
}

// store adds an entry, evicting the oldest when over capacity. Caller holds
// the lock.
func (c *Cache) store(k, v string) {
	if _, ok := c.entries[k]; !ok {
		c.order = append(c.order, k)
	}
	c.entries[k] = v
	for len(c.order) > c.max {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
}

// Len reports the number of cached entries (for tests/metrics).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// inflightLen reports how many requests are currently being computed (tests).
func (c *Cache) inflightLen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.inflight)
}

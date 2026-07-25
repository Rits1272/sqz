// Package relays publishes signed link events to nostr relays.
//
// This is what makes "kept on relays" true: a link's authenticity lives in its
// signature, but its durability lives in being on relays the owner (and anyone
// else) can read independently of sqz. sqz still indexes events in Redis for
// fast resolution, but the relays are the copy sqz does not own.
package relays

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// publishTimeout bounds a single fan-out. Generous, since it covers connecting
// to cold relays; it runs off the request path so it never delays a create.
const publishTimeout = 15 * time.Second

// Publisher fans a signed event out to a set of relays, best-effort. A create
// must never fail because a relay is slow or down, so publishing is
// fire-and-forget.
type Publisher struct {
	defaults []string
	pool     *nostr.SimplePool
	log      *slog.Logger
}

// New returns a Publisher targeting the given default relays. The pool keeps
// connections warm and reuses them across publishes.
func New(defaults []string, log *slog.Logger) *Publisher {
	return &Publisher{
		defaults: normalize(defaults),
		pool:     nostr.NewSimplePool(context.Background()),
		log:      log,
	}
}

// Publish sends evt to the default relays plus any caller-supplied extras
// (deduplicated). It returns immediately; the fan-out runs in the background
// with its own timeout, so a down relay neither blocks nor fails the create.
// Revocations are events too, so they propagate the same way.
func (p *Publisher) Publish(evt nostr.Event, extra []string) {
	urls := dedup(append(append([]string{}, p.defaults...), normalize(extra)...))
	if len(urls) == 0 {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), publishTimeout)
		defer cancel()
		for res := range p.pool.PublishMany(ctx, urls, evt) {
			if res.Error != nil {
				p.log.Warn("relay publish", "relay", res.RelayURL, "err", res.Error)
			}
		}
	}()
}

// normalize trims each URL and defaults a bare host to wss://. Empty entries are
// dropped.
func normalize(urls []string) []string {
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if !strings.HasPrefix(u, "ws://") && !strings.HasPrefix(u, "wss://") {
			u = "wss://" + u
		}
		out = append(out, strings.TrimRight(u, "/"))
	}
	return out
}

func dedup(urls []string) []string {
	seen := make(map[string]bool, len(urls))
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

// Package store is sqz's Redis layer.
//
// It holds two categories of data with fundamentally different truth models,
// and the key prefixes keep them apart:
//
//	sqz:d:*  DERIVED — a materialization of relay state (link index, names).
//	         Authoritative for nothing. Safe to flush; RebuildDerived does
//	         exactly that before replaying from relays.
//
//	sqz:l:*  LOCAL — exists nowhere else (click analytics, NIP-98 replay
//	         guard). Click events are observed server-side, unsigned, and
//	         privacy-sensitive; they can never be published to a relay.
//	         Needs real persistence and backups.
//
// Confusing the two is the main hazard here: flushing local data loses it
// permanently, and treating derived data as authoritative would quietly make
// sqz the source of truth instead of the relays.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Rits1272/sqz/internal/links"
)

const (
	derivedPrefix = "sqz:d:"
	localPrefix   = "sqz:l:"
)

// ErrNotFound is returned when a lookup misses.
var ErrNotFound = errors.New("store: not found")

// Store wraps a Redis client.
type Store struct {
	rdb *redis.Client
}

func New(rdb *redis.Client) *Store { return &Store{rdb: rdb} }

// Open connects to Redis and verifies the connection is usable, so a
// misconfigured URL fails at startup rather than on the first redirect.
func Open(ctx context.Context, url string) (*Store, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("store: parse redis url: %w", err)
	}
	rdb := redis.NewClient(opts)
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("store: connect redis: %w", err)
	}
	return New(rdb), nil
}

func (s *Store) Close() error { return s.rdb.Close() }

// ---------------------------------------------------------------- derived

func linkKey(pubkey, slug string) string {
	return derivedPrefix + "link:" + pubkey + ":" + slug
}

func nameKey(name string) string {
	return derivedPrefix + "name:" + name
}

// slugOwnerKey maps a global slug to the pubkey that owns it. Unlike linkKey
// (per-identity), this is the one authority that makes a flat sqzit.in/<slug>
// resolve to a single link.
func slugOwnerKey(slug string) string {
	return derivedPrefix + "slug:" + slug
}

// storedLink is the on-disk shape of a link. It is deliberately a separate
// type from links.Link: this is a cache format we control and may change,
// whereas links.Link mirrors what the relay event says.
type storedLink struct {
	PubKey      string `json:"pubkey"`
	Slug        string `json:"slug"`
	Destination string `json:"destination"`
	Title       string `json:"title,omitempty"`
	CreatedAt   int64  `json:"created_at"`
	ExpiresAt   int64  `json:"expires_at,omitempty"`
}

// PutLink indexes a link for resolution.
//
// Revoked and already-expired links are deleted rather than stored: the index
// answers "what resolves right now", and keeping a tombstone would mean every
// read path had to re-check validity.
func (s *Store) PutLink(ctx context.Context, l *links.Link) error {
	key := linkKey(l.PubKey, l.Slug)

	if !l.Resolvable(time.Now()) {
		return s.rdb.Del(ctx, key).Err()
	}

	rec := storedLink{
		PubKey:      l.PubKey,
		Slug:        l.Slug,
		Destination: l.Destination,
		Title:       l.Title,
		CreatedAt:   l.CreatedAt.Unix(),
	}

	// Let Redis expire the entry itself, so an expired link stops resolving
	// even if the reconciler is down when the moment arrives.
	var ttl time.Duration
	if !l.ExpiresAt.IsZero() {
		rec.ExpiresAt = l.ExpiresAt.Unix()
		ttl = time.Until(l.ExpiresAt)
		if ttl <= 0 {
			return s.rdb.Del(ctx, key).Err()
		}
	}

	blob, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("store: marshal link: %w", err)
	}
	return s.rdb.Set(ctx, key, blob, ttl).Err()
}

// GetLink resolves a link. This is the redirect hot path.
func (s *Store) GetLink(ctx context.Context, pubkey, slug string) (*links.Link, error) {
	blob, err := s.rdb.Get(ctx, linkKey(pubkey, slug)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get link: %w", err)
	}

	var rec storedLink
	if err := json.Unmarshal(blob, &rec); err != nil {
		return nil, fmt.Errorf("store: unmarshal link: %w", err)
	}

	l := &links.Link{
		PubKey:      rec.PubKey,
		Slug:        rec.Slug,
		Destination: rec.Destination,
		Title:       rec.Title,
		CreatedAt:   time.Unix(rec.CreatedAt, 0),
	}
	if rec.ExpiresAt > 0 {
		l.ExpiresAt = time.Unix(rec.ExpiresAt, 0)
	}

	// Redis TTL should have removed an expired entry already, but check
	// anyway: TTL is best-effort and this is the last gate before we send a
	// browser somewhere.
	if !l.Resolvable(time.Now()) {
		return nil, ErrNotFound
	}
	return l, nil
}

// ListLinks returns every indexed link for one pubkey.
//
// Scoped to a single pubkey by construction: the caller cannot ask for
// "everyone's links", so an authenticated user can only ever enumerate their
// own. Uses SCAN rather than KEYS so a large index does not block Redis.
func (s *Store) ListLinks(ctx context.Context, pubkey string) ([]*links.Link, error) {
	var (
		cursor uint64
		out    []*links.Link
		now    = time.Now()
	)
	for {
		keys, next, err := s.rdb.Scan(ctx, cursor, linkKey(pubkey, "*"), 200).Result()
		if err != nil {
			return nil, fmt.Errorf("store: scan links: %w", err)
		}

		for _, key := range keys {
			blob, err := s.rdb.Get(ctx, key).Bytes()
			if errors.Is(err, redis.Nil) {
				continue // expired between SCAN and GET
			}
			if err != nil {
				return nil, fmt.Errorf("store: get link: %w", err)
			}

			var rec storedLink
			if err := json.Unmarshal(blob, &rec); err != nil {
				continue // a corrupt entry should not break the whole listing
			}

			l := &links.Link{
				PubKey:      rec.PubKey,
				Slug:        rec.Slug,
				Destination: rec.Destination,
				Title:       rec.Title,
				CreatedAt:   time.Unix(rec.CreatedAt, 0),
			}
			if rec.ExpiresAt > 0 {
				l.ExpiresAt = time.Unix(rec.ExpiresAt, 0)
			}
			if l.Resolvable(now) {
				out = append(out, l)
			}
		}

		if next == 0 {
			return out, nil
		}
		cursor = next
	}
}

// DeleteLink removes a link from the index (revocation or NIP-09 delete).
func (s *Store) DeleteLink(ctx context.Context, pubkey, slug string) error {
	return s.rdb.Del(ctx, linkKey(pubkey, slug)).Err()
}

// PutName claims a NIP-05 name for a pubkey.
//
// Names are the one genuinely global namespace in sqz, so this uses SetNX and
// reports whether the claim succeeded rather than silently overwriting.
// Re-claiming a name you already own succeeds, which keeps renewal idempotent.
func (s *Store) PutName(ctx context.Context, name, pubkey string) (bool, error) {
	ok, err := s.rdb.SetNX(ctx, nameKey(name), pubkey, 0).Result()
	if err != nil {
		return false, fmt.Errorf("store: claim name: %w", err)
	}
	if ok {
		return true, nil
	}

	existing, err := s.rdb.Get(ctx, nameKey(name)).Result()
	if err != nil {
		return false, fmt.Errorf("store: check name: %w", err)
	}
	return existing == pubkey, nil
}

// LookupName resolves a NIP-05 name to a pubkey.
func (s *Store) LookupName(ctx context.Context, name string) (string, error) {
	pubkey, err := s.rdb.Get(ctx, nameKey(name)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: lookup name: %w", err)
	}
	return pubkey, nil
}

// RebuildDerived removes every derived key, leaving local data intact.
//
// This is the operation that proves relays are actually the source of truth:
// if a rebuild after this call restores every link, sqz is genuinely a cache.
// It scans rather than using KEYS so it does not block Redis on a large index.
func (s *Store) RebuildDerived(ctx context.Context) (int, error) {
	var (
		cursor  uint64
		deleted int
	)
	for {
		keys, next, err := s.rdb.Scan(ctx, cursor, derivedPrefix+"*", 500).Result()
		if err != nil {
			return deleted, fmt.Errorf("store: scan derived: %w", err)
		}
		if len(keys) > 0 {
			n, err := s.rdb.Del(ctx, keys...).Result()
			if err != nil {
				return deleted, fmt.Errorf("store: delete derived: %w", err)
			}
			deleted += int(n)
		}
		if next == 0 {
			return deleted, nil
		}
		cursor = next
	}
}

// ------------------------------------------------------------------ local

// MinNpubPrefix is the default truncated-npub length, "npub1" plus 7 data
// characters. A full npub is 63 characters, which makes the identity-namespaced
// URL longer than most links people want shortened — the whole point of the
// product. Seven bech32 characters is ~34 billion combinations, so collisions
// need a very large user base before the fallback below ever runs.
const MinNpubPrefix = len("npub1") + 7

// AssignNpubPrefix returns the short identity prefix for a pubkey, allocating
// one on first use.
//
// Deliberately stored in the LOCAL keyspace, not the derived one. The
// assignment is first-come-first-served, so replaying relays in a different
// order could hand out different prefixes — and that would silently rewrite
// every short URL already in circulation. Prefixes must survive a rebuild.
//
// This is not the same kind of namespace as names: a prefix is derived from
// your key, so nobody can claim one for a key they do not hold. Collisions
// extend the prefix a character at a time, like git short SHAs.
func (s *Store) AssignNpubPrefix(ctx context.Context, npub, pubkey string) (string, error) {
	// Already assigned? Reuse it — this must be stable forever.
	existing, err := s.rdb.Get(ctx, localPrefix+"pubkey2prefix:"+pubkey).Result()
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, redis.Nil) {
		return "", fmt.Errorf("store: lookup assigned prefix: %w", err)
	}

	for n := MinNpubPrefix; n <= len(npub); n++ {
		candidate := npub[:n]

		ok, err := s.rdb.SetNX(ctx, localPrefix+"prefix2pubkey:"+candidate, pubkey, 0).Result()
		if err != nil {
			return "", fmt.Errorf("store: claim prefix: %w", err)
		}
		if !ok {
			// Taken. If it is ours we are done; otherwise lengthen and retry.
			holder, err := s.rdb.Get(ctx, localPrefix+"prefix2pubkey:"+candidate).Result()
			if err != nil {
				return "", fmt.Errorf("store: read prefix holder: %w", err)
			}
			if holder != pubkey {
				continue
			}
		}

		if err := s.rdb.Set(ctx, localPrefix+"pubkey2prefix:"+pubkey, candidate, 0).Err(); err != nil {
			return "", fmt.Errorf("store: record prefix: %w", err)
		}
		return candidate, nil
	}

	// Every prefix length collided, which means the full npub is taken by a
	// different pubkey — impossible unless the index is corrupt.
	return "", fmt.Errorf("store: no available prefix for %s", pubkey)
}

// LookupNpubPrefix resolves a truncated npub back to a pubkey.
func (s *Store) LookupNpubPrefix(ctx context.Context, prefix string) (string, error) {
	pubkey, err := s.rdb.Get(ctx, localPrefix+"prefix2pubkey:"+prefix).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: lookup prefix: %w", err)
	}
	return pubkey, nil
}

// SeenBefore implements nip98.ReplayGuard.
//
// SetNX is atomic, which is what makes this a real guard: two concurrent
// replays of the same header cannot both observe "not seen".
func (s *Store) SeenBefore(ctx context.Context, id string, ttl time.Duration) (bool, error) {
	ok, err := s.rdb.SetNX(ctx, localPrefix+"nip98:"+id, 1, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("store: replay guard: %w", err)
	}
	return !ok, nil
}

// IssueSlug reserves a server-generated slug for a pubkey to claim on a
// subsequent create. The short TTL means an unclaimed reservation expires
// rather than pinning the name forever.
func (s *Store) IssueSlug(ctx context.Context, pubkey, slug string, ttl time.Duration) error {
	return s.rdb.Set(ctx, localPrefix+"issued:"+pubkey+":"+slug, 1, ttl).Err()
}

// ClaimIssuedSlug consumes a slug this server issued to pubkey. It returns true
// only if the slug was outstanding — so a caller cannot pass off a self-chosen
// slug as a server-issued one. Del is atomic, so a slug is claimed at most once.
func (s *Store) ClaimIssuedSlug(ctx context.Context, pubkey, slug string) (bool, error) {
	n, err := s.rdb.Del(ctx, localPrefix+"issued:"+pubkey+":"+slug).Result()
	if err != nil {
		return false, fmt.Errorf("store: claim issued slug: %w", err)
	}
	return n == 1, nil
}

// ClaimSlugOwner records pubkey as the global owner of slug. It returns true if
// the slug is now owned by pubkey — either freshly claimed, or already theirs
// (so re-publishing your own link succeeds). It returns false only when another
// key already owns it. SetNX makes the first claim atomic under contention.
func (s *Store) ClaimSlugOwner(ctx context.Context, slug, pubkey string) (bool, error) {
	ok, err := s.rdb.SetNX(ctx, slugOwnerKey(slug), pubkey, 0).Result()
	if err != nil {
		return false, fmt.Errorf("store: claim slug owner: %w", err)
	}
	if ok {
		return true, nil
	}
	owner, err := s.rdb.Get(ctx, slugOwnerKey(slug)).Result()
	if err != nil {
		return false, fmt.Errorf("store: read slug owner: %w", err)
	}
	return owner == pubkey, nil
}

// SlugOwner returns the pubkey that owns slug, or ErrNotFound if it is free.
func (s *Store) SlugOwner(ctx context.Context, slug string) (string, error) {
	owner, err := s.rdb.Get(ctx, slugOwnerKey(slug)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: slug owner: %w", err)
	}
	return owner, nil
}

// SlugTaken reports whether a slug is already owned. Exact and O(1) — the
// authority behind the availability check; the ClaimSlugOwner at create time
// remains the real guard against a race between check and claim.
func (s *Store) SlugTaken(ctx context.Context, slug string) (bool, error) {
	n, err := s.rdb.Exists(ctx, slugOwnerKey(slug)).Result()
	if err != nil {
		return false, fmt.Errorf("store: slug taken: %w", err)
	}
	return n == 1, nil
}

// RecordClick increments a link's click counter.
//
// Called off the redirect path — a redirect must never wait on, or fail
// because of, analytics.
func (s *Store) RecordClick(ctx context.Context, pubkey, slug string) error {
	key := localPrefix + "clicks:" + pubkey + ":" + slug
	return s.rdb.Incr(ctx, key).Err()
}

// Clicks returns a link's click count.
func (s *Store) Clicks(ctx context.Context, pubkey, slug string) (int64, error) {
	n, err := s.rdb.Get(ctx, localPrefix+"clicks:"+pubkey+":"+slug).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store: clicks: %w", err)
	}
	return n, nil
}

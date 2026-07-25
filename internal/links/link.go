// Package links models a sqz short link as a nostr addressable event.
//
// A link is a kind 30078 (NIP-78 application-specific data) event whose `d`
// tag is "sqz:<slug>" and whose `r` tag is the destination. Relays keep only
// the newest event per (kind, pubkey, d), which gives us slug uniqueness per
// identity for free — the entire reason sqz never has to arbitrate a global
// namespace.
//
// The event is signed and published by the user's own client. sqz only ever
// reads and validates it, and cannot forge one.
package links

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

const (
	// Kind is NIP-78 application-specific data. Using an allocated
	// general-purpose kind avoids squatting an unassigned number in the
	// addressable range; the "sqz:" prefix on `d` keeps us from colliding with
	// other apps sharing this kind.
	Kind = 30078

	// SlugPrefix namespaces our `d` tag values within kind 30078.
	SlugPrefix = "sqz:"

	// MaxSlugLen bounds the identifier. Long slugs defeat the point of a
	// shortener, and unbounded values become an index-size problem.
	MaxSlugLen = 64

	// MaxDestinationLen bounds the stored destination. Well beyond any real
	// URL, but stops an event from pinning arbitrary bytes in the index.
	MaxDestinationLen = 2048
)

var (
	ErrWrongKind     = errors.New("links: event is not kind 30078")
	ErrNotSqzLink    = errors.New("links: 'd' tag is not a sqz link")
	ErrSlugEmpty     = errors.New("links: slug is empty")
	ErrSlugTooLong   = fmt.Errorf("links: slug exceeds %d characters", MaxSlugLen)
	ErrSlugCharset   = errors.New("links: slug may only contain letters, digits, '-', '_' and '.'")
	ErrSlugReserved  = errors.New("links: slug is reserved")
	ErrNoDestination = errors.New("links: missing 'r' tag")
	ErrDestTooLong   = fmt.Errorf("links: destination exceeds %d characters", MaxDestinationLen)
	ErrDestMalformed = errors.New("links: destination is not a valid absolute URL")
	ErrDestScheme    = errors.New("links: destination must be http or https")
	ErrDestLoop      = errors.New("links: destination points back at sqz")

	ErrExpirationMalformed = errors.New("links: 'expiration' tag is not a positive unix timestamp")
)

// reservedSlugs cannot be used because they would shadow sqz's own routes.
// Slugs live in a per-identity namespace, so this is a routing concern rather
// than a naming-rights one.
var reservedSlugs = map[string]bool{
	"api": true, "admin": true, "static": true, "assets": true,
	"favicon.ico": true, "robots.txt": true, "health": true,
}

// Link is a validated short link.
type Link struct {
	PubKey      string
	Slug        string
	Destination string
	Title       string
	CreatedAt   time.Time

	// ExpiresAt is the NIP-40 expiration, or zero if the link never expires.
	ExpiresAt time.Time

	// Revoked is true when the owner republished the event with an empty
	// destination. The event still exists on relays — that is how revocation
	// propagates — but the link must stop resolving.
	Revoked bool
}

// Expired reports whether the link's NIP-40 expiration has passed.
func (l *Link) Expired(now time.Time) bool {
	return !l.ExpiresAt.IsZero() && now.After(l.ExpiresAt)
}

// Resolvable reports whether the link should still redirect.
func (l *Link) Resolvable(now time.Time) bool {
	return !l.Revoked && !l.Expired(now)
}

// Coordinate returns the NIP-01 address of the link's event, "kind:pubkey:d".
func (l *Link) Coordinate() string {
	return fmt.Sprintf("%d:%s:%s%s", Kind, l.PubKey, SlugPrefix, l.Slug)
}

// Parse validates a nostr event as a sqz link.
//
// It does NOT check the signature — callers must have already established that
// the event is authentic, either because it came from a verified relay
// subscription or because it was checked explicitly. Parsing is about shape and
// safety, not authenticity.
//
// selfHosts are hostnames belonging to sqz itself; destinations pointing at
// them are rejected to prevent redirect loops.
func Parse(evt *nostr.Event, selfHosts []string) (*Link, error) {
	if evt.Kind != Kind {
		return nil, ErrWrongKind
	}

	d := tagValue(evt.Tags, "d")
	if !strings.HasPrefix(d, SlugPrefix) {
		return nil, ErrNotSqzLink
	}
	slug := strings.TrimPrefix(d, SlugPrefix)
	if err := ValidateSlug(slug); err != nil {
		return nil, err
	}

	link := &Link{
		PubKey:    evt.PubKey,
		Slug:      slug,
		Title:     tagValue(evt.Tags, "title"),
		CreatedAt: evt.CreatedAt.Time(),
	}

	// Parsed here rather than via nip40.GetExpiration, which collapses "no
	// expiration tag" and "malformed expiration tag" into the same -1 sentinel.
	// That conflation is unsafe in both directions: -1 read as a timestamp makes
	// every unexpiring link look expired, and treating a malformed value as
	// absent turns attacker-supplied garbage into "never expires".
	if raw := tagValue(evt.Tags, "expiration"); raw != "" {
		ts, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || ts <= 0 {
			return nil, ErrExpirationMalformed
		}
		link.ExpiresAt = time.Unix(ts, 0)
	}

	// An absent or empty `r` tag is how an owner revokes a link without
	// relying on relays to honour a NIP-09 deletion (many do not). This is a
	// valid, meaningful state — not a parse failure.
	dest := tagValue(evt.Tags, "r")
	if dest == "" {
		link.Revoked = true
		return link, nil
	}

	if err := ValidateDestination(dest, selfHosts); err != nil {
		return nil, err
	}
	link.Destination = dest

	return link, nil
}

// ValidateSlug checks that a slug is safe to use as a path segment.
func ValidateSlug(slug string) error {
	switch {
	case slug == "":
		return ErrSlugEmpty
	case len(slug) > MaxSlugLen:
		return ErrSlugTooLong
	case reservedSlugs[strings.ToLower(slug)]:
		return ErrSlugReserved
	}

	// Restricting the charset keeps slugs safe as a path segment without
	// escaping, and rules out '/' and '%' which would otherwise let a slug
	// forge extra path structure.
	for _, r := range slug {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
		default:
			return ErrSlugCharset
		}
	}

	// "." and ".." would be interpreted as path traversal by clients and proxies.
	if slug == "." || slug == ".." {
		return ErrSlugCharset
	}
	return nil
}

// ValidateDestination checks that a redirect target is safe to send a browser to.
//
// This is the security-critical check in this package. sqz issues a Location
// header pointing at attacker-supplied data, so an unvalidated destination is
// an open redirect at best and stored XSS at worst — "javascript:" and "data:"
// URLs execute in the origin the user is sent from.
func ValidateDestination(dest string, selfHosts []string) error {
	if dest == "" {
		return ErrNoDestination
	}
	if len(dest) > MaxDestinationLen {
		return ErrDestTooLong
	}

	u, err := url.Parse(dest)
	if err != nil {
		return ErrDestMalformed
	}

	// Only http/https reach a browser as a navigation. Everything else —
	// javascript:, data:, file:, intent: — is either script execution or a
	// local-resource read.
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return ErrDestScheme
	}

	// A scheme-only or host-less URL ("http://") is not a usable destination.
	if u.Host == "" {
		return ErrDestMalformed
	}

	host := strings.ToLower(u.Hostname())
	for _, self := range selfHosts {
		if host == strings.ToLower(self) {
			return ErrDestLoop
		}
	}

	return nil
}

// tagValue returns the first value of the named tag, or "" if absent.
// Tags.Find is nil-safe, unlike the deprecated GetFirst.
func tagValue(tags nostr.Tags, key string) string {
	tag := tags.Find(key)
	if len(tag) < 2 {
		return ""
	}
	return tag[1]
}

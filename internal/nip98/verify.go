// Package nip98 implements NIP-98 HTTP Auth verification.
//
// Clients authenticate by signing a kind 27235 event naming the exact URL and
// method they are about to call, then sending it base64-encoded in the
// Authorization header. The pubkey on that event is the caller's identity —
// sqz has no other notion of an account.
//
// Spec: https://github.com/nostr-protocol/nips/blob/master/98.md
package nip98

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// KindHTTPAuth is the event kind reserved by NIP-98 (a nod to RFC 7235).
const KindHTTPAuth = 27235

// ClockSkew is how far an event's created_at may drift from our clock in
// either direction. The spec suggests 60 seconds.
//
// This window bounds how long a captured header stays usable, but it does not
// by itself prevent replay — an attacker who observes a header can reuse it
// freely until it expires. ReplayGuard closes that gap.
const ClockSkew = 60 * time.Second

var (
	ErrNoHeader    = errors.New("nip98: missing Authorization header")
	ErrScheme      = errors.New("nip98: Authorization scheme must be 'Nostr'")
	ErrMalformed   = errors.New("nip98: malformed authorization event")
	ErrKind        = errors.New("nip98: event kind must be 27235")
	ErrExpired     = errors.New("nip98: created_at outside acceptable window")
	ErrURLMismatch = errors.New("nip98: 'u' tag does not match request URL")
	ErrMethod      = errors.New("nip98: 'method' tag does not match request method")
	ErrSignature   = errors.New("nip98: invalid signature")
	ErrEventID     = errors.New("nip98: event id does not match its contents")
	ErrPayloadHash = errors.New("nip98: 'payload' tag does not match request body")
	ErrPayloadTag  = errors.New("nip98: request has a body but no 'payload' tag")
	ErrReplay      = errors.New("nip98: authorization event already used")
)

// ReplayGuard records event ids that have already been accepted, so a captured
// Authorization header cannot be replayed inside the clock-skew window.
//
// Entries only need to outlive the window that would accept them, which is
// 2*ClockSkew wide (an event may arrive up to ClockSkew early or late).
type ReplayGuard interface {
	// SeenBefore atomically records id and reports whether it was already
	// present. It must return true only when the id was genuinely seen before.
	SeenBefore(ctx context.Context, id string, ttl time.Duration) (bool, error)
}

// Auth is the result of a successful verification.
type Auth struct {
	PubKey string       // hex pubkey of the caller — this is the identity
	Event  *nostr.Event // the verified authorization event
}

// Request carries the parts of an HTTP request that NIP-98 binds a signature to.
//
// URL must be the absolute, externally-visible URL the client used. Behind a
// reverse proxy the server's own view of the request is relative and its notion
// of the host comes from client-controlled headers, so the caller is
// responsible for reconstructing this from trusted configuration rather than
// from the request. Getting this wrong lets an attacker replay an event signed
// for one endpoint against another.
type Request struct {
	URL    string
	Method string
	Body   []byte
}

// Verify checks an Authorization header against the request it claims to
// authorize. It performs every check the spec mandates; any failure means the
// caller should respond 401 without distinguishing which check failed.
//
// guard may be nil, which disables replay protection — acceptable only for
// tests and idempotent reads.
func Verify(ctx context.Context, header string, req Request, guard ReplayGuard) (*Auth, error) {
	evt, err := parseHeader(header)
	if err != nil {
		return nil, err
	}

	if evt.Kind != KindHTTPAuth {
		return nil, ErrKind
	}

	// Check the timestamp before doing signature work, so a flood of stale
	// events is cheap to reject.
	drift := time.Since(evt.CreatedAt.Time())
	if drift > ClockSkew || drift < -ClockSkew {
		return nil, ErrExpired
	}

	if !urlsEquivalent(tagValue(evt.Tags, "u"), req.URL) {
		return nil, ErrURLMismatch
	}

	// Method comparison is case-insensitive: RFC 7231 methods are uppercase by
	// convention, but a client sending "post" is authorizing the same request.
	method := tagValue(evt.Tags, "method")
	if method == "" || !strings.EqualFold(method, req.Method) {
		return nil, ErrMethod
	}

	if err := checkPayload(evt, req.Body); err != nil {
		return nil, err
	}

	// The id is a hash of the event's contents, and the signature covers the
	// id. Checking the id first means a forged event with a valid-looking
	// signature over different contents is caught.
	if !evt.CheckID() {
		return nil, ErrEventID
	}
	if ok, err := evt.CheckSignature(); err != nil || !ok {
		return nil, ErrSignature
	}

	// Replay check goes last: it has a write side effect, and we only want to
	// burn an id once the event is otherwise fully valid.
	if guard != nil {
		seen, err := guard.SeenBefore(ctx, evt.ID, 2*ClockSkew)
		if err != nil {
			return nil, fmt.Errorf("nip98: replay guard: %w", err)
		}
		if seen {
			return nil, ErrReplay
		}
	}

	return &Auth{PubKey: evt.PubKey, Event: evt}, nil
}

// parseHeader extracts the event from an "Authorization: Nostr <base64>" header.
func parseHeader(header string) (*nostr.Event, error) {
	if header == "" {
		return nil, ErrNoHeader
	}

	scheme, encoded, found := strings.Cut(header, " ")
	if !found {
		return nil, ErrScheme
	}
	// The scheme is case-insensitive per RFC 7235, even though the spec writes
	// it as "Nostr".
	if !strings.EqualFold(scheme, "Nostr") {
		return nil, ErrScheme
	}

	encoded = strings.TrimSpace(encoded)
	raw, err := decodeBase64(encoded)
	if err != nil {
		return nil, ErrMalformed
	}

	var evt nostr.Event
	if err := json.Unmarshal(raw, &evt); err != nil {
		return nil, ErrMalformed
	}
	return &evt, nil
}

// decodeBase64 accepts both standard and URL-safe base64, with or without
// padding. Signers in the wild differ, and the encoding carries no security
// meaning — the signature check is what matters.
func decodeBase64(s string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw, nil
		}
	}
	return nil, ErrMalformed
}

// checkPayload verifies the 'payload' tag against the actual request body.
//
// The spec makes the tag optional, but "optional" cannot mean "skippable when
// a body is present" — that would let an attacker swap the body of a signed
// request. So: no body, no tag required; body present, tag required and must
// match.
func checkPayload(evt *nostr.Event, body []byte) error {
	if len(body) == 0 {
		// A stale payload tag on a bodyless request is harmless; nothing to bind.
		return nil
	}

	hash := tagValue(evt.Tags, "payload")
	if hash == "" {
		return ErrPayloadTag
	}

	sum := sha256.Sum256(body)
	if !strings.EqualFold(hash, hex.EncodeToString(sum[:])) {
		return ErrPayloadHash
	}
	return nil
}

// tagValue returns the first value of the named tag, or "" if absent.
//
// nostr.Tags.Find is nil-safe where the older GetFirst returns a *Tag that
// panics when dereferenced, which matters here because every tag we read is
// attacker-controlled and may be missing.
func tagValue(tags nostr.Tags, key string) string {
	tag := tags.Find(key)
	if len(tag) < 2 {
		return ""
	}
	return tag[1]
}

// urlsEquivalent reports whether the signed 'u' tag denotes the same resource
// as the request URL.
//
// The spec says the tag MUST be "exactly the same as the absolute request URL",
// so this stays deliberately strict — only a trailing-slash difference on an
// otherwise identical string is tolerated. Normalizing more aggressively (case,
// query order, default ports) would widen what a single signature authorizes.
func urlsEquivalent(signed, actual string) bool {
	if signed == "" {
		return false
	}
	return signed == actual ||
		strings.TrimSuffix(signed, "/") == strings.TrimSuffix(actual, "/")
}

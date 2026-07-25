package nip98

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

const (
	testURL    = "https://sqz.link/api/links"
	testMethod = "POST"
)

// memGuard is an in-memory ReplayGuard for tests.
type memGuard struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newMemGuard() *memGuard { return &memGuard{seen: map[string]bool{}} }

func (g *memGuard) SeenBefore(_ context.Context, id string, _ time.Duration) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen[id] {
		return true, nil
	}
	g.seen[id] = true
	return false, nil
}

// authHeader builds a signed NIP-98 header. Each option mutates the event
// before signing, so tampering is always covered by a valid signature — that
// way a failing test proves the check itself works, not that the signature broke.
func authHeader(t *testing.T, sk string, body []byte, opts ...func(*nostr.Event)) string {
	t.Helper()

	evt := &nostr.Event{
		Kind:      KindHTTPAuth,
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			{"u", testURL},
			{"method", testMethod},
		},
		Content: "",
	}
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		evt.Tags = append(evt.Tags, nostr.Tag{"payload", hex.EncodeToString(sum[:])})
	}
	for _, opt := range opts {
		opt(evt)
	}
	if err := evt.Sign(sk); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return "Nostr " + base64.StdEncoding.EncodeToString([]byte(evt.String()))
}

func setTag(key, value string) func(*nostr.Event) {
	return func(evt *nostr.Event) {
		for i, tag := range evt.Tags {
			if len(tag) >= 2 && tag[0] == key {
				evt.Tags[i] = nostr.Tag{key, value}
				return
			}
		}
		evt.Tags = append(evt.Tags, nostr.Tag{key, value})
	}
}

func dropTag(key string) func(*nostr.Event) {
	return func(evt *nostr.Event) {
		out := evt.Tags[:0]
		for _, tag := range evt.Tags {
			if len(tag) == 0 || tag[0] != key {
				out = append(out, tag)
			}
		}
		evt.Tags = out
	}
}

func newKey(t *testing.T) (sk, pk string) {
	t.Helper()
	sk = nostr.GeneratePrivateKey()
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	return sk, pk
}

func TestVerifyAcceptsValidEvent(t *testing.T) {
	sk, pk := newKey(t)
	req := Request{URL: testURL, Method: testMethod}

	auth, err := Verify(context.Background(), authHeader(t, sk, nil), req, newMemGuard())
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if auth.PubKey != pk {
		t.Errorf("identity mismatch: got %s, want %s", auth.PubKey, pk)
	}
}

func TestVerifyBindsSignatureToRequest(t *testing.T) {
	sk, _ := newKey(t)
	body := []byte(`{"slug":"launch"}`)

	tests := []struct {
		name   string
		header func() string
		req    Request
		want   error
	}{
		{
			name:   "url mismatch",
			header: func() string { return authHeader(t, sk, nil, setTag("u", "https://sqz.link/api/names")) },
			req:    Request{URL: testURL, Method: testMethod},
			want:   ErrURLMismatch,
		},
		{
			name:   "missing u tag",
			header: func() string { return authHeader(t, sk, nil, dropTag("u")) },
			req:    Request{URL: testURL, Method: testMethod},
			want:   ErrURLMismatch,
		},
		{
			name:   "method mismatch",
			header: func() string { return authHeader(t, sk, nil, setTag("method", "DELETE")) },
			req:    Request{URL: testURL, Method: testMethod},
			want:   ErrMethod,
		},
		{
			name:   "missing method tag",
			header: func() string { return authHeader(t, sk, nil, dropTag("method")) },
			req:    Request{URL: testURL, Method: testMethod},
			want:   ErrMethod,
		},
		{
			name:   "wrong kind",
			header: func() string { return authHeader(t, sk, nil, func(e *nostr.Event) { e.Kind = 1 }) },
			req:    Request{URL: testURL, Method: testMethod},
			want:   ErrKind,
		},
		{
			name: "stale event",
			header: func() string {
				return authHeader(t, sk, nil, func(e *nostr.Event) {
					e.CreatedAt = nostr.Timestamp(time.Now().Add(-5 * time.Minute).Unix())
				})
			},
			req:  Request{URL: testURL, Method: testMethod},
			want: ErrExpired,
		},
		{
			name: "future event",
			header: func() string {
				return authHeader(t, sk, nil, func(e *nostr.Event) {
					e.CreatedAt = nostr.Timestamp(time.Now().Add(5 * time.Minute).Unix())
				})
			},
			req:  Request{URL: testURL, Method: testMethod},
			want: ErrExpired,
		},
		{
			name:   "body swapped after signing",
			header: func() string { return authHeader(t, sk, body) },
			req:    Request{URL: testURL, Method: testMethod, Body: []byte(`{"slug":"evil"}`)},
			want:   ErrPayloadHash,
		},
		{
			name:   "body present but unsigned",
			header: func() string { return authHeader(t, sk, nil) },
			req:    Request{URL: testURL, Method: testMethod, Body: body},
			want:   ErrPayloadTag,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(context.Background(), tt.header(), tt.req, newMemGuard())
			if !errors.Is(err, tt.want) {
				t.Errorf("got %v, want %v", err, tt.want)
			}
		})
	}
}

// Tampering must happen after signing: Sign derives PubKey from the secret key
// and overwrites whatever was there, so a pre-signing edit forges nothing.
func tamperSigned(t *testing.T, header string, mutate func(*nostr.Event)) string {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(header[len("Nostr "):])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var evt nostr.Event
	if err := json.Unmarshal(raw, &evt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	mutate(&evt)

	return "Nostr " + base64.StdEncoding.EncodeToString([]byte(evt.String()))
}

func TestVerifyRejectsForgedSignature(t *testing.T) {
	sk, _ := newKey(t)
	_, otherPK := newKey(t)
	req := Request{URL: testURL, Method: testMethod}

	tests := []struct {
		name   string
		mutate func(*nostr.Event)
	}{
		// Impersonation: claim someone else's identity on a validly signed
		// event. This is the attack that would let anyone create links as any
		// pubkey, so it must never pass.
		{"pubkey swapped", func(e *nostr.Event) { e.PubKey = otherPK }},
		// Retarget a signed authorization at a different endpoint.
		{"url swapped", func(e *nostr.Event) { e.Tags = nostr.Tags{{"u", "https://sqz.link/api/names"}, {"method", testMethod}} }},
		// A signature lifted from an unrelated event.
		{"signature replaced", func(e *nostr.Event) { e.Sig = "00" + e.Sig[2:] }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := tamperSigned(t, authHeader(t, sk, nil), tt.mutate)

			_, err := Verify(context.Background(), header, req, newMemGuard())
			if err == nil {
				t.Fatal("tampered event was accepted")
			}
			// Which check catches it depends on whether the id covers the
			// mutated field; either rejection is correct.
			if !errors.Is(err, ErrSignature) && !errors.Is(err, ErrEventID) && !errors.Is(err, ErrURLMismatch) {
				t.Errorf("unexpected rejection reason: %v", err)
			}
		})
	}
}

func TestVerifyRejectsReplay(t *testing.T) {
	sk, _ := newKey(t)
	guard := newMemGuard()
	header := authHeader(t, sk, nil)
	req := Request{URL: testURL, Method: testMethod}

	if _, err := Verify(context.Background(), header, req, guard); err != nil {
		t.Fatalf("first use should succeed, got %v", err)
	}
	// Same header, still inside the clock-skew window: without a replay guard
	// this would be indistinguishable from a legitimate request.
	if _, err := Verify(context.Background(), header, req, guard); !errors.Is(err, ErrReplay) {
		t.Errorf("second use: got %v, want ErrReplay", err)
	}
}

func TestVerifyRejectsBadHeaders(t *testing.T) {
	sk, _ := newKey(t)
	valid := authHeader(t, sk, nil)
	encoded := valid[len("Nostr "):]

	tests := []struct {
		name, header string
		want         error
	}{
		{"empty", "", ErrNoHeader},
		{"no scheme", encoded, ErrScheme},
		{"wrong scheme", "Bearer " + encoded, ErrScheme},
		{"not base64", "Nostr !!!not-base64!!!", ErrMalformed},
		{"not json", "Nostr " + base64.StdEncoding.EncodeToString([]byte("hello")), ErrMalformed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(context.Background(), tt.header, Request{URL: testURL, Method: testMethod}, newMemGuard())
			if !errors.Is(err, tt.want) {
				t.Errorf("got %v, want %v", err, tt.want)
			}
		})
	}
}

// The scheme is case-insensitive per RFC 7235 and signers differ on base64
// flavour; neither carries security meaning, so both must be accepted.
func TestVerifyToleratesEncodingVariants(t *testing.T) {
	sk, _ := newKey(t)
	req := Request{URL: testURL, Method: testMethod}
	encoded := authHeader(t, sk, nil)[len("Nostr "):]
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, header := range []string{
		"nostr " + encoded,
		"NOSTR " + encoded,
		"Nostr " + base64.RawStdEncoding.EncodeToString(raw),
		"Nostr " + base64.URLEncoding.EncodeToString(raw),
	} {
		if _, err := Verify(context.Background(), header, req, newMemGuard()); err != nil {
			t.Errorf("header %q: unexpected error %v", header[:12], err)
		}
	}
}

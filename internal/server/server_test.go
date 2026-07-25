package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/Rits1272/sqz/internal/links"
	"github.com/Rits1272/sqz/internal/nip98"
	"github.com/Rits1272/sqz/internal/store"
)

// These tests run against a real Redis rather than a fake, because the parts
// most worth testing — SetNX atomicity in the replay guard, TTL-driven
// expiry, and prefix-scoped rebuild — are Redis behaviours, not ours.
//
//	docker run -d -p 6399:6379 redis:7-alpine
//	SQZ_TEST_REDIS_URL=redis://localhost:6399/0 go test ./internal/server/
func testStore(t *testing.T) *store.Store {
	t.Helper()

	url := os.Getenv("SQZ_TEST_REDIS_URL")
	if url == "" {
		t.Skip("SQZ_TEST_REDIS_URL not set; skipping integration test")
	}

	st, err := store.Open(context.Background(), url)
	if err != nil {
		t.Fatalf("redis: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

const testBase = "http://sqz.test"

func newTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()

	st := testStore(t)
	// Each test gets a clean derived keyspace so ordering can't matter.
	if _, err := st.RebuildDerived(context.Background()); err != nil {
		t.Fatalf("clean: %v", err)
	}

	srv := New(
		Config{BaseURL: testBase, Domain: "sqz.test", SelfHosts: []string{"sqz.test"}},
		st,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)
	return ts, st
}

func newKey(t *testing.T) (sk, pk, npub string) {
	t.Helper()
	sk = nostr.GeneratePrivateKey()
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	npub, err = nip19.EncodePublicKey(pk)
	if err != nil {
		t.Fatalf("npub: %v", err)
	}
	return sk, pk, npub
}

// linkEvent builds and signs a kind 30078 sqz link event.
func linkEvent(t *testing.T, sk, slug, dest string, extra ...nostr.Tag) *nostr.Event {
	t.Helper()

	tags := nostr.Tags{{"d", links.SlugPrefix + slug}, {"r", dest}}
	tags = append(tags, extra...)

	evt := &nostr.Event{Kind: links.Kind, CreatedAt: nostr.Now(), Tags: tags}
	if err := evt.Sign(sk); err != nil {
		t.Fatalf("sign event: %v", err)
	}
	return evt
}

// createLink posts a signed link event with a matching NIP-98 header. It uses
// the custom endpoint, which accepts a chosen slug — the shape most tests want.
// authSK defaults to the event's signer unless overridden, which is how the
// identity-mismatch case is exercised.
func createLink(t *testing.T, ts *httptest.Server, authSK string, evt *nostr.Event) *http.Response {
	return createLinkAt(t, ts, authSK, evt, "/api/links/custom")
}

// createLinkAt posts to a specific create endpoint so tests can exercise both
// the custom tier and the issued-slug (auto) tier.
func createLinkAt(t *testing.T, ts *httptest.Server, authSK string, evt *nostr.Event, path string) *http.Response {
	t.Helper()

	body, err := json.Marshal(createLinkRequest{Event: evt})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// The NIP-98 event must name the URL the client actually calls, but signed
	// against the configured base URL — mirroring how a browser behind nginx
	// would sign it.
	sum := sha256.Sum256(body)
	auth := &nostr.Event{
		Kind:      nip98.KindHTTPAuth,
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			{"u", testBase + path},
			{"method", "POST"},
			{"payload", hex.EncodeToString(sum[:])},
		},
	}
	if err := auth.Sign(authSK); err != nil {
		t.Fatalf("sign auth: %v", err)
	}

	req, err := http.NewRequest("POST", ts.URL+path, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Authorization", "Nostr "+base64.StdEncoding.EncodeToString([]byte(auth.String())))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

// noRedirectClient captures the 302 instead of following it.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// The end-to-end milestone: sign a link, index it, and get redirected.
func TestCreateAndRedirect(t *testing.T) {
	ts, _ := newTestServer(t)
	sk, _, _ := newKey(t)
	const dest = "https://example.com/a/very/long/destination?x=1"

	resp := createLink(t, ts, sk, linkEvent(t, sk, "launch", dest))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d, body %s", resp.StatusCode, body)
	}

	// Flat namespace: sqzit.in/<slug> resolves via the global slug owner.
	r, err := noRedirectClient().Get(ts.URL + "/launch")
	if err != nil {
		t.Fatalf("redirect request: %v", err)
	}
	defer r.Body.Close()

	// 302, not 301: a cached 301 would make edits invisible and stop analytics.
	if r.StatusCode != http.StatusFound {
		t.Errorf("status: got %d, want 302", r.StatusCode)
	}
	if got := r.Header.Get("Location"); got != dest {
		t.Errorf("location: got %q, want %q", got, dest)
	}
}

// Republishing the same d tag changes where the link points. This is what
// makes links user-owned and editable rather than write-once.
func TestEditLinkChangesDestination(t *testing.T) {
	ts, _ := newTestServer(t)
	sk, _, _ := newKey(t)

	for _, dest := range []string{"https://example.com/first", "https://example.com/second"} {
		resp := createLink(t, ts, sk, linkEvent(t, sk, "edit", dest))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("create %s: got %d", dest, resp.StatusCode)
		}

		r, err := noRedirectClient().Get(ts.URL + "/edit")
		if err != nil {
			t.Fatalf("redirect: %v", err)
		}
		r.Body.Close()
		if got := r.Header.Get("Location"); got != dest {
			t.Errorf("location: got %q, want %q", got, dest)
		}
	}
}

// Revocation (empty r tag) and NIP-40 expiry must both stop resolution.
func TestLinkStopsResolving(t *testing.T) {
	tests := []struct {
		name  string
		slug  string
		build func(t *testing.T, sk string) *nostr.Event
	}{
		{
			name: "revoked",
			slug: "revoked",
			build: func(t *testing.T, sk string) *nostr.Event {
				return linkEvent(t, sk, "revoked", "")
			},
		},
		{
			name: "expired",
			slug: "expired",
			build: func(t *testing.T, sk string) *nostr.Event {
				past := time.Now().Add(-time.Hour).Unix()
				return linkEvent(t, sk, "expired", "https://example.com",
					nostr.Tag{"expiration", strconv.FormatInt(past, 10)})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, _ := newTestServer(t)
			sk, _, npub := newKey(t)

			resp := createLink(t, ts, sk, tt.build(t, sk))
			resp.Body.Close()

			r, err := noRedirectClient().Get(ts.URL + "/" + npub + "/" + tt.slug)
			if err != nil {
				t.Fatalf("redirect: %v", err)
			}
			r.Body.Close()
			if r.StatusCode != http.StatusNotFound {
				t.Errorf("got %d, want 404", r.StatusCode)
			}
		})
	}
}

// The core ownership guarantee: authenticating as yourself must not let you
// submit someone else's signed link event and squat their slug in the index.
func TestCannotSubmitAnotherKeysLink(t *testing.T) {
	ts, _ := newTestServer(t)
	victimSK, _, _ := newKey(t)
	attackerSK, _, _ := newKey(t)

	evt := linkEvent(t, victimSK, "victim", "https://example.com")

	resp := createLink(t, ts, attackerSK, evt)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("got %d, want 403; body %s", resp.StatusCode, body)
	}
}

func TestUnauthenticatedCreateRejected(t *testing.T) {
	ts, _ := newTestServer(t)
	sk, _, _ := newKey(t)

	body, _ := json.Marshal(createLinkRequest{Event: linkEvent(t, sk, "x", "https://example.com")})
	resp, err := http.Post(ts.URL+"/api/links", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", resp.StatusCode)
	}
}

// A replayed NIP-98 header must be refused even though it is still inside the
// clock-skew window and otherwise perfectly valid.
func TestReplayedAuthRejected(t *testing.T) {
	ts, _ := newTestServer(t)
	sk, _, _ := newKey(t)

	body, _ := json.Marshal(createLinkRequest{Event: linkEvent(t, sk, "replay", "https://example.com")})
	sum := sha256.Sum256(body)
	auth := &nostr.Event{
		Kind:      nip98.KindHTTPAuth,
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			{"u", testBase + "/api/links/custom"},
			{"method", "POST"},
			{"payload", hex.EncodeToString(sum[:])},
		},
	}
	if err := auth.Sign(sk); err != nil {
		t.Fatalf("sign: %v", err)
	}
	header := "Nostr " + base64.StdEncoding.EncodeToString([]byte(auth.String()))

	send := func() int {
		req, _ := http.NewRequest("POST", ts.URL+"/api/links/custom", strings.NewReader(string(body)))
		req.Header.Set("Authorization", header)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := send(); got != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", got)
	}
	if got := send(); got != http.StatusUnauthorized {
		t.Errorf("replayed request: got %d, want 401", got)
	}
}

func TestRedirectRejectsUnknown(t *testing.T) {
	ts, _ := newTestServer(t)
	_, _, npub := newKey(t)

	for _, path := range []string{
		"/" + npub + "/nonexistent",
		"/@nobody/slug",
		"/not-an-identity/slug",
	} {
		r, err := noRedirectClient().Get(ts.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", path, r.StatusCode)
		}
	}
}

// Names resolve to the same link as the npub form, so /@name/slug and
// /npub1.../slug are two views of one record.
func TestNameBasedRedirect(t *testing.T) {
	ts, st := newTestServer(t)
	sk, pk, _ := newKey(t)
	const dest = "https://example.com/named"

	ok, err := st.PutName(context.Background(), "ritik", pk)
	if err != nil || !ok {
		t.Fatalf("claim name: ok=%v err=%v", ok, err)
	}

	resp := createLink(t, ts, sk, linkEvent(t, sk, "hello", dest))
	resp.Body.Close()

	r, err := noRedirectClient().Get(ts.URL + "/@ritik/hello")
	if err != nil {
		t.Fatalf("redirect: %v", err)
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want 302", r.StatusCode)
	}
	if got := r.Header.Get("Location"); got != dest {
		t.Errorf("location: got %q, want %q", got, dest)
	}
}

// NIP-05 must stay public: other clients verify names cross-origin and cannot
// pay an L402 invoice to do it.
func TestNIP05Registry(t *testing.T) {
	ts, st := newTestServer(t)
	_, pk, _ := newKey(t)

	if _, err := st.PutName(context.Background(), "ritik", pk); err != nil {
		t.Fatalf("claim: %v", err)
	}

	resp, err := http.Get(ts.URL + "/.well-known/nostr.json?name=ritik")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("CORS header: got %q, want *", got)
	}

	var payload struct {
		Names map[string]string `json:"names"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Names["ritik"] != pk {
		t.Errorf("names: got %v, want ritik=%s", payload.Names, pk)
	}
}

// Names are the one global namespace sqz arbitrates, so a second claimant must
// lose while the original owner can re-claim idempotently.
func TestNameClaimIsFirstWins(t *testing.T) {
	_, st := newTestServer(t)
	_, first, _ := newKey(t)
	_, second, _ := newKey(t)
	ctx := context.Background()

	if ok, err := st.PutName(ctx, "taken", first); err != nil || !ok {
		t.Fatalf("first claim should win: ok=%v err=%v", ok, err)
	}
	if ok, err := st.PutName(ctx, "taken", second); err != nil || ok {
		t.Errorf("second claim should lose: ok=%v err=%v", ok, err)
	}
	if ok, err := st.PutName(ctx, "taken", first); err != nil || !ok {
		t.Errorf("owner re-claim should be idempotent: ok=%v err=%v", ok, err)
	}
}

// The rebuild endpoint flushes the derived keyspace, so an unauthenticated
// caller must never reach it. Critically, an *unset* token must disable the
// endpoint rather than disable the check — otherwise forgetting to configure a
// token silently publishes a keyspace-flush button.
func TestAdminRebuildRequiresToken(t *testing.T) {
	st := testStore(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	newServer := func(token string) *httptest.Server {
		srv := New(Config{BaseURL: testBase, Domain: "sqz.test", AdminToken: token}, st, log)
		ts := httptest.NewServer(srv.Routes())
		t.Cleanup(ts.Close)
		return ts
	}

	post := func(ts *httptest.Server, header string) int {
		req, _ := http.NewRequest("POST", ts.URL+"/admin/rebuild", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	t.Run("no token configured disables the endpoint", func(t *testing.T) {
		ts := newServer("")
		if got := post(ts, ""); got != http.StatusNotFound {
			t.Errorf("unauthenticated: got %d, want 404", got)
		}
		// Even a plausible guess must fail when nothing is configured.
		if got := post(ts, "Bearer "); got != http.StatusNotFound {
			t.Errorf("empty bearer: got %d, want 404", got)
		}
	})

	t.Run("wrong token rejected", func(t *testing.T) {
		ts := newServer("s3cret-operator-token")
		for _, h := range []string{"", "Bearer wrong", "s3cret-operator-token", "Basic s3cret-operator-token"} {
			if got := post(ts, h); got != http.StatusNotFound {
				t.Errorf("header %q: got %d, want 404", h, got)
			}
		}
	})

	t.Run("correct token accepted", func(t *testing.T) {
		ts := newServer("s3cret-operator-token")
		if got := post(ts, "Bearer s3cret-operator-token"); got != http.StatusOK {
			t.Errorf("got %d, want 200", got)
		}
	})
}

// Short identity prefixes are what make sqz actually shorten. A full npub is
// 63 characters, so the untruncated form produces URLs longer than most links
// people want shortened.
// The short URL is a flat sqzit.in/<slug> with no identity segment, and it
// resolves via the global slug owner.
func TestShortURLIsFlat(t *testing.T) {
	ts, _ := newTestServer(t)
	sk, _, _ := newKey(t)

	resp := createLink(t, ts, sk, linkEvent(t, sk, "short", "https://example.com/very/long/path"))
	defer resp.Body.Close()

	var body struct {
		ShortURL string `json:"short_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if want := testBase + "/short"; body.ShortURL != want {
		t.Errorf("short_url: got %q, want %q", body.ShortURL, want)
	}

	r, err := noRedirectClient().Get(ts.URL + "/short")
	if err != nil {
		t.Fatalf("redirect: %v", err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusFound {
		t.Errorf("flat form: got %d, want 302", r.StatusCode)
	}
}

// TestIssuedSlugFlow covers the auto tier: a slug issued by /api/links/slug can
// be created via /api/links, but a chosen slug there is refused.
func TestIssuedSlugFlow(t *testing.T) {
	ts, _ := newTestServer(t)
	sk, _, _ := newKey(t)

	// A chosen slug on the cheap endpoint is refused.
	resp := createLinkAt(t, ts, sk, linkEvent(t, sk, "chosen", "https://example.com"), "/api/links")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("chosen slug on /api/links: got %d, want 403", resp.StatusCode)
	}

	// Reserve a slug, then create it on the cheap endpoint.
	slug := reserveSlug(t, ts, sk)
	resp = createLinkAt(t, ts, sk, linkEvent(t, sk, slug, "https://example.com"), "/api/links")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("issued slug on /api/links: got %d, body %s", resp.StatusCode, b)
	}
}

// reserveSlug asks /api/links/slug for a server-issued slug.
func reserveSlug(t *testing.T, ts *httptest.Server, sk string) string {
	t.Helper()
	auth := &nostr.Event{
		Kind:      nip98.KindHTTPAuth,
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			{"u", testBase + "/api/links/slug"},
			{"method", "POST"},
		},
	}
	if err := auth.Sign(sk); err != nil {
		t.Fatalf("sign: %v", err)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/links/slug", nil)
	req.Header.Set("Authorization", "Nostr "+base64.StdEncoding.EncodeToString([]byte(auth.String())))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reserve slug: got %d", resp.StatusCode)
	}
	var out struct {
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode slug: %v", err)
	}
	return out.Slug
}

// A custom slug is globally unique: a second key claiming it is refused, and
// availability reflects the claim.
func TestCustomSlugGlobalUniqueness(t *testing.T) {
	ts, _ := newTestServer(t)
	owner, _, _ := newKey(t)
	other, _, _ := newKey(t)

	if got := available(t, ts, "mine"); !got {
		t.Fatalf("expected 'mine' available before claim")
	}

	resp := createLink(t, ts, owner, linkEvent(t, owner, "mine", "https://example.com/owner"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner create: got %d", resp.StatusCode)
	}

	if got := available(t, ts, "mine"); got {
		t.Errorf("expected 'mine' unavailable after claim")
	}

	resp = createLink(t, ts, other, linkEvent(t, other, "mine", "https://example.com/other"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("other claiming taken slug: got %d, want 409", resp.StatusCode)
	}
}

// available queries the public availability endpoint.
func available(t *testing.T, ts *httptest.Server, slug string) bool {
	t.Helper()
	r, err := http.Get(ts.URL + "/api/links/available?slug=" + slug)
	if err != nil {
		t.Fatalf("available: %v", err)
	}
	defer r.Body.Close()
	var out struct {
		Available bool `json:"available"`
	}
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out.Available
}

// The analytics endpoint totals clicks and ranks links most-clicked first.
// (Tests hit sqzd directly, so the nginx paywall isn't in the path.)
func TestAnalyticsAggregates(t *testing.T) {
	ts, st := newTestServer(t)
	sk, pk, _ := newKey(t)
	ctx := context.Background()

	for _, slug := range []string{"aaa", "bbb"} {
		resp := createLink(t, ts, sk, linkEvent(t, sk, slug, "https://example.com/"+slug))
		resp.Body.Close()
	}
	for i := 0; i < 3; i++ {
		if err := st.RecordClick(ctx, pk, "aaa"); err != nil {
			t.Fatalf("click: %v", err)
		}
	}
	if err := st.RecordClick(ctx, pk, "bbb"); err != nil {
		t.Fatalf("click: %v", err)
	}

	auth := &nostr.Event{
		Kind:      nip98.KindHTTPAuth,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{{"u", testBase + "/api/analytics"}, {"method", "GET"}},
	}
	if err := auth.Sign(sk); err != nil {
		t.Fatalf("sign: %v", err)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/analytics", nil)
	req.Header.Set("Authorization", "Nostr "+base64.StdEncoding.EncodeToString([]byte(auth.String())))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("analytics: got %d, body %s", resp.StatusCode, b)
	}

	var out struct {
		TotalLinks  int `json:"total_links"`
		TotalClicks int `json:"total_clicks"`
		Links       []struct {
			Slug   string `json:"slug"`
			Clicks int    `json:"clicks"`
		} `json:"links"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.TotalLinks != 2 || out.TotalClicks != 4 {
		t.Errorf("totals: got links=%d clicks=%d, want 2/4", out.TotalLinks, out.TotalClicks)
	}
	if len(out.Links) != 2 || out.Links[0].Slug != "aaa" {
		t.Errorf("leaderboard not ranked by clicks: %+v", out.Links)
	}
}

// The public leaderboard shows only opted-in links, ranked by clicks.
func TestPublicLeaderboard(t *testing.T) {
	ts, st := newTestServer(t)
	sk, pk, _ := newKey(t)
	ctx := context.Background()

	resp := createLink(t, ts, sk, linkEvent(t, sk, "pub", "https://example.com/pub", nostr.Tag{"public", "1"}))
	resp.Body.Close()
	resp = createLink(t, ts, sk, linkEvent(t, sk, "priv", "https://example.com/priv"))
	resp.Body.Close()

	for i := 0; i < 5; i++ {
		st.RecordClick(ctx, pk, "pub")
	}
	for i := 0; i < 9; i++ {
		st.RecordClick(ctx, pk, "priv") // more clicks, but not opted in
	}

	r, err := http.Get(ts.URL + "/api/leaderboard")
	if err != nil {
		t.Fatalf("leaderboard: %v", err)
	}
	defer r.Body.Close()
	var out struct {
		Links []struct {
			Slug   string `json:"slug"`
			Clicks int    `json:"clicks"`
		} `json:"links"`
	}
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Links) != 1 || out.Links[0].Slug != "pub" || out.Links[0].Clicks != 5 {
		t.Errorf("leaderboard should be only opted-in 'pub' with 5 clicks: %+v", out.Links)
	}
}

// Replaying events rebuilds the index, and a contested slug goes to whoever's
// event is replayed first (reconcile replays oldest-first).
func TestReindexRebuildsAndFirstClaimWins(t *testing.T) {
	_, st := newTestServer(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(Config{BaseURL: testBase, Domain: "sqz.test", SelfHosts: []string{"sqz.test"}}, st, log)
	ctx := context.Background()

	skA, pkA, _ := newKey(t)
	skB, _, _ := newKey(t)

	// A's event is replayed first, so A wins the contested slug.
	if err := srv.reindex(ctx, linkEvent(t, skA, "hot", "https://example.com/a")); err != nil {
		t.Fatalf("reindex A: %v", err)
	}
	if err := srv.reindex(ctx, linkEvent(t, skB, "hot", "https://example.com/b")); err != nil {
		t.Fatalf("reindex B: %v", err)
	}

	owner, err := st.SlugOwner(ctx, "hot")
	if err != nil || owner != pkA {
		t.Errorf("hot should belong to first claimer A: owner=%s err=%v", owner, err)
	}
	link, err := st.GetLink(ctx, pkA, "hot")
	if err != nil || link.Destination != "https://example.com/a" {
		t.Errorf("hot should resolve to A's destination: %+v %v", link, err)
	}

	// A non-sqz event (wrong d-tag) is a harmless no-op.
	other := &nostr.Event{Kind: links.Kind, CreatedAt: nostr.Now(), Tags: nostr.Tags{{"d", "other:x"}, {"r", "https://example.com/x"}}}
	if err := other.Sign(skA); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := srv.reindex(ctx, other); err != nil {
		t.Errorf("non-sqz event should be a no-op, got %v", err)
	}
}

// A prefix collision must extend rather than hand one key's prefix to another.
func TestNpubPrefixCollisionExtends(t *testing.T) {
	_, st := newTestServer(t)
	ctx := context.Background()

	// Two distinct pubkeys whose npubs share the default-length prefix.
	npubA := "npub1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	npubB := "npub1aaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	a, err := st.AssignNpubPrefix(ctx, npubA, "pubkey-a")
	if err != nil {
		t.Fatalf("assign a: %v", err)
	}
	b, err := st.AssignNpubPrefix(ctx, npubB, "pubkey-b")
	if err != nil {
		t.Fatalf("assign b: %v", err)
	}

	if a == b {
		t.Fatalf("distinct keys got the same prefix %q", a)
	}
	if len(b) <= len(a) {
		t.Errorf("colliding prefix should have extended: a=%q b=%q", a, b)
	}

	// Each prefix must resolve to its own key.
	for prefix, want := range map[string]string{a: "pubkey-a", b: "pubkey-b"} {
		got, err := st.LookupNpubPrefix(ctx, prefix)
		if err != nil {
			t.Fatalf("lookup %q: %v", prefix, err)
		}
		if got != want {
			t.Errorf("prefix %q resolved to %q, want %q", prefix, got, want)
		}
	}
}

// Prefixes live in the local keyspace precisely so a rebuild cannot reassign
// them and invalidate URLs that are already published.
func TestNpubPrefixSurvivesRebuild(t *testing.T) {
	_, st := newTestServer(t)
	ctx := context.Background()
	_, pk, npub := newKey(t)

	before, err := st.AssignNpubPrefix(ctx, npub, pk)
	if err != nil {
		t.Fatalf("assign: %v", err)
	}

	if _, err := st.RebuildDerived(ctx); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	after, err := st.AssignNpubPrefix(ctx, npub, pk)
	if err != nil {
		t.Fatalf("reassign after rebuild: %v", err)
	}
	if after != before {
		t.Errorf("rebuild changed the prefix: %q -> %q; every published URL would break", before, after)
	}
}

func mustPubkey(t *testing.T, sk string) string {
	t.Helper()
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	return pk
}

// On a paid route the Authorization header belongs to L402, so NIP-98 must be
// read from X-Nostr-Authorization instead. This proves the dedicated header is
// accepted and that it wins even when Authorization carries an (unrelated)
// L402-style credential — the exact collision that 401'd real-mode requests.
func TestNostrAuthHeaderResolvesCollision(t *testing.T) {
	ts, _ := newTestServer(t)
	sk, _, npub := newKey(t)
	const dest = "https://example.com/via-dedicated-header"

	evt := linkEvent(t, sk, "hdr", dest)
	body, _ := json.Marshal(createLinkRequest{Event: evt})

	sum := sha256.Sum256(body)
	auth := &nostr.Event{
		Kind:      nip98.KindHTTPAuth,
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			{"u", testBase + "/api/links/custom"},
			{"method", "POST"},
			{"payload", hex.EncodeToString(sum[:])},
		},
	}
	if err := auth.Sign(sk); err != nil {
		t.Fatalf("sign: %v", err)
	}
	nostrCred := "Nostr " + base64.StdEncoding.EncodeToString([]byte(auth.String()))

	req, _ := http.NewRequest("POST", ts.URL+"/api/links/custom", strings.NewReader(string(body)))
	req.Header.Set("X-Nostr-Authorization", nostrCred)
	// Simulate what nginx forwards after a settled L402 payment: Authorization
	// holds the macaroon:preimage, which is not a NIP-98 credential.
	req.Header.Set("Authorization", "L402 c29tZS1tYWNhcm9vbg==:0000000000000000000000000000000000000000000000000000000000000000")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("got %d, want 200 (dedicated header should win over L402 Authorization); body %s", resp.StatusCode, b)
	}

	r, err := noRedirectClient().Get(ts.URL + "/" + npub + "/hdr")
	if err != nil {
		t.Fatalf("redirect: %v", err)
	}
	r.Body.Close()
	if r.Header.Get("Location") != dest {
		t.Errorf("location: got %q, want %q", r.Header.Get("Location"), dest)
	}
}

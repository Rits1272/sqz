// Package server exposes sqz over HTTP.
//
// It sits behind nginx, which owns the L402 paywall. Nothing in here knows
// about payment: nginx either passes a request through or answers 402 itself.
// That split keeps payment policy in configuration rather than in code.
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/Rits1272/sqz/internal/links"
	"github.com/Rits1272/sqz/internal/nip98"
	"github.com/Rits1272/sqz/internal/store"
)

// maxBodyBytes caps request bodies. A link event is well under a kilobyte;
// this only needs to be generous enough for a signed event with tags.
const maxBodyBytes = 64 << 10

type Config struct {
	// BaseURL is sqz's externally-visible origin, e.g. "https://sqz.link".
	//
	// NIP-98 signatures are bound to the absolute request URL, and behind a
	// proxy the only trustworthy source for that is configuration — deriving it
	// from Host or X-Forwarded-* would let a client choose what its own
	// signature covers.
	BaseURL string

	// Domain is the NIP-05 domain served at /.well-known/nostr.json.
	Domain string

	// AdminToken guards destructive operator endpoints. When empty those
	// endpoints are disabled outright rather than left open — an unset
	// credential must never mean "no credential required", since that turns a
	// missing config value into a public keyspace-flush button.
	AdminToken string

	// SelfHosts are hostnames belonging to sqz; link destinations pointing at
	// them are rejected as redirect loops.
	SelfHosts []string

	// Firebase web-analytics config, served to the browser via /api/config.
	// Zero value disables analytics.
	Firebase FirebaseConfig
}

// FirebaseConfig is Firebase's public web config. The values are public
// identifiers, not secrets; they reach the browser via /api/config.
type FirebaseConfig struct {
	APIKey            string `json:"apiKey,omitempty"`
	AuthDomain        string `json:"authDomain,omitempty"`
	ProjectID         string `json:"projectId,omitempty"`
	StorageBucket     string `json:"storageBucket,omitempty"`
	MessagingSenderID string `json:"messagingSenderId,omitempty"`
	AppID             string `json:"appId,omitempty"`
	MeasurementID     string `json:"measurementId,omitempty"`
}

func (f FirebaseConfig) Enabled() bool { return f.APIKey != "" }

type Server struct {
	cfg   Config
	store *store.Store
	log   *slog.Logger
	web   fs.FS
}

func New(cfg Config, st *store.Store, log *slog.Logger) *Server {
	return &Server{cfg: cfg, store: st, log: log}
}

// WithWeb attaches the embedded web app. Optional so tests can run the API
// without the frontend.
func (s *Server) WithWeb(web fs.FS) *Server {
	s.web = web
	return s
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /api/config", s.handleConfig)
	mux.HandleFunc("GET /api/qr", s.handleQR)
	mux.HandleFunc("GET /.well-known/nostr.json", s.handleNIP05)
	mux.HandleFunc("POST /api/links", s.handleCreateLink)
	mux.HandleFunc("POST /api/links/custom", s.handleCreateLinkCustom)
	mux.HandleFunc("POST /api/links/slug", s.handleGenerateSlug)
	mux.HandleFunc("GET /api/links/available", s.handleSlugAvailable)
	mux.HandleFunc("GET /api/links", s.handleListLinks)
	mux.HandleFunc("GET /api/analytics", s.handleAnalytics)
	mux.HandleFunc("POST /admin/rebuild", s.handleRebuild)

	// The web app. "/{$}" matches only the bare root, and "/assets/{file}" is
	// two segments with a literal first — strictly more specific than the
	// redirect pattern, which is what lets both coexist. A bare "/assets/"
	// subtree pattern would be ambiguous against "/{ident}/{slug}" and panics
	// at startup. "assets" is a reserved slug, so no link can shadow it.
	if s.web != nil {
		files := http.FileServerFS(s.web)
		mux.Handle("GET /{$}", files)
		mux.Handle("GET /assets/{file}", files)
	}

	// Flat redirect is the current form: sqzit.in/<slug> resolves via the global
	// slug owner. The two-segment form is kept so links minted under the old
	// per-identity scheme keep resolving. Both are less specific than the API
	// routes above, which therefore win.
	mux.HandleFunc("GET /{slug}", s.handleRedirect)
	mux.HandleFunc("GET /{ident}/{slug}", s.handleRedirectLegacy)

	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleRedirect is the hot path. It resolves the global slug to its owner and
// redirects, reading only from Redis so a slow relay can never delay a redirect.
func (s *Server) handleRedirect(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	pubkey, err := s.store.SlugOwner(r.Context(), slug)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("resolve slug owner", "slug", slug, "err", err)
		}
		http.NotFound(w, r)
		return
	}
	s.serveRedirect(w, r, pubkey, slug)
}

// handleRedirectLegacy resolves the old two-segment /<ident>/<slug> form.
func (s *Server) handleRedirectLegacy(w http.ResponseWriter, r *http.Request) {
	pubkey, err := s.resolveIdentity(r.Context(), r.PathValue("ident"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.serveRedirect(w, r, pubkey, r.PathValue("slug"))
}

// serveRedirect looks up (pubkey, slug), records a click off the hot path, and
// issues the redirect. Shared by both the flat and legacy routes.
func (s *Server) serveRedirect(w http.ResponseWriter, r *http.Request, pubkey, slug string) {
	link, err := s.store.GetLink(r.Context(), pubkey, slug)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("resolve link", "pubkey", pubkey, "slug", slug, "err", err)
		}
		http.NotFound(w, r)
		return
	}

	// Analytics must never delay or fail a redirect, so it runs detached with
	// its own context — r.Context() is cancelled the moment we respond.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.store.RecordClick(ctx, pubkey, slug); err != nil {
			s.log.Warn("record click", "pubkey", pubkey, "slug", slug, "err", err)
		}
	}()

	// Short links aren't content to index — only the landing page is.
	w.Header().Set("X-Robots-Tag", "noindex")

	// 302, deliberately not 301: browsers cache a 301 indefinitely, which would
	// make destination edits invisible and silently stop counting clicks.
	http.Redirect(w, r, link.Destination, http.StatusFound)
}

// resolveIdentity turns the first path segment into a pubkey.
//
// Two forms are supported: "npub1..." works for any nostr user with no
// registration at all, and "@name" resolves through sqz's own NIP-05 registry.
func (s *Server) resolveIdentity(ctx context.Context, ident string) (string, error) {
	if name, ok := strings.CutPrefix(ident, "@"); ok {
		return s.store.LookupName(ctx, strings.ToLower(name))
	}

	if strings.HasPrefix(ident, "npub1") {
		// A full npub decodes on its own, with no lookup and no state — this
		// keeps working for anyone who has the whole key, including links
		// minted before prefixes existed.
		if hrp, data, err := nip19.Decode(ident); err == nil && hrp == "npub" {
			if pubkey, ok := data.(string); ok {
				return pubkey, nil
			}
		}
		// Otherwise it is a truncated prefix, which needs the local index.
		return s.store.LookupNpubPrefix(ctx, ident)
	}

	return "", store.ErrNotFound
}

// createLinkRequest carries the user's signed link event.
//
// The event is sent directly rather than fetched from a relay by coordinate.
// A signed event is self-authenticating, so accepting it inline is exactly as
// trustworthy as reading it from a relay, and it removes a relay round-trip
// from an interactive request. sqz republishes it to relays afterwards, so the
// relays remain the durable source of truth.
type createLinkRequest struct {
	Event  *nostr.Event `json:"event"`
	Relays []string     `json:"relays,omitempty"`
}

// handleCreateLink serves the cheaper tier: the slug must be one this server
// issued (via /api/links/slug), so a chosen name can't sneak through here.
func (s *Server) handleCreateLink(w http.ResponseWriter, r *http.Request) {
	s.createLink(w, r, true)
}

// handleCreateLinkCustom serves the pricier tier, where the caller picks the
// slug. No issued-slug check — the nginx paywall charges the higher amount.
func (s *Server) handleCreateLinkCustom(w http.ResponseWriter, r *http.Request) {
	s.createLink(w, r, false)
}

func (s *Server) createLink(w http.ResponseWriter, r *http.Request, requireIssued bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}

	auth, err := s.authenticate(r, body)
	if err != nil {
		// Deliberately uniform: telling a caller which check failed helps them
		// probe the auth logic.
		s.log.Debug("auth rejected", "err", err)
		writeError(w, http.StatusUnauthorized, "invalid or missing NIP-98 authorization")
		return
	}

	var req createLinkRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Event == nil {
		writeError(w, http.StatusBadRequest, "body must be {\"event\": <signed kind 30078 event>}")
		return
	}

	// The link event carries its own signature, independent of the NIP-98
	// header. Verify it, or sqz would index unsigned data that no relay would
	// ever accept.
	if !req.Event.CheckID() {
		writeError(w, http.StatusBadRequest, "event id does not match its contents")
		return
	}
	if ok, err := req.Event.CheckSignature(); err != nil || !ok {
		writeError(w, http.StatusBadRequest, "invalid event signature")
		return
	}

	// Both signatures must come from the same key. Without this, anyone could
	// authenticate as themselves and submit someone else's link event, taking
	// over that person's slug in sqz's index.
	if req.Event.PubKey != auth.PubKey {
		writeError(w, http.StatusForbidden, "link event must be signed by the authenticated key")
		return
	}

	link, err := links.Parse(req.Event, s.cfg.SelfHosts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Claiming a name only applies to a new link. Revoking (empty destination)
	// is exempt — the owner is deleting their own link, not claiming a name — so
	// revocation keeps working through the cheap endpoint.
	if !link.Revoked {
		// Cheap tier: the slug must be one this server issued, so a chosen name
		// can't slip through at the auto price.
		if requireIssued {
			ok, err := s.store.ClaimIssuedSlug(r.Context(), auth.PubKey, link.Slug)
			if err != nil {
				s.log.Error("claim issued slug", "err", err)
				writeError(w, http.StatusInternalServerError, "could not verify slug")
				return
			}
			if !ok {
				writeError(w, http.StatusForbidden,
					"this slug was not issued by sqz; a chosen name is a custom link — POST /api/links/custom")
				return
			}
		}

		// Flat namespace: claim the global slug. Fails only if another key
		// already owns it.
		owned, err := s.store.ClaimSlugOwner(r.Context(), link.Slug, auth.PubKey)
		if err != nil {
			s.log.Error("claim slug owner", "err", err)
			writeError(w, http.StatusInternalServerError, "could not claim slug")
			return
		}
		if !owned {
			writeError(w, http.StatusConflict, "that name is already taken")
			return
		}
	}

	if err := s.store.PutLink(r.Context(), link); err != nil {
		s.log.Error("index link", "coordinate", link.Coordinate(), "err", err)
		writeError(w, http.StatusInternalServerError, "could not index link")
		return
	}

	s.log.Info("link indexed", "coordinate", link.Coordinate(), "revoked", link.Revoked)

	writeJSON(w, http.StatusOK, map[string]any{
		"coordinate": link.Coordinate(),
		"short_url":  s.cfg.BaseURL + "/" + link.Slug,
		"revoked":    link.Revoked,
	})
}

// slugTTL is how long a server-issued slug stays claimable before it lapses.
// Long enough to sign and pay the invoice, short enough that abandoned
// reservations don't accumulate.
const slugTTL = 15 * time.Minute

// handleGenerateSlug issues a random, currently-free slug and reserves it for
// the authenticated key to claim on the cheap create tier. It is public (no
// paywall) — a slug is worthless until a paid, signed link claims it.
func (s *Server) handleGenerateSlug(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	auth, err := s.authenticate(r, body)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or missing NIP-98 authorization")
		return
	}

	slug, err := s.freeSlug(r.Context())
	if err != nil {
		s.log.Error("generate slug", "err", err)
		writeError(w, http.StatusInternalServerError, "could not allocate a slug")
		return
	}
	if err := s.store.IssueSlug(r.Context(), auth.PubKey, slug, slugTTL); err != nil {
		s.log.Error("reserve slug", "err", err)
		writeError(w, http.StatusInternalServerError, "could not reserve slug")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"slug": slug})
}

// freeSlug returns a random slug not already owned in the global namespace.
func (s *Server) freeSlug(ctx context.Context) (string, error) {
	for i := 0; i < 8; i++ {
		slug := randomSlug()
		taken, err := s.store.SlugTaken(ctx, slug)
		if err != nil {
			return "", err
		}
		if !taken {
			return slug, nil
		}
	}
	return "", fmt.Errorf("could not find a free slug after 8 tries")
}

// handleSlugAvailable reports whether a custom slug is free to claim. Public and
// best-effort — the ClaimSlugOwner at create time is the real guard. Invalid or
// reserved slugs report unavailable, matching what a create would do.
func (s *Server) handleSlugAvailable(w http.ResponseWriter, r *http.Request) {
	slug := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("slug")))
	resp := map[string]any{"slug": slug, "available": false}

	if err := links.ValidateSlug(slug); err != nil {
		if errors.Is(err, links.ErrSlugReserved) {
			resp["reason"] = "reserved"
		} else {
			resp["reason"] = "invalid"
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	taken, err := s.store.SlugTaken(r.Context(), slug)
	if err != nil {
		s.log.Error("slug availability", "err", err)
		writeError(w, http.StatusInternalServerError, "could not check availability")
		return
	}
	resp["available"] = !taken
	if taken {
		resp["reason"] = "taken"
	}
	writeJSON(w, http.StatusOK, resp)
}

// randomSlug returns 7 lowercase base32 characters (~35 bits), collision-safe
// within a single key's namespace and within the slug charset.
func randomSlug() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	var b [7]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read from crypto/rand does not fail in practice; fall back to a
		// fixed but still-checked-for-collision value rather than panicking.
		return "aaaaaaa"
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b[:])
}

// handleListLinks returns the authenticated user's own links.
//
// There is no way to ask for anyone else's: the pubkey comes from the verified
// NIP-98 signature, never from a query parameter.
func (s *Server) handleListLinks(w http.ResponseWriter, r *http.Request) {
	auth, err := s.authenticate(r, nil)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or missing NIP-98 authorization")
		return
	}

	found, err := s.store.ListLinks(r.Context(), auth.PubKey)
	if err != nil {
		s.log.Error("list links", "pubkey", auth.PubKey, "err", err)
		writeError(w, http.StatusInternalServerError, "could not list links")
		return
	}

	out := make([]map[string]any, 0, len(found))
	for _, l := range found {
		clicks, err := s.store.Clicks(r.Context(), l.PubKey, l.Slug)
		if err != nil {
			// Analytics is a nice-to-have; a failure here must not hide links.
			s.log.Warn("clicks", "slug", l.Slug, "err", err)
		}
		out = append(out, map[string]any{
			"slug":        l.Slug,
			"destination": l.Destination,
			"title":       l.Title,
			"short_url":   s.cfg.BaseURL + "/" + l.Slug,
			"created_at":  l.CreatedAt.Unix(),
			"clicks":      clicks,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"links": out})
}

// handleAnalytics returns an aggregate view over the caller's links: totals
// plus a click-ranked leaderboard. It aggregates the same click counters the
// links list exposes per link — no extra tracking. The nginx paywall gates it
// (100 sats, one-time indefinite access); sqzd only authenticates the caller.
func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	auth, err := s.authenticate(r, nil)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or missing NIP-98 authorization")
		return
	}

	found, err := s.store.ListLinks(r.Context(), auth.PubKey)
	if err != nil {
		s.log.Error("analytics list", "pubkey", auth.PubKey, "err", err)
		writeError(w, http.StatusInternalServerError, "could not load analytics")
		return
	}

	type row struct {
		Slug        string `json:"slug"`
		ShortURL    string `json:"short_url"`
		Destination string `json:"destination"`
		Clicks      int64  `json:"clicks"`
	}
	rows := make([]row, 0, len(found))
	var totalClicks int64
	for _, l := range found {
		clicks, err := s.store.Clicks(r.Context(), l.PubKey, l.Slug)
		if err != nil {
			s.log.Warn("analytics clicks", "slug", l.Slug, "err", err)
		}
		totalClicks += clicks
		rows = append(rows, row{
			Slug:        l.Slug,
			ShortURL:    s.cfg.BaseURL + "/" + l.Slug,
			Destination: l.Destination,
			Clicks:      clicks,
		})
	}
	// Leaderboard: most-clicked first.
	sort.Slice(rows, func(i, j int) bool { return rows[i].Clicks > rows[j].Clicks })

	writeJSON(w, http.StatusOK, map[string]any{
		"total_links":  len(rows),
		"total_clicks": totalClicks,
		"links":        rows,
	})
}

// handleConfig tells the web app the origin its NIP-98 events must be signed
// against. The browser cannot infer this safely — behind a proxy the origin it
// sees may differ from the one the server verifies against, and a mismatch
// silently fails every signature.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"base_url": s.cfg.BaseURL,
		"domain":   s.cfg.Domain,
	}
	if s.cfg.Firebase.Enabled() {
		out["firebase"] = s.cfg.Firebase
	}
	writeJSON(w, http.StatusOK, out)
}

// nostrAuthHeader carries the NIP-98 credential.
//
// NIP-98 puts it in Authorization, but on a paywalled route the L402 module
// claims that header for its own `L402 macaroon:preimage` credential and 401s
// anything else. So sqz reads identity from a dedicated header, leaving
// Authorization to L402. See docs/payments.md.
const nostrAuthHeader = "X-Nostr-Authorization"

// authenticate verifies the NIP-98 header against this exact request.
//
// It prefers the dedicated header but falls back to Authorization, so
// unpaywalled routes and older clients that still send `Authorization: Nostr`
// keep working. On a paid route Authorization holds the L402 credential, but
// there the dedicated header is always present and wins, so the fallback never
// misreads an L402 value as NIP-98.
func (s *Server) authenticate(r *http.Request, body []byte) (*nip98.Auth, error) {
	header := r.Header.Get(nostrAuthHeader)
	if header == "" {
		header = r.Header.Get("Authorization")
	}
	return nip98.Verify(
		r.Context(),
		header,
		nip98.Request{
			// Built from configuration, not from request headers — see Config.BaseURL.
			URL:    s.cfg.BaseURL + r.URL.RequestURI(),
			Method: r.Method,
			Body:   body,
		},
		s.store,
	)
}

// handleNIP05 serves sqz's name registry.
//
// Must stay public and unpaid: NIP-05 verification is performed by other
// clients, which have no way to pay an L402 invoice.
func (s *Server) handleNIP05(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(r.URL.Query().Get("name"))

	resp := map[string]any{"names": map[string]string{}}
	if name != "" {
		if pubkey, err := s.store.LookupName(r.Context(), name); err == nil {
			resp["names"] = map[string]string{name: pubkey}
		}
	}

	// NIP-05 is fetched cross-origin by clients, so it must be CORS-open.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, resp)
}

// handleRebuild drops the derived keyspace so it can be replayed from relays.
//
// TODO: trigger the relay replay once the reconciler exists. Right now this
// only clears, which leaves the index empty until links are re-submitted.
func (s *Server) handleRebuild(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		// 404 rather than 401: an unauthenticated caller learns nothing about
		// whether this endpoint exists or whether admin access is configured.
		http.NotFound(w, r)
		return
	}

	deleted, err := s.store.RebuildDerived(r.Context())
	if err != nil {
		s.log.Error("rebuild", "err", err)
		writeError(w, http.StatusInternalServerError, "rebuild failed")
		return
	}
	s.log.Warn("derived keyspace flushed", "deleted", deleted)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": deleted})
}

// authorizeAdmin checks the operator bearer token.
//
// Fails closed: with no token configured, no request is ever authorized. The
// comparison is constant-time so a caller cannot recover the token by timing
// how long a wrong guess takes to reject.
func (s *Server) authorizeAdmin(r *http.Request) bool {
	if s.cfg.AdminToken == "" {
		return false
	}
	presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.cfg.AdminToken)) == 1
}

// npubOrHex prefers the npub form in user-facing URLs, falling back to hex if
// encoding fails rather than dropping the link entirely.
func npubOrHex(pubkey string) string {
	if npub, err := nip19.EncodePublicKey(pubkey); err == nil {
		return npub
	}
	return pubkey
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

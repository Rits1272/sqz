// Package server exposes sqz over HTTP.
//
// It sits behind nginx, which owns the L402 paywall. Nothing in here knows
// about payment: nginx either passes a request through or answers 402 itself.
// That split keeps payment policy in configuration rather than in code.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
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
}

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
	mux.HandleFunc("GET /api/links", s.handleListLinks)
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

	// The redirect route is last and most general. Go's ServeMux prefers more
	// specific patterns, so the API routes above win over "/{ident}/{slug}".
	mux.HandleFunc("GET /{ident}/{slug}", s.handleRedirect)

	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleRedirect is the hot path. It reads only from Redis — never from relays
// — so a slow or unreachable relay cannot delay or break a redirect.
func (s *Server) handleRedirect(w http.ResponseWriter, r *http.Request) {
	ident := r.PathValue("ident")
	slug := r.PathValue("slug")

	pubkey, err := s.resolveIdentity(r.Context(), ident)
	if err != nil {
		http.NotFound(w, r)
		return
	}

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

// shortIdent returns the identity segment to put in a user-facing URL: their
// assigned short npub prefix, falling back to the full npub if assignment
// fails. A long URL is worse than an elegant one; a broken URL is worse than
// both.
func (s *Server) shortIdent(ctx context.Context, pubkey string) string {
	npub := npubOrHex(pubkey)
	if !strings.HasPrefix(npub, "npub1") {
		return npub
	}

	prefix, err := s.store.AssignNpubPrefix(ctx, npub, pubkey)
	if err != nil {
		s.log.Warn("assign npub prefix", "pubkey", pubkey, "err", err)
		return npub
	}
	return prefix
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

func (s *Server) handleCreateLink(w http.ResponseWriter, r *http.Request) {
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

	if err := s.store.PutLink(r.Context(), link); err != nil {
		s.log.Error("index link", "coordinate", link.Coordinate(), "err", err)
		writeError(w, http.StatusInternalServerError, "could not index link")
		return
	}

	s.log.Info("link indexed", "coordinate", link.Coordinate(), "revoked", link.Revoked)

	writeJSON(w, http.StatusOK, map[string]any{
		"coordinate": link.Coordinate(),
		"short_url":  s.cfg.BaseURL + "/" + s.shortIdent(r.Context(), link.PubKey) + "/" + link.Slug,
		"revoked":    link.Revoked,
	})
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

	ident := s.shortIdent(r.Context(), auth.PubKey)
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
			"short_url":   s.cfg.BaseURL + "/" + ident + "/" + l.Slug,
			"created_at":  l.CreatedAt.Unix(),
			"clicks":      clicks,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"links": out})
}

// handleConfig tells the web app the origin its NIP-98 events must be signed
// against. The browser cannot infer this safely — behind a proxy the origin it
// sees may differ from the one the server verifies against, and a mismatch
// silently fails every signature.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"base_url": s.cfg.BaseURL,
		"domain":   s.cfg.Domain,
	})
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

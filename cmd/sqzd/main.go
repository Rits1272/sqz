// Command sqzd is the sqz application server.
//
// It runs behind nginx, which owns the L402 paywall. sqzd verifies NIP-98
// identity, validates link events, serves redirects from the Redis index, and
// hosts the NIP-05 name registry.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Rits1272/sqz/internal/server"
	"github.com/Rits1272/sqz/internal/store"
	"github.com/Rits1272/sqz/web"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(env("SQZ_LOG_LEVEL", "info")),
	}))

	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	baseURL := strings.TrimSuffix(env("SQZ_BASE_URL", "http://localhost:8000"), "/")

	st, err := store.Open(ctx, env("SQZ_REDIS_URL", "redis://localhost:6379/0"))
	if err != nil {
		return err
	}
	defer st.Close()

	cfg := server.Config{
		BaseURL:    baseURL,
		Domain:     env("SQZ_DOMAIN", "localhost"),
		AdminToken: os.Getenv("SQZ_ADMIN_TOKEN"),
		SelfHosts:  selfHosts(baseURL, env("SQZ_SELF_HOSTS", "")),
	}

	// SQZ_WEB_DIR serves the frontend from disk instead of the embedded copy,
	// so design work can iterate without a rebuild. Development only — the
	// deployed binary always uses its embedded assets.
	webFS := web.FS()
	if dir := os.Getenv("SQZ_WEB_DIR"); dir != "" {
		log.Warn("serving web assets from disk", "dir", dir)
		webFS = os.DirFS(dir)
	}

	addr := env("SQZ_LISTEN", ":8080")
	srv := &http.Server{
		Addr:    addr,
		Handler: server.New(cfg, st, log).WithWeb(webFS).Routes(),

		// A redirect is a Redis lookup; anything slower is a stuck client.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("sqzd listening", "addr", addr, "base_url", cfg.BaseURL, "domain", cfg.Domain)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// selfHosts collects hostnames that a link must not redirect to, so a link
// cannot point back at sqz and create a loop.
func selfHosts(baseURL, extra string) []string {
	hosts := []string{"localhost", "127.0.0.1"}

	if trimmed := strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://"); trimmed != "" {
		if host, _, found := strings.Cut(trimmed, ":"); found {
			hosts = append(hosts, host)
		} else if host, _, found := strings.Cut(trimmed, "/"); found {
			hosts = append(hosts, host)
		} else {
			hosts = append(hosts, trimmed)
		}
	}

	for _, h := range strings.Split(extra, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseLevel(s string) slog.Level {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return lvl
}

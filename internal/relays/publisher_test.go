package relays

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// TestPublishReachesRelay publishes a signed event through Publisher and reads
// it back from the relay. It's a live network test, so it's opt-in
// (SQZ_RELAY_LIVE=1) and normal runs stay hermetic.
func TestPublishReachesRelay(t *testing.T) {
	if os.Getenv("SQZ_RELAY_LIVE") != "1" {
		t.Skip("set SQZ_RELAY_LIVE=1 to run the live relay test")
	}
	const relayURL = "wss://relay.damus.io"

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	evt := nostr.Event{
		Kind:      30078,
		CreatedAt: nostr.Now(),
		PubKey:    pk,
		Tags: nostr.Tags{
			{"d", fmt.Sprintf("sqz:relaytest-%d", time.Now().UnixNano())},
			{"r", "https://example.com/relay-test"},
		},
	}
	if err := evt.Sign(sk); err != nil {
		t.Fatalf("sign: %v", err)
	}

	New([]string{relayURL}, slog.Default()).Publish(evt, nil)

	// Publish is fire-and-forget; give the fan-out a moment, then read it back.
	time.Sleep(4 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	relay, err := nostr.RelayConnect(ctx, relayURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	sub, err := relay.Subscribe(ctx, nostr.Filters{{IDs: []string{evt.ID}}})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	select {
	case got := <-sub.Events:
		if got.ID != evt.ID {
			t.Errorf("got event %s, want %s", got.ID, evt.ID)
		}
	case <-ctx.Done():
		t.Fatal("event did not come back from the relay — publish did not land")
	}
}

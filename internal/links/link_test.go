package links

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

var selfHosts = []string{"sqz.link", "localhost"}

func event(tags ...nostr.Tag) *nostr.Event {
	return &nostr.Event{
		Kind:      Kind,
		PubKey:    "abc123",
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags(tags),
	}
}

func TestParseValidLink(t *testing.T) {
	evt := event(
		nostr.Tag{"d", "sqz:launch"},
		nostr.Tag{"r", "https://example.com/a/very/long/path"},
		nostr.Tag{"title", "Launch post"},
	)

	link, err := Parse(evt, selfHosts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if link.Slug != "launch" {
		t.Errorf("slug: got %q, want %q", link.Slug, "launch")
	}
	if link.Destination != "https://example.com/a/very/long/path" {
		t.Errorf("destination: got %q", link.Destination)
	}
	if link.Title != "Launch post" {
		t.Errorf("title: got %q", link.Title)
	}
	if !link.Resolvable(time.Now()) {
		t.Error("expected link to be resolvable")
	}
	want := "30078:abc123:sqz:launch"
	if link.Coordinate() != want {
		t.Errorf("coordinate: got %q, want %q", link.Coordinate(), want)
	}
}

// An empty 'r' tag is revocation, not an error: relays often ignore NIP-09
// deletes, so republishing with no destination is the reliable way to kill a
// link. It must parse cleanly and then refuse to resolve.
func TestParseRevocation(t *testing.T) {
	for _, tags := range [][]nostr.Tag{
		{{"d", "sqz:gone"}, {"r", ""}},
		{{"d", "sqz:gone"}},
	} {
		link, err := Parse(event(tags...), selfHosts)
		if err != nil {
			t.Fatalf("revocation should parse, got %v", err)
		}
		if !link.Revoked {
			t.Error("expected Revoked")
		}
		if link.Resolvable(time.Now()) {
			t.Error("revoked link must not resolve")
		}
	}
}

func TestParseExpiration(t *testing.T) {
	past := time.Now().Add(-time.Hour).Unix()
	link, err := Parse(event(
		nostr.Tag{"d", "sqz:old"},
		nostr.Tag{"r", "https://example.com"},
		nostr.Tag{"expiration", strconv.FormatInt(past, 10)},
	), selfHosts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !link.Expired(time.Now()) {
		t.Error("expected expired")
	}
	if link.Resolvable(time.Now()) {
		t.Error("expired link must not resolve")
	}
}

func TestParseRejectsBadEvents(t *testing.T) {
	tests := []struct {
		name string
		evt  *nostr.Event
		want error
	}{
		{
			name: "wrong kind",
			evt:  &nostr.Event{Kind: 1, Tags: nostr.Tags{{"d", "sqz:x"}, {"r", "https://example.com"}}},
			want: ErrWrongKind,
		},
		{
			name: "another app's kind 30078 event",
			evt:  event(nostr.Tag{"d", "some-other-app"}, nostr.Tag{"r", "https://example.com"}),
			want: ErrNotSqzLink,
		},
		{
			name: "empty slug",
			evt:  event(nostr.Tag{"d", "sqz:"}, nostr.Tag{"r", "https://example.com"}),
			want: ErrSlugEmpty,
		},
		{
			name: "slug with slash would forge path structure",
			evt:  event(nostr.Tag{"d", "sqz:a/b"}, nostr.Tag{"r", "https://example.com"}),
			want: ErrSlugCharset,
		},
		{
			name: "slug with percent encoding",
			evt:  event(nostr.Tag{"d", "sqz:a%2fb"}, nostr.Tag{"r", "https://example.com"}),
			want: ErrSlugCharset,
		},
		{
			name: "reserved slug shadows sqz route",
			evt:  event(nostr.Tag{"d", "sqz:api"}, nostr.Tag{"r", "https://example.com"}),
			want: ErrSlugReserved,
		},
		{
			name: "path traversal slug",
			evt:  event(nostr.Tag{"d", "sqz:.."}, nostr.Tag{"r", "https://example.com"}),
			want: ErrSlugCharset,
		},
		// Must fail closed: silently ignoring an unparseable expiration would
		// turn "expires soon" into "never expires".
		{
			name: "malformed expiration",
			evt:  event(nostr.Tag{"d", "sqz:x"}, nostr.Tag{"r", "https://example.com"}, nostr.Tag{"expiration", "not-a-number"}),
			want: ErrExpirationMalformed,
		},
		{
			name: "negative expiration",
			evt:  event(nostr.Tag{"d", "sqz:x"}, nostr.Tag{"r", "https://example.com"}, nostr.Tag{"expiration", "-1"}),
			want: ErrExpirationMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(tt.evt, selfHosts); !errors.Is(err, tt.want) {
				t.Errorf("got %v, want %v", err, tt.want)
			}
		})
	}
}

// sqz puts attacker-supplied data straight into a Location header, so this is
// the security boundary of the whole redirect path.
func TestValidateDestinationRejectsDangerousSchemes(t *testing.T) {
	tests := []struct {
		name, dest string
		want       error
	}{
		{"javascript xss", "javascript:alert(document.cookie)", ErrDestScheme},
		{"javascript mixed case", "JavaScript:alert(1)", ErrDestScheme},
		{"data uri", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", ErrDestScheme},
		{"file read", "file:///etc/passwd", ErrDestScheme},
		{"ftp", "ftp://example.com/x", ErrDestScheme},
		{"scheme relative", "//example.com", ErrDestScheme},
		{"no host", "https://", ErrDestMalformed},
		{"empty", "", ErrNoDestination},
		{"redirect loop", "https://sqz.link/@a/b", ErrDestLoop},
		{"redirect loop case insensitive", "https://SQZ.LINK/@a/b", ErrDestLoop},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateDestination(tt.dest, selfHosts); !errors.Is(err, tt.want) {
				t.Errorf("dest %q: got %v, want %v", tt.dest, err, tt.want)
			}
		})
	}
}

func TestValidateDestinationAcceptsNormalURLs(t *testing.T) {
	for _, dest := range []string{
		"https://example.com",
		"http://example.com/path?query=1#frag",
		"https://sub.example.co.uk:8443/a",
		"https://example.com/unicode/é",
	} {
		if err := ValidateDestination(dest, selfHosts); err != nil {
			t.Errorf("dest %q: unexpected error %v", dest, err)
		}
	}
}

func TestValidateDestinationLength(t *testing.T) {
	long := "https://example.com/" + string(make([]byte, MaxDestinationLen))
	if err := ValidateDestination(long, selfHosts); !errors.Is(err, ErrDestTooLong) {
		t.Errorf("got %v, want ErrDestTooLong", err)
	}
}

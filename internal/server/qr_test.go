package server

import (
	"strings"
	"testing"
)

// The endpoint must stay a Lightning-invoice renderer, not a general QR
// service that will encode anything a caller sends.
func TestValidateInvoice(t *testing.T) {
	valid := "lnbc100n1p49685ehp50kncf9zk35xg4lxewt4974ry6mudygsztsz8qn3ar8pn3mtpe50snp4q"

	tests := []struct {
		name    string
		invoice string
		wantErr bool
	}{
		{"mainnet invoice", valid, false},
		{"uppercase invoice", strings.ToUpper(valid), false},
		{"testnet invoice", "lntb100n1p49685ehp50kncf9zk35", false},
		{"empty", "", true},
		{"not an invoice", "https://evil.example.com/phishing", true},
		{"arbitrary text", "pay me 100 dollars", true},
		{"wrong prefix", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", true},
		{"invalid charset", "lnbc100n!@#$%^&*()", true},
		{"too long", "lnbc" + strings.Repeat("a", maxInvoiceLen), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInvoice(tt.invoice)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateInvoice(%.30q) error = %v, wantErr %v", tt.invoice, err, tt.wantErr)
			}
		})
	}
}

// A QR that will not scan is worse than one that clashes with the page, so the
// rendering must stay dark-on-white regardless of theme.
func TestRenderQRSVG(t *testing.T) {
	bitmap := [][]bool{
		{true, true, false, true},
		{false, false, false, false},
		{true, false, true, true},
	}

	svg := renderQRSVG(bitmap)

	for _, want := range []string{
		`viewBox="0 0 4 3"`,
		`fill="#ffffff"`,
		`fill="#000000"`,
		`shape-rendering="crispEdges"`,
	} {
		if !strings.Contains(svg, want) {
			t.Errorf("svg missing %q", want)
		}
	}

	// Horizontal runs must merge: row 0 is [XX.X], which is two rects, not three.
	if got := strings.Count(svg, "<rect"); got != 1+4 {
		t.Errorf("rect count = %d, want 5 (1 background + 4 merged runs); runs are not merging", got)
	}
	if !strings.Contains(svg, `<rect x="0" y="0" width="2" height="1"/>`) {
		t.Error("expected the two adjacent modules in row 0 to merge into one rect")
	}

	if strings.Contains(renderQRSVG(nil), "<svg") {
		t.Error("empty bitmap should not produce an svg")
	}
}

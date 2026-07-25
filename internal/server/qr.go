package server

import (
	"fmt"
	"net/http"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// maxInvoiceLen bounds what we will encode. Real BOLT11 invoices sit well
// under this; the cap stops a caller pushing arbitrary bulk through the
// encoder.
const maxInvoiceLen = 2048

// bolt11Prefixes are the human-readable parts BOLT11 defines per network.
var bolt11Prefixes = []string{"lnbc", "lntb", "lnbcrt", "lntbs", "lnsb"}

// handleQR renders a Lightning invoice as an SVG QR code.
//
// This exists because paying and signing are different acts on different
// devices. The nostr extension signs the link on the desktop; the invoice is
// usually paid from a phone. Without a QR the only route is a `lightning:`
// link, which assumes a wallet on the same machine.
//
// Public and unpaywalled by necessity — it renders the very invoice that the
// paywall is asking the user to settle.
func (s *Server) handleQR(w http.ResponseWriter, r *http.Request) {
	invoice := strings.TrimSpace(r.URL.Query().Get("invoice"))

	if err := validateInvoice(invoice); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Medium recovery is the usual choice for payment QRs: enough redundancy
	// to survive a scuffed screen without inflating the module count, which
	// would make it harder to scan at small sizes.
	code, err := qrcode.New(strings.ToUpper(invoice), qrcode.Medium)
	if err != nil {
		s.log.Error("encode qr", "err", err)
		writeError(w, http.StatusInternalServerError, "could not encode invoice")
		return
	}

	svg := renderQRSVG(code.Bitmap())

	// Invoices are single-use, so this must never be cached by a proxy or the
	// browser — a stale QR would send someone's sats to an already-settled
	// invoice.
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	_, _ = w.Write([]byte(svg))
}

// validateInvoice keeps this endpoint a Lightning-invoice renderer rather than
// a general-purpose QR service for arbitrary attacker-supplied content.
func validateInvoice(invoice string) error {
	if invoice == "" {
		return fmt.Errorf("missing invoice")
	}
	if len(invoice) > maxInvoiceLen {
		return fmt.Errorf("invoice too long")
	}

	lower := strings.ToLower(invoice)
	ok := false
	for _, p := range bolt11Prefixes {
		if strings.HasPrefix(lower, p) {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("not a BOLT11 invoice")
	}

	// bech32 is alphanumeric only; anything else means this is not an invoice.
	for _, c := range lower {
		isDigit := c >= '0' && c <= '9'
		isAlpha := c >= 'a' && c <= 'z'
		if !isDigit && !isAlpha {
			return fmt.Errorf("invoice contains invalid characters")
		}
	}
	return nil
}

// renderQRSVG turns a module bitmap into an SVG.
//
// Horizontal runs are merged into single rects rather than emitting one rect
// per module, which cuts the output several-fold for a payment-sized code.
//
// Colours are deliberately hard-coded dark-on-white rather than themed. An
// inverted QR fails on some scanners, and a payment code that will not scan is
// worse than one that clashes with the page.
func renderQRSVG(bitmap [][]bool) string {
	rows := len(bitmap)
	if rows == 0 || len(bitmap[0]) == 0 {
		return ""
	}
	// Width is taken from the rows themselves rather than assumed equal to the
	// row count. QR bitmaps are square in practice, but deriving both
	// dimensions from len(bitmap) would silently drop columns if that ever
	// stopped being true.
	cols := len(bitmap[0])

	var b strings.Builder
	fmt.Fprintf(&b,
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" aria-label="Lightning invoice QR code">`,
		cols, rows)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#ffffff"/>`, cols, rows)
	b.WriteString(`<g fill="#000000">`)

	for y, row := range bitmap {
		x := 0
		for x < len(row) {
			if !row[x] {
				x++
				continue
			}
			run := x
			for run < len(row) && row[run] {
				run++
			}
			fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="1"/>`, x, y, run-x)
			x = run
		}
	}

	b.WriteString(`</g></svg>`)
	return b.String()
}

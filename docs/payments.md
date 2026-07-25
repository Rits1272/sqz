# Payments: the Authorization-header collision

## What works today

With a real Lightning address configured (`LNURL_ADDRESS`) and `l402_dry_run
off`, the paywall issues genuine, payable invoices. Verified end-to-end against
a live mainnet address:

- `POST /api/links` with **no** `Authorization` header →
  `402 Payment Required` with `WWW-Authenticate: L402 macaroon="…" invoice="lnbc100n…"`.
- The invoice is a real mainnet 10-sat invoice (`lnbc100n`) payable to the
  configured address; `/api/qr` renders it for scanning.
- The macaroon is bound to `RequestPath = /api/links` and `RequestMethod = POST`.

So the money side is real. The blocker is not payment — it is identity.

## The collision

sqz needs **two** things on a link-creation request:

1. **Payment** — the L402 module reads the `Authorization` header for an
   `L402 <macaroon>:<preimage>` credential.
2. **Identity** — sqzd reads the `Authorization` header for a NIP-98
   `Nostr <base64-event>` credential, to learn *who* is creating the link and to
   enforce that the link event is signed by that same key.

Both want the same header. Proven empirically in real mode:

| Request | Result |
|---|---|
| No `Authorization` | `402` + invoice (L402 challenge — correct) |
| `Authorization: Nostr …` (NIP-98) | **`401`** — the L402 module rejects it as a malformed L402 credential, before the 402 handshake can begin |

In dry-run this never surfaced: dry-run makes the L402 module pass every request
through untouched, so `Authorization: Nostr` reached sqzd and NIP-98 worked. Turn
dry-run off and the two layers fight over the header.

## Why LNURL alone can't paper over it

`l402_auto_detect_payment on` is meant to let the client omit the preimage and
have the module confirm settlement node-side. But a static Lightning address
(`LN_CLIENT_TYPE=LNURL`) gives the module **no node** to query — it only knows
how to *mint* an invoice via the payee's LNURL callback, not to check whether one
was paid. So with LNURL the only completion path is the classic
preimage-in-header flow, which is exactly the path that collides with NIP-98.

## The fix (two parts)

**1. Move NIP-98 off `Authorization`.** Have the client send NIP-98 in a custom
header (`X-Nostr-Authorization`) and let `Authorization` belong to L402. This
keeps every NIP-98 property (identity, request binding, replay protection) and
just relocates it. sqz controls both ends, so the non-standard header is safe.
nginx forwards the custom header upstream untouched.

**2. Add a WebLN payment loop.** On a `402`, the frontend:
   - reads the invoice from `WWW-Authenticate`,
   - pays it with `window.webln.sendPayment(invoice)`, which returns the
     `preimage`,
   - retries the request with `Authorization: L402 <macaroon>:<preimage>` plus
     the NIP-98 event in `X-Nostr-Authorization`.

Alby provides *both* nostr signing and WebLN payment, so for the target audience
this is one approve-in-extension step. The QR (already built) plus manual
preimage entry is the fallback for wallets without WebLN.

### Cleaner alternative for non-WebLN wallets

Switch `LN_CLIENT_TYPE` from `LNURL` to `NWC` with a Nostr Wallet Connect string
(Primal issues these). NWC gives the module a real settlement-lookup channel, so
`l402_auto_detect_payment` works and the client never has to surface a preimage —
it just pays the invoice by any means and retries. This removes the WebLN
dependency at the cost of holding an NWC connection secret server-side.

## Current state — resolved and live

Both parts landed. `/api/links` runs with `l402_dry_run off` and a real
`LNURL_ADDRESS`. NIP-98 moved to `X-Nostr-Authorization`
(server reads it, preferring it over Authorization; frontend sends it there),
and the frontend settles the L402 challenge inline via WebLN with a manual
preimage fallback.

Verified against the live module:

| Check | Result |
|---|---|
| Properly-formed create (NIP-98 in `X-Nostr-Authorization`, no L402) | `402` + real 10-sat invoice (was `401` before the fix) |
| Frontend WebLN loop | retry carries **both** `X-Nostr-Authorization` and `Authorization: L402 …` → `200` |
| Frontend manual fallback | invoice + QR shown; preimage entry fires the same retry |
| Bogus preimage | rejected at the paywall (`401`), not passed through — confirms stateless preimage verification |

Not yet exercised: a **real 10-sat settlement**. That needs a human paying the
invoice with a wallet (Alby/WebLN completes it in one step; any wallet works via
the preimage fallback). Everything up to the sats leaving a wallet is verified.

To return to a free demo mode: set `l402_dry_run on` and
`docker compose -p sqz up -d --force-recreate nginx`.

## Deploy note

`nginx/nginx.conf` is bind-mounted as a single file. `rsync` replaces it by
inode, so a plain `docker compose up -d` keeps serving the **old** config. After
changing it, force a rebind:

    docker compose -p sqz up -d --force-recreate nginx

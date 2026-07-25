/* sqz — receipt terminal.
 *
 * Signing happens entirely in the user's NIP-07 extension — this page never
 * sees a private key, and never asks for one. Every authenticated request
 * carries a fresh NIP-98 event bound to that exact URL, method, and body.
 *
 * Protocol logic (bech32, NIP-98, request shapes) is carried over verbatim
 * from the verified reference implementation.
 */

const KIND_HTTP_AUTH = 27235;
const KIND_LINK = 30078;
const SLUG_PREFIX = "sqz:";
const PRICE_SATS = 10;

const el = (id) => document.getElementById(id);

const ui = {
  signin: el("signin"),
  signout: el("signout"),
  cust: el("cust"),
  stampTime: el("stamp-time"),
  form: el("form"),
  url: el("url"),
  urlCount: el("url-count"),
  slug: el("slug"),
  slugPrefix: el("slug-prefix"),
  print: el("print"),
  notice: el("notice"),
  result: el("result"),
  resultUrl: el("result-url"),
  resultNote: el("result-note"),
  copy: el("copy"),
  invoice: el("invoice"),
  invoiceCode: el("invoice-code"),
  invoiceOpen: el("invoice-open"),
  invoiceCopy: el("invoice-copy"),
  ledger: el("ledger"),
  emptyState: el("empty-state"),
  totals: el("totals"),
  tItems: el("t-items"),
  tClicks: el("t-clicks"),
  tVoid: el("t-void"),
  tPaid: el("t-paid"),
  barcode: el("barcode"),
  footCode: el("foot-code"),
};

const state = {
  baseUrl: window.location.origin,
  pubkey: null,
  npub: null,
};

/* ------------------------------------------------------------------ util */

function say(message, kind = "info") {
  ui.notice.textContent = message;
  ui.notice.hidden = false;
  ui.notice.dataset.kind = kind;
}

function clearNotice() {
  ui.notice.hidden = true;
}

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function shortKey(npub) {
  return npub ? `${npub.slice(0, 9)}…${npub.slice(-4)}` : "";
}

function stampTime(date = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${p(date.getMonth() + 1)}-${p(date.getDate())} ` +
         `${p(date.getHours())}:${p(date.getMinutes())}`;
}

/* Derive a slug when the user doesn't name one. Short, unambiguous, and
   avoids look-alike characters so a slug read aloud or copied by hand
   survives the trip. */
function autoSlug() {
  const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(7));
  return [...bytes].map((b) => alphabet[b % alphabet.length]).join("");
}

/* ------------------------------------------------------------- identity */

async function connect() {
  if (!window.nostr) {
    say(
      "No nostr extension found. Install Alby or nos2x, then reload this page — sqz never asks for your private key.",
      "error",
    );
    return;
  }

  try {
    state.pubkey = await window.nostr.getPublicKey();
  } catch {
    say("Sign-in cancelled. Approve the request in your extension to continue.", "error");
    return;
  }

  state.npub = await encodeNpub(state.pubkey);
  ui.cust.textContent = shortKey(state.npub);
  ui.signin.hidden = true;
  ui.signout.hidden = false;
  ui.slugPrefix.textContent = `${shortKey(state.npub)}/`;
  ui.footCode.textContent = state.npub;
  drawBarcode(state.pubkey);
  clearNotice();

  sessionStorage.setItem("sqz.connected", "1");
  await loadLinks();
}

function disconnect() {
  state.pubkey = null;
  state.npub = null;
  ui.cust.textContent = "not signed in";
  ui.signin.hidden = false;
  ui.signout.hidden = true;
  ui.slugPrefix.textContent = "sqz/";
  ui.footCode.textContent = "npub —";
  drawBarcode("");
  ui.totals.hidden = true;
  ui.result.hidden = true;
  ui.invoice.hidden = true;
  renderLedger([]);
  sessionStorage.removeItem("sqz.connected");
  say("Signed out. Your links stay on the relays — nothing here was deleted.");
}

/* bech32 npub encoding. Implemented here rather than pulled from a library so
   the page ships with no dependencies and no CDN. */
async function encodeNpub(hex) {
  const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const bytes = hex.match(/../g).map((h) => parseInt(h, 16));

  // 8-bit groups -> 5-bit groups.
  let acc = 0, bits = 0;
  const words = [];
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      words.push((acc >> bits) & 31);
    }
  }
  if (bits > 0) words.push((acc << (5 - bits)) & 31);

  const polymod = (values) => {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
      const top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk;
  };

  const hrp = "npub";
  const expanded = [
    ...[...hrp].map((c) => c.charCodeAt(0) >> 5),
    0,
    ...[...hrp].map((c) => c.charCodeAt(0) & 31),
  ];
  const checksum = polymod([...expanded, ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
  const check = [];
  for (let i = 0; i < 6; i++) check.push((checksum >> (5 * (5 - i))) & 31);

  return `${hrp}1${[...words, ...check].map((w) => CHARSET[w]).join("")}`;
}

/* -------------------------------------------------------------- signing */

/* Build the NIP-98 Authorization header for one specific request. The event
   names the absolute URL and method, so it authorizes that call and nothing
   else. */
async function authHeader(method, path, body) {
  const tags = [
    ["u", state.baseUrl + path],
    ["method", method],
  ];
  if (body) tags.push(["payload", await sha256Hex(body)]);

  const signed = await window.nostr.signEvent({
    kind: KIND_HTTP_AUTH,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: "",
  });

  return "Nostr " + btoa(JSON.stringify(signed));
}

async function signLinkEvent(slug, destination, title) {
  const tags = [
    ["d", SLUG_PREFIX + slug],
    ["r", destination],
  ];
  if (title) tags.push(["title", title]);

  return window.nostr.signEvent({
    kind: KIND_LINK,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: "",
  });
}

/* ------------------------------------------------------------- requests */

async function createLink(event) {
  const body = JSON.stringify({ event });
  const header = await authHeader("POST", "/api/links", body);

  const res = await fetch("/api/links", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: header },
    body,
  });

  // The paywall answers before the app ever sees the request.
  if (res.status === 402) {
    showInvoice(res.headers.get("WWW-Authenticate"));
    throw new Error("payment required");
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

async function loadLinks() {
  if (!state.pubkey) return;

  try {
    const header = await authHeader("GET", "/api/links", null);
    const res = await fetch("/api/links", { headers: { Authorization: header } });
    if (!res.ok) return;

    const { links = [] } = await res.json();
    renderLedger(links);
  } catch {
    // A failed listing should never block the page from working.
  }
}

function showInvoice(wwwAuthenticate) {
  const match = /invoice="([^"]+)"/.exec(wwwAuthenticate || "");
  if (!match) {
    say("The till asked for payment but returned no invoice. Check the paywall configuration.", "error");
    return;
  }
  const invoice = match[1];
  ui.invoiceCode.textContent = invoice;
  ui.invoiceOpen.href = `lightning:${invoice}`;
  ui.invoice.hidden = false;
  ui.invoice.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

/* --------------------------------------------------------------- render */

function renderLedger(links) {
  const live = links.filter((l) => l.destination);

  if (!links.length) {
    ui.ledger.replaceChildren(ui.emptyState);
    ui.emptyState.innerHTML = state.pubkey
      ? "Nothing on the tape yet.<br>Paste a destination and print your first link."
      : "Nothing on the tape yet.<br>Sign in, paste a destination, print your first link.";
    ui.totals.hidden = true;
    return;
  }

  links.sort((a, b) => b.created_at - a.created_at);
  ui.ledger.replaceChildren(...links.map(renderItem));

  const clicks = links.reduce((n, l) => n + (l.clicks || 0), 0);
  ui.tItems.textContent = live.length;
  ui.tClicks.textContent = clicks;
  ui.tVoid.textContent = links.length - live.length;
  ui.tPaid.textContent = `${links.length * PRICE_SATS} sat`;
  ui.totals.hidden = false;
}

function renderItem(link) {
  const voided = !link.destination;

  const item = document.createElement("article");
  item.className = "item" + (voided ? " item-void" : "");

  const head = document.createElement("div");
  head.className = "item-head";

  const slug = document.createElement("a");
  slug.className = "item-slug";
  slug.href = link.short_url;
  slug.rel = "noopener";
  slug.textContent = "/" + link.slug;

  const dots = document.createElement("span");
  dots.className = "dots";
  dots.setAttribute("aria-hidden", "true");

  const qty = document.createElement("span");
  qty.className = "item-qty";
  const clicks = link.clicks || 0;
  qty.innerHTML = `${clicks} <span>${clicks === 1 ? "click" : "clicks"}</span>`;

  head.append(slug, dots, qty);

  const dest = document.createElement("p");
  dest.className = "item-dest";
  dest.textContent = voided ? "destination cleared" : link.destination;

  const foot = document.createElement("div");
  foot.className = "item-foot";

  const date = document.createElement("span");
  date.className = "item-date";
  date.textContent = link.created_at ? stampTime(new Date(link.created_at * 1000)) : "";

  foot.append(date);

  if (voided) {
    const mark = document.createElement("span");
    mark.className = "voided";
    mark.textContent = "Void";
    foot.append(mark);
  } else {
    const copy = document.createElement("button");
    copy.className = "item-act";
    copy.type = "button";
    copy.textContent = "Copy";
    copy.setAttribute("aria-label", `Copy short link for /${link.slug}`);
    copy.addEventListener("click", async () => {
      await navigator.clipboard.writeText(link.short_url);
      copy.textContent = "Copied";
      setTimeout(() => (copy.textContent = "Copy"), 1400);
    });

    const revoke = document.createElement("button");
    revoke.className = "item-act";
    revoke.type = "button";
    revoke.textContent = "Void";
    revoke.setAttribute("aria-label", `Void /${link.slug}`);
    revoke.addEventListener("click", () => revokeLink(link.slug, revoke));

    foot.append(copy, revoke);
  }

  item.append(head, dest, foot);
  return item;
}

/* Revocation republishes the same coordinate with an empty destination.
   The event stays on relays — that is how the revocation propagates. */
async function revokeLink(slug, button) {
  button.disabled = true;
  button.textContent = "Voiding";

  try {
    const event = await signLinkEvent(slug, "", "");
    await createLink(event);
    await loadLinks();
    say(`Voided /${slug}. It no longer resolves.`);
  } catch (err) {
    button.disabled = false;
    button.textContent = "Void";
    if (err.message !== "payment required") say(err.message, "error");
  }
}

/* A barcode struck from the pubkey. It encodes nothing a scanner wants —
   it is the same key, drawn as bars, so the receipt carries its own mark. */
function drawBarcode(hex) {
  const source = hex || "sqz00000000000000";
  const bars = [];
  for (let i = 0; i < 44; i++) {
    const v = parseInt(source[i % source.length], 36) || 1;
    const bar = document.createElement("i");
    bar.style.width = `${1 + (v % 3)}px`;
    bar.style.height = `${58 + (v % 5) * 8}%`;
    bars.push(bar);
  }
  ui.barcode.replaceChildren(...bars);
}

/* ---------------------------------------------------------------- events */

ui.url.addEventListener("input", () => {
  ui.urlCount.textContent = ui.url.value.trim().length;
});

ui.signin.addEventListener("click", connect);
ui.signout.addEventListener("click", disconnect);

ui.form.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearNotice();
  ui.invoice.hidden = true;

  if (!state.pubkey) {
    await connect();
    if (!state.pubkey) return;
  }

  const destination = ui.url.value.trim();
  const slug = (ui.slug.value.trim() || autoSlug()).toLowerCase();

  ui.print.disabled = true;
  const label = ui.print.querySelector(".btn-print-label");
  label.textContent = "Signing";

  try {
    const event = await signLinkEvent(slug, destination, "");
    const data = await createLink(event);
    showResult(destination, data.short_url);
    ui.slug.value = "";
    await loadLinks();
  } catch (err) {
    if (err.message !== "payment required") {
      say(err.message || "That link could not be printed. Check the destination and try again.", "error");
    }
  } finally {
    ui.print.disabled = false;
    label.textContent = "Print link";
  }
});

function showResult(destination, shortUrl) {
  const before = destination.length;
  const after = shortUrl.length;

  ui.resultUrl.href = shortUrl;
  ui.resultUrl.textContent = shortUrl.replace(/^https?:\/\//, "");
  ui.resultNote.textContent =
    `${before} characters in · ${after} out · ${PRICE_SATS} sat · ${stampTime()}`;
  ui.result.hidden = false;
}

ui.copy.addEventListener("click", async () => {
  await navigator.clipboard.writeText(ui.resultUrl.href);
  ui.copy.textContent = "Copied";
  setTimeout(() => (ui.copy.textContent = "Copy"), 1400);
});

ui.invoiceCopy.addEventListener("click", async () => {
  await navigator.clipboard.writeText(ui.invoiceCode.textContent);
  ui.invoiceCopy.textContent = "Copied";
  setTimeout(() => (ui.invoiceCopy.textContent = "Copy invoice"), 1400);
});

/* ------------------------------------------------------------------ boot */

(async function boot() {
  ui.stampTime.textContent = stampTime();
  drawBarcode("");

  try {
    const res = await fetch("/api/config");
    if (res.ok) {
      const cfg = await res.json();
      // NIP-98 binds signatures to the origin the SERVER verifies against, not
      // the one the browser happens to be on. A mismatch fails every signature,
      // so take the server's word for it.
      if (cfg.base_url) state.baseUrl = cfg.base_url.replace(/\/$/, "");
    }
  } catch {
    // Fall back to window.location.origin.
  }

  if (!window.nostr) {
    say("No nostr extension found. Install Alby or nos2x, then reload this page.", "error");
  }

  // Reconnect silently if the extension already granted access this session.
  if (sessionStorage.getItem("sqz.connected") && window.nostr) {
    connect().catch(() => {});
  }
})();

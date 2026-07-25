/* sqz web app — "signal".
 *
 * Protocol logic (bech32 npub, NIP-98 auth, event signing) is carried over
 * unchanged from the reference build. Signing happens entirely in the user's
 * NIP-07 extension — this page never sees a private key and never asks for one.
 *
 * The presentation layer is one idea: a string is drawn as individual character
 * boxes, so collapsing their widths physically pulls the string shorter. The
 * compression is not illustrated, it is performed.
 */

const KIND_HTTP_AUTH = 27235;
const KIND_LINK = 30078;
const SLUG_PREFIX = "sqz:";

/* Reference width for the gauge. Long enough that a typical tracking-laden
   URL nearly fills the rail, so the retraction reads. */
const RAIL_CHARS = 180;
const MAX_CHARS = 220;

const el = (id) => document.getElementById(id);

const ui = {
  signin: el("signin"),
  signout: el("signout"),
  identity: el("identity"),
  identityKey: el("identity-key"),
  form: el("form"),
  url: el("url"),
  slug: el("slug"),
  slugPrefix: el("slug-prefix"),
  squeeze: el("squeeze"),
  price: el("price"),
  strip: el("strip"),
  stripIn: el("strip-in"),
  stripOut: el("strip-out"),
  stageTag: el("stage-tag"),
  gaugeFill: el("gauge-fill"),
  gaugeRail: document.querySelector(".gauge-rail"),
  countIn: el("count-in"),
  countOut: el("count-out"),
  countRatio: el("count-ratio"),
  landed: el("landed"),
  resultUrl: el("result-url"),
  copy: el("copy"),
  notice: el("notice"),
  invoice: el("invoice"),
  invoiceCode: el("invoice-code"),
  invoiceOpen: el("invoice-open"),
  invoiceCopy: el("invoice-copy"),
  ledger: el("ledger"),
  ledgerBody: el("ledger-body"),
};

const state = {
  baseUrl: window.location.origin,
  pubkey: null,
  npub: null,
  demo: true,
  busy: false,
};

const stillness = window.matchMedia("(prefers-reduced-motion: reduce)");
const still = () => stillness.matches;

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
  return npub ? `${npub.slice(0, 10)}…${npub.slice(-4)}` : "";
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

/* The stage's one-word status. It names what has happened to the string
   below it, not what the page is doing. */
function setTag(text, kind = "idle") {
  ui.stageTag.textContent = text;
  ui.stageTag.dataset.state = kind;
}

/* Derive a slug when the user doesn't name one. Short, unambiguous, and
   avoids look-alike characters so a slug read aloud or copied by hand
   survives the trip. */
function autoSlug() {
  const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(7));
  return [...bytes].map((b) => alphabet[b % alphabet.length]).join("");
}

/* -------------------------------------------------------------- the strip
 *
 * One character per element. Widths are what animate; the browser's own
 * reflow does the rest.
 */

function paint(node, text, { hidden = false } = {}) {
  if (still()) {
    node.textContent = text;
    return [];
  }
  const chars = [...text.slice(0, MAX_CHARS)];
  const spans = chars.map((c) => {
    const s = document.createElement("span");
    s.className = hidden ? "ch hidden" : "ch";
    s.textContent = c === " " ? " " : c;
    return s;
  });
  node.replaceChildren(...spans);
  return spans;
}

/* Collapse from the tail inwards, so the string retracts toward its origin
   rather than dissolving in place. */
function collapse(node) {
  const spans = [...node.querySelectorAll(".ch")];
  if (still() || !spans.length) {
    node.replaceChildren();
    return Promise.resolve();
  }
  const n = spans.length;
  const step = Math.min(5, 340 / n);
  spans.forEach((s, i) => {
    s.style.transitionDelay = `${(n - 1 - i) * step}ms`;
  });
  // Force layout so the delayed transitions actually run.
  void node.offsetWidth;
  spans.forEach((s) => s.classList.add("gone"));
  return wait((n - 1) * step + 360);
}

/* Emit outward from the same origin. */
function emit(node, text) {
  const spans = paint(node, text, { hidden: true });
  if (still() || !spans.length) return Promise.resolve();

  const m = spans.length;
  const step = Math.min(16, 300 / m);
  spans.forEach((s, i) => {
    s.style.transitionDelay = `${i * step}ms`;
  });
  void node.offsetWidth;
  spans.forEach((s) => s.classList.remove("hidden"));
  return wait((m - 1) * step + 360);
}

function railPct(len) {
  return Math.min(100, Math.max(1.5, (len / RAIL_CHARS) * 100));
}

/* Tick a number toward a target. Purposeful: it is the measurement changing,
   not decoration. */
function tickTo(node, from, to, ms) {
  if (still() || from === to) {
    node.textContent = to;
    return;
  }
  const t0 = performance.now();
  const frame = (t) => {
    const p = Math.min(1, (t - t0) / ms);
    const eased = 1 - Math.pow(1 - p, 3);
    node.textContent = Math.round(from + (to - from) * eased);
    if (p < 1) requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}

/* The one orchestrated moment: long in, short out, same place. */
async function compress(longText, shortText, { demo = false } = {}) {
  const before = longText.length;
  const after = shortText.length;

  ui.strip.dataset.state = "running";
  ui.strip.dataset.dim = demo ? "1" : "0";
  ui.landed.hidden = true;
  setTag(demo ? "Example" : "Compressing");

  if (still()) {
    paint(ui.stripIn, longText);
    paint(ui.stripOut, shortText);
  } else {
    ui.stripOut.replaceChildren();
    await collapse(ui.stripIn);
    ui.gaugeFill.style.width = `${railPct(after)}%`;
    ui.gaugeRail.dataset.done = "1";
    tickTo(ui.countOut, 0, after, 420);
    await emit(ui.stripOut, shortText);
  }

  ui.countIn.textContent = before;
  ui.countOut.textContent = after;
  ui.gaugeFill.style.width = `${railPct(after)}%`;
  ui.gaugeRail.dataset.done = "1";
  ui.countRatio.textContent =
    after && before / after > 1 ? `${(before / after).toFixed(1)}× shorter` : "";
  ui.strip.dataset.state = demo ? "demo-done" : "done";
  setTag(demo ? "Example" : "Signed and published", demo ? "idle" : "done");
}

/* Live mirror while typing. */
function mirror() {
  const text = ui.url.value.trim();

  if (state.demo && text) leaveDemo();
  if (state.busy) return;

  if (state.demo) return;

  ui.strip.dataset.state = text ? "armed" : "idle";
  // Empty is still a state worth drawing: the stage holds the shape of a URL
  // so the space never reads as a hole.
  ui.strip.dataset.dim = text ? "0" : "1";
  ui.gaugeRail.dataset.done = "0";
  ui.stripOut.replaceChildren();
  ui.landed.hidden = true;
  setTag(text ? "Not signed yet" : "Paste a destination below");

  paint(ui.stripIn, text || "https://");
  ui.countIn.textContent = text.length;
  ui.countOut.textContent = "—";
  ui.countRatio.textContent = "";
  ui.gaugeFill.style.width = `${text.length ? railPct(text.length) : 0}%`;
}

function leaveDemo() {
  state.demo = false;
  ui.stripIn.replaceChildren();
  ui.stripOut.replaceChildren();
}

/* ------------------------------------------------------------- identity */

async function connect() {
  if (!window.nostr) {
    say(
      "No nostr extension found. Install Alby or nos2x, then reload — sqz signs through the extension and never asks for your key.",
      "error",
    );
    return;
  }

  try {
    state.pubkey = await window.nostr.getPublicKey();
  } catch {
    say("Connection cancelled. Approve the request in your extension to continue.", "error");
    return;
  }

  state.npub = await encodeNpub(state.pubkey);
  ui.identityKey.textContent = shortKey(state.npub);
  ui.identity.hidden = false;
  ui.signin.hidden = true;
  ui.slugPrefix.textContent = `${shortKey(state.npub)}/`;
  clearNotice();

  sessionStorage.setItem("sqz.connected", "1");
  await loadLinks();
}

function disconnect() {
  state.pubkey = null;
  state.npub = null;
  ui.identity.hidden = true;
  ui.signin.hidden = false;
  ui.ledger.hidden = true;
  ui.slugPrefix.textContent = "sqz.link/";
  sessionStorage.removeItem("sqz.connected");
  say("Disconnected. Your links stay on the relays.");
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
    say("Payment required, but the server returned no invoice. Check the paywall configuration.", "error");
    return;
  }
  const invoice = match[1];
  ui.invoiceCode.textContent = invoice;
  ui.invoiceOpen.href = `lightning:${invoice}`;
  ui.invoice.hidden = false;
  ui.invoice.scrollIntoView({
    behavior: still() ? "auto" : "smooth",
    block: "nearest",
  });
}

/* --------------------------------------------------------------- render */

function renderLedger(links) {
  ui.ledger.hidden = false;

  if (!links.length) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = "No links yet. Paste a destination above and compress it.";
    ui.ledgerBody.replaceChildren(p);
    return;
  }

  links.sort((a, b) => b.created_at - a.created_at);
  ui.ledgerBody.replaceChildren(...links.map(renderRow));
}

function renderRow(link) {
  const row = document.createElement("div");
  row.className = "row";

  const main = document.createElement("div");
  main.className = "row-main";

  const slug = document.createElement("a");
  slug.className = "row-slug";
  slug.href = link.short_url;
  slug.textContent = "/" + link.slug;
  slug.rel = "noopener";

  const dest = document.createElement("span");
  dest.className = "row-dest";
  dest.textContent = link.destination || "revoked — no destination";

  main.append(slug, dest);

  const clicks = document.createElement("span");
  clicks.className = "row-clicks";
  const n = document.createTextNode(`${link.clicks} `);
  const word = document.createElement("span");
  word.textContent = link.clicks === 1 ? "click" : "clicks";
  clicks.append(n, word);

  const revoke = document.createElement("button");
  revoke.className = "row-act";
  revoke.type = "button";
  revoke.textContent = "Revoke";
  revoke.addEventListener("click", () => revokeLink(link.slug, revoke));

  row.append(main, clicks, revoke);
  return row;
}

/* Revocation republishes the same coordinate with an empty destination.
   The event stays on relays — that is how the revocation propagates. */
async function revokeLink(slug, button) {
  button.disabled = true;
  button.textContent = "Revoking";

  try {
    const event = await signLinkEvent(slug, "", "");
    await createLink(event);
    await loadLinks();
    say(`Revoked /${slug}. It no longer resolves.`, "good");
  } catch (err) {
    button.disabled = false;
    button.textContent = "Revoke";
    if (err.message !== "payment required") say(err.message, "error");
  }
}

/* ---------------------------------------------------------------- events */

/* The example holds the stage until the user actually types — focusing the
   field alone should not empty it. */
ui.url.addEventListener("input", mirror);

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

  state.busy = true;
  ui.squeeze.disabled = true;
  const label = ui.squeeze.querySelector(".btn-go-label");
  label.textContent = "Signing";

  try {
    const event = await signLinkEvent(slug, destination, "");
    label.textContent = "Publishing";
    const data = await createLink(event);

    // Animate only once the server has actually taken the link, so the
    // motion reports a fact rather than a hope.
    await compress(destination, data.short_url.replace(/^https?:\/\//, ""));

    ui.resultUrl.href = data.short_url;
    ui.resultUrl.textContent = data.short_url;
    ui.landed.hidden = false;

    say(`Published as /${slug}. It resolves now, and you can revoke it below.`, "good");
    ui.slug.value = "";
    await loadLinks();
  } catch (err) {
    if (err.message !== "payment required") {
      say(err.message || "Could not compress that link. Check the URL and try again.", "error");
    }
  } finally {
    state.busy = false;
    ui.squeeze.disabled = false;
    label.textContent = "Compress";
  }
});

ui.copy.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(ui.resultUrl.href);
    ui.copy.textContent = "Copied";
    setTimeout(() => (ui.copy.textContent = "Copy"), 1400);
  } catch {
    say("Clipboard blocked by the browser. Select the link and copy it by hand.", "error");
  }
});

ui.invoiceCopy.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(ui.invoiceCode.textContent);
    ui.invoiceCopy.textContent = "Copied";
    setTimeout(() => (ui.invoiceCopy.textContent = "Copy invoice"), 1400);
  } catch {
    say("Clipboard blocked by the browser. Select the invoice and copy it by hand.", "error");
  }
});

/* ------------------------------------------------------------------ boot */

const DEMO_LONG =
  "https://relay.example.org/notes/2024/long-form/the-case-for-user-owned-links?utm_source=newsletter&utm_campaign=q3&ref=timeline&session=8f2c19ad";
const DEMO_SHORT = "sqz.link/npub1q8s7f2v/case";

(async function boot() {
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

  // State the thesis once, before the user does anything.
  paint(ui.stripIn, DEMO_LONG);
  ui.strip.dataset.dim = "1";
  ui.strip.dataset.state = "armed";
  ui.countIn.textContent = DEMO_LONG.length;
  ui.gaugeFill.style.width = `${railPct(DEMO_LONG.length)}%`;

  if (still()) {
    await compress(DEMO_LONG, DEMO_SHORT, { demo: true });
  } else {
    await wait(620);
    if (state.demo) await compress(DEMO_LONG, DEMO_SHORT, { demo: true });
  }

  // Reconnect silently if the extension already granted access this session.
  if (sessionStorage.getItem("sqz.connected") && window.nostr) {
    connect().catch(() => {});
  }
})();

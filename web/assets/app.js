/* sqz web app.
 *
 * Signing is done by an active `signer`: either a NIP-07 extension (the key
 * stays isolated in the extension — sqz never sees it) or a key generated and
 * stored in this browser (see localkey.js — convenient but weaker, offered as an
 * explicit, backed-up alternative). Every authenticated request carries a fresh
 * NIP-98 event bound to that exact URL, method, and body.
 *
 * encodeNpub is verified against Go's reference implementation on 14 vectors
 * including the all-zero and all-ff edge cases; change it only with that rerun.
 */

const KIND_HTTP_AUTH = 27235;
const KIND_LINK = 30078;
const SLUG_PREFIX = "sqz:";

/* Reference width for the character meter. Most URLs worth shortening land
   well under this, so the bar reads as "how long is this really". */
const METER_REF = 180;

const el = (id) => document.getElementById(id);
const reduced = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const ui = {
  signin: el("signin"), signinLocal: el("signin-local"), signinGroup: el("signin-group"),
  signinImport: el("signin-import"),
  signout: el("signout"), keyBadge: el("key-badge"), backupBtn: el("backup-btn"),
  keyModal: el("keymodal"), keyModalTitle: el("keymodal-title"),
  keyModalBackup: el("keymodal-backup"), keyModalImport: el("keymodal-import"),
  nsecOut: el("nsec-out"), nsecCopy: el("nsec-copy"), backupDone: el("backup-done"),
  keyForget: el("key-forget"),
  nsecIn: el("nsec-in"), importSubmit: el("import-submit"), keyModalClose: el("keymodal-close"),
  identity: el("identity"), identityKey: el("identity-key"),
  form: el("form"), url: el("url"), slug: el("slug"), slugPrefix: el("slug-prefix"),
  slugHint: el("slug-hint"), priceAmount: el("price-amount"),
  squeeze: el("squeeze"), btnLabel: el("btn-label"), btnMeta: el("btn-meta"),
  meter: el("meter"), meterFill: el("meter-fill"), meterVal: el("meter-val"),
  result: el("result"), resultUrl: el("result-url"),
  resultRatio: el("result-ratio"), resultNote: el("result-note"),
  copy: el("copy"), notice: el("notice"),
  invoice: el("invoice"), invoiceCode: el("invoice-code"),
  qr: el("qr"), qrImg: el("qr-img"), qrStatus: el("qr-status"),
  payWebln: el("pay-webln"),
  invoiceManual: el("invoice-manual"), preimage: el("preimage"), preimageSubmit: el("preimage-submit"),
  invoiceOpen: el("invoice-open"), invoiceCopy: el("invoice-copy"),
  links: el("links"), linksBody: el("links-body"), linksCount: el("links-count"),
  footDomain: el("foot-domain"),
  analyticsBtn: el("analytics-btn"), analyticsModal: el("analytics-modal"),
  analyticsClose: el("analytics-close"),
  anClicks: el("an-clicks"), anLinks: el("an-links"), anList: el("an-list"), anEmpty: el("an-empty"),
};

const state = {
  baseUrl: window.location.origin,
  domain: window.location.host,
  pubkey: null,
  npub: null,
  signer: null,      // active signer (extension or browser key)
  signerKind: null,  // "extension" | "local"
  links: [],
};

/* A link awaiting manual payment: the request is fully signed and the invoice
   is on screen, waiting only for a preimage to complete. */
let pendingPayment = null;

/* ------------------------------------------------------------------ util */

function say(message, kind = "note") {
  ui.notice.textContent = message;
  ui.notice.dataset.kind = kind;
  ui.notice.hidden = false;
}

/* Render a notice built from trusted, static nodes. Used only for messages
   this file authors — never for anything derived from a response or user
   input, which must go through say()'s textContent path. */
function sayNodes(kind, ...nodes) {
  ui.notice.replaceChildren(...nodes);
  ui.notice.dataset.kind = kind;
  ui.notice.hidden = false;
}

function link(href, text) {
  const a = document.createElement("a");
  a.href = href;
  a.textContent = text;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  return a;
}

function clearNotice() { ui.notice.hidden = true; }

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function shortKey(npub) {
  return npub ? `${npub.slice(0, 10)}…${npub.slice(-4)}` : "";
}

/* Slug alphabet omits look-alike characters, so a name survives being read
   aloud or copied by hand. */
function neutralNamespace() {
  ui.slugPrefix.textContent = `${displayHost()}/`;
}

/* Hosts are shown without a port. A dev port is noise, and on the real domain
   there is none — either way the user is being shown where their link lives,
   not a socket address. */
function displayHost() {
  return state.domain.replace(/:\d+$/, "");
}

/* -------------------------------------------------------- microinteraction */

/* Count up to the ratio. Small, but it makes the payoff feel earned rather
   than simply printed. `done` fires once the number settles, so the landing
   beat is attached to the count instead of guessed at with a timer. */
function countUp(node, to, suffix, done, ms = 620) {
  if (reduced()) { node.textContent = to.toFixed(1) + suffix; done?.(); return; }

  const from = 1;
  const start = performance.now();
  const step = (now) => {
    const t = Math.min(1, (now - start) / ms);
    const eased = 1 - Math.pow(1 - t, 3);
    node.textContent = (from + (to - from) * eased).toFixed(1) + suffix;
    if (t < 1) requestAnimationFrame(step);
    else done?.();
  };
  requestAnimationFrame(step);
}

/* Restart a CSS animation that may already have run on this element. Removing
   the class alone is not enough — the browser coalesces it with the re-add
   unless a layout read forces the change to commit. */
function replay(node, className) {
  node.classList.remove(className);
  void node.offsetWidth;
  node.classList.add(className);
}

/* Sparks from the ratio. The one unreservedly celebratory thing on the page,
   spent only on the moment a link actually exists. */
function burst(anchor, host) {
  if (reduced()) return;

  const hostBox = host.getBoundingClientRect();
  const box = anchor.getBoundingClientRect();
  const sparks = document.createElement("div");
  sparks.className = "sparks";
  sparks.style.left = `${box.left - hostBox.left + box.width / 2}px`;
  sparks.style.top = `${box.top - hostBox.top + box.height / 2}px`;

  for (let i = 0; i < 12; i++) {
    const dot = document.createElement("i");
    dot.className = "spark";
    const angle = (i / 12) * Math.PI * 2 + Math.random() * 0.5;
    const dist = 34 + Math.random() * 40;
    dot.style.setProperty("--dx", `${Math.cos(angle) * dist}px`);
    dot.style.setProperty("--dy", `${Math.sin(angle) * dist}px`);
    dot.style.setProperty("--c", i % 3 === 0 ? "var(--amber)" : "var(--violet)");
    dot.style.animationDelay = `${i * 8}ms`;
    sparks.append(dot);
  }

  host.append(sparks);
  setTimeout(() => sparks.remove(), 1000);
}

/* A short tap on phones that support it. Silent everywhere else, and never
   used for anything the user didn't just do. */
function tap(ms = 10) {
  if (reduced()) return;
  try { navigator.vibrate?.(ms); } catch { /* unsupported or blocked */ }
}

/* Ink from the point of contact. Delegated once, so it covers buttons that
   don't exist yet (link rows, invoice actions) without any wiring. */
document.addEventListener("pointerdown", (e) => {
  if (reduced()) return;
  const btn = e.target.closest?.(".btn");
  if (!btn || btn.disabled) return;

  const box = btn.getBoundingClientRect();
  const size = Math.max(box.width, box.height) * 2.2;
  const ink = document.createElement("span");
  ink.className = "ripple";
  ink.style.width = ink.style.height = `${size}px`;
  ink.style.left = `${e.clientX - box.left}px`;
  ink.style.top = `${e.clientY - box.top}px`;
  ink.addEventListener("animationend", () => ink.remove(), { once: true });
  btn.append(ink);
});

/* The pointer carries a light: the graph paper brightens under it, and so does
   the primary action. Pointer-only — there is nothing here to miss on touch or
   by keyboard — and written straight to custom properties, so the compositor
   does the work and no layout is touched on move. */
function trackPointer() {
  if (reduced() || !window.matchMedia("(hover: hover)").matches) return;

  const root = document.documentElement;
  let x = 0, y = 0, queued = false;

  const flush = () => {
    queued = false;
    root.style.setProperty("--mx", `${x}px`);
    root.style.setProperty("--my", `${y}px`);

    // The button wants the same point in its own coordinates.
    const box = ui.squeeze.getBoundingClientRect();
    ui.squeeze.style.setProperty("--bx", `${x - box.left}px`);
    ui.squeeze.style.setProperty("--by", `${y - box.top}px`);
  };

  window.addEventListener("pointermove", (e) => {
    if (e.pointerType !== "mouse") return;
    x = e.clientX; y = e.clientY;
    root.style.setProperty("--spot-on", "1");
    if (!queued) { queued = true; requestAnimationFrame(flush); }
  }, { passive: true });

  // Light goes out when the cursor leaves the window, so a backgrounded tab
  // isn't left with a stale glow sitting wherever the pointer last was.
  root.addEventListener("pointerleave", () => root.style.setProperty("--spot-on", "0"));
  window.addEventListener("blur", () => root.style.setProperty("--spot-on", "0"));
}

/* Copy confirms in place: the control becomes its own receipt, so no toast is
   needed and focus never moves. */
function wireCopy(button, getText, idleLabel) {
  const label = button.querySelector(".copy-label") || button;
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(getText());
      label.textContent = "Copied";
      button.classList.add("is-done");
      tap();
      setTimeout(() => {
        label.textContent = idleLabel;
        button.classList.remove("is-done");
      }, 1500);
    } catch {
      // Rare (blocked clipboard permission / no user gesture). Surface it, but
      // let it clear itself — a persistent red banner over a working page reads
      // as broken.
      say("Couldn't copy automatically — select the text and copy it manually.", "error");
      setTimeout(clearNotice, 4000);
    }
  });
}

function setWaiting(on, label) {
  ui.squeeze.classList.toggle("is-waiting", on);
  ui.squeeze.disabled = on;
  if (label) ui.btnLabel.textContent = label;
}

/* --------------------------------------------------------------- identity */

/* Two interchangeable signers. Both expose getPublicKey()/signEvent(); the rest
   of the app never cares which one is active. */
const extensionSigner = {
  kind: "extension",
  getPublicKey: () => window.nostr.getPublicKey(),
  signEvent: (e) => window.nostr.signEvent(e),
};
const browserSigner = {
  kind: "local",
  getPublicKey: async () => window.sqzLocalKey.pubkey(),
  signEvent: (e) => window.sqzLocalKey.signEvent(e),
};

/* Connect via a signing extension (Alby, nos2x). The key stays in the
   extension — sqz never sees it. */
async function connectExtension() {
  if (!window.nostr) {
    sayNodes(
      "error",
      document.createTextNode("No signing extension found. Install "),
      link("https://getalby.com", "Alby"),
      document.createTextNode(" or "),
      link("https://github.com/fiatjaf/nos2x", "nos2x"),
      document.createTextNode(" and reload — or use a browser key instead. sqz never sees your private key."),
    );
    return false;
  }
  let pubkey;
  try {
    pubkey = await window.nostr.getPublicKey();
  } catch {
    say("Connection cancelled. Approve the request in your extension to continue.", "error");
    return false;
  }
  return finishConnect(extensionSigner, pubkey);
}

/* Connect with a key generated and stored in this browser. Creates one on first
   use (and forces a backup), reuses the stored one afterwards. Less secure than
   an extension — see localkey.js — so the backup step is not optional. */
async function connectLocal() {
  const lk = await localKeyReady();
  if (!lk) {
    say("Key tools are still loading — try again in a second.", "error");
    return false;
  }
  if (lk.exists()) {
    return finishConnect(browserSigner, lk.pubkey());
  }
  const { pubkey, nsec } = lk.create();
  const ok = await finishConnect(browserSigner, pubkey);
  if (ok) showKeyModal("backup", nsec); // brand-new key — make them save it
  return ok;
}

async function finishConnect(signer, pubkey) {
  state.signer = signer;
  state.signerKind = signer.kind;
  state.pubkey = pubkey;
  state.npub = await encodeNpub(pubkey);
  ui.identityKey.textContent = shortKey(state.npub);
  ui.keyBadge.hidden = signer.kind !== "local";
  ui.backupBtn.hidden = signer.kind !== "local";
  ui.identity.hidden = false;
  ui.signinGroup.hidden = true;
  clearNotice();
  localStorage.setItem("sqz.lastSigner", signer.kind);
  await loadLinks();
  return true;
}

function disconnect() {
  state.signer = null;
  state.signerKind = null;
  state.pubkey = null;
  state.npub = null;
  state.links = [];
  ui.identity.hidden = true;
  ui.signinGroup.hidden = false;
  ui.links.hidden = true;
  neutralNamespace();
  localStorage.removeItem("sqz.lastSigner");
  // A browser key stays in localStorage so its links remain manageable; only
  // "Forget key" deletes it.
}

/* The local-key crypto is an ES module (deferred), so it may not be ready the
   instant this classic script runs. Resolve once it announces itself. */
function localKeyReady() {
  if (window.sqzLocalKey) return Promise.resolve(window.sqzLocalKey);
  return new Promise((resolve) => {
    const done = () => resolve(window.sqzLocalKey || null);
    window.addEventListener("sqz:localkey-ready", done, { once: true });
    setTimeout(done, 3000);
  });
}

/* The key modal has two modes: "backup" reveals the nsec to save (this is the
   only place a private key is ever shown), "import" restores one from an nsec. */
function showKeyModal(mode, nsec) {
  const backup = mode === "backup";
  ui.keyModalTitle.textContent = backup ? "Back up your key" : "Import a key";
  ui.keyModalBackup.hidden = !backup;
  ui.keyModalImport.hidden = backup;
  if (backup) {
    ui.nsecOut.textContent = nsec || "";
    ui.keyForget.hidden = !(window.sqzLocalKey && window.sqzLocalKey.exists());
  } else {
    ui.nsecIn.value = "";
  }
  ui.keyModal.hidden = false;
  (backup ? ui.backupDone : ui.nsecIn).focus();
}

function hideKeyModal() {
  ui.keyModal.hidden = true;
  ui.nsecOut.textContent = "";
  ui.nsecIn.value = "";
}

/* bech32 npub encoding, implemented here so the page ships with no dependency
   and no CDN. Verified against go-nostr's nip19 on 14 vectors. */
async function encodeNpub(hex) {
  const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const bytes = hex.match(/../g).map((h) => parseInt(h, 16));

  let acc = 0, bits = 0;
  const words = [];
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) { bits -= 5; words.push((acc >> bits) & 31); }
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
    ...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0,
    ...[...hrp].map((c) => c.charCodeAt(0) & 31),
  ];
  const checksum = polymod([...expanded, ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
  const check = [];
  for (let i = 0; i < 6; i++) check.push((checksum >> (5 * (5 - i))) & 31);

  return `${hrp}1${[...words, ...check].map((w) => CHARSET[w]).join("")}`;
}

/* ---------------------------------------------------------------- signing */

/* One NIP-98 header authorizes one request: the event names the absolute URL
   and method, so it cannot be replayed against a different endpoint. */
async function authHeader(method, path, body) {
  const tags = [["u", state.baseUrl + path], ["method", method]];
  if (body) tags.push(["payload", await sha256Hex(body)]);

  const signed = await state.signer.signEvent({
    kind: KIND_HTTP_AUTH,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: "",
  });
  return "Nostr " + btoa(JSON.stringify(signed));
}

async function signLinkEvent(slug, destination, title) {
  const tags = [["d", SLUG_PREFIX + slug], ["r", destination]];
  if (title) tags.push(["title", title]);

  return state.signer.signEvent({
    kind: KIND_LINK,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: "",
  });
}

/* --------------------------------------------------------------- requests */

/* Signal used to unwind the submit flow when payment is owed but could not be
   settled automatically. The invoice UI is already on screen; the caller just
   stops without treating it as an error. */
const PAYMENT_PENDING = "payment-pending";

/* Create a link, settling the L402 paywall inline when it asks.
 *
 * Identity (NIP-98) travels in X-Nostr-Authorization, leaving the standard
 * Authorization header free for the L402 credential — the two used to collide
 * there. See docs/payments.md.
 */
/* Ask the server for a random slug to use on the cheap (auto) tier. The server
   reserves it so the create can prove it was server-issued, not chosen. */
async function fetchServerSlug() {
  const nostrCred = await authHeader("POST", "/api/links/slug", "");
  const res = await fetch("/api/links/slug", {
    method: "POST",
    headers: { "X-Nostr-Authorization": nostrCred },
  });
  if (!res.ok) throw new Error("Could not reserve a name — try again.");
  const { slug } = await res.json();
  if (!slug) throw new Error("Server returned no slug.");
  return slug;
}

/* Is a custom name free? Best-effort UX only — the create is the real guard. */
async function checkAvailable(slug) {
  const res = await fetch(`/api/links/available?slug=${encodeURIComponent(slug)}`);
  if (!res.ok) return null;
  return res.json(); // { slug, available, reason? }
}

/* Reflect the price (100 auto / 500 custom) and, for a typed name, a debounced
   availability hint. */
let slugCheckTimer = null;
function refreshSlugState() {
  const custom = ui.slug.value.trim().toLowerCase();
  ui.priceAmount.textContent = custom ? "500 sats" : "100 sats";

  clearTimeout(slugCheckTimer);
  if (!custom) { ui.slugHint.hidden = true; return; }

  ui.slugHint.hidden = false;
  ui.slugHint.className = "slug-hint";
  ui.slugHint.textContent = "checking…";
  slugCheckTimer = setTimeout(async () => {
    const avail = await checkAvailable(custom);
    if (ui.slug.value.trim().toLowerCase() !== custom) return; // input moved on
    if (!avail) { ui.slugHint.hidden = true; return; }
    if (avail.available) {
      ui.slugHint.className = "slug-hint is-free";
      ui.slugHint.textContent = "available";
    } else {
      ui.slugHint.className = "slug-hint is-taken";
      ui.slugHint.textContent = avail.reason === "reserved" ? "reserved" : "taken";
    }
  }, 350);
}

async function createLink(event, path = "/api/links") {
  const body = JSON.stringify({ event });
  const nostrCred = await authHeader("POST", path, body);

  const post = (l402) => {
    const headers = { "Content-Type": "application/json", "X-Nostr-Authorization": nostrCred };
    if (l402) headers.Authorization = l402;
    return fetch(path, { method: "POST", headers, body });
  };

  let res = await post(null);

  // 402 comes from the paywall (nginx), before sqzd ever sees the request, so
  // no NIP-98 event is consumed on the challenge — a later retry reuses it.
  if (res.status === 402) {
    const challenge = parseChallenge(res.headers.get("WWW-Authenticate"));
    if (!challenge) {
      say("Payment is required, but no invoice came back. Check the paywall configuration.", "error");
      throw new Error(PAYMENT_PENDING);
    }

    // Always show the invoice — the QR leads. WebLN is offered as one option in
    // the panel, never forced ahead of showing the invoice. Everything needed
    // to complete (by extension, scan, or pasted preimage) is stashed here.
    pendingPayment = { body, nostrCred, path, ...challenge, event };
    showInvoice(res.headers.get("WWW-Authenticate"));
    throw new Error(PAYMENT_PENDING);
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  pendingPayment = null;
  return data;
}

/* Pull the macaroon and invoice out of a WWW-Authenticate: L402 header. */
function parseChallenge(header) {
  const mac = /macaroon="([^"]+)"/.exec(header || "");
  const inv = /invoice="([^"]+)"/.exec(header || "");
  if (!mac || !inv) return null;
  return { macaroon: mac[1], invoice: inv[1] };
}

/* Pay via WebLN and return the preimage, or null if unavailable/declined.
 *
 * WebLN (Alby and others) settles the invoice and hands back the preimage,
 * which is exactly the proof L402 needs. A static Lightning address has no node
 * for the server to confirm settlement against, so this client-side proof is
 * what closes the loop — the same extension that signs the link can pay for it. */
async function payWithWebln(invoice) {
  if (!window.webln) return null;
  try {
    await window.webln.enable();
    const res = await window.webln.sendPayment(invoice);
    return res && res.preimage ? res.preimage : null;
  } catch {
    return null; // user cancelled, insufficient balance, etc. — fall back to QR
  }
}

/* Retry a stashed link with a payment proof (preimage), from either the manual
   field or a WebLN payment. */
async function completePendingPayment(preimage) {
  if (!pendingPayment) return;
  if (pendingPayment.kind === "analytics") return completeAnalyticsUnlock(preimage);
  const { body, macaroon, event, path } = pendingPayment;

  // Re-sign NIP-98 fresh. The original was signed when Shorten was clicked, and
  // paying can take minutes — long enough for that signature to age out of the
  // ±60s window and be rejected by the app. A new one authorizes this retry.
  const nostrCred = await authHeader("POST", path, body);

  const res = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Nostr-Authorization": nostrCred,
      Authorization: `L402 ${macaroon}:${preimage.trim()}`,
    },
    body,
  });

  if (res.ok) {
    pendingPayment = null;

    window.sqzTrack?.("payment_completed", { amount_sats: path === "/api/links/custom" ? 500 : 100 });

    const data = await res.json().catch(() => ({}));
    const destination = event.tags.find((t) => t[0] === "r")?.[1] || "";

    // Stamp the code paid and let the panel go before the result arrives.
    // Sequenced, not simultaneous: settling the invoice and revealing the link
    // are two different pieces of news.
    await settleInvoice();
    showResult(destination, data.short_url);
    await loadLinks();
    return;
  }

  // A non-OK response has two distinct sources, and telling them apart is the
  // difference between "your proof was wrong" and "you weren't allowed":
  //   · the paywall (nginx) rejects a preimage that doesn't match the invoice —
  //     an HTML body, so JSON parsing yields nothing;
  //   · the app (sqzd) rejects identity/validation with a JSON {error}.
  const contentType = res.headers.get("content-type") || "";
  if (!contentType.includes("json")) {
    throw new Error(
      `The paywall rejected that preimage (status ${res.status}) — it doesn't match this invoice. ` +
      `Custodial and mobile wallets often don't expose the real preimage; if that's yours, use "Pay with extension" instead.`,
    );
  }
  const data = await res.json().catch(() => ({}));
  throw new Error(data.error || `Could not publish the link (status ${res.status}).`);
}

/* Close out the invoice panel: stamp the QR paid, hold long enough to be read,
   then collapse the panel away. Resolves once the panel is gone, so the caller
   can reveal the link into the space it left. */
function settleInvoice() {
  if (ui.invoice.hidden) return Promise.resolve();

  if (ui.qrStatus) ui.qrStatus.textContent = "Paid";
  // "Scan to pay <span>10 sats</span>" → "Paid <span>10 sats</span>". Only the
  // leading text node moves, so the gradient amount stays as it is.
  const title = el("invoice-title");
  if (title?.firstChild?.nodeType === Node.TEXT_NODE) title.firstChild.textContent = "Paid ";
  ui.qr.classList.add("is-paid");
  tap(18);

  if (reduced()) {
    ui.invoice.hidden = true;
    return Promise.resolve();
  }

  return new Promise((resolve) => {
    // Hold on the seal, then let the panel leave.
    setTimeout(() => {
      ui.invoice.classList.add("is-leaving");
      setTimeout(() => {
        ui.invoice.hidden = true;
        ui.invoice.classList.remove("is-leaving");
        resolve();
      }, 380);
    }, 680);
  });
}

async function loadLinks() {
  if (!state.pubkey) return;
  try {
    const header = await authHeader("GET", "/api/links", null);
    const res = await fetch("/api/links", { headers: { "X-Nostr-Authorization": header } });
    if (!res.ok) return;

    const { links = [] } = await res.json();
    state.links = links;
    renderLinks(links);
  } catch {
    // A failed listing must never block creating a link.
  }
}

/* -------------------------------------------------------------- analytics */

const ANALYTICS_CRED = "sqz:analytics-l402";

/* Open the paid analytics dashboard. Reuses a stored L402 credential when the
   100-sat unlock has already been bought (indefinite access), otherwise runs
   the invoice flow and stores the credential on success. */
async function openAnalytics() {
  if (!state.signer) {
    say("Sign in to see your analytics.", "note");
    return;
  }
  const nostrCred = await authHeader("GET", "/api/analytics", null);
  const headers = { "X-Nostr-Authorization": nostrCred };
  const stored = localStorage.getItem(ANALYTICS_CRED);
  if (stored) headers.Authorization = `L402 ${stored}`;

  let res;
  try {
    res = await fetch("/api/analytics", { headers });
  } catch {
    say("Could not reach analytics.", "error");
    return;
  }

  if (res.status === 402) {
    const challenge = parseChallenge(res.headers.get("WWW-Authenticate"));
    if (!challenge) {
      say("Payment is required, but no invoice came back.", "error");
      return;
    }
    pendingPayment = { kind: "analytics", ...challenge };
    showInvoice(res.headers.get("WWW-Authenticate"));
    const amt = document.querySelector(".invoice-amount");
    if (amt) amt.textContent = "100 sats"; // unlock price, not the link tier
    return;
  }
  if (res.status === 401) {
    say("Sign in to see your analytics.", "note");
    return;
  }
  if (!res.ok) {
    say("Could not load analytics.", "error");
    return;
  }
  renderAnalytics(await res.json());
}

/* Retry the analytics request with a fresh preimage, store the credential for
   next time, and reveal the dashboard. */
async function completeAnalyticsUnlock(preimage) {
  const { macaroon } = pendingPayment;
  const cred = `${macaroon}:${preimage.trim()}`;
  const nostrCred = await authHeader("GET", "/api/analytics", null);
  const res = await fetch("/api/analytics", {
    headers: { "X-Nostr-Authorization": nostrCred, Authorization: `L402 ${cred}` },
  });
  if (res.ok) {
    localStorage.setItem(ANALYTICS_CRED, cred);
    pendingPayment = null;
    window.sqzTrack?.("analytics_unlocked", { amount_sats: 100 });
    await settleInvoice();
    renderAnalytics(await res.json());
    return;
  }
  say("That didn't unlock analytics — check the preimage and try again.", "error");
}

/* Fill the dashboard from the aggregate response and show it. Rendered from
   response data, so every value goes through textContent, never innerHTML. */
function renderAnalytics(data) {
  ui.anClicks.textContent = (data.total_clicks ?? 0).toLocaleString();
  ui.anLinks.textContent = (data.total_links ?? 0).toLocaleString();

  const rows = Array.isArray(data.links) ? data.links : [];
  ui.anList.replaceChildren();
  ui.anEmpty.hidden = rows.length > 0;
  for (const l of rows) {
    const row = document.createElement("div");
    row.className = "an-row";

    const name = document.createElement("a");
    name.className = "an-slug";
    name.href = l.short_url;
    name.textContent = "/" + l.slug;
    name.target = "_blank";
    name.rel = "noopener noreferrer";

    const clicks = document.createElement("span");
    clicks.className = "an-clicks";
    clicks.textContent = `${(l.clicks ?? 0).toLocaleString()} clicks`;

    row.append(name, clicks);
    ui.anList.append(row);
  }

  ui.analyticsModal.hidden = false;
}

function showInvoice(wwwAuthenticate) {
  const match = /invoice="([^"]+)"/.exec(wwwAuthenticate || "");
  if (!match) {
    say("Payment is required, but no invoice came back. Check the paywall configuration.", "error");
    return;
  }
  const invoice = match[1];
  ui.invoiceCode.textContent = invoice;
  ui.invoiceOpen.href = `lightning:${invoice}`;

  // Mirror the tier's price (100 auto / 500 custom) into the invoice heading.
  const amountEl = document.querySelector(".invoice-amount");
  if (amountEl) amountEl.textContent = ui.priceAmount.textContent;

  // Rendered server-side so the page keeps shipping no third-party code.
  // Hidden until it actually loads: a broken image icon where a payment code
  // should be would be worse than showing only the string.
  ui.qr.hidden = true;
  ui.qrImg.onload = () => { ui.qr.hidden = false; };
  ui.qrImg.onerror = () => { ui.qr.hidden = true; };
  ui.qrImg.src = `/api/qr?invoice=${encodeURIComponent(invoice)}`;

  // WebLN is an option, not the gate. Offer the one-tap pay button only when a
  // wallet is present; the QR and manual entry serve everyone else.
  ui.payWebln.hidden = !window.webln;
  ui.payWebln.disabled = false;
  ui.preimage.value = "";
  if (ui.qrStatus) ui.qrStatus.textContent = "Waiting for payment…";
  // A previous invoice may have been settled in this session; this one has not.
  ui.qr.classList.remove("is-paid");
  ui.invoice.classList.remove("is-leaving");
  const title = el("invoice-title");
  if (title?.firstChild?.nodeType === Node.TEXT_NODE) title.firstChild.textContent = "Scan to pay ";
  ui.invoice.hidden = false;
  ui.invoice.scrollIntoView({ behavior: reduced() ? "auto" : "smooth", block: "nearest" });
}

/* ----------------------------------------------------------------- render */

function renderLinks(links) {
  ui.links.hidden = false;

  if (!links.length) {
    ui.linksCount.textContent = "";
    ui.linksBody.innerHTML =
      '<p class="empty">No links yet. Shorten one above and it will appear here.</p>';
    return;
  }

  const clicks = links.reduce((n, l) => n + (l.clicks || 0), 0);
  ui.linksCount.textContent =
    `${links.length} link${links.length === 1 ? "" : "s"} · ${clicks} click${clicks === 1 ? "" : "s"}`;

  const sorted = [...links].sort((a, b) => b.created_at - a.created_at);
  ui.linksBody.replaceChildren(...sorted.map(renderRow));
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
  dest.textContent = link.destination;

  main.append(slug, dest);

  const clicks = document.createElement("span");
  clicks.className = "row-clicks";
  const n = link.clicks || 0;
  clicks.innerHTML = `${n} <span>${n === 1 ? "click" : "clicks"}</span>`;

  const revoke = document.createElement("button");
  revoke.className = "row-act";
  revoke.type = "button";
  revoke.textContent = "Revoke";
  revoke.addEventListener("click", () => revokeLink(link.slug, row, revoke));

  row.append(main, clicks, revoke);
  return row;
}

/* Revocation republishes the same coordinate with an empty destination. The
   event stays on relays — that is how the revocation travels. */
async function revokeLink(slug, row, button) {
  button.disabled = true;
  button.textContent = "Revoking";

  try {
    const event = await signLinkEvent(slug, "", "");
    await createLink(event, "/api/links");

    // Let the row leave before the list redraws, so the change is legible.
    row.classList.add("is-leaving");
    setTimeout(() => { loadLinks(); }, reduced() ? 0 : 320);
    say(`Revoked /${slug}. It no longer resolves.`, "good");
  } catch (err) {
    button.disabled = false;
    button.textContent = "Revoke";
    if (err.message !== PAYMENT_PENDING) say(err.message, "error");
  }
}

function showResult(destination, shortUrl) {
  const before = destination.length;
  const after = shortUrl.length;
  const ratio = before / after;

  ui.resultUrl.href = shortUrl;
  ui.resultUrl.textContent = shortUrl.replace(/^https?:\/\//, "");
  ui.resultNote.textContent = `${before} characters in, ${after} out.`;
  ui.result.hidden = false;
  replay(ui.result, "is-fresh");
  tap(14);

  if (ratio > 1) {
    // The number climbs, lands with a little weight, and throws sparks. Three
    // beats on one event, because this is the event the whole page is for.
    countUp(ui.resultRatio, ratio, "× shorter", () => {
      replay(ui.resultRatio, "is-hit");
      burst(ui.resultRatio, ui.result);
    });
  } else {
    // Never dress a non-result up as a win.
    ui.resultRatio.textContent = "Ready";
  }

  // Guard on destination so revocations (empty destination) aren't counted.
  if (destination) window.sqzTrack?.("link_created", { method: state.signerKind });
}

/* ------------------------------------------------------------------ meter */

function measureInput() {
  const n = ui.url.value.trim().length;
  ui.meter.hidden = n === 0;
  if (!n) return;

  ui.meterVal.textContent = n;
  ui.meterFill.style.width = `${Math.min(100, (n / METER_REF) * 100)}%`;
  // Past two thirds of the reference width the bar starts to glow: this is the
  // kind of URL the product exists for.
  ui.meter.classList.toggle("is-long", n / METER_REF > 0.66);
}

/* ----------------------------------------------------------------- events */

ui.url.addEventListener("input", measureInput);
ui.slug.addEventListener("input", refreshSlugState);

/* Paste can land a beat before the input event fires in some browsers; this
   keeps the meter in step with what the user just did. */
ui.url.addEventListener("paste", () => setTimeout(measureInput, 0));

ui.signin.addEventListener("click", connectExtension);
ui.signinLocal.addEventListener("click", connectLocal);
ui.signout.addEventListener("click", disconnect);
ui.backupBtn.addEventListener("click", () => showKeyModal("backup", window.sqzLocalKey.nsec()));
ui.signinImport.addEventListener("click", () => showKeyModal("import"));
ui.keyModalClose.addEventListener("click", hideKeyModal);
ui.backupDone.addEventListener("click", hideKeyModal);
ui.keyModal.addEventListener("click", (e) => { if (e.target === ui.keyModal) hideKeyModal(); });

ui.analyticsBtn.addEventListener("click", openAnalytics);
ui.analyticsClose.addEventListener("click", () => { ui.analyticsModal.hidden = true; });
ui.analyticsModal.addEventListener("click", (e) => { if (e.target === ui.analyticsModal) ui.analyticsModal.hidden = true; });
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !ui.keyModal.hidden) hideKeyModal(); });
wireCopy(ui.nsecCopy, () => ui.nsecOut.textContent, "Copy");

ui.keyForget.addEventListener("click", () => {
  if (window.sqzLocalKey) window.sqzLocalKey.clear();
  hideKeyModal();
  disconnect();
  say("Browser key forgotten. Its links can't be managed from here anymore.", "note");
});

ui.importSubmit.addEventListener("click", async () => {
  const lk = await localKeyReady();
  if (!lk) return;
  try {
    const { pubkey } = lk.import(ui.nsecIn.value);
    hideKeyModal();
    await finishConnect(browserSigner, pubkey);
    say("Key imported. You're signed in.", "good");
  } catch (err) {
    say(err.message, "error");
  }
});

ui.form.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearNotice();
  ui.invoice.hidden = true;

  const destination = ui.url.value.trim();
  if (!destination) { ui.url.focus(); return; }

  // Signing in is an explicit choice now (extension vs browser key), so don't
  // silently pick one — point the user at the two options.
  if (!state.signer) {
    say("Sign in first — connect a signer, or create a key in this browser.", "note");
    ui.signinGroup.scrollIntoView({ behavior: reduced() ? "auto" : "smooth", block: "nearest" });
    return;
  }

  const custom = ui.slug.value.trim().toLowerCase();
  // A typed name is a custom link (500 sats); a blank one gets a server-issued
  // slug at the auto price (100 sats). The endpoint sets the price.
  const path = custom ? "/api/links/custom" : "/api/links";

  // The paywall charges before sqzd sees the request, so a taken custom name
  // would bill 500 sats and then 409. Check first. (The claim at create time is
  // still the real guard against a race between here and payment.)
  if (custom) {
    const avail = await checkAvailable(custom);
    if (avail && !avail.available) {
      say(avail.reason === "reserved" ? "That name is reserved — pick another." : `"${custom}" is taken — pick another.`, "error");
      ui.slug.focus();
      return;
    }
  }

  // The wait is the signature — an extension prompt, or a fast local sign.
  setWaiting(true, state.signerKind === "extension" ? "Waiting for your extension" : "Signing");

  try {
    const slug = custom || (await fetchServerSlug());
    const event = await signLinkEvent(slug, destination, "");
    setWaiting(true, "Publishing");

    const data = await createLink(event, path);
    showResult(destination, data.short_url);
    ui.slug.value = "";
    refreshSlugState();
    await loadLinks();
  } catch (err) {
    if (err.message !== PAYMENT_PENDING) {
      say(err.message || "Could not shorten that link.", "error");
    }
  } finally {
    setWaiting(false, "Shorten");
  }
});

wireCopy(ui.copy, () => ui.resultUrl.href, "Copy");
wireCopy(ui.invoiceCopy, () => ui.invoiceCode.textContent, "Copy invoice");

// One-tap pay for wallets that expose WebLN. It settles the invoice and hands
// back the preimage, which completes exactly like a pasted one — so the QR and
// this button share a single completion path.
ui.payWebln.addEventListener("click", async () => {
  if (!pendingPayment) return;
  ui.payWebln.disabled = true;
  ui.payWebln.querySelector(".btn-label").textContent = "Confirm in your wallet";
  if (ui.qrStatus) ui.qrStatus.textContent = "Paying…";
  try {
    const preimage = await payWithWebln(pendingPayment.invoice);
    if (!preimage) {
      say("Payment wasn't completed. Scan the code, or paste a preimage below.", "note");
      return;
    }
    await completePendingPayment(preimage);
    say("Paid. Your link is live.", "good");
  } catch (err) {
    say(err.message, "error");
  } finally {
    ui.payWebln.disabled = false;
    ui.payWebln.querySelector(".btn-label").textContent = "Pay with extension";
  }
});

ui.preimageSubmit.addEventListener("click", async () => {
  const preimage = ui.preimage.value.trim();
  if (!/^[0-9a-f]{64}$/i.test(preimage)) {
    say("A preimage is 64 hexadecimal characters. Copy the payment proof from your wallet.", "error");
    return;
  }
  ui.preimageSubmit.disabled = true;
  ui.preimageSubmit.textContent = "Completing";
  try {
    await completePendingPayment(preimage);
    say("Payment confirmed. Your link is live.", "good");
  } catch (err) {
    say(err.message, "error");
  } finally {
    ui.preimageSubmit.disabled = false;
    ui.preimageSubmit.textContent = "Complete";
  }
});

/* ------------------------------------------------------------------- boot */

(async function boot() {
  let cfg = null;
  try {
    const res = await fetch("/api/config");
    if (res.ok) {
      cfg = await res.json();
      // NIP-98 binds signatures to the origin the SERVER verifies against, not
      // the one the browser happens to be on. A mismatch fails every signature,
      // so take the server's word for it.
      if (cfg.base_url) {
        state.baseUrl = cfg.base_url.replace(/\/$/, "");
        try { state.domain = new URL(state.baseUrl).host; } catch { /* keep default */ }
      }
      if (cfg.domain) ui.footDomain.textContent = cfg.domain;
    }
  } catch {
    // Fall back to window.location.
  }

  // Hand the config to the analytics module in index.html. The global covers
  // the case where it initialised first; the event covers the reverse.
  window.__sqzConfig = cfg;
  window.dispatchEvent(new CustomEvent("sqz:config-ready", { detail: cfg }));

  neutralNamespace();
  measureInput();
  trackPointer();

  // Reconnect to the signer used last time. Extension: only if it's present
  // (avoids errors). Browser key: only if one is actually stored.
  const last = localStorage.getItem("sqz.lastSigner");
  if (last === "extension" && window.nostr) {
    connectExtension().catch(() => {});
  } else if (last === "local") {
    localKeyReady().then((lk) => { if (lk && lk.exists()) connectLocal(); });
  }

  // A signer is required before anything — including the invoice — because a
  // link is a signed event. Say so up front rather than letting someone paste a
  // URL, click Shorten, and only then learn they need one. The short delay lets
  // a slow-injecting extension register first.
  setTimeout(() => {
    if (!state.signer && !window.nostr) {
      sayNodes(
        "note",
        document.createTextNode("sqz signs each link with a nostr key before you pay. Install "),
        link("https://getalby.com", "Alby"),
        document.createTextNode(" to use your own — or just tap “Create key” to make one in this browser."),
      );
    }
  }, 900);

  // Focus the one thing the page is for — but not on touch, where it would
  // throw a keyboard over the page before anyone has read it.
  if (window.matchMedia("(hover: hover)").matches) ui.url.focus();
})();

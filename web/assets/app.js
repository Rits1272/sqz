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
  nsecOut: el("nsec-out"), nsecCopy: el("nsec-copy"), nsecReveal: el("nsec-reveal"),
  backupDone: el("backup-done"),
  keyForget: el("key-forget"),
  nsecIn: el("nsec-in"), importSubmit: el("import-submit"), keyModalClose: el("keymodal-close"),
  identity: el("identity"), identityKey: el("identity-key"),
  form: el("form"), url: el("url"), slug: el("slug"), slugPrefix: el("slug-prefix"),
  slugHint: el("slug-hint"), priceAmount: el("price-amount"),
  customPrice: el("custom-price"),
  squeeze: el("squeeze"), btnLabel: el("btn-label"), btnMeta: el("btn-meta"),
  meter: el("meter"), meterFill: el("meter-fill"), meterVal: el("meter-val"),
  urlHost: el("url-host"),
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
  publicOptin: el("public-optin"),
  board: el("board"), boardList: el("board-list"),
};

const state = {
  baseUrl: window.location.origin,
  domain: window.location.host,
  pubkey: null,
  npub: null,
  signer: null,      // active signer (extension or browser key)
  signerKind: null,  // "extension" | "local"
  links: [],
  priceSats: 100,   // the tier the composer is currently priced at
};

/* A link awaiting manual payment: the request is fully signed and the invoice
   is on screen, waiting only for a preimage to complete. */
let pendingPayment = null;

/* What the pending payment is actually buying. Creating a link and destroying
   one both post to /api/links and both get charged, but they are opposite
   pieces of news — without this the payment panel offers to "publish" a link
   the user is paying to remove, and the receipt afterwards calls a dead link
   Live. Shape: { kind: "create" | "revoke", slug }. */
let pendingIntent = { kind: "create" };

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

/* -------------------------------------------------------- payment recovery
 *
 * The mobile happy path is "tap Open in wallet → pay → come back", and that
 * hands the browser to another app. If the tab is reclaimed — routine on iOS
 * and Android — an in-memory pendingPayment took the macaroon, the invoice and
 * the signed event with it. The user had paid, and there was no route back to
 * what they bought.
 *
 * The macaroon has no expiry (l402_macaroon_timeout 0), so the credential is
 * still good; only the handle was being thrown away. sessionStorage keeps it
 * for the life of the tab.
 */
const STASH_KEY = "sqz:pending-payment";

function stashPayment() {
  if (!pendingPayment) return;
  try {
    sessionStorage.setItem(STASH_KEY, JSON.stringify({ payment: pendingPayment, intent: pendingIntent }));
  } catch { /* private mode or full — recovery is best-effort */ }
}

function clearStash() {
  try { sessionStorage.removeItem(STASH_KEY); } catch { /* nothing to undo */ }
}

/* Restore an unfinished payment on boot and say so plainly, because the user
   may well have already paid for it. */
function restorePayment() {
  let saved;
  try { saved = JSON.parse(sessionStorage.getItem(STASH_KEY) || "null"); } catch { return; }
  if (!saved?.payment?.invoice) return;

  pendingPayment = saved.payment;
  pendingIntent = saved.intent || { kind: "create" };
  showInvoice(`invoice="${saved.payment.invoice}" macaroon="${saved.payment.macaroon}"`);
  say("You have an unfinished invoice from earlier in this tab. If you already paid it, paste the preimage below to claim it.", "note");
  if (ui.invoiceManual) ui.invoiceManual.open = true;
}

/* ------------------------------------------------------------------ price */

/* "100 sats" is the price of the product in a unit almost no first-time
   visitor can convert, and an unknown price is a reason to close the tab.
 *
 * The rate is a constant rather than a third-party request: this page ships no
 * external code by design, and a figure that is roughly right does far more
 * work than an exact one nobody can read. /api/config may override it, so the
 * server can keep it current without a redeploy of this file. */
const SATS_PER_BTC = 100_000_000;
let usdPerBtc = 100_000; // Approximate by construction — hence the "≈" on screen.

function fiatFor(sats) {
  const usd = (sats / SATS_PER_BTC) * usdPerBtc;
  if (!Number.isFinite(usd) || usd <= 0) return "";
  if (usd < 0.01) return "<1¢";
  if (usd < 1) return `${Math.round(usd * 100)}¢`;
  return `$${usd.toFixed(2)}`;
}

/* Render a price into a node. Takes the sat figure as a number rather than
   re-reading the node, so calling it twice can't compound "100 sats ≈ 10¢"
   into nonsense. */
function setPrice(node, sats) {
  if (!node) return;
  const fiat = fiatFor(sats);
  node.textContent = fiat ? `${sats} sats ≈ ${fiat}` : `${sats} sats`;
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
      document.createTextNode(" and reload — or tap “Create a key” instead. sqz never sees your private key."),
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
/* ------------------------------------------------------------ modal focus
 *
 * Both dialogs declared aria-modal="true" while letting Tab walk straight out
 * into the page behind them — with, in the backup dialog's case, a private key
 * on screen. Declaring aria-modal and not honouring it is worse than not
 * declaring it: assistive tech hides the background content while the DOM
 * still hands focus to it.
 */
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])';

let trapped = null;        // the dialog currently holding focus
let returnFocusTo = null;  // what to give it back to

function trapFocus(modal) {
  trapped = modal;
  returnFocusTo = document.activeElement;
  // Background is inert as far as both pointer and assistive tech go.
  for (const node of [el("main-content") || document.querySelector("main"),
                      document.querySelector("header.nav"),
                      document.querySelector("footer.foot")]) {
    if (node) { node.inert = true; node.setAttribute("aria-hidden", "true"); }
  }
}

function releaseFocus() {
  for (const node of [el("main-content") || document.querySelector("main"),
                      document.querySelector("header.nav"),
                      document.querySelector("footer.foot")]) {
    if (node) { node.inert = false; node.removeAttribute("aria-hidden"); }
  }
  trapped = null;
  // Send focus back where it came from, so a keyboard user isn't dumped at the
  // top of the document.
  if (returnFocusTo && document.contains(returnFocusTo)) returnFocusTo.focus();
  returnFocusTo = null;
}

document.addEventListener("keydown", (e) => {
  if (e.key !== "Tab" || !trapped || trapped.hidden) return;
  const items = [...trapped.querySelectorAll(FOCUSABLE)].filter((n) => n.offsetParent !== null);
  if (!items.length) return;
  const first = items[0], last = items[items.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
});

function showKeyModal(mode, nsec) {
  const backup = mode === "backup";
  ui.keyModalTitle.textContent = backup ? "Back up your key" : "Import a key";
  ui.keyModalBackup.hidden = !backup;
  ui.keyModalImport.hidden = backup;
  if (backup) {
    ui.nsecOut.textContent = nsec || "";
    ui.nsecOut.classList.add("is-masked");
    if (ui.nsecReveal) {
      ui.nsecReveal.textContent = "Reveal";
      ui.nsecReveal.setAttribute("aria-pressed", "false");
    }
    ui.keyForget.hidden = !(window.sqzLocalKey && window.sqzLocalKey.exists());
  } else {
    ui.nsecIn.value = "";
  }
  ui.keyModal.hidden = false;
  trapFocus(ui.keyModal);
  (backup ? ui.backupDone : ui.nsecIn).focus();
}

function hideKeyModal() {
  ui.keyModal.hidden = true;
  releaseFocus();
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

async function signLinkEvent(slug, destination, title, isPublic) {
  const tags = [["d", SLUG_PREFIX + slug], ["r", destination]];
  if (title) tags.push(["title", title]);
  if (isPublic) tags.push(["public", "1"]);

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
  state.priceSats = custom ? 500 : 100;
  setPrice(ui.priceAmount, state.priceSats);

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
    stashPayment();
    showInvoice(res.headers.get("WWW-Authenticate"));
    throw new Error(PAYMENT_PENDING);
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  pendingPayment = null;
  clearStash();
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
    clearStash();

    window.sqzTrack?.("payment_completed", { amount_sats: path === "/api/links/custom" ? 500 : 100 });

    const data = await res.json().catch(() => ({}));
    const destination = event.tags.find((t) => t[0] === "r")?.[1] || "";

    // Stamp the code paid and let the panel go before the result arrives.
    // Sequenced, not simultaneous: settling the invoice and revealing the link
    // are two different pieces of news.
    await settleInvoice();

    // A revocation has no result to celebrate. Routing it through showResult
    // rendered the link the user just destroyed with a live badge, a "Ready"
    // ratio and a Copy button.
    if (pendingIntent.kind === "revoke") {
      say(`Revoked /${pendingIntent.slug}. It no longer resolves.`, "good");
      pendingIntent = { kind: "create" };
      await loadLinks();
      return;
    }

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

/* ------------------------------------------------------------ leaderboard */

/* Public top-links board. Free and unauthenticated — the engagement surface on
   the landing page. Only opted-in links appear; the section hides itself when
   the board is empty. Rendered via textContent, never innerHTML. */
async function loadLeaderboard() {
  let data;
  try {
    const res = await fetch("/api/leaderboard");
    if (!res.ok) return;
    data = await res.json();
  } catch {
    return;
  }
  const rows = Array.isArray(data.links) ? data.links : [];
  if (!rows.length) { ui.board.hidden = true; return; }

  ui.boardList.replaceChildren();
  rows.forEach((l, i) => {
    const row = document.createElement("li");
    row.className = "board-row";

    const rank = document.createElement("span");
    rank.className = "board-rank";
    rank.textContent = String(i + 1);

    const name = document.createElement("a");
    name.className = "board-slug";
    name.href = l.short_url;
    name.textContent = "/" + l.slug;
    name.target = "_blank";
    name.rel = "noopener noreferrer";

    const clicks = document.createElement("span");
    clicks.className = "board-clicks";
    clicks.textContent = `${(l.clicks ?? 0).toLocaleString()} clicks`;

    row.append(rank, name, clicks);
    ui.boardList.append(row);
  });
  ui.board.hidden = false;
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
  trapFocus(ui.analyticsModal);
  ui.analyticsClose?.focus();
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
  // Revoking is always the base rate — it posts to /api/links, not the custom
  // endpoint — so it must not inherit a 500-sat label from a typed name.
  const revoking = pendingIntent.kind === "revoke";
  setPrice(document.querySelector(".invoice-amount"), revoking ? 100 : state.priceSats);

  // The panel says what the money is actually for. Offering to "publish" a
  // link the user is paying to destroy is how you lose someone's trust at the
  // exact moment you are taking their money.
  const titleEl = el("invoice-title");
  if (titleEl?.firstChild?.nodeType === Node.TEXT_NODE) {
    titleEl.firstChild.textContent = revoking ? "Pay to revoke " : "Scan to pay ";
  }
  const leadEl = el("invoice-lead");
  if (leadEl) {
    leadEl.textContent = revoking
      ? `Point any Lightning wallet at the code below. /${pendingIntent.slug} stops resolving the moment this is paid.`
      : "Point any Lightning wallet at the code below. Your link publishes the moment it's paid. Paying needs a Lightning wallet — not a nostr one.";
  }

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
  // The primary verb on a saved link is "copy it again". Before this the only
  // button on a row was the destructive one, and clicking the slug navigated
  // away from the app.
  const copy = document.createElement("button");
  copy.className = "row-act row-copy";
  copy.type = "button";
  copy.innerHTML = '<span class="copy-label">Copy</span>';
  wireCopy(copy, () => link.short_url, "Copy");

  revoke.addEventListener("click", () => armRevoke(revoke, link.slug, row));
  revoke.addEventListener("blur", () => { if (revoke.dataset.armed) resetRevoke(revoke); });

  row.append(main, clicks, copy, revoke);
  return row;
}

/* Revocation republishes the same coordinate with an empty destination. The
   event stays on relays — that is how the revocation travels. */
async function revokeLink(slug, row, button) {
  button.disabled = true;
  button.textContent = "Revoking";
  // Republishing an empty destination is still a create as far as the paywall
  // is concerned, so it is charged at the base rate. Everything downstream —
  // the invoice copy, the receipt — reads this to know what it is paying for.
  pendingIntent = { kind: "revoke", slug };

  try {
    const event = await signLinkEvent(slug, "", "");
    await createLink(event, "/api/links");

    // Let the row leave before the list redraws, so the change is legible.
    row.classList.add("is-leaving");
    setTimeout(() => { loadLinks(); }, reduced() ? 0 : 320);
    say(`Revoked /${slug}. It no longer resolves.`, "good");
    pendingIntent = { kind: "create" };
  } catch (err) {
    button.disabled = false;
    resetRevoke(button);
    // On PAYMENT_PENDING the invoice is up and pendingIntent must survive —
    // it is what tells the receipt this was a revocation.
    if (err.message !== PAYMENT_PENDING) {
      pendingIntent = { kind: "create" };
      say(err.message, "error");
    }
  }
}

/* Revoke is destructive, irreversible and — because the paywall sits in front
   of the app — costs 100 sats. It asks once, with the price on the button,
   before any of that happens. */
function armRevoke(button, slug, row) {
  if (button.dataset.armed === "1") {
    delete button.dataset.armed;
    clearTimeout(Number(button.dataset.timer));
    revokeLink(slug, row, button);
    return;
  }
  button.dataset.armed = "1";
  button.textContent = "Revoke · 100 sats?";
  button.classList.add("is-armed");
  // Disarm on its own, so a stray click doesn't leave a primed destructive
  // control sitting in the list.
  button.dataset.timer = String(setTimeout(() => resetRevoke(button), 4000));
}

function resetRevoke(button) {
  delete button.dataset.armed;
  clearTimeout(Number(button.dataset.timer));
  button.classList.remove("is-armed");
  button.textContent = "Revoke";
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

/* ------------------------------------------------------------ field input
 *
 * Both fields are validated again on the server (internal/links/link.go), and
 * that check is the authority. What happens here is only to stop a user
 * reaching the paywall with input the server was always going to refuse —
 * paying and *then* being told the scheme was missing is the worst failure
 * this form can produce, and at 500 sats for a custom name it is not cheap.
 */

/* Something a browser would treat as a bare host: "example.com/a", but not
   "hello world" and not a scheme we were never going to accept. */
const BARE_HOST = /^[\w-]+(\.[\w-]+)+([/:?#]|$)/;

/* Tidy a pasted URL. Wrapped lines from an email, a stray leading space, and
   above all a missing scheme — which ValidateDestination rejects outright, and
   which is the single most common way a paste fails. Anything already carrying
   a scheme is left exactly as it is: silently rewriting "javascript:" into
   https would turn a rejection into a working link nobody asked for. */
function normalizeUrl(raw) {
  const text = raw.replace(/[\r\n\t]+/g, "").trim();
  if (!text) return "";
  if (/^[a-z][a-z0-9+.-]*:/i.test(text)) return text;
  return BARE_HOST.test(text) ? `https://${text}` : text;
}

/* Reduce a name to what ValidateSlug will accept: lowercase, [a-z0-9._-], with
   whitespace becoming the hyphen the user almost certainly meant. Runs of
   hyphens collapse, but a trailing one survives — stripping it mid-word would
   make "my-link" impossible to type. */
function sanitizeSlug(raw) {
  return raw
    .toLowerCase()
    // Decompose accents and drop the combining marks, so "héllo" becomes
    // "hello" rather than "hllo". Stripping a letter to nothing is the kind of
    // silent mangling that makes a field feel hostile to anyone not typing
    // English.
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9._-]/g, "")
    .replace(/-{2,}/g, "-");
}

/* Rewrite the name field in place, keeping the caret where the user left it.
   Assigning to .value alone would send it to the end on every keystroke. */
function applySlugInput() {
  const before = ui.slug.value;
  const next = sanitizeSlug(before);
  if (next === before) return;

  const caret = ui.slug.selectionStart ?? before.length;
  const head = sanitizeSlug(before.slice(0, caret)).length;
  ui.slug.value = next;
  const pos = Math.min(head, next.length);
  ui.slug.setSelectionRange(pos, pos);
}

/* A URL pasted into the name field almost always means "use the end of this",
   which is more useful than stripping it to an unreadable run of characters. */
function slugFromPaste(text) {
  const trimmed = text.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return sanitizeSlug(trimmed);
  try {
    const seg = new URL(trimmed).pathname.split("/").filter(Boolean).pop();
    // URL percent-encodes the path, and "%20" would otherwise survive
    // sanitizing as a literal "20" glued into the middle of the name.
    return sanitizeSlug(decodeURIComponent(seg || ""));
  } catch {
    return sanitizeSlug(trimmed);
  }
}

/* Mirrors MaxDestinationLen in internal/links/link.go. */
const MAX_DEST_LEN = 2048;

/* Mirrors ValidateDestination. The server remains the authority — this exists
   only so nobody reaches the paywall, pays, and *then* learns the destination
   was never going to be accepted. Returns a message, or null when the URL is
   fine.
 *
 * Every branch here corresponds to an error the server would have raised, so a
 * change to ValidateDestination should be reflected here or the two drift into
 * disagreeing about what is spendable. */
function destinationProblem(raw) {
  const dest = raw.trim();
  if (!dest) return "Paste a URL to shorten.";
  if (dest.length > MAX_DEST_LEN) {
    return `That URL is ${dest.length} characters — the limit is ${MAX_DEST_LEN}.`;
  }

  let u;
  try {
    u = new URL(dest);
  } catch {
    return "That isn't a URL yet. Try something like example.com/page.";
  }

  // Only http/https reach a browser as a navigation; the rest are script
  // execution or a local-resource read, and the server refuses them.
  const scheme = u.protocol.replace(/:$/, "").toLowerCase();
  if (scheme !== "http" && scheme !== "https") {
    return `Links have to be http or https — “${scheme}” isn't allowed.`;
  }
  if (!u.host) return "That URL is missing a domain.";
  if (u.hostname.toLowerCase() === displayHost().toLowerCase()) {
    return "That already points at sqz — shortening it would just loop.";
  }
  return null;
}

/* Show or clear the field's invalid state. Held back until the user has
   finished with the field: marking a half-typed URL wrong is nagging, and it
   would be red for most of the time anyone spends typing. */
function markUrlProblem(problem) {
  ui.url.classList.toggle("is-invalid", Boolean(problem));
  ui.url.setAttribute("aria-invalid", problem ? "true" : "false");
}

/* Echo the host back. The input scrolls to the tail of a long URL, so without
   this there is no way to confirm what was actually pasted. */
function reflectUrlHost() {
  const value = ui.url.value.trim();
  let host = "";
  try {
    const u = new URL(value);
    if (/^https?:$/i.test(u.protocol)) host = u.host;
  } catch { /* not parseable yet — mid-type, or not a URL at all */ }

  if (!host) { ui.urlHost.hidden = true; return; }

  // A link back to sqz is refused by ValidateDestination as a redirect loop.
  const self = host.replace(/:\d+$/, "").toLowerCase() === displayHost().toLowerCase();
  ui.urlHost.textContent = self ? `${host} — that's sqz` : host;
  ui.urlHost.dataset.kind = self ? "bad" : "ok";
  ui.urlHost.hidden = false;
}

function measureInput() {
  const n = ui.url.value.trim().length;
  ui.meter.hidden = n === 0;
  reflectUrlHost();
  if (!n) return;

  ui.meterVal.textContent = n;
  ui.meterFill.style.width = `${Math.min(100, (n / METER_REF) * 100)}%`;
  // Past two thirds of the reference width the bar starts to glow: this is the
  // kind of URL the product exists for.
  ui.meter.classList.toggle("is-long", n / METER_REF > 0.66);
}

/* ----------------------------------------------------------------- events */

ui.url.addEventListener("input", measureInput);

/* Sanitize first, then let refreshSlugState price it and ask the server
   whether it's free — it should be judging the name that will actually be
   submitted, not the one with the spaces still in it. */
ui.slug.addEventListener("input", () => { applySlugInput(); refreshSlugState(); });

/* Paste can land a beat before the input event fires in some browsers; this
   keeps the meter in step with what the user just did — and is where a pasted
   URL gets tidied, since that is the moment the whole value arrives at once. */
ui.url.addEventListener("paste", () => setTimeout(() => {
  const tidied = normalizeUrl(ui.url.value);
  // Only touch the field if it actually changed, so a caret parked mid-URL
  // after an ordinary paste isn't thrown to the end for nothing.
  if (tidied !== ui.url.value) ui.url.value = tidied;
  measureInput();
}, 0));

// Leaving the field is the other safe moment to tidy: the user has finished
// with it, so moving the caret costs nothing — and it is the first point at
// which flagging a bad URL is fair rather than premature.
ui.url.addEventListener("blur", () => {
  const tidied = normalizeUrl(ui.url.value);
  if (tidied !== ui.url.value) { ui.url.value = tidied; measureInput(); }
  markUrlProblem(ui.url.value.trim() ? destinationProblem(ui.url.value) : null);
});

// Editing earns the benefit of the doubt back immediately.
ui.url.addEventListener("input", () => markUrlProblem(null));

ui.slug.addEventListener("paste", (e) => {
  const text = e.clipboardData?.getData("text");
  if (!text) return;
  e.preventDefault();
  const slug = slugFromPaste(text);
  // Splice into whatever is selected, so pasting mid-name behaves normally.
  const start = ui.slug.selectionStart ?? ui.slug.value.length;
  const end = ui.slug.selectionEnd ?? start;
  ui.slug.value = sanitizeSlug(ui.slug.value.slice(0, start) + slug + ui.slug.value.slice(end));
  const pos = Math.min(start + slug.length, ui.slug.value.length);
  ui.slug.setSelectionRange(pos, pos);
  refreshSlugState();
});

// A hyphen is allowed to trail while typing; once the field is done, it isn't
// part of the name.
ui.slug.addEventListener("blur", () => {
  const tidied = ui.slug.value.replace(/^-+|-+$/g, "");
  if (tidied !== ui.slug.value) { ui.slug.value = tidied; refreshSlugState(); }
});

ui.signin.addEventListener("click", connectExtension);
ui.signinLocal.addEventListener("click", connectLocal);
ui.signout.addEventListener("click", disconnect);
ui.backupBtn.addEventListener("click", () => showKeyModal("backup", window.sqzLocalKey.nsec()));
ui.signinImport.addEventListener("click", () => showKeyModal("import"));
ui.keyModalClose.addEventListener("click", hideKeyModal);
ui.backupDone.addEventListener("click", hideKeyModal);
ui.keyModal.addEventListener("click", (e) => { if (e.target === ui.keyModal) hideKeyModal(); });

ui.analyticsBtn.addEventListener("click", openAnalytics);
const closeAnalytics = () => { ui.analyticsModal.hidden = true; releaseFocus(); };
ui.analyticsClose.addEventListener("click", closeAnalytics);
ui.analyticsModal.addEventListener("click", (e) => { if (e.target === ui.analyticsModal) closeAnalytics(); });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !ui.analyticsModal.hidden) closeAnalytics();
});
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !ui.keyModal.hidden) hideKeyModal(); });
wireCopy(ui.nsecCopy, () => ui.nsecOut.textContent, "Copy");

/* Reveal is a deliberate act. Copy works either way, so the common path —
   copy straight into a password manager — never puts the key on screen. */
ui.nsecReveal?.addEventListener("click", () => {
  const masked = ui.nsecOut.classList.toggle("is-masked");
  ui.nsecReveal.textContent = masked ? "Reveal" : "Hide";
  ui.nsecReveal.setAttribute("aria-pressed", masked ? "false" : "true");
});

/* Forgetting the key destroys control of every link it ever paid for. That is
   the most expensive irreversible action on the page and it was one click,
   sitting beside the key itself. It now asks, and says what is actually lost. */
ui.keyForget.addEventListener("click", () => {
  if (ui.keyForget.dataset.armed !== "1") {
    ui.keyForget.dataset.armed = "1";
    ui.keyForget.textContent = "Really forget? This can't be undone";
    setTimeout(() => {
      if (!ui.keyForget.dataset.armed) return;
      delete ui.keyForget.dataset.armed;
      ui.keyForget.textContent = "Forget this key";
    }, 5000);
    return;
  }
  delete ui.keyForget.dataset.armed;
  ui.keyForget.textContent = "Forget this key";
  if (window.sqzLocalKey) window.sqzLocalKey.clear();
  hideKeyModal();
  disconnect();
  say("Browser key forgotten. Without its backup you can no longer revoke or repoint any link you paid for with it.", "note");
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
  ui.result.hidden = true;

  // Enter submits without ever firing blur, so this is the last chance to tidy
  // the URL before it gets signed into an event and paid for.
  const destination = normalizeUrl(ui.url.value);
  if (destination !== ui.url.value) { ui.url.value = destination; measureInput(); }
  // The paywall sits in front of sqzd, so an invalid destination is charged
  // for before it is ever validated. Refuse it here instead.
  const problem = destinationProblem(destination);
  if (problem) {
    markUrlProblem(problem);
    say(problem, "error");
    replay(ui.url, "is-rejected");
    ui.url.focus();
    return;
  }
  markUrlProblem(null);

  // Signing in is an explicit choice now (extension vs browser key), so don't
  // silently pick one — point the user at the two options.
  if (!state.signer) {
    // Point at the choice where the intent is, rather than scroll-jumping to a
    // nav that was already on screen. Most visitors have no nostr key, so the
    // offer leads with making one.
    const makeKey = document.createElement("button");
    makeKey.type = "button";
    makeKey.className = "linklike linklike-strong";
    makeKey.textContent = "Create a key";
    makeKey.addEventListener("click", () => { clearNotice(); connectLocal(); });

    const useExt = document.createElement("button");
    useExt.type = "button";
    useExt.className = "linklike";
    useExt.textContent = "use a nostr extension";
    useExt.addEventListener("click", () => { clearNotice(); connectExtension(); });

    sayNodes(
      "note",
      document.createTextNode("A link has to be signed before it can be paid for. "),
      makeKey,
      document.createTextNode(" — it takes a second and stays in this browser — or "),
      useExt,
      document.createTextNode("."),
    );
    return;
  }

  // Sanitize here too: Enter can submit before blur has trimmed a trailing
  // hyphen, and a 500-sat request is not the place to discover that.
  const custom = sanitizeSlug(ui.slug.value).replace(/^-+|-+$/g, "");
  if (custom !== ui.slug.value) ui.slug.value = custom;
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

  // This submit is a create. Reset in case a revoke was abandoned mid-payment.
  pendingIntent = { kind: "create" };

  // The wait is the signature — an extension prompt, or a fast local sign.
  setWaiting(true, state.signerKind === "extension" ? "Waiting for your extension" : "Signing");

  try {
    const slug = custom || (await fetchServerSlug());
    const event = await signLinkEvent(slug, destination, "", ui.publicOptin.checked);
    setWaiting(true, "Publishing");

    const data = await createLink(event, path);
    showResult(destination, data.short_url);
    ui.slug.value = "";
    ui.publicOptin.checked = false;
    refreshSlugState();
    await loadLinks();
    loadLeaderboard();
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

  // The server may carry a fresher rate than the constant compiled in here.
  if (Number.isFinite(cfg?.usd_per_btc) && cfg.usd_per_btc > 0) usdPerBtc = cfg.usd_per_btc;
  setPrice(ui.priceAmount, state.priceSats);
  setPrice(ui.customPrice, 500);

  neutralNamespace();
  measureInput();
  trackPointer();
  restorePayment();
  loadLeaderboard();

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
    // Never talk over a recovered invoice. Someone who may already have paid
    // needs to see how to claim it far more than they need an install pitch.
    if (pendingPayment) return;
    if (!state.signer && !window.nostr) {
      sayNodes(
        "note",
        document.createTextNode("sqz signs each link with a nostr key before you pay. Install "),
        link("https://getalby.com", "Alby"),
        document.createTextNode(" to use your own — or just tap “Create a key” to make one in this browser."),
      );
    }
  }, 900);

  // Focus the one thing the page is for — but not on touch, where it would
  // throw a keyboard over the page before anyone has read it.
  if (window.matchMedia("(hover: hover)").matches) ui.url.focus();
})();

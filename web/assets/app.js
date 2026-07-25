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
};

const state = {
  baseUrl: window.location.origin,
  domain: window.location.host,
  pubkey: null,
  npub: null,
  signer: null,      // active signer (extension or browser key)
  signerKind: null,  // "extension" | "local"
  namespace: null,   // the short prefix the SERVER assigned, never guessed here
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
function autoSlug() {
  const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(7));
  return [...bytes].map((b) => alphabet[b % alphabet.length]).join("");
}

/* The namespace comes from the server's short_url and is never constructed
   here. The server assigns a truncated npub prefix, and only it knows which
   length was allocated after any collision. */
function adoptNamespace(shortUrl) {
  try {
    const u = new URL(shortUrl);
    const ident = u.pathname.split("/").filter(Boolean)[0];
    if (!ident) return;
    state.namespace = ident;
    ui.slugPrefix.textContent = `${u.host.replace(/:\d+$/, "")}/${ident}/`;
  } catch { /* leave the neutral placeholder in place */ }
}

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
   than simply printed. */
function countUp(node, to, suffix, ms = 620) {
  if (reduced()) { node.textContent = to.toFixed(1) + suffix; return; }

  const from = 1;
  const start = performance.now();
  const step = (now) => {
    const t = Math.min(1, (now - start) / ms);
    const eased = 1 - Math.pow(1 - t, 3);
    node.textContent = (from + (to - from) * eased).toFixed(1) + suffix;
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
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
  state.namespace = null;
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
async function createLink(event) {
  const body = JSON.stringify({ event });
  const nostrCred = await authHeader("POST", "/api/links", body);

  const post = (l402) => {
    const headers = { "Content-Type": "application/json", "X-Nostr-Authorization": nostrCred };
    if (l402) headers.Authorization = l402;
    return fetch("/api/links", { method: "POST", headers, body });
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
    pendingPayment = { body, nostrCred, ...challenge, event };
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
  const { body, macaroon, event } = pendingPayment;

  // Re-sign NIP-98 fresh. The original was signed when Shorten was clicked, and
  // paying can take minutes — long enough for that signature to age out of the
  // ±60s window and be rejected by the app. A new one authorizes this retry.
  const nostrCred = await authHeader("POST", "/api/links", body);

  const res = await fetch("/api/links", {
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
    ui.invoice.hidden = true;

    window.sqzTrack?.("payment_completed", { amount_sats: 10 });

    const data = await res.json().catch(() => ({}));
    const destination = event.tags.find((t) => t[0] === "r")?.[1] || "";
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

async function loadLinks() {
  if (!state.pubkey) return;
  try {
    const header = await authHeader("GET", "/api/links", null);
    const res = await fetch("/api/links", { headers: { "X-Nostr-Authorization": header } });
    if (!res.ok) return;

    const { links = [] } = await res.json();
    state.links = links;
    if (links.length) adoptNamespace(links[0].short_url);
    renderLinks(links);
  } catch {
    // A failed listing must never block creating a link.
  }
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
    await createLink(event);

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

  if (ratio > 1) {
    countUp(ui.resultRatio, ratio, "× shorter");
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
}

/* ----------------------------------------------------------------- events */

ui.url.addEventListener("input", measureInput);

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

  const slug = (ui.slug.value.trim() || autoSlug()).toLowerCase();

  // The wait is the signature — an extension prompt, or a fast local sign.
  setWaiting(true, state.signerKind === "extension" ? "Waiting for your extension" : "Signing");

  try {
    const event = await signLinkEvent(slug, destination, "");
    setWaiting(true, "Publishing");

    const data = await createLink(event);
    if (data.short_url) adoptNamespace(data.short_url);

    showResult(destination, data.short_url);
    ui.slug.value = "";
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

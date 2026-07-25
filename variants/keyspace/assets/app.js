/* sqz — keyspace
 *
 * Signing happens entirely in the user's NIP-07 extension. This page never sees
 * a private key and never asks for one. Every authenticated request carries a
 * fresh NIP-98 event bound to that exact URL, method and body.
 *
 * Protocol logic (bech32, NIP-98, request shapes) is carried over unchanged
 * from the reference implementation. The identity rendering is this variant's
 * own work: everything drawn is derived from the real 32 key bytes.
 */

const KIND_HTTP_AUTH = 27235;
const KIND_LINK = 30078;
const SLUG_PREFIX = "sqz:";

const el = (id) => document.getElementById(id);

const ui = {
  connect: el("connect"),
  connect2: el("connect-2"),
  disconnect: el("disconnect"),
  chip: el("chip"),
  chipSigil: el("chip-sigil"),
  chipKey: el("chip-key"),
  sigil: el("sigil"),
  sigilCap: el("sigil-cap"),
  railOut: el("rail-out"),
  railIn: el("rail-in"),
  tabNpub: el("tab-npub"),
  tabHex: el("tab-hex"),
  keyblock: el("keyblock"),
  copyKey: el("copy-key"),
  statLinks: el("stat-links"),
  statClicks: el("stat-clicks"),
  form: el("form"),
  url: el("url"),
  slug: el("slug"),
  slugPrefix: el("slug-prefix"),
  create: el("create"),
  signing: el("signing"),
  signingNote: el("signing-note"),
  signingEvent: el("signing-event"),
  notice: el("notice"),
  result: el("result"),
  resultUrl: el("result-url"),
  resultNote: el("result-note"),
  copy: el("copy"),
  invoice: el("invoice"),
  invoiceCode: el("invoice-code"),
  invoiceOpen: el("invoice-open"),
  invoiceCopy: el("invoice-copy"),
  links: el("links"),
  linksBody: el("links-body"),
  linksCount: el("links-count"),
};

const state = {
  baseUrl: window.location.origin,
  domain: "sqz.link",
  pubkey: null,
  npub: null,
  keyView: "npub",
  links: null,   // last successful listing, kept so a redraw needs no signature
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
  return npub ? `${npub.slice(0, 11)}…${npub.slice(-5)}` : "";
}

function hexBytes(hex) {
  return (hex.match(/../g) || []).map((h) => parseInt(h, 16));
}

/* Derive a slug when the user doesn't name one. Short, unambiguous, and avoids
   look-alike characters so a slug read aloud survives the trip. */
function autoSlug() {
  const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(7));
  return [...bytes].map((b) => alphabet[b % alphabet.length]).join("");
}

/* ------------------------------------------------------------- the mark */

/* A sigil plotted from the key itself. Each of the 32 bytes becomes one vertex:
   its index sets the angle, its value sets the radius. Chords connect byte i to
   the byte it points at. Two hues come out of the first three bytes. Nothing
   here is random — the same key always draws the same figure, and a different
   key cannot draw this one. */
function sigilSVG(hex, opts = {}) {
  const dark = matchMedia("(prefers-color-scheme: dark)").matches;
  const bytes = hex ? hexBytes(hex) : new Array(32).fill(0);
  const N = 32;
  const C = 60;

  const blank = !hex;
  // Two related hues, not two clashing ones: the second sits within a fifth of
  // the first so the figure reads as one object.
  const h1 = ((bytes[0] << 8) | bytes[1]) % 360;
  const h2 = (h1 + 28 + (bytes[2] % 44)) % 360;

  const L = dark ? 66 : 46;
  const S = dark ? 58 : 62;
  const ink = blank
    ? (dark ? "hsl(228 12% 42%)" : "hsl(228 14% 72%)")
    : `hsl(${h1} ${S}% ${L}%)`;
  const ink2 = blank
    ? (dark ? "hsl(228 12% 34%)" : "hsl(228 14% 80%)")
    : `hsl(${h2} ${S}% ${L}%)`;

  const pt = (i) => {
    const a = (i / N) * Math.PI * 2 - Math.PI / 2;
    const r = 19 + (bytes[i % N] / 255) * 33;
    return [C + Math.cos(a) * r, C + Math.sin(a) * r];
  };

  const verts = Array.from({ length: N }, (_, i) => pt(i));
  const hull = verts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(2)} ${y.toFixed(2)}`).join("") + "Z";

  // Chords: byte i points at byte (i + 1 + b mod 29). Half of them are drawn so
  // the figure stays legible instead of collapsing into a mesh.
  let chords = "";
  for (let i = 0; i < N; i += 2) {
    const j = (i + 1 + (bytes[i] % 29)) % N;
    const [x1, y1] = verts[i];
    const [x2, y2] = verts[j];
    chords += `<line x1="${x1.toFixed(2)}" y1="${y1.toFixed(2)}" x2="${x2.toFixed(2)}" y2="${y2.toFixed(2)}"/>`;
  }

  // A dot per byte, sized by its low nibble.
  const dots = verts
    .map(([x, y], i) => {
      const r = 0.8 + (bytes[i] & 15) / 15 * 1.6;
      return `<circle cx="${x.toFixed(2)}" cy="${y.toFixed(2)}" r="${r.toFixed(2)}"/>`;
    })
    .join("");

  const rings = [20, 36, 52]
    .map((r) => `<circle cx="${C}" cy="${C}" r="${r}"/>`)
    .join("");

  // With no key there is nothing honest to plot, so the figure shows the shape
  // waiting to be filled: 32 empty slots, one per byte.
  if (blank) {
    let ticks = "";
    for (let i = 0; i < N; i++) {
      const a = (i / N) * Math.PI * 2 - Math.PI / 2;
      const [c, s] = [Math.cos(a), Math.sin(a)];
      ticks += `<line x1="${(C + c * 40).toFixed(2)}" y1="${(C + s * 40).toFixed(2)}" x2="${(C + c * 52).toFixed(2)}" y2="${(C + s * 52).toFixed(2)}"/>`;
    }
    return `<svg viewBox="0 0 120 120" xmlns="http://www.w3.org/2000/svg">
  <g stroke="${ink}" stroke-width="1.6" opacity=".45" stroke-linecap="round">${ticks}</g>
  <circle cx="${C}" cy="${C}" r="40" fill="none" stroke="${ink}" stroke-width=".6" opacity=".3"/>
  <circle cx="${C}" cy="${C}" r="15" fill="none" stroke="${ink}" stroke-width=".6" opacity=".3"/>
</svg>`;
  }

  // At chip size the chords and dots turn to mush, so the small mark keeps only
  // the outline — still the same figure, just read at a distance.
  if (opts.simple) {
    return `<svg viewBox="0 0 120 120" xmlns="http://www.w3.org/2000/svg">
  <path d="${hull}" fill="${ink}" fill-opacity=".2" stroke="${ink}" stroke-width="5" stroke-linejoin="round"/>
</svg>`;
  }

  return `<svg viewBox="0 0 120 120" xmlns="http://www.w3.org/2000/svg">
  <g stroke="${ink}" stroke-width=".5" fill="none" opacity="${blank ? .3 : .16}">${rings}</g>
  <g stroke="${ink2}" stroke-width=".6" opacity="${blank ? .3 : .38}">${chords}</g>
  <path d="${hull}" fill="${ink}" fill-opacity="${blank ? .05 : .11}" stroke="${ink}" stroke-width="1.5" stroke-linejoin="round"/>
  <g fill="${ink2}" opacity="${blank ? .45 : .8}">${dots}</g>
</svg>`;
}

/* The mark a link carries. Hue is the owner's — taken from the key — so every
   link in the list is visibly signed by the same person. The bars come from the
   slug, so each link is still its own object. */
function linkMarkSVG(pubkey, slug) {
  const dark = matchMedia("(prefers-color-scheme: dark)").matches;
  const bytes = hexBytes(pubkey || "");
  const h = bytes.length ? ((bytes[0] << 8) | bytes[1]) % 360 : 228;
  const color = `hsl(${h} ${dark ? 55 : 60}% ${dark ? 64 : 48}%)`;

  let seed = 2166136261;
  for (const ch of slug) {
    seed ^= ch.charCodeAt(0);
    seed = Math.imul(seed, 16777619) >>> 0;
  }

  // A 3x5 cell block: the owner's hue, the link's pattern.
  let cells = "";
  for (let i = 0; i < 15; i++) {
    if (i % 5 === 0) seed = Math.imul(seed ^ i, 16777619) >>> 0;
    const v = (seed >>> ((i % 5) * 6)) & 63;
    if (v < 20) continue;
    const o = 0.3 + (v / 63) * 0.7;
    const x = (i % 3) * 7.5;
    const y = Math.floor(i / 3) * 6;
    cells += `<rect x="${x}" y="${y}" width="5.5" height="4" rx="1.3" opacity="${o.toFixed(2)}"/>`;
  }
  return `<svg viewBox="0 0 20 28" xmlns="http://www.w3.org/2000/svg"><g fill="${color}" transform="translate(0,1)">${cells}</g></svg>`;
}

/* --------------------------------------------------------- key rendering */

/* Two ways of looking at the same key. The hex is 64 characters of raw entropy,
   rendered so its own byte values set the weight — the texture is the data. The
   npub is the same bytes in bech32, human-checkable, with the prefix marked. */
function renderKeyBlock() {
  if (!state.pubkey) return;

  if (state.keyView === "hex") {
    ui.keyblock.innerHTML = hexBytes(state.pubkey)
      .map((b, i) => {
        const cls = b > 0xaa ? "hx-3" : b > 0x55 ? "hx-2" : "hx";
        const pair = state.pubkey.slice(i * 2, i * 2 + 2);
        return `<span class="${cls}">${pair}</span>`;
      })
      .join(" ");
    ui.copyKey.textContent = "Copy hex";
  } else {
    ui.keyblock.innerHTML =
      `<span class="hrp">npub1</span><span class="bech">${state.npub.slice(5)}</span>`;
    ui.copyKey.textContent = "Copy npub";
  }

  ui.tabNpub.classList.toggle("is-on", state.keyView === "npub");
  ui.tabHex.classList.toggle("is-on", state.keyView === "hex");
  ui.tabNpub.setAttribute("aria-selected", String(state.keyView === "npub"));
  ui.tabHex.setAttribute("aria-selected", String(state.keyView === "hex"));
}

function paintIdentity() {
  ui.sigil.innerHTML = sigilSVG(state.pubkey);
  ui.sigil.setAttribute(
    "aria-label",
    state.pubkey ? `Sigil drawn from public key ${state.npub}` : "No key connected",
  );
  if (state.pubkey) ui.chipSigil.innerHTML = sigilSVG(state.pubkey, { simple: true });
}

/* ------------------------------------------------------------- identity */

async function connect() {
  if (!window.nostr) {
    say(
      "No nostr extension found in this browser. Install Alby or nos2x, then reload — sqz signs through the extension and never asks for your private key.",
      "error",
    );
    return;
  }

  try {
    state.pubkey = await window.nostr.getPublicKey();
  } catch {
    say("Your extension declined the request. Approve it to connect your key.", "error");
    return;
  }

  state.npub = await encodeNpub(state.pubkey);

  ui.chipKey.textContent = shortKey(state.npub);
  ui.chip.hidden = false;
  ui.connect.hidden = true;
  ui.railOut.hidden = true;
  ui.railIn.hidden = false;
  ui.sigilCap.textContent =
    "Plotted from the 32 bytes of this key. Same key, same figure — every time, on any machine.";
  ui.slugPrefix.textContent = `${state.domain}/${state.npub.slice(0, 9)}…/`;

  paintIdentity();
  renderKeyBlock();
  clearNotice();

  sessionStorage.setItem("sqz.connected", "1");
  ui.linksBody.innerHTML = '<p class="empty">Reading your links…</p>';
  await loadLinks();
}

function disconnect() {
  state.pubkey = null;
  state.npub = null;
  ui.chip.hidden = true;
  ui.connect.hidden = false;
  ui.railOut.hidden = false;
  ui.railIn.hidden = true;
  ui.result.hidden = true;
  ui.invoice.hidden = true;
  ui.slugPrefix.textContent = "sqz.link/…/";
  ui.sigilCap.textContent =
    "Drawn from the 32 bytes of your public key. Nobody else's looks like it.";
  ui.linksBody.innerHTML =
    '<p class="empty">Connect your key to see the links signed with it.</p>';
  ui.linksCount.textContent = "";
  ui.statLinks.textContent = "0";
  ui.statClicks.textContent = "0";
  state.links = null;
  paintIdentity();
  sessionStorage.removeItem("sqz.connected");
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

/* Signing is the one moment where the user is being asked to commit their key
   to something. Show them exactly what they are putting a signature on. */
function showSigning(note, rows) {
  ui.signingNote.textContent = note;
  ui.signingEvent.replaceChildren(
    ...rows.flatMap(([k, v]) => {
      const dt = document.createElement("dt");
      dt.textContent = k;
      const dd = document.createElement("dd");
      dd.textContent = v;
      return [dt, dd];
    }),
  );
  ui.signing.hidden = false;
}

function hideSigning() {
  ui.signing.hidden = true;
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
  if (!res.ok) throw new Error(data.error || `sqz refused the event (${res.status}).`);
  return data;
}

async function loadLinks() {
  if (!state.pubkey) return;

  try {
    const header = await authHeader("GET", "/api/links", null);
    const res = await fetch("/api/links", { headers: { Authorization: header } });
    if (!res.ok) {
      listingFailed();
      return;
    }

    const { links = [] } = await res.json();
    renderLinks(links);
  } catch {
    // A failed listing should never block the page, and must never silently
    // erase links the user can already see.
    listingFailed();
  }
}

function listingFailed() {
  if (state.links) return; // keep what is on screen
  ui.linksBody.innerHTML =
    '<p class="empty">sqz could not read your links just now. Reload to try again — your links are events on relays either way.</p>';
}

function showInvoice(wwwAuthenticate) {
  const match = /invoice="([^"]+)"/.exec(wwwAuthenticate || "");
  if (!match) {
    say(
      "sqz asked for payment but returned no invoice. That is a server misconfiguration — try again shortly.",
      "error",
    );
    return;
  }
  const invoice = match[1];
  ui.invoiceCode.textContent = invoice;
  ui.invoiceOpen.href = `lightning:${invoice}`;
  ui.invoice.hidden = false;
  ui.invoice.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

/* --------------------------------------------------------------- render */

function renderLinks(links) {
  state.links = links;
  const live = links.filter((l) => l.destination);

  ui.linksCount.textContent = live.length
    ? `${live.length} live · ${live.reduce((n, l) => n + (l.clicks || 0), 0)} clicks`
    : "";

  ui.statLinks.textContent = live.length;
  ui.statClicks.textContent = live.reduce((n, l) => n + (l.clicks || 0), 0);

  if (!live.length) {
    ui.linksBody.innerHTML =
      '<p class="empty">Nothing under your key yet. Paste a destination above and sign your first link.</p>';
    return;
  }

  live.sort((a, b) => b.created_at - a.created_at);
  ui.linksBody.replaceChildren(...live.map(renderLink));
}

function renderLink(link) {
  const row = document.createElement("article");
  row.className = "link";

  const mark = document.createElement("span");
  mark.className = "link-mark";
  mark.setAttribute("aria-hidden", "true");
  mark.innerHTML = linkMarkSVG(state.pubkey, link.slug);

  const main = document.createElement("div");
  main.className = "link-main";

  const slug = document.createElement("a");
  slug.className = "link-slug";
  slug.href = link.short_url;
  slug.rel = "noopener";
  slug.textContent = "/" + link.slug;

  const dest = document.createElement("span");
  dest.className = "link-dest";
  dest.textContent = link.destination;
  dest.title = link.destination;

  main.append(slug, dest);

  const clicks = document.createElement("p");
  clicks.className = "link-clicks";
  clicks.innerHTML = `<b>${link.clicks || 0}</b><span>${link.clicks === 1 ? "click" : "clicks"}</span>`;

  const revoke = document.createElement("button");
  revoke.className = "link-revoke";
  revoke.type = "button";
  revoke.textContent = "Revoke";
  revoke.addEventListener("click", () => revokeLink(link.slug, revoke));

  row.append(mark, main, clicks, revoke);
  return row;
}

/* Revocation republishes the same coordinate with an empty destination. The
   event stays on relays — that is how the revocation propagates. */
async function revokeLink(slug, button) {
  button.disabled = true;
  button.textContent = "Signing";
  clearNotice();

  showSigning("Sign this to strip the destination off /" + slug + ". The event stays on relays; the link stops resolving.", [
    ["kind", "30078"],
    ["d", SLUG_PREFIX + slug],
    ["r", "(empty — revoked)"],
  ]);

  try {
    const event = await signLinkEvent(slug, "", "");
    await createLink(event);
    await loadLinks();
    say(`Revoked /${slug}. It no longer resolves.`, "good");
  } catch (err) {
    button.disabled = false;
    button.textContent = "Revoke";
    if (err.message !== "payment required") {
      say(err.message || "That revocation did not go through. Try again.", "error");
    }
  } finally {
    hideSigning();
  }
}

/* ---------------------------------------------------------------- events */

ui.connect.addEventListener("click", connect);
ui.connect2.addEventListener("click", connect);
ui.disconnect.addEventListener("click", disconnect);

ui.tabNpub.addEventListener("click", () => { state.keyView = "npub"; renderKeyBlock(); });
ui.tabHex.addEventListener("click", () => { state.keyView = "hex"; renderKeyBlock(); });

ui.copyKey.addEventListener("click", async () => {
  const value = state.keyView === "hex" ? state.pubkey : state.npub;
  await navigator.clipboard.writeText(value);
  const was = ui.copyKey.textContent;
  ui.copyKey.textContent = "Copied";
  setTimeout(() => (ui.copyKey.textContent = was), 1400);
});

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

  ui.create.disabled = true;
  ui.create.querySelector(".btn-create-label").textContent = "Signing…";

  showSigning("Approve the signature to publish this event under your key.", [
    ["kind", "30078"],
    ["d", SLUG_PREFIX + slug],
    ["r", destination],
    ["by", state.npub],
  ]);

  try {
    const event = await signLinkEvent(slug, destination, "");
    ui.signingNote.textContent = "Signed. Handing the event to sqz to index.";
    const data = await createLink(event);
    showResult(destination, data.short_url);
    ui.slug.value = "";
    ui.url.value = "";
    await loadLinks();
  } catch (err) {
    if (err.message !== "payment required") {
      say(err.message || "That link could not be published.", "error");
    }
  } finally {
    hideSigning();
    ui.create.disabled = false;
    ui.create.querySelector(".btn-create-label").textContent = "Sign & publish";
  }
});

function showResult(destination, shortUrl) {
  ui.resultUrl.href = shortUrl;
  ui.resultUrl.textContent = shortUrl.replace(/^https?:\/\//, "");
  ui.resultNote.textContent =
    shortUrl.length < destination.length
      ? `${destination.length} characters down to ${shortUrl.length}. Signed by your key, resolving now.`
      : "Signed by your key and resolving now. Nobody but you can replace it.";
  ui.result.hidden = false;
  ui.copy.textContent = "Copy";
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

// The sigil's colours are tuned per theme, so redraw when the theme flips.
// Redrawing must never cost a signature, so it reuses the cached listing.
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
  paintIdentity();
  if (state.links) renderLinks(state.links);
});

/* ------------------------------------------------------------------ boot */

(async function boot() {
  paintIdentity();

  try {
    const res = await fetch("/api/config");
    if (res.ok) {
      const cfg = await res.json();
      // NIP-98 binds signatures to the origin the SERVER verifies against, not
      // the one the browser happens to be on. A mismatch fails every signature,
      // so take the server's word for it.
      if (cfg.base_url) state.baseUrl = cfg.base_url.replace(/\/$/, "");
      if (cfg.domain) {
        state.domain = cfg.domain;
        if (!state.pubkey) ui.slugPrefix.textContent = `${cfg.domain}/…/`;
      }
    }
  } catch {
    // Fall back to window.location.origin.
  }

  if (!window.nostr) {
    ui.sigilCap.textContent =
      "No nostr extension detected. Install Alby or nos2x and reload to draw your own.";
  }

  // Reconnect silently if the extension already granted access this session.
  if (sessionStorage.getItem("sqz.connected") && window.nostr) {
    connect().catch(() => {});
  }
})();

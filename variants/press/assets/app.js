/* sqz — the press.
 *
 * Protocol logic (bech32 npub, NIP-98 signing, L402 handling) is carried over
 * unchanged from the verified reference implementation. Signing happens in the
 * user's NIP-07 extension; this page never sees a private key.
 */

const KIND_HTTP_AUTH = 27235;
const KIND_LINK = 30078;
const SLUG_PREFIX = "sqz:";

const el = (id) => document.getElementById(id);

const ui = {
  press: el("press"),
  lamp: el("lamp"),
  signin: el("signin"),
  signout: el("signout"),
  identity: el("identity"),
  identityKey: el("identity-key"),
  form: el("form"),
  url: el("url"),
  slug: el("slug"),
  slugPrefix: el("slug-prefix"),
  squeeze: el("squeeze"),
  ramLabel: el("ram-label"),
  countIn: el("count-in"),
  countOut: el("count-out"),
  result: el("result"),
  resultUrl: el("result-url"),
  resultRatio: el("result-ratio"),
  copy: el("copy"),
  notice: el("notice"),
  invoice: el("invoice"),
  invoiceCode: el("invoice-code"),
  invoiceOpen: el("invoice-open"),
  invoiceCopy: el("invoice-copy"),
  ledger: el("ledger"),
  ledgerBody: el("ledger-body"),
  logCount: el("log-count"),
};

const state = {
  baseUrl: window.location.origin,
  pubkey: null,
  npub: null,
};

/* ------------------------------------------------------------------ util */

function say(message, kind = "note") {
  ui.notice.textContent = message;
  ui.notice.dataset.kind = kind;
  ui.notice.hidden = false;
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

/* Derive a slug when the operator doesn't name one. Short, unambiguous, and
   free of look-alike characters so a slug survives being read aloud. */
function autoSlug() {
  const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(7));
  return [...bytes].map((b) => alphabet[b % alphabet.length]).join("");
}

/* Drive a mechanical counter: four wheels, leading zeros dimmed the way an
   unrolled wheel sits behind the window. */
function setCounter(node, value) {
  const digits = String(Math.min(9999, value)).padStart(4, "0");
  const firstReal = digits.search(/[1-9]/);
  node.replaceChildren(
    ...[...digits].map((d, i) => {
      const cell = document.createElement("b");
      cell.textContent = d;
      if (firstReal === -1 ? i < 3 : i < firstReal) cell.className = "pad";
      return cell;
    }),
  );
}

/* ------------------------------------------------------------- identity */

async function connect() {
  if (!window.nostr) {
    say(
      "No nostr extension found. Install Alby or nos2x, reload this page, then connect your key. sqz never asks for a private key.",
      "error",
    );
    return;
  }

  try {
    state.pubkey = await window.nostr.getPublicKey();
  } catch {
    say("Your extension refused the request. Approve it there, then connect again.", "error");
    return;
  }

  state.npub = await encodeNpub(state.pubkey);
  ui.identityKey.textContent = shortKey(state.npub);
  ui.identity.hidden = false;
  ui.signin.hidden = true;
  ui.lamp.dataset.state = "on";
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
  ui.lamp.dataset.state = "off";
  showIdleLog();
  ui.slugPrefix.textContent = "sqz/";
  sessionStorage.removeItem("sqz.connected");
  say("Key released. The press is idle until you connect one again.");
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
  if (!res.ok) throw new Error(data.error || `The server refused the link (${res.status}).`);
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
    // A failed listing should never block the press from running.
  }
}

function showInvoice(wwwAuthenticate) {
  const match = /invoice="([^"]+)"/.exec(wwwAuthenticate || "");
  if (!match) {
    say(
      "The server asked for payment but returned no invoice. Its paywall is misconfigured — try again shortly.",
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

function showIdleLog() {
  ui.logCount.textContent = "No key";
  ui.ledgerBody.replaceChildren(
    makeEmpty("Connect a key and this log fills with every link that key has pressed. sqz reads them back from your signed events — it holds no account for you."),
  );
}

function renderLedger(links) {
  if (!links.length) {
    ui.logCount.textContent = "0 links";
    ui.ledgerBody.replaceChildren(
      makeEmpty("Nothing pressed yet. Load a URL into the bed above and press — 10 sat a cycle."),
    );
    return;
  }

  ui.logCount.textContent = `${links.length} ${links.length === 1 ? "link" : "links"}`;
  links.sort((a, b) => b.created_at - a.created_at);
  ui.ledgerBody.replaceChildren(...links.map(renderRow));
}

function makeEmpty(text) {
  const p = document.createElement("p");
  p.className = "empty";
  p.textContent = text;
  return p;
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
  clicks.append(String(link.clicks));
  const unit = document.createElement("span");
  unit.textContent = link.clicks === 1 ? "click" : "clicks";
  clicks.append(unit);

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
    say(`Revoked /${slug}. It stops resolving as relays pick up the new event.`, "done");
  } catch (err) {
    button.disabled = false;
    button.textContent = "Revoke";
    if (err.message !== "payment required") say(err.message, "error");
  }
}

/* ---------------------------------------------------------------- events */

function measureInput() {
  setCounter(ui.countIn, ui.url.value.trim().length);
  // The bed opens to hold whatever stock is loaded — a long URL is never
  // clipped or hidden behind an inner scrollbar.
  ui.url.style.height = "auto";
  ui.url.style.height = `${ui.url.scrollHeight}px`;
}

ui.url.addEventListener("input", measureInput);

ui.signin.addEventListener("click", connect);
ui.signout.addEventListener("click", disconnect);

ui.form.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearNotice();
  ui.invoice.hidden = true;

  const destination = ui.url.value.trim();
  if (!destination) {
    say("There is nothing in the bed. Paste a URL to press.", "error");
    ui.url.focus();
    return;
  }
  if (!/^https?:\/\/\S+$/i.test(destination)) {
    say("That is not a full URL. Include the scheme, for example https://example.com/page.", "error");
    ui.url.focus();
    return;
  }

  if (!state.pubkey) {
    await connect();
    if (!state.pubkey) return;
  }

  const slug = (ui.slug.value.trim() || autoSlug()).toLowerCase();

  ui.squeeze.disabled = true;
  ui.press.classList.add("is-pressing");
  ui.ramLabel.textContent = "Signing";

  try {
    const event = await signLinkEvent(slug, destination, "");
    ui.ramLabel.textContent = "Pressing";
    const data = await createLink(event);
    showResult(destination, data.short_url);
    ui.slug.value = "";
    await loadLinks();
  } catch (err) {
    if (err.message !== "payment required") {
      say(err.message || "The cycle failed. Check your extension approved the signature, then press again.", "error");
    }
  } finally {
    ui.squeeze.disabled = false;
    ui.press.classList.remove("is-pressing");
    ui.ramLabel.textContent = "Press";
  }
});

function showResult(destination, shortUrl) {
  const before = destination.length;
  const after = shortUrl.length;

  setCounter(ui.countOut, after);

  ui.resultUrl.href = shortUrl;
  ui.resultUrl.textContent = shortUrl.replace(/^https?:\/\//, "");

  const ratio = before / after;
  ui.resultRatio.innerHTML =
    ratio > 1
      ? `${before} characters in, ${after} out — <strong>${ratio.toFixed(1)}×</strong> shorter.`
      : `${before} characters in, ${after} out.`;

  ui.result.hidden = false;
  ui.result.getAnimations?.().forEach((a) => a.cancel());
  ui.result.style.animation = "none";
  void ui.result.offsetHeight;
  ui.result.style.animation = "";
}

ui.copy.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(ui.resultUrl.href);
    ui.copy.textContent = "Copied";
    setTimeout(() => (ui.copy.textContent = "Copy"), 1400);
  } catch {
    say("Your browser blocked the clipboard. Select the link and copy it by hand.", "error");
  }
});

ui.invoiceCopy.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(ui.invoiceCode.textContent);
    ui.invoiceCopy.textContent = "Copied";
    setTimeout(() => (ui.invoiceCopy.textContent = "Copy invoice"), 1400);
  } catch {
    say("Your browser blocked the clipboard. Select the invoice and copy it by hand.", "error");
  }
});

/* ------------------------------------------------------------------ boot */

(async function boot() {
  setCounter(ui.countIn, 0);
  setCounter(ui.countOut, 0);
  showIdleLog();

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

  measureInput();

  if (!window.nostr) {
    say("No nostr extension detected. Install Alby or nos2x to sign links — you can still look around.");
  }

  // Reconnect silently if the extension already granted access this session.
  if (sessionStorage.getItem("sqz.connected") && window.nostr) {
    connect().catch(() => {});
  }
})();

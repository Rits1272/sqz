/* Local (browser-generated) nostr key.
 *
 * An on-ramp for people without a signing extension: sqz generates a nostr
 * keypair here and signs with it. This is a deliberate security trade-off — a
 * key held in the page's own storage is convenient but weaker than one isolated
 * in an extension (any XSS on this page, or anyone with this browser profile,
 * could read it). It is offered as an equal alternative to a real signer, with a
 * mandatory backup step, never silently.
 *
 * Crypto is the vendored, audited noble-secp256k1 (BIP-340 schnorr). This module
 * is the ONLY place a private key is generated, stored, or used to sign.
 */

import { schnorr, utils } from "/assets/noble-secp256k1.js";

// Versioned so the storage shape can change without colliding with old data.
const STORAGE_KEY = "sqz.localkey.v1";

/* ------------------------------------------------------------ storage */

function loadPrivHex() {
  try { return localStorage.getItem(STORAGE_KEY); } catch { return null; }
}
function savePrivHex(hex) { localStorage.setItem(STORAGE_KEY, hex); }

/* ------------------------------------------------------------- bech32 */
/* NIP-19 bare-key encoding: plain bech32 of the 32 key bytes (no TLV). Encode
   for showing/backing up an nsec, decode for importing one. */

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
  }
  return chk;
}

function hrpExpand(hrp) {
  const out = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

function convertBits(data, from, to, pad) {
  let acc = 0, bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  for (const value of data) {
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
  }
  if (pad) { if (bits > 0) out.push((acc << (to - bits)) & maxv); }
  else if (bits >= from || ((acc << (to - bits)) & maxv)) return null;
  return out;
}

function bech32Encode(hrp, bytes) {
  const words = convertBits([...bytes], 8, 5, true);
  const checksum = polymod([...hrpExpand(hrp), ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
  const check = [];
  for (let i = 0; i < 6; i++) check.push((checksum >> (5 * (5 - i))) & 31);
  return `${hrp}1${[...words, ...check].map((w) => CHARSET[w]).join("")}`;
}

function bech32Decode(str, expectedHrp) {
  const s = str.trim().toLowerCase();
  const pos = s.lastIndexOf("1");
  if (pos < 1 || pos + 7 > s.length) return null;
  const hrp = s.slice(0, pos);
  if (expectedHrp && hrp !== expectedHrp) return null;

  const words = [];
  for (const c of s.slice(pos + 1)) {
    const v = CHARSET.indexOf(c);
    if (v === -1) return null;
    words.push(v);
  }
  if (polymod([...hrpExpand(hrp), ...words]) !== 1) return null; // bad checksum

  const bytes = convertBits(words.slice(0, -6), 5, 8, false);
  if (!bytes || bytes.length !== 32) return null;
  return new Uint8Array(bytes);
}

const toHex = (bytes) => utils.bytesToHex(bytes);
const pubOf = (privHex) => toHex(schnorr.getPublicKey(privHex));

/* -------------------------------------------------------------- event */

async function computeId(evt) {
  const serialized = JSON.stringify([
    0, evt.pubkey, evt.created_at, evt.kind, evt.tags, evt.content,
  ]);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(serialized));
  return toHex(new Uint8Array(digest));
}

/* --------------------------------------------------------------- api */

const api = {
  /** Is a local key stored in this browser? */
  exists: () => !!loadPrivHex(),

  /** Generate and persist a new key. Returns { pubkey, nsec } for the backup step. */
  create() {
    const privHex = toHex(utils.randomPrivateKey());
    savePrivHex(privHex);
    return { pubkey: pubOf(privHex), nsec: bech32Encode("nsec", utils.hexToBytes(privHex)) };
  },

  /** Import an existing key from an nsec (or 64-char hex). Returns { pubkey } or throws. */
  import(input) {
    const s = (input || "").trim();
    let bytes;
    if (s.startsWith("nsec1")) {
      bytes = bech32Decode(s, "nsec");
      if (!bytes) throw new Error("That doesn't look like a valid nsec.");
    } else if (/^[0-9a-f]{64}$/i.test(s)) {
      bytes = utils.hexToBytes(s.toLowerCase());
    } else {
      throw new Error("Enter an nsec (nsec1…) or a 64-character hex key.");
    }
    const privHex = toHex(bytes);
    // Round-trips through the curve, which rejects an out-of-range scalar.
    const pubkey = pubOf(privHex);
    savePrivHex(privHex);
    return { pubkey };
  },

  /** Current key's hex pubkey, or null. */
  pubkey() {
    const p = loadPrivHex();
    return p ? pubOf(p) : null;
  },

  /** Current key's nsec (for backup), or null. */
  nsec() {
    const p = loadPrivHex();
    return p ? bech32Encode("nsec", utils.hexToBytes(p)) : null;
  },

  /** Sign a nostr event with the local key (same shape a NIP-07 signer returns). */
  async signEvent(evt) {
    const priv = loadPrivHex();
    if (!priv) throw new Error("No local key in this browser.");
    const e = {
      kind: evt.kind,
      created_at: evt.created_at,
      tags: evt.tags || [],
      content: evt.content || "",
      pubkey: pubOf(priv),
    };
    e.id = await computeId(e);
    e.sig = toHex(await schnorr.sign(e.id, priv));
    return e;
  },

  /** Forget the key (sign out of local mode / delete). */
  clear() {
    try { localStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
  },
};

window.sqzLocalKey = api;
window.dispatchEvent(new Event("sqz:localkey-ready"));

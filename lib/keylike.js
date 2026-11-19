// Checks for values that look like key material rather than a name, a path, a
// version or a URL, so a key pasted in the wrong place is stopped before it is
// sent, echoed or written. Shared by the CLI (lib/cli.js) and the registry base
// URL check (lib/listing.js).

// A whole value that looks like a key: 32 or more hex digits (colons and
// spaces allowed), PEM text, more than 128 characters, or a base64 run of 40 or
// more characters with digits, capitals and small letters.
export function looksLikeKey(s) {
  s = String(s);
  const base64Like = /^[A-Za-z0-9+/_-]{40,}={0,2}$/.test(s) && /[0-9]/.test(s) && /[A-Z]/.test(s) && /[a-z]/.test(s);
  return /^[0-9a-fA-F:\s]{32,}$/.test(s) || s.includes('-----BEGIN') || s.length > 128 || base64Like;
}

// A key inside a longer value (key-<hex>.json, k-<hex>, <base64>.signed.json).
export function holdsKeyRun(v) {
  const s = String(v);
  return /[0-9a-fA-F]{64,}/.test(s) || (s.match(/[A-Za-z0-9+_-]{40,}/g) || []).some((m) => /[0-9]/.test(m) && /[A-Z]/.test(m) && /[a-z]/.test(m));
}

// A hex key cut into pieces: runs of 16 or more hex digits that add up to the
// 64 digits of a 32 byte key. Ordinary words hold few hex letters (a to f), so
// a run of 16 is rare outside of hashes and keys, and a single run of 40 hex
// digits, such as a git commit hash, is not refused.
export function holdsSplitHexKey(v) {
  const s = String(v);
  return (s.match(/[0-9a-fA-F]{16,}/g) || []).reduce((n, m) => n + m.length, 0) >= 64;
}

// A server name that holds key material: a key run, a hex key cut into pieces
// (com.example/<32 hex>-<32 hex>), or a part between "/" and "." that looks
// like a key. Base64 pieces are not added up for a name, because a long name
// of mixed case words would add up to a key's length. prepare and init screen
// names with this rule; check-listing, which reads any listing, applies only
// the hex rule (holdsSplitHexKey).
export function nameHoldsKey(name) {
  const s = String(name);
  return holdsKeyRun(s) || holdsSplitHexKey(s) || s.split(/[/.]/).some((part) => looksLikeKey(part));
}

// A key cut into pieces inside a value sent to the registry or published (a
// version, a contact, a registry URL): hex pieces as above, or base64 runs of
// mixed case and digits of 16 or more characters that add up to the 43
// characters of one. Server names are checked for hex pieces only
// (holdsSplitHexKey): a long name of mixed case words would add up to 43 too.
export function holdsSplitKey(v) {
  const s = String(v);
  const b64 = (s.match(/[A-Za-z0-9+_-]{16,}/g) || []).filter((m) => /[0-9]/.test(m) && /[A-Z]/.test(m) && /[a-z]/.test(m)).reduce((n, m) => n + m.length, 0);
  return holdsSplitHexKey(s) || b64 >= 43;
}

// A URL (such as --registry) that holds key material in one of the forms a
// key is commonly pasted in. This is a best effort courtesy for those common
// forms, not a complete filter: it is kept narrow so ordinary custom registry
// URLs (mixed case words and digits in the host and path, a 32 hex digit
// tenant id) are accepted. The path is percent decoded once; then the URL is
// refused only when
//   1. one path segment or host label holds a run of 64 or more hex digits;
//   2. runs of 16 or more hex digits anywhere in the path add up to 64 or more;
//   3. the path with ":" removed holds a run of 64 or more hex digits;
//   4. one path segment is a base64url or base64 run of 43 or 44 characters
//      with capitals, small letters and a digit that decodes to exactly 32
//      bytes (one key);
//   5. the value holds PEM text.
// Known gaps, accepted on purpose: a standard base64 key holding "/" reads as
// several path segments and is not joined back; hex pieces shorter than 16
// digits are not added up; base64 pieces are not added up; a key with other
// text in the same path segment (key-<base64>) is not found by rule 4.
export function urlHoldsKey(u) {
  const s = String(u);
  if (s.includes('-----BEGIN')) return true;
  const m = /^[A-Za-z][A-Za-z0-9+.-]*:(?:\/\/)?([^/?#\\]*)([\s\S]*)$/.exec(s);
  const authority = m ? m[1] : '';
  let p = m ? m[2] : s;
  try {
    p = decodeURIComponent(p);
  } catch {
    // not valid percent encoding: the path is checked as written
  }
  if (p.includes('-----BEGIN')) return true;
  const hex64 = /[0-9a-fA-F]{64,}/;
  const segments = p.split(/[/\\?#]/);
  if (authority.split(/[.:@]/).some((x) => hex64.test(x)) || segments.some((x) => hex64.test(x))) return true;
  if (holdsSplitHexKey(p)) return true;
  if (hex64.test(p.replace(/:/g, ''))) return true;
  return segments.some((x) => {
    if (!/^(?:[A-Za-z0-9_-]{43,44}|[A-Za-z0-9+]{43,44}|[A-Za-z0-9_-]{43}=|[A-Za-z0-9+]{43}=)$/.test(x)) return false;
    if (!/[A-Z]/.test(x) || !/[a-z]/.test(x) || !/[0-9]/.test(x)) return false;
    return Buffer.from(x, x.includes('+') ? 'base64' : 'base64url').length === 32;
  });
}

# Add on Declaration Spec v0.2 (draft)

Status: draft, 19 November 2026 (format 0.2 added, then revised after a review on the same day; section 8a, checking a registry listing by name, added the same day; the format 0.1 text dates from 18 November 2026). Published as a draft for comment under the Apache 2.0 licence. Spec ids: `addon-declaration/0.2`, the default for new declarations, defined in section 17 as a list of its differences from 0.1; and `addon-declaration/0.1`, defined in sections 3 to 15, still fully specified and still verifiable, and no longer the default for new declarations.

How to read this document: sections 1 to 16 define format 0.1, with short notes where 0.2 differs. Section 17 holds every rule of format 0.2 that is not a rule of 0.1. A verifier reads the `spec` member of a declaration and applies the rules of that format; a 0.1 declaration is parsed, hashed, signed and verified exactly as before 0.2 existed.

## 1. Purpose

A listing in an MCP registry can change after anyone looked at it. Nothing today lets a publisher state, in a form anyone can check, "for this version of this server, these are the tools, the remote endpoints, the price and the pay address I stand behind".

An add on declaration is a small JSON file that says exactly that, signed with the key the publisher already published to prove their domain namespace to the official MCP Registry. The publisher needs no new key, account or service. Any registry, client or person can check it with the public key in the publisher's DNS or on the publisher's web server, without trusting whoever wrote the verifier or hosts the file.

v0.1 covers MCP servers whose registry name is in a domain namespace (for example `com.example/weather`), and so does 0.2. Section 14 lists what is out of scope.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 2. What the registry already publishes (checked 18 November 2026; records per string rechecked 19 November 2026)

These facts come from the registry documentation page `https://modelcontextprotocol.io/registry/authentication` and from the registry source, `internal/api/handlers/v0/auth/common.go`, `dns.go` and `http.go` in the `modelcontextprotocol/registry` repository. This spec reuses them unchanged.

| Item | Registry behavior |
|---|---|
| Proof record text | `v=MCPv1; k=<alg>; p=<public key>`, matched by the Go RE2 pattern `v=MCPv1;\s*k=([^;]+);\s*p=([A-Za-z0-9+/=]+)`. In RE2, `\s` is only tab, line feed, form feed, carriage return and space, so in other regex dialects the pattern is written `v=MCPv1;[\t\n\f\r ]*k=([^;]+);[\t\n\f\r ]*p=([A-Za-z0-9+/=]+)` (JavaScript and many others also match vertical tab, U+00A0, U+FEFF and other spaces with `\s`). The captured `k=` value is compared to the algorithm names exactly, with no trimming, so `k=ed25519 ;` is refused |
| Algorithms | `ed25519` and `ecdsap384` only |
| Public key `p=` | standard base64 with padding, decoded with Go `base64.StdEncoding.DecodeString` (not `Strict()`): padding is required and nothing may follow it, but nonzero unused bits in the last character are accepted. `ed25519`: the 32 byte raw key. `ecdsap384`: the 49 byte compressed point, first byte `0x02` or `0x03` |
| Signature form | `ed25519`: 64 bytes, no prehash. `ecdsap384`: 96 bytes `r` then `s` (not DER), over SHA 384 of the message |
| DNS method | TXT record on the apex of the domain, not under a selector. Every MCPv1 record found is tried. 5 second limit, no retry. Grants the namespace `reverse(domain)` and every namespace that starts with `reverse(domain) + "."` (the registry's permission pattern is `<reverse(domain)>.*`) |
| HTTP method | `GET https://<domain>/.well-known/mcp-registry-auth`, `Accept: text/plain`, `User-Agent: mcp-registry/1.0`, status 200 only, redirects not followed, body at most 4096 bytes, surrounding whitespace trimmed. At most 2 attempts of 10 seconds each, 15 seconds overall; statuses 408, 429 and 5xx are treated as transient and retried. The dialer drops resolved addresses in loopback, private, link local, multicast, unspecified or CGNAT ranges (and the IPv6 ranges `2002::/16`, `64:ff9b::/96`, `64:ff9b:1::/48`, `fec0::/10`), then dials the remaining public addresses in turn, 3 seconds each, and uses the first one that connects. It fails when every address is blocked or every public address fails. Grants only the exact namespace `reverse(domain)` |
| Records per string | Every proof record in a string is read, not only the first: `ParseMCPKeysFromStrings` in `common.go` uses Go `FindAllStringSubmatch` (registry PR 1849, merged 12 November 2026; read at main commit `115f852` on 19 November 2026). A string is one TXT record as the resolver returns it, or the whole `mcp-registry-auth` body after trimming. The login signature is checked against every valid key found and is accepted if any of them matches, so one HTTP body or one TXT record can hold several proof records; the registry documentation now says to put each record of an HTTP body on its own line. The reference verifier also reads every match (section 9) |
| Refused domains | IP literals, single label names, `github.io` and its subdomains |
| Server name | pattern `^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$`, 3 to 200 characters (server.json schema 2025-12-11) |
| Publisher metadata | `_meta["io.modelcontextprotocol.registry/publisher-provided"]` is kept, at most 4096 bytes of JSON; other `_meta` keys are dropped |
| Reading one listing (checked 19 November 2026) | `GET /v0.1/servers/{serverName}/versions/{version}` in `docs/reference/api/openapi.yaml`, with the name and the version URL encoded in the path (`com.example%2Fmy-server`); `version` may be `latest`. The answer is `{ "server": <server.json>, "_meta": { "io.modelcontextprotocol.registry/official": { "status", "publishedAt", "updatedAt", "statusChangedAt", "isLatest" } } }`, and 404 when the server or version is not found. The publisher metadata above is inside `server._meta`. The API changelog calls `/v0.1/` stable (additive changes only); `/v0/` answers the same today. `official-registry-api.md` says that `latest` can be a deprecated version, so a client checks `status` |
| Remotes (checked 19 November 2026) | The registry page on publishing remote servers says the registry does not verify that the publisher controls the remote URL, or that it is on the namespace's domain, whatever the authentication method |
| Intended readers (checked 19 November 2026) | The registry documentation (`/registry/about`) says the registry is meant to be read by downstream aggregators, on a regular but infrequent basis (for example once an hour), and is not meant to be read directly by host applications. It gives no rate limits |

`reverse(domain)` reverses the dot separated labels: `example.com` gives `com.example`.

## 3. The declaration

A declaration is one JSON object, valid UTF-8, at most 16384 bytes as stored (the limit is on the file bytes, before decoding). Member order and whitespace in the file have no meaning; the signature covers the canonical form (section 5).

| Member | Required | Rule |
|---|---|---|
| `spec` | yes | exactly `"addon-declaration/0.1"`; in format 0.2, exactly `"addon-declaration/0.2"` (section 17) |
| `name` | yes | server name exactly as in the registry, same pattern and length as the registry. In addition, neither the namespace nor the server part may be `.` or `..`, because they would be dot segments in the paths of section 8 |
| `version` | yes | server version as in the registry: string, 1 to 255 Unicode code points (counted as JSON Schema `maxLength` counts, which is how the registry schema limits it), no unsafe characters (defined below). The registry itself does not refuse unsafe characters, so a registry version that holds one cannot be declared |
| `toolsHash` | yes in 0.1; refused in 0.2 | `"sha256:"` and 64 lowercase hex digits, see section 4 |
| `toolSetDigest` | refused in 0.1; yes in 0.2 | the two digests of mcp-tool-set-digest/1, see section 17.1 |
| `remotes` | no | array of 1 to 16 objects with exactly `type` (`"streamable-http"` or `"sse"`) and `url` (an https URL as defined below, at most 2048 characters). Same meaning as `remotes` in server.json, without headers or variables. A URL template such as `https://{tenant}.example.com/mcp` is not an https URL under this rule |
| `payment` | no | array of 1 to 16 payment options, see below |
| `contact` | yes in 0.1; no in 0.2 | at most 256 characters: a mailto address or an https URL, both as defined below (the same rule in 0.2 when present) |
| `issuedAt` | yes | UTC time, exactly `YYYY-MM-DDTHH:MM:SSZ`, a real calendar date and time (second `60`, a leap second, is refused) |
| `expiresAt` | no | same form, later than `issuedAt` |
| `previous` | no | declaration hash (section 7) of the declaration this one follows |
| `key` | yes | object with exactly `method`, `domain`, `alg`, `id`, see below |
| `signature` | yes | standard padded base64 of the signature, section 6 |

Payment option members:

| Member | Required | Rule |
|---|---|---|
| `network` | yes | a `CAIP-2` chain id, for example `eip155:8453`. Pattern `^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$` |
| `asset` | yes | the asset identifier on that network (for an EVM token, its contract address), 1 to 128 printable ASCII characters, no spaces. Exactly three uppercase letters (`^[A-Z]{3}$`, the ISO 4217 form x402 version 2 uses for a fiat price) is refused, because fiat prices are out of scope |
| `payTo` | yes | the address that receives payment, same character rule |
| `amount` | yes | price of one tool call, as a base 10 integer string in the asset's smallest unit (for a token with 6 decimals, `"10000"` is 0.01 of the token). 1 to 78 digits, no decimals, no exponent, no leading zeros. Pattern `^(0\|[1-9][0-9]{0,77})$` |
| `tool` | no | a tool name, 1 to 128 UTF-16 code units, no unsafe characters; if present the option applies only to that tool |

The amount is a string so no verifier has to round a number. The field names follow the payment requirements of x402 version 2 (`network` as a CAIP-2 id, `asset`, `payTo`, `amount` in the smallest unit; x402 version 1 used `maxAmountRequired` and named networks instead) so a client can compare what a server asks for at call time with what was declared. `amount` has the meaning of the x402 `exact` scheme: the price of one call. A server that asks for payment under another scheme is not covered by a v0.1 payment option.

Key members:

| Member | Rule |
|---|---|
| `method` | `"dns"` or `"http"`: where the key is published, as in the registry. Signed and binding: the key is looked up by this method and its namespace rule applies (sections 9 and 11) |
| `domain` | the domain holding the key: lowercase, 2 or more labels, at most 253 characters; each label 1 to 63 characters of `a-z`, `0-9` and inner hyphens (pattern `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`); the last label not all digits (this refuses IPv4 literals); not `github.io` or below it |
| `alg` | `"ed25519"` or `"ecdsap384"` |
| `id` | `"sha256:"` and the lowercase hex SHA 256 of the raw public key bytes, that is the base64 decoded `p=` value of the proof record (32 bytes or 49 bytes) |

A declaration with any member not listed here, at any level, is malformed. New members need a new spec id. Each format accepts only its own members: `toolSetDigest` in a 0.1 declaration and `toolsHash` in a 0.2 declaration are malformed, and so is a declaration that carries both.

Definitions used above:

* Unsafe characters: every character of Unicode general category Cc (U+0000 to U+001F, U+007F, U+0080 to U+009F) and Cf (format characters, which include the bidirectional controls U+061C, U+200E, U+200F, U+202A to U+202E and U+2066 to U+2069, the zero width characters U+200B to U+200D and U+2060 to U+2064, U+00AD, U+180E, U+FEFF and the tag characters), categories Zl and Zp (U+2028, U+2029), Co (private use) and Cn (unassigned), the 66 noncharacters (U+FDD0 to U+FDEF and the last two code points of every plane), every code point with the property Default_Ignorable_Code_Point, every code point of the tag block U+E0000 to U+E007F whether assigned or not, and lone surrogates. Default_Ignorable_Code_Point adds the invisible characters outside Cf: the variation selectors U+FE00 to U+FE0F and U+E0100 to U+E01EF (256 of them, enough to hide arbitrary bytes after a visible character), the Hangul fillers U+115F, U+1160, U+3164 and U+FFA0, U+034F, U+17B4, U+17B5, U+180B to U+180F, and the reserved ranges U+FFF0 to U+FFF8 and U+E0000 to U+E0FFF. These can change what a terminal or interface shows, or carry hidden text, without changing the bytes that were signed: `1.0.0` followed by U+3164 displays as `1.0.0` but is another version. A regex engine with Unicode properties can write the set as `[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cn}\p{Noncharacter_Code_Point}\p{Default_Ignorable_Code_Point}\u{E0000}-\u{E007F}]` plus lone surrogates. Cn depends on the Unicode version an implementation uses: a code point assigned in a later version is unassigned, and so refused, by an implementation on an earlier one. Two verifiers can disagree only about such code points, so a publisher SHOULD keep `version` and `tool` to characters assigned in Unicode 15.0 or earlier (the field vectors use only code points that are unassigned in every version so far). The reference implementation uses the Unicode version of its Node runtime (Unicode 17.0 on Node 24.22.1).
* https URL: all of these hold. (a) Only RFC 3986 characters: `A-Z a-z 0-9 - . _ ~ : / ? # [ ] @ ! $ & ' ( ) * + , ; =` and `%` followed by two hex digits. This excludes spaces, backslashes, `{`, `}`, `<`, `>`, `"` and all non ASCII text. (b) It starts with `https://` and has a nonempty host. (c) No userinfo: nothing before an `@` in the authority. (d) It is in canonical form: it equals its own serialization by the WHATWG URL Standard (lowercase host, a path of at least `/`, no default port `:443`, no dot segments). Rule (d) removes the inputs that different URL parsers read as different hosts, such as `https://evil.com\@good.com/` and `https:evil.com/`. It also inherits WHATWG details that other URL libraries do not share: for example `https://a.com/?x='` is not canonical (WHATWG percent encodes `'` in the query of special schemes) and `https://a.com/a/%2e%2e/b` is not canonical (WHATWG treats `%2e%2e` as a dot segment). An implementation without a WHATWG URL parser can check itself against the field vectors (section 15), which list these cases.
* mailto address: `mailto:` followed by a local part of `A-Z a-z 0-9 . _ + -` (one or more), `@`, and a domain of two or more labels, each 1 to 63 letters, digits and inner hyphens. This is a deliberately small subset of RFC 6068; an address outside it needs an https contact page instead.

## 4. Tools hash

Input: the ordered list of `tools/list` messages the server sent, one per page, each as JSON text exactly as the server sent it on the wire, before any SDK parsing, validation or normalization (an SDK may drop members it does not know or change values, and the hash covers what the server sent, not what a library kept). The tool list is the `tools` arrays of all pages joined in page order. A single bare array is accepted as the already joined form. With the Streamable HTTP transport a response can arrive as server sent events; the `data:` framing is removed first, and the text hashed is the JSON-RPC message it carried. The reference CLI does not remove the framing itself: it refuses a page that starts with an SSE field (`event:`, `data:`, `id:`, `retry:` or a `:` comment line) and says to save the JSON-RPC message alone. `nextCursor` and every other member of a result outside `tools` are not part of the hash.

A tool that accepts a wrapper reads the array from exactly one place. The accepted inputs are: a bare array; a `tools/list` result, that is an object with `tools` and none of `jsonrpc`, `id` or `result`; or a JSON-RPC response, that is an object with `result` holding a `tools/list` result and no top level `tools`. Any other shape, in particular an object with both `tools` and `result`, or `tools` next to `jsonrpc` or `id`, MUST be rejected: a JSON-RPC client reads only `result.tools`, so a second list elsewhere could be hashed while the client runs the other one. Each page is parsed on its own under section 5 and must have one of these shapes; the nesting limit is counted from that page's `tools` array, whatever wrapper it came in. So the wrapper levels do not count (a JSON-RPC response may hold a `tools` array of 64 levels, 66 in all), and members next to the `tools` array, such as `nextCursor`, `_meta` or the JSON-RPC `id`, are not limited by the 64 level rule because they are not hashed. The other rules of section 5 (UTF-8, duplicate members, lone surrogates, number range) apply to the whole page. As a resource limit only, a verifier MAY refuse a page nested deeper than 512 levels in total; the reference verifier does, with the reason `depth`. The duplicate name rule below applies across all pages.

Canonical form:

1. Each tool MUST be a JSON object with a nonempty string `name`. Two tools with the same `name` make the list invalid (the MCP specification requires unique names). A verifier that receives an invalid list (not parseable under section 5, a duplicate name, a tool that is not an object) reports `tools_hash_mismatch` with the reason, because such a list cannot be the declared one.
2. Sort the tools by `name`, comparing UTF-16 code units (the same order RFC 8785 uses for member names).
3. Serialize the sorted array with RFC 8785 (section 5). Every member of every tool is included as returned: `name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`, `icons`, `_meta` and any other.

`toolsHash = "sha256:" + lowercase hex of SHA 256 over the UTF-8 bytes of that serialization.`

Reasons. Sorting removes a difference that has no meaning (the order a server lists tools in). Including every member means a changed description, schema, annotation or `_meta` entry is a changed hash; a description is what a model reads, so it is part of what the publisher stands behind. A server that puts per session values into tool `_meta` will not produce a stable hash; v0.1 treats that as the publisher's problem to fix rather than leaving any part of a tool unsigned.

The empty list `[]` has a defined hash.

## 4a. Relation to mcp-tool-set-digest/1 (NON NORMATIVE)

This section is NON NORMATIVE. It adds no rule and changes no rule of v0.1.

What `toolsHash` covers. The v0.1 `toolsHash` (section 4) is one value, `sha256:` and lowercase hex, over the RFC 8785 form of the whole tools array, joined across pages and sorted by name. Every member of every tool is included as the server sent it: `name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`, `icons`, `_meta` and any other.

mcp-tool-set-digest/1 (editors' draft of 13 November 2026, `https://github.com/alexar76/mcp-tool-set-digest`) is a separate document that projects observing MCP servers use to compare tool lists. Over the same tools array it defines two digests, each written as `sha256-` and standard base64: a contract digest over one entry per tool holding exactly `name`, `description` (`""` when it is not a string), `inputSchema` (`{}` when it is not an object) and `outputSchema` (only when it is an object), and an extras digest over the object `{"tools": {<name>: <every other member>}}`, with one member for each tool that has at least one other member and none for a tool that has none, which is `null` when no tool has another member.

Why `toolsHash` is in general not comparable with either digest. Both use RFC 8785 and sort tools by UTF-16 code units, as section 4 does, but in general each hashes different bytes. The contract digest leaves out members that `toolsHash` covers and fills in defaults that `toolsHash` does not; the extras digest hashes a different object; and the text forms differ. There is one case where the bytes are the same: when no tool has a member other than the four contract members (the extras digest is then `null`), every `description` is a string, every `inputSchema` is an object and every `outputSchema` present is an object, the two canonical texts are identical, so the `toolsHash` equals the contract digest written as `sha256:` and hex. The empty list is one such case. The input rules differ too: v0.1 refuses repeated member names, integers beyond `2^53 - 1`, literals that underflow or have no double, lone surrogates (section 5) and tools that share a name (section 4), while that document keeps the last repeated member, rounds every number to the nearest double, keeps tools that share a name, and gives an error code in place of a digest for the rest. Outside that case a `toolsHash` cannot be turned into either digest, or either digest into a `toolsHash`, without the tool list itself, and a mismatch between a `toolsHash` and one of them says nothing about the lists.

Comparing. The reference CLI prints both digests of that document for a tool list, labelled as that document labels them (`tool-set-digest`, described in README.md), so whoever holds the list can compare it with records that use those digests. For the tool list of section 15:

```
node bin/addon-declare.js tool-set-digest examples/tools.example.json
```

gives the contract digest `sha256-kPg5tlmErvzQUS4WkIEQscLXmvWdkFLa4vQ7dqH0fdQ=` and the extras digest `sha256-aoHUAjyTPtj0I4RgFX1rt4KRONuWTYAVpmsccm/vRZ0=`, next to the `toolsHash` of section 15.

Intention, now carried out. The 0.1 text of this section stated that the next version of this declaration format was intended to carry those two labelled digests, under the identifier `mcp-tool-set-digest/1`, in place of a third format of its own. Format 0.2 (section 17) does that: its `toolSetDigest` member holds both digests in the `sha256-` and base64 form, so a publisher's signed statement can be compared directly with what observers using that document record. v0.1 keeps `toolsHash` exactly as section 4 defines it, and a 0.1 declaration is checked against it as before.

## 5. Canonical JSON

Canonical form is RFC 8785 (JSON Canonicalization Scheme): members sorted by UTF-16 code units, no whitespace, strings with only the escapes RFC 8785 requires and all other characters as UTF-8, numbers in the ECMAScript shortest round trip form.

RFC 8785 was chosen over a custom form because it is a published standard with independent implementations in many languages and test vectors (its appendix B), and because the declaration and tool schemas are ordinary JSON. Inputs are parsed strictly before canonicalization. A parser for this spec MUST reject:

* input bytes that are not valid UTF-8 (including UTF-16 text); a verifier MUST NOT replace bad bytes and go on
* duplicate member names in one object
* lone UTF-16 surrogates, raw or escaped
* numbers that overflow an IEEE 754 double
* integer literals (no fraction, no exponent) outside the range from -(2^53 - 1) to 2^53 - 1, as I-JSON (RFC 7493 section 2.2) advises: `9007199254740993` would otherwise hash like `9007199254740992`. The rule is about how the literal is written: a plain integer reads as an exact value, and silent rounding would change it, while a literal with a fraction or exponent is already a decimal approximation and is rounded like any other (so `1.8446744073709552e19` is accepted). Some schema generators write the int64 or uint64 limits, such as `"maximum": 18446744073709551615`. The change belongs in the server, not in the saved tool list: change the server so its `tools/list` no longer sends this literal (remove the bound, or write a value within range), then capture the tool list again. Editing `tools.json` alone gives a hash that no client can reproduce, because a client hashes the list as the server sends it, which still holds the literal and is refused
* nonzero literals that round to zero, such as `1e-400`
* anything that is not RFC 8259 JSON (trailing commas, comments, single quotes, leading zeros, `NaN`)
* nesting deeper than 64 levels, where the depth of a value is the number of arrays and objects on its deepest path, counting the outermost one; scalars do not count. `[[1]]` has depth 2. For a declaration the count starts at the declaration object; for a tool list it starts at the `tools` array of each page, and members of a page outside that array are not counted (section 4)

Every other number is the IEEE 754 double it rounds to, as RFC 8785 requires: literals that round to the same double, such as `1E2` and `100.0`, are the same value and hash the same. A client that keeps more precision than a double for numbers with a fraction or exponent has to round them the same way before comparing.

A leading byte order mark is ignored. No Unicode normalization is applied: `"é"` written as one code point and as `e` plus a combining accent are different strings.

## 6. Signing

Signing input, exactly:

```
UTF-8 bytes of "addon-declaration/0.1"
one byte 0x0A
UTF-8 bytes of the RFC 8785 form of the declaration with the "signature" member removed
```

That is the signing input of a 0.1 declaration. For every format the first line is the declaration's own `spec` member, so a 0.2 declaration starts with `addon-declaration/0.2` (section 17.2), and an object whose `spec` names no known format has no signing input.

The signature is made with the private key matching `key.alg` and `key.id`:

* `ed25519`: Ed25519 (RFC 8032) over the signing input, 64 bytes.
* `ecdsap384`: ECDSA on curve `P-384` with SHA 384 over the signing input, encoded as 96 bytes `r` then `s`, each left padded to 48 bytes.

These are the registry's own signature forms, so any tool that can sign a registry login can sign a declaration. `signature` is the standard padded base64 of those bytes, with no line breaks; a verifier MUST reject base64 that does not decode and encode back to the same text.

The spec id prefix separates declaration signatures from registry login signatures made with the same key. A registry login signs a bare timestamp string; a declaration signing input starts with its own spec id (`addon-declaration/0.1` or `addon-declaration/0.2`) and a line feed, so neither can be accepted as the other (section 12, T4).

## 7. Declaration hash and history

`declarationHash = "sha256:" + lowercase hex of SHA 256 over the signing input` (section 6).

The hash covers everything the signature covers, including the key, and not the signature bytes. ECDSA signatures are malleable (a second valid signature can be derived from the first without the key), so a hash over the signature would let anyone produce a copy of the same declaration with a different hash. Leaving the signature out avoids that.

A declaration MAY carry `previous`, the declaration hash of the declaration it follows. A chain is a list of declarations for one `name`, each pointing at the one before, with `issuedAt` not decreasing. A new declaration is issued for each new version, and also within a version when a remote, payment option or contact changes.

The link check (result `chain_mismatch` when it fails) checks that the earlier declaration passes the parsing and member rules of sections 3 and 5 for its own format (a malformed earlier declaration fails the link check), that its format is not a later one than this declaration's (section 17.5: a 0.2 declaration may follow a 0.1 one, and a 0.1 declaration may not follow a 0.2 one), that `previous` equals its declaration hash, that the names are equal, and that the earlier one was not issued later. The verifier also checks the earlier signature if it holds the key the earlier declaration names (`alg` and `id`): when both declarations name the same key, and when the keys differ but the earlier key is among the keys the verifier was given offline or found in its lookup (with the record kind rule of section 9 applied to the earlier declaration's `key.method`). A failure is `chain_mismatch`. When the keys differ and the earlier key is not at hand (it may have been rotated out, section 10), the earlier signature is not checked. If the keys differ, the output MUST say that the key changed between the two declarations, MUST say whether the earlier signature was checked, and SHOULD say when `key.method` or `key.domain` changed.

Output for programs MUST carry the key change as a structured value, not only as text, and MUST NOT list a link across a key change in the same words as a link under one key. The reference verifier's `--json` output holds, after a link check that passed:

```json
"chain": {
  "previous": "sha256:<hex>",
  "keyChanged": true,
  "previousKey": { "method": "dns", "domain": "example.com", "alg": "ed25519", "id": "sha256:<hex>" },
  "previousSignature": "not_checked",
  "keyLocationChanged": false,
  "previousFormat": "addon-declaration/0.1"
}
```

`previousSignature` is `checked` or `not_checked`. `previousFormat` is the `spec` of the earlier declaration (added with format 0.2; when it differs from the format checked, the text output also has a note). Under one key the `checked` list says `chain link to previous declaration`; across a key change it says `chain link (hash, name and order only; the key changed, so this does not show continuity)`. A program that follows history reads `chain.keyChanged` and treats `true` as a new publisher until it has other evidence (section 10).

A link proves only what the newer signer chose to point at. `previous` is a public hash, so anyone who can sign for the namespace can point at the real history, or at an invented earlier file. A link across a change of key says nothing about whether the same holder signed both declarations (section 10).

## 8. Where declarations are served

A publisher SHOULD serve each declaration at these paths under `https://<key.domain>/.well-known/addon-declaration/<namespace>/<server>/`, where `<namespace>/<server>` is `name` as written:

```
by-hash/<hex>.json         every declaration ever issued, <hex> being its declaration hash without "sha256:"
versions/<version>.json    the newest declaration for that version
latest.json                the newest declaration of the newest version
```

`<version>` is `version` percent encoded byte by byte over its UTF-8 form: every byte outside the RFC 3986 unreserved set (`A-Z a-z 0-9 - . _ ~`) becomes `%` and two uppercase hex digits. So `1.0.0+build:7` becomes `1.0.0%2Bbuild%3A7`. Versions sit in their own folder so that a version named `latest` cannot collide with `latest.json`.

A publisher who serves declarations at all MUST keep every declaration it issued at its `by-hash` path. That path is what makes the chain walkable: a client holding `latest.json` reads `previous`, strips `sha256:`, and fetches `by-hash/<hex>.json`, and so on back. `versions/<version>.json` can be overwritten when a declaration is reissued within a version (section 7), but the `by-hash` copies stay. A file fetched from a `by-hash` path whose declaration hash differs from the path is not the one asked for. A client MUST check that a fetched declaration's `name` equals the name it asked for, and for a `versions/` path that its `version` equals the version it asked for; a file that differs is not the one asked for, whatever its signature.

A publisher MAY also point to it from server.json, inside the only `_meta` key the registry keeps:

```json
"_meta": {
  "io.modelcontextprotocol.registry/publisher-provided": {
    "addonDeclaration": {
      "url": "https://example.com/.well-known/addon-declaration/com.example/weather/by-hash/24049ba84d92f99d49ba09d755a7c22e1b1d476288752fe43c772937aff9f9d3.json",
      "hash": "sha256:24049ba84d92f99d49ba09d755a7c22e1b1d476288752fe43c772937aff9f9d3"
    }
  }
}
```

The pointer is a convenience and is not trusted: the declaration's validity comes only from its signature and the published key. There is no loop, because the declaration does not reference server.json, so its hash is known before server.json is published. The pointer counts toward the registry's 4096 byte limit on publisher metadata.

The pointer is the member `addonDeclaration` of the publisher metadata, an object with exactly the members `url` (a string) and `hash` (a declaration hash, section 7). Its `url` SHOULD be the by-hash path above, on the domain the namespace names, because a client that follows the rules of section 8a fetches nothing else. A version of a server can be published only once, so a pointer names the declaration that was current at publication; a newer declaration for the same version is found next to it (section 8a).

Where the file was fetched from does not matter to verification. A copy kept by a registry, a client cache or an archive verifies the same way. The fetch rules of section 8a decide which requests a client makes, not whether a file verifies.

## 8a. Checking a listing by name

Added 19 November 2026. This section says what a client does with a registry listing that may point to a declaration, as the reference command `addon-declare check-listing` does it. Rules written with MUST or MUST NOT are client behaviour that closes a named attack (T6, T12, T14, T18, T19, T20); the rest is reference behaviour, which a client MAY do differently. Section 11 lists the result states.

Order. A client MUST run the steps in this order and report the state of the first one that fails, so that two clients give the same state for the same answers: the registry read (`registry_not_found`, `registry_unreachable`, `registry_response_invalid`); the pointer (`no_declaration`, `pointer_malformed`, with `namespace_out_of_scope` decided from the name before the registry is read); the fetch rules (`pointer_refused`); the fetch and the hash (`declaration_unreachable`, `declaration_not_the_named_one`); the rules of the declaration's own format (`malformed`); the listing match (`listing_mismatch`); verification by section 11 (the states of the first table there); newer declarations (`listing_mismatch` for a newer declaration in force, below); the tool check (`tools_hash_mismatch`, `tools_fetch_failed`).

Reading the listing. The reference command reads one listing with the get by name endpoint of the registry API (section 2): `GET <base>/v0.1/servers/<name>/versions/<version>`, with the name and the version each percent encoded as one path segment by the rule of section 8 (`com.rtlpdf%2Farabic-pdf`). `<version>` is a version or `latest`. It reads the answer under the strict rules of section 5, at most 262144 bytes, with no redirects, and refuses an answer whose `server.name` is not the name asked for, or whose `server.version` is not the version asked for (`registry_response_invalid`). A 404 is `registry_not_found`; the registry also answers 404 for a deleted version, because `include_deleted` is false by default in its OpenAPI file. A failed read or another status is `registry_unreachable`. It reports `publishedAt`, `status` and `isLatest` from the registry's own `_meta` and notes a status other than `active` (for example `deprecated`); such a status does not change the state or the exit code. Every read of a check other than the tools fetch shares one time limit of 90 seconds, on top of the limit of each request; a read that would start after it is not sent and is reported as failed for that reason. Only the registry host given (by default `https://registry.modelcontextprotocol.io`) is contacted for this read, over https; `http://127.0.0.1:<port>` and `http://localhost:<port>` are accepted for local test doubles, and are then dialed on loopback addresses only. The registry asks host applications to read it through aggregators (section 2), so the command is meant for a check by hand; a client that checks many listings reads them from an aggregator or a mirror that implements the same API.

The pointer. Only `server._meta["io.modelcontextprotocol.registry/publisher-provided"].addonDeclaration` names a declaration (section 8); the registry's own `_meta` next to `server` is not read for it, and other members of the publisher metadata are ignored. A listing without `server._meta`, without publisher metadata or without `addonDeclaration` names no declaration: `no_declaration`, which is a result and not an error. A `server._meta` that is present and not a JSON object, publisher metadata that is not a JSON object, or an `addonDeclaration` that is not an object with exactly `url` (a string) and `hash` (`sha256:` and 64 lowercase hex digits): `pointer_malformed`. In either case nothing is fetched. The flat member name is the one the live listing in the example at the end of this section uses. A reverse DNS key of its own for the pointer inside the publisher metadata is an open question (section 14); no such name is defined, and a client reads only `addonDeclaration` until a later version defines one.

Namespaces. A name in the namespace `io.github` or `io.github.*` is out of scope (section 14): `namespace_out_of_scope`, decided from the name before the registry is read.

Fetch rules. A client MUST NOT fetch a pointer URL unless all of the following hold; otherwise the result is `pointer_refused` and nothing is fetched.

1. `url` is an https URL under the rule of section 3 (canonical form, no user name or password).
2. Its host is a domain whose key could prove the listing's namespace under section 11 step 2: `reverse(namespace)` itself, or a parent of it with two or more labels (a dns key there covers the namespace). For `com.rtlpdf` that is `rtlpdf.com` and nothing else; for the sub namespace `com.example.sub` it is `sub.example.com` or `example.com`. A namespace that names no valid domain allows no host.
3. `url` is exactly `https://<host>/.well-known/addon-declaration/<name>/by-hash/<hex>.json`: the by-hash path of section 8 for the listing's name as written and the pointer's own hash, with no port, query or fragment.

The fetch itself MUST use only public unicast addresses, dialed as checked, as section 9 requires for the key lookup; MUST NOT follow a redirect (a 3xx is an answer); and MUST stop reading after 16384 bytes, the size limit of section 3. The reference command sends `Accept: application/json` and makes at most 2 attempts within 15 seconds. A status other than 200, or a fetch that could not be completed (including a refused address): `declaration_unreachable`. A body over 16384 bytes, a body that is not a declaration, or a declaration whose declaration hash (section 7) is not the pointer hash: `declaration_not_the_named_one`. A client MUST compare the hash before it uses anything from the file, because the hash is the only link between the listing and the file: a site that serves another declaration under the path (an older one, or one for another version) must not be read as the one the listing names.

Against the listing. A client MUST check that the declaration's `name` and `version` equal `server.name` and `server.version` of the listing. It MUST also check that the listing's remotes and the declared remotes are the same set, both ways: each listing remote is compared as its `type` and the WHATWG serialization of its `url` (section 11, "Comparing remotes") with a declared `type` and `url`, and a listing remote that is a URL template, is not https, or carries a user name or password matches no declared remote. The registry does not check remotes (section 2), so the listing's remote is the one a client would connect to, and the declaration is the publisher's signed statement about it. Any difference: `listing_mismatch`. The reference command checks this before the key lookup, so a listing that does not match causes no further request.

Verification. The declaration is then verified by steps 1 to 5 of section 11, exactly as `verify` does (the same code in the reference implementation), with a live key lookup by `key.method`. A failure gives its own state and exit code (`malformed`, `invalid_signature`, `key_not_found` and the others of section 11), with one exception: a declaration that fails only step 5, the time window (`expired` or `not_yet_valid`, after its signature verified with the published key), still goes on to the newer declarations below, because a listing's pointer cannot change while a publisher renews a declaration for the same version (section 7). If a newer declaration is put in force there, the result is `verified_newer_declaration` and the output says that the named declaration has expired; otherwise the time window state is the result. Any other failure ends the check, and no newer declaration is read: a newer one cannot repair a signature, and a link across a change of key is refused anyway (section 10), so after a rotation that removed the old key, a listing version whose pointer names a declaration under the old key gives `key_not_found`, and only a new listing version can point to a declaration under the new key. Step 6, the tool check, runs on the declaration in force, below.

Newer declarations. A listing's pointer cannot change after publication, while section 7 issues a new declaration within a version when a remote, payment option or contact changes, and section 17.5 lets a 0.2 declaration follow a 0.1 one for the same version. The reference command therefore also reads `versions/<version>.json` and `latest.json` in the folder of the by-hash URL (section 8), under the same fetch rules. A file there is put in force in place of the declaration the listing names only when all of these hold:

* it is a declaration that passes section 3 for its format, with a declaration hash other than the pointer hash, and with the listing's `name` and `version` (a `latest.json` for another version is reported and set aside);
* its `previous` history reaches the pointer hash within 8 links. Each earlier declaration is fetched from its by-hash path in the same folder, and a client MUST accept it only when its declaration hash is the hash asked for, it passes section 3 for its format and its `name` is the listing's, and MUST check that a `previous` it follows is a declaration hash (`sha256:` and 64 lowercase hex digits) before it builds the next path from it. A substituted file, a loop, a file that breaks its format or a `previous` of any other form ends the walk, so every read stays at a fixed by-hash path of the folder (T18);
* each declaration on the way verifies under section 11 with the one it follows given as its earlier declaration (the link check of section 7, which refuses a 0.1 declaration after a 0.2 one, section 17.5). Only the newest one is checked against the clock (step 5); the ones between it and the declaration the listing names were superseded by it, so their own `expiresAt` does not set the newest aside;
* no link crosses a change of key or of key location. A client MUST NOT accept a change of key because a chain link exists (section 10), so such a file is reported (`key_changed`) and not put in force.

A file that fails a condition is reported with its reason and its result (`not_chained`, `key_changed`, `invalid`, `expired`, `not_yet_valid`, `unreachable` or `other_version`) and set aside; the declaration the listing names stays in force. When both files qualify and one follows the other, the later one is used; when they do not follow one another (a fork in the history), the one at `versions/<version>.json` is used and the output says so. The declaration put in force is the publisher's signed statement for this version now, so its remotes are compared with the listing as above: when they differ, the result is `listing_mismatch` and the file is reported as `remotes_differ`, not set aside. Otherwise the result is `verified_newer_declaration`, and the output names both declarations and the history walked.

What this shows, and what it does not. Whoever runs the publisher's web server chooses which files it serves, and so chooses which signed declaration on the history is in force: it can hold back the newest one and serve a superseded one that the key holder also signed. For a key published by the http method the web server holder is the key holder, so this changes nothing; for a dns key they can be different parties. Nothing unsigned can be put in force and a change of key is refused, so this is a rollback within the publisher's own signed history, bounded only by the `expiresAt` of the declaration served. The output therefore calls the declaration in force the newest one the site served, not the newest one that exists. This narrows T6 for a client that reads the publisher's site, and it does not show that no newer declaration exists (section 13).

Tools. With saved tool list pages (`--tools`), the tool check of section 11 step 6 runs on the declaration in force: the tools hash for 0.1, the two digests for 0.2 (section 17.3). With `--fetch-tools` the reference command reads the tool list itself, after the declaration in force verified, from the first `streamable-http` remote that declaration declares and the listing names. A client MUST NOT send such a request to a remote that is not in a declaration it verified (T19). The command acts as a client of MCP revision 2026-07-28 that also speaks the earlier revisions, following the backward compatibility rules of that revision (`basic/transports/streamable-http` and `basic/versioning`, read 19 November 2026):

1. It POSTs `tools/list` with the per request metadata of 2026-07-28 in `params._meta` (`io.modelcontextprotocol/protocolVersion` set to `2026-07-28`, `io.modelcontextprotocol/clientInfo`, and an empty `io.modelcontextprotocol/clientCapabilities`) and the headers `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method: tools/list`, `Content-Type: application/json` and `Accept: application/json, text/event-stream`. Revision 2026-07-28 has no session and no `initialize`.
2. A server that answers with a 4xx status without a recognized modern JSON-RPC error (codes `-32020`, `-32021` and `-32022`, or `-32601` with a 404) speaks an earlier revision, as the dual era rule of the versioning page says. The exceptions are 401, and 403 with a `Bearer` challenge, which ask for authorization (below), and 408 and 429, which ask the client to come back later and end the fetch. The deprecated HTTP+SSE transport, which the streamable-http page probes with a GET after a 404 or 405, is not tried. The command then POSTs `initialize` with protocol version `2025-11-25`, keeps the `Mcp-Session-Id` header if the answer has one (visible ASCII only), POSTs `notifications/initialized`, POSTs `tools/list` with the `MCP-Protocol-Version` the server negotiated and the session header, and ends a session with DELETE, as revision 2025-11-25 says. An `UnsupportedProtocolVersionError` (`-32022`) that lists `2025-11-25`, `2025-06-18` or `2025-03-26` leads to the same flow with that version; one that lists none of the versions the command speaks ends the fetch.
3. It follows `nextCursor` for at most 16 pages and stops on a repeated cursor. It reads an `application/json` answer, or takes the JSON-RPC response to its request from a `text/event-stream` answer (notifications and comments before it are skipped), and gives each page to the tool check as the server sent it: the body, or the data of that event (section 4).
4. Every request goes through the fetch rules above (public addresses, no redirects), with a request body of at most 16384 bytes, an answer of at most 1048576 bytes, 15 seconds per request and 60 seconds in all. It sends no credentials and calls no tool.

A server that answers 401, or 403 with a `Bearer` challenge, asked for authorization: the tool check is reported as not checked for that reason, and the state stays `verified` or `verified_newer_declaration`, so the exit code alone does not show that the tool list was not compared; the text output then says so next to the state, and `tools.check` in `--json` is `not_checked`. Any other failure to read the list, including a list longer than 16 pages and an answer the client cannot use (a `resultType` or a negotiated version that is not a string, for example): `tools_fetch_failed`, and the declaration in force is still verified without a tool list, so the output shows its own checks. A client MUST NOT let a value from the server end the check with an error outside the closed list of states. The output names the protocol version sent and the flow used, because a server can answer differently by protocol version, and a digest can then differ while the server changed nothing (section 17.8). Without `--tools` or `--fetch-tools` the tool check is reported as not run.

Output. The reference command prints one state from the closed list of section 11 with its own exit code, then a line in plain words that says what the state means for this run (for a state passed through from `verify`, which declaration gives it), then the meaning line of `verify` whenever a declaration verified (`verified`, `verified_newer_declaration`, `tools_fetch_failed` and `tools_hash_mismatch`), then the reasons. It goes on with what was checked and what was not (every step of this section that did not run is listed with the state the check stopped at, and the tool check is always listed when it did not run), notes, and one line per request with its HTTP method (and the JSON-RPC method for an MCP request), its status or why it failed (a request refused before connecting is told apart from one that failed), and its URL. Strings from the listing are shown escaped and cut to 200 characters; the `--json` output keeps them whole. Every string taken from the listing, the publisher's site or the MCP server is escaped as section 11 says for display (T14), in the text and in the `--json` output.

The `--json` output is one object with these members: `command` (`"check-listing"`), `state`, `exitCode`, `reasons`; `listing` (`name`, `requestedVersion`, `registry`, `url`, `version`, `publishedAt`, `registryStatus`, `isLatest`, `remoteCount`); `pointer` (`url`, `hash`, or `null`); `fetched` (one entry per request, key lookups and MCP requests included: `purpose`, `method` (the HTTP method, or `TXT` for a dns key lookup), `url`, `status` (`null` when there was no HTTP answer), `bytes` when this command read the body itself (not for key lookups or MCP requests), `error` and `refused` when the request failed, `rpc` (the JSON-RPC method) for an MCP request, and for a dns key lookup the url `dns:<domain> (TXT)`, `domain` and `answered`); `declaration` (the declaration the listing names: `url`, `hash`, `format`, `state` and `verify`, the details of `verify --json`); `newer` (one entry per file read for a newer declaration: `path`, `url`, `status`, `result`, which is `in_force`, `superseded`, `remotes_differ`, `absent`, `unreachable`, `invalid`, `not_chained`, `key_changed`, `expired`, `not_yet_valid`, `other_version` or `same_as_pointer`, and `hash`, `format`, `reason`, `state`, `links`, `chain` and `sameAs` (the path of an identical file read before) when known); `newerSetAside` (true when a valid declaration for this version was read and not put in force); `inForce` (`source`, which is `pointer` or the path read, `url`, `hash`, `format`, `state` and `verify`; `state` is `null` and `verify` is absent when the check stopped before the declaration in force was verified as a whole, as for `listing_mismatch` from a newer declaration, and on `tools_fetch_failed` both are those of a verification without a tool list); `chain` (the history walked, newest first, each `hash`, `format`, `issuedAt` and `url`); `remotes` (`listing`, `declared`, `match`, `onlyInListing`, `onlyInDeclaration`, `listingCount`), and `remotesInForce` of the same shape when a newer declaration was compared; `tools` (`check`, which is `run`, `not_run`, `not_checked` or `failed`; `result` when it ran, which is `match`, `mismatch` or `not_reached` (the declaration in force failed before the tool step); `era`, which is `modern` (revision 2026-07-28, no session) or `legacy` (the `initialize` flow); and `source` (`files` or `remote`), `remote`, `protocolVersion`, `session`, `pages`, `requests`, `reason` and `notes` as they apply); `historToolSets` (for information only, and no state depends on it: `null` when the publisher metadata of the listing has no `dev.modelmarket.histor/tool-sets` member, the member HISTOR, a third party watcher of MCP servers, reads; else `member`, `readable` (true when HISTOR takes a set or the url from it), `problem`, `mtl`, `sets` and `digests` (the sets HISTOR takes: at most 8, each digest in the `sha256-` base64 form and named once, each count an integer from 0 to 5000), `url` (as given), `urlRefused` (why HISTOR does not read that url, such as a host off the domain of the namespace, or `null`), `skipped` (why HISTOR skips an entry), `comparedWith`, `matches`, which is `all`, `some` or `none` as those digests equal the contract digest of the verified declaration in force, or `null` when nothing was compared, and `notCompared`, the reason when nothing was compared); `checked`, `notChecked` (the steps of this section that did not run, and the tool check when it did not run) and `notes`. The top level members are always present; one that does not apply is `null` or an empty list, and inside the objects a member that does not apply is left out or `null`. `chain_mismatch` is never the top level state of a listing check: a broken link ends the walk for that file, which is then reported in `newer` with `state` `chain_mismatch` and set aside.

Example. On 19 November 2026 the listing `com.rtlpdf/arabic-pdf` 1.0.0 was the one listing in the official registry with a pointer. It names a 0.1 declaration by hash, and the publisher's site also serves a 0.2 declaration for the same version, under the same key, whose `previous` is that hash (copies in `examples/live-rtlpdf/`):

```
node bin/addon-declare.js check-listing com.rtlpdf/arabic-pdf --fetch-tools
```

Output as run on 19 November 2026 after review round 5 (exit code 11):

```
verified_newer_declaration: com.rtlpdf/arabic-pdf 1.0.0
  the declaration the listing names verifies; a newer declaration for this version that follows it under the same key, the newest one the publisher's site served, is in force (from versions/1.0.0.json, sha256:919ed174f2c34c1ae788b5c05e56804a273ecc26fe80d6fc11375172ab3cd069)
  meaning: the holder of the named key signed this content. It does not show that the server is safe or that it behaves as declared.
  listing: https://registry.modelcontextprotocol.io/v0.1/servers/com.rtlpdf%2Farabic-pdf/versions/latest (published 2026-11-19T01:16:58.545256Z, status active, latest)
  pointer: https://rtlpdf.com/.well-known/addon-declaration/com.rtlpdf/arabic-pdf/by-hash/9170020c77a92f039806c11f714d1aa6eb50780bdb90c27e52016958045baca6.json
    hash sha256:9170020c77a92f039806c11f714d1aa6eb50780bdb90c27e52016958045baca6
  declaration named by the listing: sha256:9170020c77a92f039806c11f714d1aa6eb50780bdb90c27e52016958045baca6 (addon-declaration/0.1): valid
  newer declaration at versions/1.0.0.json: in force, sha256:919ed174f2c34c1ae788b5c05e56804a273ecc26fe80d6fc11375172ab3cd069 (addon-declaration/0.2)
  newer declaration at latest.json: in force, sha256:919ed174f2c34c1ae788b5c05e56804a273ecc26fe80d6fc11375172ab3cd069 (addon-declaration/0.2), the same declaration as versions/1.0.0.json
  in force: sha256:919ed174f2c34c1ae788b5c05e56804a273ecc26fe80d6fc11375172ab3cd069 (addon-declaration/0.2), from versions/1.0.0.json
  history walked: sha256:919ed174f2c34c1ae788b5c05e56804a273ecc26fe80d6fc11375172ab3cd069 (addon-declaration/0.2) follows sha256:9170020c77a92f039806c11f714d1aa6eb50780bdb90c27e52016958045baca6 (addon-declaration/0.1)
  key source: https://rtlpdf.com/.well-known/mcp-registry-auth (http method)
  key: ed25519 sha256:57b47ffa643b43cc1dedebd1d2438bf5202551175eb289a39fb63e78e808e29c (MCPv1 record, registry login key)
  checked: the served declaration is the one the listing names (its declaration hash equals the pointer hash)
  checked: the listing name and version equal the declaration's
  checked: the listing's remotes equal the declared remotes (https://rtlpdf.com/mcp)
  checked: a newer declaration for this version (versions/1.0.0.json) follows the one the listing names in 1 link under the same key, and declares the same remotes
  checked (declaration in force): name: namespace covered by an http key at rtlpdf.com
  checked (declaration in force): signature
  checked (declaration in force): time window
  checked (declaration in force): tool set digest (mcp-tool-set-digest/1): contract and extras
  checked (declaration in force): chain link to previous declaration
  checked (declaration in force): signature of previous declaration (same key)
  tool set digest: contract match, extras match
  tools: read from https://rtlpdf.com/mcp with MCP protocol version 2026-07-28 (per request metadata, no session), 1 page
  note: the declaration the listing names (0.1) pins its tools with toolsHash and the one in force (0.2) with the two digests of mcp-tool-set-digest/1; the tool list was compared with the declaration in force only, so this does not show whether the tools changed between the two (SPEC.md section 4a)
  request: HTTP 200 GET https://registry.modelcontextprotocol.io/v0.1/servers/com.rtlpdf%2Farabic-pdf/versions/latest
  request: HTTP 200 GET https://rtlpdf.com/.well-known/addon-declaration/com.rtlpdf/arabic-pdf/by-hash/9170020c77a92f039806c11f714d1aa6eb50780bdb90c27e52016958045baca6.json
  request: HTTP 200 GET https://rtlpdf.com/.well-known/mcp-registry-auth
  request: HTTP 200 GET https://rtlpdf.com/.well-known/addon-declaration/com.rtlpdf/arabic-pdf/versions/1.0.0.json
  request: HTTP 200 GET https://rtlpdf.com/.well-known/addon-declaration/com.rtlpdf/arabic-pdf/latest.json
  request: HTTP 200 POST tools/list https://rtlpdf.com/mcp
```

The run made six requests: the listing, the named declaration, the key file, `versions/1.0.0.json`, `latest.json` (the same declaration) and one `tools/list` POST to the remote. The server answered the 2026-07-28 request directly, so no `initialize` was sent.

## 9. Finding the key

The verifier takes `key.method` and `key.domain` from the declaration and looks up the published records by that method, the same way the registry does. A live lookup MUST use `key.method`: the method is signed, and a declaration checked by another method could get a different answer from different verifiers (a dns key proves sub namespaces, an http key does not). A verifier that wants a second opinion (T5) uses a second resolver or an archived record, not the other method.

* `dns`: TXT records at `key.domain` itself. The character strings of one TXT record are joined before matching. No selector names are queried. 5 second limit.
* `http`: `GET https://<key.domain>/.well-known/mcp-registry-auth` with `Accept: text/plain`, status 200 only, no redirects, body at most 4096 bytes, whitespace trimmed, at most 2 attempts of 10 seconds each within 15 seconds overall; statuses 408, 429 and 5xx are retried within those limits, and a body over 4096 bytes or a refused address is not retried (before 19 November 2026 the reference verifier read an oversized body twice, with the same result). For each attempt the verifier resolves the host, drops every address that is not a public unicast address (the ranges the registry refuses, section 2, plus `0.0.0.0/8`, `240.0.0.0/4`, the IPv4 compatible IPv6 range `::/96`, such as `::8.8.8.8`, which also holds `::` and `::1`, and, since 19 November 2026, the special use ranges `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, the IPv4 translated range `::ffff:0:0:0/96`, `100::/64` and `2001:db8::/32`, none of which holds a reachable public host), dials the remaining addresses in order, 3 seconds each, until one connects, and MUST connect only to an address it checked, so that a second DNS answer cannot point the request at an internal host. If no public address remains, the lookup is refused. This is the registry's own rule (section 2), so a domain with a public A record and, say, a unique local AAAA record works for both. The reference verifier sends its own User-Agent, not the registry's; a server, CDN or bot filter that answers differently by User-Agent can give the two different answers.

Every record found is parsed, with the pattern and the `p=` decoding of section 2 (RE2 spaces only; Go's base64 decoding, which accepts nonzero unused bits). Two record kinds are read, with the same syntax and the same key forms:

* `v=MCPv1; k=<alg>; p=<key>`: the registry login record.
* `v=ADKv1; k=<alg>; p=<key>`: a declaration only key. It is read from TXT records by the dns method only. The registry's pattern does not match it, so such a key can sign declarations but cannot log in to the registry. In v0.1 the http method reads only MCPv1 records in `mcp-registry-auth` (every one in the body, section 2), not ADKv1 records.

The `k=` value is compared exactly, as the registry does (no trimming). Records with another algorithm or an invalid key are ignored. The verifier then selects the record whose algorithm equals `key.alg` and whose key id (section 3) equals `key.id`. It MUST NOT try other published keys: the declaration names its key, and a verifier that tried all keys would accept a declaration that names a key the domain does not publish.

Answers and failures are kept apart:

* The domain answered and publishes no matching key: `key_not_found`. For dns this includes NXDOMAIN and an empty answer; for http, a 200 without a matching record, any 3xx (the registry source read for section 2 does not follow redirects either), 404 and 410.
* The lookup could not be completed: `key_lookup_failed`. For dns, a timeout, SERVFAIL, a refused query or any other resolver error; for http, a failed host lookup, a timeout, a connection or TLS error, a refused address, a body over 4096 bytes, and every status not listed above: 408, 429 and 5xx (which the registry retries), and 401, 403, 451 and other refusals, which often come from a CDN, firewall or bot challenge and do not show that the key is absent. This state says nothing about the key; a consumer can retry. The output SHOULD give the status.

NXDOMAIN is treated differently by the two methods on purpose. The dns method asks a name server and gets an answer that says the name does not exist. The http method resolves the host through the system resolver, which reports a missing name and an unreachable name server the same way, so a failed host lookup there is a lookup failure.

Offline: a verifier MAY be given the public key directly (an MCPv1 or ADKv1 record, or a PEM public key). The record kind rules still apply: a declaration whose `key.method` is `http` is not matched by an ADKv1 record (the http method reads only MCPv1), and gives `key_not_found`; a PEM key carries no record kind and is accepted for either method. The signature check is then complete, but the result only shows that the holder of that key signed the declaration. Whether that key is or was published at the domain is the job of whoever supplied it, and the verifier MUST say so in its output. An archive of dated proof records (for example a census that stores the records it observed) is the intended source for checking old declarations offline.

## 10. Keys over time

Rotation with the dns method:

1. Add a second MCPv1 TXT record with the new key; keep the old one. The registry code tries every published record (`VerifySignatureWithKeys`), so both work for registry login. The troubleshooting section of the registry documentation says the same: the registry tries all valid published MCP keys, and another record does not take precedence (read 18 November 2026). The same page also has an older note about a stale record being tried first; this step follows the code and the troubleshooting section.
2. Sign a new declaration with the new key, with `previous` set to the hash of the last declaration signed with the old key. The link keeps the history walkable; it does not prove that the holder of the old key agreed to the new one (see below).
3. Remove the old record.

With the http method the registry reads every record in the file (section 2), and its documentation now says to put each record on its own line, so rotation works as with dns: add the new record on its own line, sign a new declaration, then remove the old record.

A declaration only key (`v=ADKv1`, section 9) rotates the same way, and its records can be added and removed without touching the registry login record.

After the old record is gone, a live lookup of an older declaration returns `key_not_found`. This is intended: a live check answers "does the domain stand behind this key now". To check history, verify offline against an archived copy of the old record.

Revocation is removal of the record. There is no separate revocation list in v0.1. A declaration that was valid when looked up live can still be checked offline later, against an archived copy of the record (section 9); its result says what was signed by which key, not whether the publisher still stands behind it.

If a domain changes hands, or someone takes over its DNS (T5) or a dangling subdomain (T13), the new holder can publish keys and sign declarations, and can also link them to the old history: `previous` is a public hash, so linking costs nothing. A chain link therefore proves only what the newer signer chose to point at, and says nothing about a change of key holder. A client MUST NOT accept a change of key because a chain link exists. What a verifier can show is that the key changed: the link check reports it in text and as a structured value (`chain.keyChanged` in the reference `--json` output, section 7), and a client that remembers the key of the declarations it accepted before can see the change and treat it as a new publisher until it has other evidence. When the verifier also holds the earlier key, for example because both records are published during a rotation, it checks the earlier signature too (section 7); that shows the earlier declaration is genuine, and still not that the holder of the old key agreed to the new one. Formats 0.1 and 0.2 cannot tell a rotation by the same publisher from a new owner. A rotation proof (the old key signs a statement naming the new key id, or the first declaration under a new key carries an endorsement signature by the previous key) is an open question for a later format (section 14).

## 11. Verification procedure and result states

A verifier runs these steps in order and stops at the first failure:

1. Parse strictly (section 5) and check every rule in section 3 for the format the `spec` member names (for 0.2, as changed by section 17.1). A verifier MAY be set to accept only some formats; a declaration of another format then fails here too, with a reason that names its format and the accepted ones, and output for programs MUST tell this refusal apart from a broken file (section 17.4). Failure: `malformed`.
2. Namespace rule. Let `ns` be the part of `name` before `/`, lowercased, and `rev` be `reverse(key.domain)`. The rule is the one of `key.method`, for live and offline checks alike. With `http`, `ns` MUST equal `rev`. With `dns`, `ns` MUST equal `rev` or start with `rev + "."`. So a dns key at `example.com` (`rev` is `com.example`) covers `com.example` and `com.example.sub`, and does not cover `sub.com.example` or `foo.com.example`, which belong to other domains. A namespace that is `io.github` or starts with `io.github.` is out of scope. Failure: `name_domain_mismatch`.
3. Find the key by `key.method` (section 9). The lookup could not be completed: `key_lookup_failed`. No record with matching `alg` and `id`: `key_not_found`.
4. Verify the signature over the signing input. Failure: `invalid_signature`.
5. Time, against the verifier's clock: if `issuedAt` is more than 300 seconds in the future, `not_yet_valid`; if `expiresAt` is present and not later than now, `expired`.
6. If the verifier has the tool list it received from the server, compute its tools hash; if the list is invalid or the hash differs, `tools_hash_mismatch`. For a 0.2 declaration this step compares the two digests of mcp-tool-set-digest/1 instead, and the output says which one differs or could not be computed (section 17.3).
7. If the verifier has the earlier declaration, run the link check (section 7). Failure: `chain_mismatch`.
8. Otherwise `valid`. The output MUST name the format that was checked (since format 0.2 was added; the reference verifier prints a `format:` line and a `format` member in `--json`), MUST name where the key came from and MUST list each of steps 6 and 7 that was not run, whether or not the declaration has `previous`. When step 7 ran across a change of key, the output MUST say so, in text and, for output meant for programs, as a structured value (section 7).

When the check stops at step 6, the reference verifier also lists step 7 as not run (since format 0.2 was added), so a program that gave an earlier declaration can see that the link was not checked.

Namespace comparison ignores case, as DNS does; everything else is compared exactly.

| State | Exit code of `addon-declare verify` | Meaning |
|---|---|---|
| `valid` | 0 | all checks that were run passed |
| `malformed` | 2 | not a declaration of a format the check accepts (0.1 or 0.2, or the formats it was set to accept), or it breaks a rule of its format. A refusal by the format setting alone is a policy refusal, not a broken file; the reference `--json` output then has `formatAccepted: false` (section 17.4) |
| `invalid_signature` | 3 | content or signature changed after signing, or signed by another key |
| `key_not_found` | 4 | the domain answered, and the named key is not published there (or is not the key supplied offline) |
| `expired` | 5 | past `expiresAt` |
| `not_yet_valid` | 6 | `issuedAt` is in the future |
| `name_domain_mismatch` | 7 | the key's domain does not prove the server's namespace |
| `tools_hash_mismatch` | 8 | the tools the server returned differ from the declared ones; for 0.2 also when the received list could not be compared with them (a digest could not be computed, which is not evidence of a change; the check fails closed), and the output says for each digest whether it differs or could not be computed (section 17.3) |
| `chain_mismatch` | 9 | the given earlier declaration is not the one this declaration follows |
| `key_lookup_failed` | 10 | the key lookup could not be completed (timeout, resolver or server error, refused address); nothing is known about the key |

Exit code 1 is reserved for usage and file errors.

Result states of a listing check (section 8a), with the exit codes of `addon-declare check-listing`. The states of the table above other than `valid` are passed through with their own exit codes (2 to 10) when the declaration check gives them; `tools_hash_mismatch` (8) then comes from the tool check of the declaration in force, and `chain_mismatch` (9) is not produced at the top level (a broken link sets that newer file aside). A registry status other than `active`, such as `deprecated`, is a note and does not change the state.

| Listing check state | Exit code of `addon-declare check-listing` | Meaning |
|---|---|---|
| `verified` | 0 | the declaration the listing names is the served file, matches the listing and verifies, no newer declaration was put in force, and every check that was run passed |
| `verified_newer_declaration` | 11 | the declaration the listing names is the served file and matches the listing, and verifies or has only expired; a newer declaration for the same version that follows it under the same key, the newest one the site served, is in force and verifies; every check that was run passed |
| `no_declaration` | 12 | the listing names no declaration (no `addonDeclaration` in its publisher metadata); nothing was verified |
| `pointer_malformed` | 13 | the pointer is not an object with exactly `url` and `hash`, or the hash is not a declaration hash; nothing was fetched |
| `pointer_refused` | 14 | the pointer URL breaks a fetch rule: not a canonical https URL, a host the namespace does not name, or not the by-hash path for this name and hash; nothing was fetched |
| `namespace_out_of_scope` | 15 | an `io.github` namespace; nothing was fetched |
| `declaration_unreachable` | 16 | the pointer URL could not be read: a status other than 200 (a redirect is not followed), a refused address or a network failure |
| `declaration_not_the_named_one` | 17 | the pointer URL serves a file that is not the declaration the pointer hash names, or more than 16384 bytes |
| `listing_mismatch` | 18 | the declaration (or the newer one in force) differs from the listing in name, version or remotes |
| `tools_fetch_failed` | 19 | the declaration verifies, and `--fetch-tools` could not read the tool list from the declared remote (other than a request for authorization, which is reported as not checked) |
| `registry_not_found` | 20 | the registry answered 404 for this name and version, which includes a deleted version |
| `registry_unreachable` | 21 | the registry could not be read, or answered with a status other than 200 or 404 |
| `registry_response_invalid` | 22 | the registry's answer is not strict JSON, has no `server`, or is for another name or version |

A program that reads only the exit code treats 0 and 11 as passed and every other code as not passed.

Display guidance (SHOULD; these are interface rules, not verification steps): an interface that shows a declaration SHOULD show `key.domain` next to the server name, because a declaration proves control of that domain and nothing more (T2). It SHOULD show text taken from a declaration or a tool list with unsafe characters (section 3) escaped, not interpreted.

Comparing remotes: a declared remote URL is in WHATWG canonical form (section 3), while server.json and the registry keep the string the publisher wrote, which may be a bare origin such as `https://mcp.example.com`. A client compares the URL it connects to with a declared remote after WHATWG serialization of both. The reference `init` writes a server.json remote in canonical form when the only differences are a lowercase scheme or host, a dropped `:443` or an added `/` path, and says so; other differences are refused. A remote with a user name or password is refused without repeating the URL, since it may hold a password.

## 12. Threats

T1. Listing changed after review. A registry entry, a remote endpoint, a price or a pay address changes quietly. A declaration binds these to a version under the publisher's key; any change needs a new signature, and a client that keeps the declaration it accepted can see the difference.

T2. A lookalike publisher. A declaration proves control of `key.domain` and nothing more. `com.examp1e` is a different, equally valid domain. See the display guidance in section 11. Lookalike detection is a separate problem.

T3. Stolen key. The holder of the private key can sign any declaration until the record is removed. Reusing the registry key adds no new secret, but it means a key that leaks through declaration signing in CI also lets the thief publish to the registry, and the reverse. A publisher who wants these apart publishes a declaration only key (`v=ADKv1`, section 9), which the registry does not accept for login. Either way, keep the key in a protected CI environment, as the registry's own guidance for CI says, and keep any key file outside the repository and out of version control (the reference CLI reads the key from an environment variable with `--key-env`, or from a file path given to `--key-file`).

T4. Signatures reused across protocols. The registry login signs a timestamp string with the same key. The fixed prefix `addon-declaration/0.1` plus a line feed (`addon-declaration/0.2` for a 0.2 declaration; the prefix is always the declaration's own spec id, see T16 for the formats among themselves) means a declaration signature cannot be a login signature and a captured login signature cannot be a declaration signature. A publisher SHOULD NOT use this key to sign bytes chosen by someone else in any other protocol.

T5. Forged DNS answers. Without DNSSEC, someone on the network path can answer a TXT query with their own key. Use a resolver you trust, ask a second resolver on another network path, or check against an archived record. The http method relies on TLS and the web certificate system.

T6. Rollback. An older declaration that has not expired, or an older one for the same version, can be served again (for example with an earlier pay address). Short `expiresAt` values limit this; a verifier that follows `latest.json` and the chain sees the newer one; a verifier that only has the old file cannot know. v0.1 has no freshness proof. Reading the publisher's site does not give one either: whoever runs the web server chooses which signed declaration of the history it serves at `latest.json` and `versions/`, so with a dns key, where that party need not hold the key, it can hold back the newest declaration and put a superseded one in force for a listing check (section 8a). Only `expiresAt` bounds how old that one can be.

T7. Different tools for different clients. A server can return one tool list to the publisher's hashing step and another to a user. The hash protects only a client that hashes the list it actually received, as sent on the wire. Nothing in the declaration covers what a tool does when called. A server whose tool set legitimately depends on configuration, authorization scope or request headers cannot match one `toolsHash` (in 0.1) or one pair of digests (in 0.2) for every user (section 14). The same holds for the protocol version a client negotiates: a server can send a different list, for example without `outputSchema`, to a client that sends no `MCP-Protocol-Version` header, and neither format says under which protocol version or authorization the publisher read the list it signed (section 17.8).

T8. Parser differences. Two parsers reading one file differently could show one value and verify another. Strict parsing (invalid UTF-8, duplicates, surrogates, number range and precision), the canonical URL rule of section 3, the single accepted shape of a tool list wrapper (section 4) and the closed member list remove the known cases. The field vectors (section 15) let implementations in other languages check that they accept and refuse the same values. The tool list of a 0.2 check is the exception: it is read under the lenient input rules of mcp-tool-set-digest/1, which bring one known case back (T17).

T9. Signature malleability. Handled by leaving the signature out of the declaration hash (section 7).

T10. Resource use. A declaration is at most 16384 bytes, a key response at most 4096 bytes, nesting at most 64 levels, a dns lookup at most 5 seconds, an http lookup at most 15 seconds.

T11. The party running a census or hosting declarations. Verification does not depend on it. It could hide or delay declarations but cannot make a false one verify.

T12. A verifier run as a service. `key.domain` comes from an untrusted file, so a registry, census or client that checks declarations in bulk sends DNS queries and HTTPS requests to hosts an attacker picks. The address rule of section 9 keeps the http method from reaching loopback, private or link local hosts (the registry refuses the same ranges). DNS queries to attacker chosen names remain, as for any resolver use.

T13. Dangling subdomain records. With the dns method a key at `api.example.com` proves `com.example.api`. If `api.example.com` is a CNAME to a host the publisher no longer controls (a deleted cloud resource, an expired service), whoever takes that host can answer the TXT query and sign declarations for the namespace. The registry has the same exposure for login. Publishers should remove CNAMEs to resources they have released.

T14. Terminal and interface tricks. Text from a declaration, a tool list or a key response can hold control or bidirectional formatting characters that move the cursor, hide text or reorder what is shown, and invisible characters that make two different strings look the same. `version` and `payment[].tool` refuse every unsafe character (section 3); everything else is escaped before display (section 11, display guidance). Tag characters and variation selectors can also carry hidden bytes that a language model reading the output would see (the variation selector form is known as emoji smuggling): `version` refuses both, and both are escaped wherever else they occur. The reference CLI escapes every unsafe character taken from input as `\u` escapes, in its text output and in its `--json` output (where the escapes decode back to the same strings, so the JSON stays valid). It does not echo an argument value that looks like key material, refuses an `--out` path or a `--version` value that looks like key material before writing anything, and refuses a server.json remote with a user name or password without repeating it.

T15. A takeover link read by a program. A program that reads verifier output can mistake a link across a key change for continuity if the change is reported only in prose. Section 7 requires a structured value for it and different wording in the list of checks, and section 10 says how a client treats it.

T16. Format confusion and downgrade. A declaration of one format presented as the other, a body that mixes the members of both, a signature made under the other format's prefix, an older 0.1 declaration served to a client that expects 0.2, and a chain that goes back from 0.2 to 0.1. Section 17.6 lists each case and the result it gets.

T17. Lenient digest input. The input rules of mcp-tool-set-digest/1 are more lenient than section 5, so two tool lists that differ in their bytes can have the same digests. A 0.2 signature pins the tools as that document reads them, which is what observers using it record (section 17.3). Two of these leniencies can change what a client acts on, not only how a value is spelled:

* Repeated member names. That document keeps the last value of a repeated member. A client whose JSON parser keeps the first value, or refuses the object, reads another tool definition than the one the digests pin: `"annotations":{"readOnlyHint":true},"annotations":{"readOnlyHint":false}` matches a declaration that signed `readOnlyHint` false, while a first value parser sees true. This is the parser difference that T8 removes for 0.1, back for the tool list of a 0.2 check.
* Tools that share a name. MCP requires unique tool names, and 0.1 refuses a list that repeats one. That document keeps such tools and groups extras by name, so when only one of them has extras, the digests do not pin which one: `annotations` with `readOnlyHint` can move from a tool described as a read only view to one described as deleting everything, with both digests unchanged.

So a verifier MUST report each repeated member name and each tool name that more than one tool carries, in text and, for output meant for programs, as a structured value (section 17.3; the reference verifier gives `toolSetDigest.repeatedMembers` and `toolSetDigest.repeatedNames`), whatever the result of the comparison. A client SHOULD refuse a tool list in which two tools share a name, and SHOULD refuse a list with repeated member names unless its own parser keeps the last value. A publisher's signing tool SHOULD refuse to compute the digests it signs from such a list; the reference `init` does.

One case is closed outright. mcp-tool-set-digest/1 starts at the tools array and does not say how the page around it is read. A member name repeated outside every array of a page (for example two `tools` members, or two `result` members) would let a parser that keeps the first value see a wholly different list than the one digested. A verifier MUST treat such a page as having no digest (section 17.3, `no_digest` with no code), so the check fails closed. A member repeated inside a tool is still read as that document says and reported as above.

T18. A listing as a request forgery vector. Whoever writes a listing (the publisher, or a mirror that serves it, T20) chooses the pointer URL. A client that fetched any URL it found there would send requests, from wherever it runs, to hosts the listing picks: an internal service, a cloud metadata address, a router page, another party's site. Section 8a lets a client fetch only an https URL that is exactly the by-hash path of the listing's own name and hash, on the domain the namespace names or a parent of it, only from public addresses, without redirects and with a 16384 byte limit; the reads for a newer declaration stay in the same folder of the same host, because a by-hash path is built only from a `previous` that has been checked to be a declaration hash, in a file that has been checked against its own hash and format (a `previous` such as `sha256:../../admin?x=` would otherwise reach any path and query on the host). All of these reads share one time limit, so a slow site cannot stretch a check for minutes. What is left is a few requests to fixed paths on a public host of the namespace's own domain. The key lookup that follows reaches `key.domain` under the rules of section 9 (T12).

T19. A tools fetch against a third party remote. A declaration can name an endpoint on another party's host (section 13), and the registry does not check remotes (section 2). A client that reads a tool list from a declared remote sends requests to that host, and a hostile publisher could use many clients to send them. Section 8a sends them only on explicit request (`--fetch-tools` in the reference command), only after the declaration verified, only to a remote that the declaration declares and the listing names, only to public addresses, without redirects, with small request bodies, no credentials and no tool call, and at most 16 pages; the output notes a remote that is not on the key domain. What is left is a few small requests per check to a host the publisher named, which is what any MCP client that connects to that listing would send.

T20. A hostile registry or mirror. A registry, an aggregator or a mirror can answer with any listing: another pointer, other remotes, another version, or no pointer. It cannot make a false declaration verify, because the declaration is checked against the publisher's key and its name, version and remotes against the listing. It can hide a pointer (`no_declaration`), list a remote the publisher did not sign (`listing_mismatch`), point to an older declaration of the same publisher for the same name and version (T6; the newer declaration reads of section 8a narrow this), or not answer. Its answers are read under the strict JSON rules of section 5 with a size limit and refused when they are not for the name and version asked, and every string from them is escaped before it is shown (T14). The person running the check chooses the registry base, and only https is accepted for it, except a loopback http base for local test doubles.

## 13. Limits: what a valid result does and does not show

A `valid` result shows:

* the holder of the key named in `key` signed exactly this content;
* with a live lookup, that key is published now at `key.domain` by `key.method`, and that domain proves the server's namespace under the registry's rules;
* if a tool list was given, it is byte for byte (in canonical form) the declared one; for a 0.2 declaration, that its two digests under mcp-tool-set-digest/1 equal the declared ones, with the limits of section 17.8;
* if an earlier declaration was given, this one names it as its predecessor, and, when the verifier held the key the earlier one names (the same key, or another key among those given or looked up), the earlier one was signed by that key.

It does not show:

* that the server, the publisher or any tool is safe, honest or lawful;
* that the server returns these tools to every client, or that tools behave as described;
* that the remote endpoints are operated by the publisher (a domain can declare an endpoint on someone else's host);
* that the pay address belongs to the publisher, or that a payment request at call time matches (the client has to compare);
* that this is the newest declaration for the server;
* with an offline key, anything about publication at the domain;
* across a change of key, that the same holder signed both linked declarations.

A `verified` or `verified_newer_declaration` result of a listing check (section 8a) shows in addition that the listing the registry gave names this declaration by its hash, that the publisher's site serves it, that its name, version and remotes equal the listing's, and, for `verified_newer_declaration`, that the declaration in force follows the named one under the same key and is the newest one the site served. It does not show that this is the newest one the key holder signed (the site chooses which one it serves, T6), that another registry, mirror or client is given the same listing (T20), that no newer declaration exists beyond the two paths read, that the tool list a client receives later, or under another protocol version or authorization, is the one compared (T7, section 17.8), or anything that the list above says a `valid` result does not show.

## 14. Out of scope in v0.1, and open questions

Format 0.2 leaves every item below as it is, except where an item says otherwise; section 17.9 lists the open questions that 0.2 adds.

* GitHub account namespaces (`io.github.<user>/*`). A count of the official registry's public listing, made for this draft on 18 November 2026 and not published, finds 17,736 of 40,920 active publisher names (43%, names compared without case) proven by a GitHub account; those names hold 36,288 of 65,771 active listings (55%). The registry proves them through GitHub OAuth or GitHub Actions OIDC at publish time, which leaves no public key anyone can check later. Candidate directions, none adopted: a key file at a fixed path in a repository the account owns (proves write access to that repository at fetch time, not account ownership); a signature by a key listed on the account's public GitHub profile (GitHub publishes users' SSH and signing keys, but organizations have none); Sigstore keyless signing tied to a GitHub Actions identity (checkable, but brings a transparency log dependency). Each needs a separate threat review. Until then a declaration for such a name is reported as `name_domain_mismatch` with a reason that says so.
* Keys held in Google Cloud KMS or Azure Key Vault. The registry supports them for login. The signature forms in section 6 are the same, so such a signer can produce a declaration, but the reference CLI only reads local keys.
* Skills, agents and other add on kinds that are not MCP servers in the registry.
* Prompts and resources lists (only tools are hashed).
* Package artifacts (npm, PyPI, OCI). Package registries have their own provenance systems.
* Freshness proofs, transparency logs, and a revocation list.
* Per tool pricing beyond a single `tool` filter, subscriptions, payment schemes other than x402 `exact`, and prices in fiat currency.
* Whether `expiresAt` should be required, and a recommended maximum lifetime (the CLI suggests 180 days).
* Tool sets that change with configuration, authorization scope or headers, and clients that only see SDK processed tools. A candidate for a later format: declare a map from tool name to per tool hash, with `toolsHash` computed over that map, so a client can check the subset it received and name any tool that is undeclared or changed. Not adopted in v0.1 because it changes the signed format and needs its own review. Given the intention of section 4a, the per tool digests of mcp-tool-set-digest/1 (its section 9) are the first thing to look at for this purpose, in place of a map format of this document's own. Format 0.2 signs the two whole set digests of that document and does not sign per tool digests, so this item stays open.
* A declaration only key for the http method (a second well known path). v0.1 offers `v=ADKv1` records with the dns method only.
* A rotation proof, so that continuity across a key change can be shown: the old key signs a statement naming the new key id, or the first declaration under a new key also carries an endorsement signature made with the previous key. A link across a key change would count as continuity only with that proof. Not adopted in v0.1 because it adds a signed member and needs its own review.
* An explicit grammar for the https URL rule (section 3, rule d), so that implementations without a WHATWG URL parser need no such parser.
* The name of the pointer in the publisher metadata (sections 8 and 8a). The flat member `addonDeclaration` is what clients read now. A key of its own in reverse DNS form inside the publisher metadata would avoid a collision with another publisher convention that picks the same flat name; which name, and whether clients should read both for a while, is open. No such name is defined here.
* Special use address ranges for the http method. Since 19 November 2026 the reference implementation refuses `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `100::/64` and the IPv4 translated form `::ffff:0:0:0/96` as additions to the registry's list (section 9), because the listing check of section 8a dials more hosts than the key lookup, and none of these ranges holds a reachable public host. The registry's dialer (Go `net.IP` methods) treats them as public, so a domain whose only addresses are in them can log in to the registry and give `key_lookup_failed` here; no such domain is known. Still open: `192.88.99.0/24` (the deprecated 6to4 relay anycast range) and Teredo `2001::/32`, which are still treated as public.

## 14a. What this asks of the registry

Nothing. Formats 0.1 and 0.2 need no change to the registry, its API, its server.json schema or `mcp-publisher`. It reads records the registry already requires and a `_meta` key the registry already keeps. Points a registry maintainer is likely to raise, and the answers:

* "This turns our short lived login key into a long lived signing key." A publisher who does not want that uses a declaration only key (`v=ADKv1`), which the registry ignores. Reusing the login key is the zero setup option, not a requirement. Declaration signatures cannot be confused with login signatures (T4).
* "Removing a record after rotation breaks old declarations." A live check answers whether the domain stands behind the key now, which is the intended reading; history is checked offline against archived records (section 10). The registry's own advice to remove retired records stays correct.
* "A future move away from static keys (OIDC, KMS, short lived keys) would break this." KMS held keys already sign the same forms (section 14). A registry that stopped publishing static keys would not break existing declarations checked offline, and a declaration only key keeps working because it does not depend on registry login.
* "It covers under half the registry." True for formats 0.1 and 0.2 when counted by listings: in the count of 18 November 2026 made for this draft, GitHub account namespaces hold 55% of active listings (36,288 of 65,771), though they are 43% of active publisher names (17,736 of 40,920). They are out of scope until one of the directions above is reviewed.

## 15. Worked example

Throwaway key used only to make this example (its private half was discarded):

```
v=MCPv1; k=ed25519; p=ArfAqopg2AEFR2nDxSy89dJ3rzBRV0ngw6c43lh8cdw=
key id: sha256:b4f34f91b345d4e995da13820af592d4a99b6e1ba935d01d350027c6b4b6ecb0
```

The publisher of `com.example/weather` would have that record as a TXT record on `example.com`.

Tools from `tools/list` (file `examples/tools.example.json`), in canonical form, sorted by name:

```
[{"annotations":{"readOnlyHint":true},"description":"Active weather alerts for a region.","inputSchema":{"properties":{"region":{"type":"string"}},"required":["region"],"type":"object"},"name":"get_alerts","title":"Get alerts"},{"annotations":{"readOnlyHint":true},"description":"Weather forecast for a place, up to 7 days.","inputSchema":{"properties":{"days":{"maximum":7,"minimum":1,"type":"integer"},"place":{"type":"string"}},"required":["place"],"type":"object"},"name":"get_forecast","title":"Get forecast"}]
```

`toolsHash`: `sha256:46e08db5359e52129f4317a0a8a2d74238c4a1a8c83e379dc227ea939bc0a0fb`

The declaration for version 1.4.0 (file `examples/declaration.example.json`). The pay address and asset are placeholders on the Base Sepolia test network:

```json
{
  "spec": "addon-declaration/0.1",
  "name": "com.example/weather",
  "version": "1.4.0",
  "toolsHash": "sha256:46e08db5359e52129f4317a0a8a2d74238c4a1a8c83e379dc227ea939bc0a0fb",
  "remotes": [{ "type": "streamable-http", "url": "https://mcp.example.com/mcp" }],
  "payment": [
    {
      "network": "eip155:84532",
      "asset": "0x1111111111111111111111111111111111111111",
      "payTo": "0x2222222222222222222222222222222222222222",
      "amount": "10000"
    }
  ],
  "contact": "mailto:security@example.com",
  "issuedAt": "2026-11-18T12:00:00Z",
  "expiresAt": "2027-05-17T12:00:00Z",
  "previous": "sha256:e99b6c16265b87bb1da03d0f4ede46aa18df41d6fd04cb7c5c2bb093ae28f069",
  "key": {
    "method": "dns",
    "domain": "example.com",
    "alg": "ed25519",
    "id": "sha256:b4f34f91b345d4e995da13820af592d4a99b6e1ba935d01d350027c6b4b6ecb0"
  },
  "signature": "8FYnyC6oZZUWWmd2fWlL/cbm2YHAYc0bqO8Nq/sjiBQmXcrLUK5sPkRuhavlISR2IqPuvgDNDkJgb1N7uijqAg=="
}
```

Signing input (the first line, a line feed byte, then one line of canonical JSON):

```
addon-declaration/0.1
{"contact":"mailto:security@example.com","expiresAt":"2027-05-17T12:00:00Z","issuedAt":"2026-11-18T12:00:00Z","key":{"alg":"ed25519","domain":"example.com","id":"sha256:b4f34f91b345d4e995da13820af592d4a99b6e1ba935d01d350027c6b4b6ecb0","method":"dns"},"name":"com.example/weather","payment":[{"amount":"10000","asset":"0x1111111111111111111111111111111111111111","network":"eip155:84532","payTo":"0x2222222222222222222222222222222222222222"}],"previous":"sha256:e99b6c16265b87bb1da03d0f4ede46aa18df41d6fd04cb7c5c2bb093ae28f069","remotes":[{"type":"streamable-http","url":"https://mcp.example.com/mcp"}],"spec":"addon-declaration/0.1","toolsHash":"sha256:46e08db5359e52129f4317a0a8a2d74238c4a1a8c83e379dc227ea939bc0a0fb","version":"1.4.0"}
```

Its declaration hash is `sha256:24049ba84d92f99d49ba09d755a7c22e1b1d476288752fe43c772937aff9f9d3`. Its `previous` is the hash of `examples/declaration-1.3.0.example.json`.

Check it offline:

```
node bin/addon-declare.js verify examples/declaration.example.json --pubkey examples/example-key.txt --tools examples/tools.example.json --previous examples/declaration-1.3.0.example.json --now 2026-11-18T13:00:00Z
```

Output as run on 18 November 2026, with the `format:` line the verifier has printed since format 0.2 was added (19 November 2026):

```
valid: com.example/weather 1.4.0
  format: addon-declaration/0.1
  key source: offline: supplied by the person running the check; publication at the domain was not checked
  key: ed25519 sha256:b4f34f91b345d4e995da13820af592d4a99b6e1ba935d01d350027c6b4b6ecb0 (MCPv1 record, registry login key)
  checked: name: namespace covered by a dns key at example.com
  checked: signature
  checked: time window
  checked: tools hash
  checked: chain link to previous declaration
  checked: signature of previous declaration (same key)
  meaning: the holder of the named key signed this content. It does not show that the server is safe or that it behaves as declared.
```

Change `payTo` by one character and the same command returns `invalid_signature` with exit code 3. A live check (`--dns`) of this example would return `key_not_found`, because `example.com` does not publish this key (not run here: the example was checked offline only).

Under section 8 this declaration is served at `.../com.example/weather/by-hash/24049ba84d92f99d49ba09d755a7c22e1b1d476288752fe43c772937aff9f9d3.json`, `.../versions/1.4.0.json` and `.../latest.json`.

### Conformance vectors

The folder `vectors/` next to this file holds fixed inputs for independent implementations. `vectors/manifest.json` has three lists.

* `declarations`: the declaration file, the public key record, the clock time, the optional tool list and earlier declaration, and the expected state, exit code and declaration hash. The set covers both algorithms, both key methods, MCPv1 and ADKv1 records (including an http key that an ADKv1 record does not match), and every state that can be reached offline (`valid`, `malformed`, `invalid_signature`, `key_not_found`, `expired`, `not_yet_valid`, `name_domain_mismatch` in both directions of the dns rule and for an http key, `tools_hash_mismatch`, `chain_mismatch`). File level cases: a byte order mark, a file of exactly 16384 bytes (`valid`) and one of 16385 bytes (`malformed`), each with its size in `expect.bytes`, invalid UTF-8 and a duplicate member. Chain cases: a forged earlier file under the same key (`chain_mismatch`); a valid link across a key change with only the new key given (`valid`, with `keyChangeNote` and `chain`: the output has to report the change, and the earlier signature is `not_checked`); the same link with both keys given (`valid`, earlier signature `checked`); and a forged earlier file across a key change with both keys given (`chain_mismatch`).
* `fields`: one member of `ed25519-valid.json` replaced (a JSON pointer and a value) and whether the result passes step 1 of section 11 (`accept`) or is `malformed` (`reject`). They cover the https URL rule with the WHATWG cases above, userinfo, backslash, uppercase host, `:443` and a missing path; mailto edge cases; domain labels of 63 and 64 characters and an all numeric last label; unsafe characters in `version` and `tool`, including the variation selectors U+FE0F and U+E0100, the Hangul filler U+3164, other default ignorable code points, private use, a noncharacter and the unassigned U+0378; leap seconds and impossible dates; amounts, networks, assets, names and tool names; and signature text that is not canonical base64.
* `tools`: one input file, or `inputs` with one file per page, and either the expected tools hash or a rejection with a `reason` code (`range`, `underflow`, `depth`, `encoding`, `duplicate-member`, `duplicate-name`, `ambiguous`). They cover UTF-16 versus code point sorting of names, number spellings of one double, integers beyond 2^53 - 1 (including the uint64 limit) next to the same value written with an exponent, underflow, nesting of 64 and 65 levels (bare and inside a JSON-RPC wrapper, where the wrapper does not count), members next to the `tools` array nested 65 levels deep (accepted and not hashed), a byte order mark, invalid UTF-8, duplicate members, a JSON-RPC wrapper, an ambiguous wrapper, two pages, a duplicate name across pages and the empty list.

`key_lookup_failed` needs a live lookup and has no fixed vector. The ECDSA vectors are fixed files, so their randomized signatures are fixed too.

The vectors above are those of format 0.1 and stay as they were written. The vectors of format 0.2 are in `vectors/v0.2/`, with their own `manifest.json` (section 17.11).

## 16. References

* MCP Registry authentication: `https://modelcontextprotocol.io/registry/authentication` (read 18 November 2026; its source, `docs/modelcontextprotocol-io/authentication.mdx`, re-read at main `115f852` on 19 November 2026)
* Registry source: `modelcontextprotocol/registry`, `internal/api/handlers/v0/auth/` (`common.go`, `dns.go`, `http.go`), main branch, read 18 November 2026; re-read at main `115f852` on 19 November 2026 (PR 1849)
* server.json schema: `https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json`
* Official registry requirements for `_meta`: `docs/reference/server-json/official-registry-requirements.md` in the registry repository
* RFC 8785 JSON Canonicalization Scheme; RFC 8259 JSON; RFC 7493 I-JSON; RFC 8032 Ed25519; RFC 3986 URIs; RFC 6068 mailto; WHATWG URL Standard; CAIP-2 chain ids
* x402 version 2 payment requirements (`scheme`, `network` as a CAIP-2 id, `amount` in atomic units, `asset`, `payTo`), checked 18 November 2026 during review: `asset` may also be an ISO 4217 code for a fiat price, which section 3 refuses
* mcp-tool-set-digest/1, editors' draft of 13 November 2026: `https://github.com/alexar76/mcp-tool-set-digest`, commit `aca5812` (format 0.2, section 17)
* Registry API: `docs/reference/api/openapi.yaml`, `official-registry-api.md`, `generic-registry-api.md` and `CHANGELOG.md` in the registry repository, and the pages `/registry/about` and `/registry/remote-servers` of `modelcontextprotocol.io`, read 19 November 2026 (sections 2 and 8a)
* MCP specification, revision 2026-07-28: `basic/index`, `basic/versioning` and `basic/transports/streamable-http`, read 19 November 2026, including their notes on revision 2025-11-25 (section 8a)

## 17. Format 0.2

Spec id `addon-declaration/0.2`, added 19 November 2026. It is the default for new declarations. This section lists every difference from format 0.1; whatever it does not name is exactly as in sections 1 to 15, among them payment options, remotes, the key and its lookup, the namespace rule, the time window, the size and nesting limits and the parsing rules of section 5 for the declaration file, and the serving paths of section 8. A 0.1 declaration is still parsed, hashed, signed and verified by the 0.1 rules, with the same signing input and the same declaration hash as before 0.2 existed.

The one substantive change: a 0.2 declaration signs the two digests of mcp-tool-set-digest/1 (section 4a) in place of the 0.1 `toolsHash`, so a publisher's signed statement can be compared directly with what observers using that document record. The one small change: `contact` is optional, because a contact field for publishers is still an open question in the registry, where the discussion raises PII and abuse concerns (`https://github.com/modelcontextprotocol/registry/issues/480`, open when read on 19 November 2026).

### 17.1 Members

| Member | Format 0.1 | Format 0.2 |
|---|---|---|
| `spec` | exactly `"addon-declaration/0.1"` | exactly `"addon-declaration/0.2"` |
| `toolsHash` | required (section 4) | refused |
| `toolSetDigest` | refused | required, an object as below |
| `contact` | required | optional; when present, the rule of section 3 |

`toolSetDigest` has exactly these three members, all required:

| Member | Rule |
|---|---|
| `spec` | exactly `"mcp-tool-set-digest/1"` |
| `contract` | the contract digest of the tool list as mcp-tool-set-digest/1 defines it, written as `sha256-` and the standard padded base64 of the 32 hash bytes: 44 characters after the prefix, matching `^sha256-[A-Za-z0-9+/]{43}=$`, and canonical, so decoding the base64 and encoding it again gives the same text (the character before `=` is one of `AEIMQUYcgkosw048`) |
| `extras` | the extras digest in the same form, or JSON `null` exactly when that document defines the extras digest as null (no tool has a member other than `name`, `description`, `inputSchema` and `outputSchema`). The member is present in both cases |

One form only. mcp-tool-set-digest/1 also writes the same hash as `sha256:` and lowercase hex. A declaration refuses that form, and refuses the base64url alphabet, missing padding and nonzero unused bits, so each digest has one byte representation in the signed text and two declarations of the same tools sign the same bytes. A client that holds a digest in the hex form converts it before comparing. The `spec` member inside `toolSetDigest` names the definition the two values follow, so the signed text says what they mean; a later digest definition needs a new declaration format, because the member list is closed.

### 17.2 Signing input and declaration hash

As in sections 6 and 7, with the format's own spec id as the first line:

```
UTF-8 bytes of "addon-declaration/0.2"
one byte 0x0A
UTF-8 bytes of the RFC 8785 form of the declaration with the "signature" member removed
```

The rule for every format: the first line equals the declaration's `spec` member. `declarationHash` is `"sha256:"` and the lowercase hex SHA 256 of this signing input, as in section 7. The signature forms of section 6 are unchanged.

### 17.3 The tool check (step 6)

Given the tool list it received, the verifier computes the contract digest and the extras digest as mcp-tool-set-digest/1 defines them (editors' draft of 13 November 2026, commit `aca5812`), with that document's input rules (its section 3: repeated member names keep the last value, numbers are read as the nearest double) in place of the strict rules of section 5, which still apply to the declaration file.

How the list is read. That document starts from the `tools` array and does not say how the array is read from what the server sent, so these parts of section 4 apply, and only these: the input is the `tools/list` messages one per page, each as the JSON text the server sent; each page has one of the three accepted shapes (a bare array, a `tools/list` result, a JSON-RPC response), and an ambiguous wrapper is refused; the pages are joined in page order; server sent events framing is removed before reading (the reference verifier does not remove it and refuses such a page). The rest of sections 4 and 5 does not apply to this list: there is no 64 level nesting limit, two tools may share a name (that document keeps them, see T17), and repeated member names, large integers and literals that round to zero are read as that document says. The text MUST be UTF-8; one leading byte order mark is ignored, as in section 5, and anything after it is read as JSON text (a second byte order mark is not JSON). As a resource bound, a verifier MAY refuse a page nested deeper than it can read; the reference verifier refuses a page nested deeper than 512 levels, counted from the page root (the outermost value of the page), and two verifiers with different bounds can disagree only about lists nested that deep. The last page must not carry `nextCursor`.

Each computed digest is compared with the declared one as text. A digest has one of three results:

* `match`: equal to the declared value (for `extras`, both `null` counts);
* `mismatch`: a different value, including `null` against a digest or a digest against `null`;
* `no_digest`: that document gives an error code in place of this digest (`TSD-PAGE`, `TSD-TOOL`, `TSD-NAME`, `TSD-NUMBER`, `TSD-TEXT`), or the list cannot be read at all (not UTF-8, not JSON, not one of the accepted page shapes, nested beyond the verifier's resource bound), which has no code. `TSD-PAGE` means the list given to the verifier is incomplete.

When both results are `match`, step 6 passes. Otherwise the result is `tools_hash_mismatch` with exit code 8, the same state and code as in 0.1, and the output MUST say, for each digest, whether it matched, differed or could not be computed (with its code), in text and, for output meant for programs, as a structured value.

A `no_digest` result means the list could not be compared with the declared one for that digest. It is not evidence that the server changed its tools: mcp-tool-set-digest/1 (its section 10) says a comparison with a set whose digest could not be computed has no result and is not a change. This format departs from that on purpose for the state only: the check fails closed, because a declaration whose tools cannot be compared has not been shown to match, and a client that reads only the exit code stays on the safe side. Output for programs MUST keep the two apart, so a program can tell "could not be compared" from "differs".

The reference verifier prints a line such as `tool set digest: contract match, extras mismatch` (with `(could not be compared)` added when a result is `no_digest`), and its `--json` output holds:

```json
"toolSetDigest": {
  "spec": "mcp-tool-set-digest/1",
  "contract": { "result": "match", "declared": "sha256-<base64>", "computed": "sha256-<base64>" },
  "extras": { "result": "mismatch", "declared": "sha256-<base64>", "computed": "sha256-<base64>" },
  "differs": ["extras"],
  "noDigest": [],
  "comparable": true,
  "repeatedMembers": 0,
  "repeatedNames": []
}
```

The members:

* `contract` and `extras`: the result of each digest. A `no_digest` entry also has `code` (the TSD code, or `null` when the list could not be read) and `detail`, and its `computed` is `null`.
* `differs`: the digests whose result is `mismatch`, in the order contract, extras. A digest whose result is `no_digest` is not listed here.
* `noDigest`: the digests whose result is `no_digest`.
* `comparable`: `false` when `noDigest` is not empty.
* `repeatedMembers`: the number of repeated member names the verifier read in the list (the last value of each was used), and `repeatedNames`: one `{ "name", "count" }` entry for each tool name that more than one tool carries (T17). Both are `null` when the list could not be read at all. They are reported whatever the results, also with `valid`.
* `notes`, when present: the same facts in words.

The reasons of the reference verifier start `the contract digest differs`, `only the extras digest differs` (when the contract digest matches) or `the extras digest differs too` for a `mismatch`, and `the contract digest could not be computed` or `the extras digest could not be computed` for a `no_digest`; a list that cannot be read at all gives one reason that starts `the received tool list could not be compared`.

Why the two kinds of difference are told apart, and why they share one state. A contract difference (`differs` holds `contract`) means a tool was added, removed or renamed, or a description or schema changed: the tools a model calls are not the declared ones. An extras only difference (`extras.result` is `mismatch` and `contract.result` is `match`) means the names, descriptions and schemas are as declared, as mcp-tool-set-digest/1 reads them (with the limits of section 17.8), and another member changed, such as `title`, `annotations`, `icons` or `_meta`. That is not harmless by default: annotations such as `readOnlyHint` and `destructiveHint` can decide whether a client asks the user before a call. Both are differences from what the publisher signed, so both keep exit code 8. A client that treats them apart reads the two `result` members (or `differs` together with `noDigest`), not `differs` alone: an extras digest that could not be computed is in `noDigest`, not in `differs`, and is not an extras only difference. A separate state was not added, because a client that reads only the exit code would then have to learn a new code to stay safe.

### 17.4 Verification steps

The steps of section 11, with these changes. Step 1 applies the rules of the format named by `spec`. A verifier MAY be set to accept only some formats (the reference CLI takes `verify --format 0.1` or `--format 0.2`); a declaration of another format is then `malformed`, with a reason that names its format and the accepted ones. That is a refusal by the verifier's setting and says nothing about whether the file is well formed under its own format, so output for programs MUST tell it apart from a broken file; the reference `--json` output has `formatAccepted`, `false` for such a refusal and `true` whenever the format named by `spec` is accepted (a broken file of an accepted format is `malformed` with `formatAccepted: true`). The state and exit code stay `malformed` and 2, so a program that reads only the exit code refuses the file either way. The setting applies to the declaration being checked, not to the earlier declaration of a link check, so a check that accepts only 0.2 still follows a link to a 0.1 declaration. Step 6 is section 17.3. Step 7 is section 7 with section 17.5. Step 8: the output MUST name the format that was checked.

### 17.5 Links between formats

`previous` of a 0.2 declaration may be the declaration hash of a 0.1 declaration (over the 0.1 signing input, as section 7 defines it) or of a 0.2 declaration. A 0.2 declaration that points to the last 0.1 declaration of a server is the upgrade path, also within one version (a reissue, section 7). The link check of section 7 applies as it is: the earlier declaration is checked under the rules of its own format and its signature over its own signing input, and a change of key is reported in text and in `chain.keyChanged` as before. In addition, a 0.1 declaration whose earlier declaration is a 0.2 one fails the link check (`chain_mismatch`): along a chain the format can move forward and not back. The chain object carries `previousFormat`, and the text output has a note when the format changed.

### 17.6 Cross version confusion

Each case below has a vector in `vectors/v0.2/` and a test.

* A 0.1 declaration with `spec` changed to 0.2: `malformed`, because `toolsHash` is refused in 0.2. With `toolsHash` also replaced by a well formed `toolSetDigest`: `invalid_signature`, because both the first line and the body differ from what was signed.
* A 0.2 declaration with `spec` changed to 0.1: `malformed` (`toolSetDigest` is refused in 0.1), and `invalid_signature` once `toolsHash` takes its place.
* A body with both `toolsHash` and `toolSetDigest`: `malformed` under either `spec`.
* A body signed under the other format's prefix (a signer that kept a fixed first line): `invalid_signature`.
* A `spec` that names neither format: `malformed`; such an object has no signing input.
* A verifier set to accept one format, given a declaration of the other: `malformed` with a reason that names both (section 17.4).
* A downgrade by serving an older 0.1 declaration in place of a newer 0.2 one: the 0.1 declaration is still a valid statement about its own content, so this is the rollback of T6. A client that expects 0.2, for example because the publisher has moved to 0.2, sets its verifier to accept 0.2 only (`verify --format 0.2`). A client that has accepted a 0.2 declaration for a name SHOULD refuse a 0.1 declaration for the same name whose `issuedAt` is later than that of the accepted 0.2 declaration; a 0.1 declaration issued earlier is history, which a chain from 0.1 to 0.2 contains by design. A verifier that holds the earlier file refuses a 0.1 declaration that follows a 0.2 one (section 17.5); without the earlier file, a 0.1 declaration's `previous` is only a hash and does not show the format it points to.
* A link across formats: section 17.5. Its hash is computed with the earlier declaration's own prefix, so a hash computed with the wrong prefix does not link.

### 17.7 Threats

T16 and T17 in section 12 are the threats this format adds. T7 is lighter in one respect: a server that puts per session values into tool `_meta` changes only the extras digest, so the contract digest stays comparable. T7 is also sharper in one respect: the stated aim of 0.2 is comparison with what observers record, and observers read lists under their own protocol version and authorization (section 17.8). T8 does not hold for the tool list of a 0.2 check: repeated member names are a parser difference there, and T17 says how a verifier and a client handle them.

### 17.8 Limits of the tool check

The two digests together cover every member of every tool, with the exceptions that come from mcp-tool-set-digest/1 itself: a `description` that is absent or not a string reads as `""`, an `inputSchema` that is absent or not an object reads as `{}`, an `outputSchema` that is not an object is left out as if absent, repeated member names keep the last value, numbers are read as doubles, and two tools may share a name. Tool lists that differ only in these ways have the same digests and the same 0.2 result. A 0.1 `toolsHash` refuses or tells apart such lists instead (sections 4 and 5).

Two of these exceptions change what a client acts on (T17). With repeated member names, a client whose parser keeps the first value reads another definition than the digests pin. With two tools of one name of which only one has extras, the digests do not pin which of the two carries them: a list in which `{"name":"f","description":"Read only view",...,"annotations":{"readOnlyHint":true}}` comes with `{"name":"f","description":"Delete everything",...}` has the same contract digest and the same extras digest as the list in which the annotation sits on the second tool, so a `valid` result does not show which tool is marked read only. A verifier reports both cases (section 17.3, `repeatedMembers` and `repeatedNames`), and a client SHOULD refuse such a list (T17). The vectors `valid-repeated-tool-name` and `valid-repeated-member` show both (section 17.11).

The conditions of reading. mcp-tool-set-digest/1 (its sections 3.2, 11 and 11.1) says a digest is comparable only with one read under like conditions: the same protocol version (and `MCP-Protocol-Version` header), the same authorization and complete paging; a missing protocol header is an observed cause of a list without `outputSchema`. A 0.2 declaration signs only the identifier `mcp-tool-set-digest/1` and the two values. It does not say under which protocol version or authorization the publisher read the list. A client that reads the list under another protocol version, or with another authorization scope, can get a contract mismatch from a server that changed nothing, and the declaration gives no hint why. A publisher SHOULD compute the digests from the list as the server sends it under the protocol version that current clients negotiate, with the authorization a typical client has, and SHOULD say which in its own documentation; a client that gets a mismatch SHOULD read the list again with the current protocol version and complete paging before treating it as a change. Whether a later format signs these conditions is an open question (section 17.9). The reference `check-listing --fetch-tools` (section 8a) reports the protocol version it sent and whether the server answered under revision 2026-07-28 or the earlier `initialize` flow, so a mismatch can be read with that in mind.

### 17.9 Open questions added by 0.2

* Per tool digests (section 14), so that a client that received part of a tool set can check that part: still open.
* Whether an extras only difference should be acceptable to clients by default: left to client policy; a later format could let the publisher sign which members may change.
* Whether `contact` should be dropped entirely rather than made optional.
* Whether the signed member should also carry the conditions under which the publisher read the list, as mcp-tool-set-digest/1 section 11.1 advises for a signed record (it SHOULD carry the profile, the members covered and the context of observation): at least the MCP protocol version, perhaps a label for the authorization scope. A member such as `toolSetDigest.protocolVersion` would let a client request the same version before comparing (section 17.8). Not adopted in this draft, because the member list is closed and the form of such a member (one version or several, how to name an authorization scope without exposing it) needs its own review before 0.2 is final.
* Whether a verifier should fail, rather than report, a received list in which two tools share a name or a member name repeats (T17). This draft reports them and leaves the refusal to the client, so that a 0.2 result stays comparable with what observers using mcp-tool-set-digest/1 record.
* mcp-tool-set-digest/1 is an editors' draft. A change to it that changes digests is expected to come with a new identifier, and a declaration that uses a new identifier needs a new declaration format; 0.2 accepts only `mcp-tool-set-digest/1` as read at commit `aca5812`.
* The items of section 14 (GitHub namespaces, rotation proof, freshness and the others) are unchanged.

### 17.10 Worked example

The tool list of section 15 (`examples/tools.example.json`) has the contract digest `sha256-kPg5tlmErvzQUS4WkIEQscLXmvWdkFLa4vQ7dqH0fdQ=` and the extras digest `sha256-aoHUAjyTPtj0I4RgFX1rt4KRONuWTYAVpmsccm/vRZ0=` (section 4a). `examples/declaration-0.2.example.json` is a 0.2 declaration of `com.example/weather` 1.4.0 that signs them, made with another throwaway key whose private half was discarded (public record in `examples/example-key-0.2.txt`). Its declaration hash is `sha256:ee452cc2c0e159c7634978cf0d520116da1bfb642013e9a2589a983a767da943`. Check it offline:

```
node bin/addon-declare.js verify examples/declaration-0.2.example.json --pubkey examples/example-key-0.2.txt --tools examples/tools.example.json --now 2026-11-19T13:00:00Z
```

Output as run on 19 November 2026:

```
valid: com.example/weather 1.4.0
  format: addon-declaration/0.2
  tool set digest: contract match, extras match
  key source: offline: supplied by the person running the check; publication at the domain was not checked
  key: ed25519 sha256:7bf0d86a39e3126e418044a7dbfbe2a8d8320ea10eae9be3a0a66c5418778b21 (MCPv1 record, registry login key)
  checked: name: namespace covered by a dns key at example.com
  checked: signature
  checked: time window
  checked: tool set digest (mcp-tool-set-digest/1): contract and extras
  not checked: chain link (this declaration names no previous declaration)
  meaning: the holder of the named key signed this content. It does not show that the server is safe or that it behaves as declared.
```

Give the same command a tool list in which only an annotation changed, and it returns `tools_hash_mismatch` with exit code 8 and `tool set digest: contract match, extras mismatch`; change a description instead, and the contract digest is the one that differs.

To make a 0.2 declaration, `init` needs no new option: 0.2 is its default, and it prints which format it wrote. `--format 0.1` writes the earlier format. With 0.2, `init` takes `--tools` (it computes both digests) or `--contract-digest` and `--extras-digest` (`null` for a null extras digest).

### 17.11 Conformance vectors for 0.2

`vectors/v0.2/manifest.json` lists the 0.2 vectors, with paths relative to that folder, written by `vectors/generate-0.2.js` (which writes only inside `vectors/v0.2/`; the 0.1 vectors stay as they were). Run again without options, the script adds the cases that are not written yet and keeps every written case byte for byte (its files, its public key and its declaration hash); `--fresh` rewrites the whole set with new keys. Like the manifest of section 15 it has `declarations` and `fields`; unlike it, it has no `tools` list, because the tool list rules of a 0.2 check are those of mcp-tool-set-digest/1, whose own published vectors are vendored in `vectors/third_party/mcp-tool-set-digest-1/`.

Each declaration vector gives the declaration, the public key record, the clock time, and optionally `tools` (one page), `previous` (the earlier declaration) and `formats` (the formats the check accepts; all when absent). Its `expect` holds the state, exit code and declaration hash, and optionally:

* `format`: the format the check names.
* `toolSetDigest`: a compact form of the result of section 17.3. `contract` and `extras` hold the result words (`match`, `mismatch`, `no_digest`); `contractCode` and `extrasCode` the TSD code of a `no_digest` result, or `null` when the list cannot be read at all; `differs`, `noDigest`, `repeatedMembers` and `repeatedNames` the values of section 17.3. A member that is absent is not checked.
* `chain`: members of the chain object of section 7.
* `keyChangeNote` and `formatChangeNote`: `true` when the output has to say that the key, or the format, changed along the link (section 7 and section 17.5). The reference test looks for the words `key changed` and `format changed` in the notes; another implementation checks that its own output says so.

The set covers both algorithms; valid declarations with and without `contact` and with a null extras digest; links from 0.1 to 0.2 under one key, across a key change with one key and with both keys given, and to a forged 0.1 file; a 0.1 declaration that follows a 0.2 one; an extras only mismatch, a contract mismatch, a declared null extras digest against a list with extras and the reverse; each kind of `no_digest` on the verify path: no extras digest (`TSD-NAME`, with the contract digest differing), an incomplete list (`TSD-PAGE`), a lone surrogate in an extra with the contract digest matching (`TSD-TEXT`), a number with no double in a schema with the extras digest matching (`TSD-NUMBER`), a tool without a name (`TSD-TOOL`) and a page saved with its server sent events framing (no code); a `valid` result over two tools that share a name, with the annotation moved to the other tool (`valid-repeated-tool-name`, section 17.8), and over a repeated member name (`valid-repeated-member`); and every case of section 17.6. The field vectors change one member of `ed25519-valid.json`, or remove it (`"remove": true`), and cover the digest forms, the `extras` and `spec` members of `toolSetDigest`, `toolsHash` in 0.2, the `spec` value and an absent or invalid `contact`.

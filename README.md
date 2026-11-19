# addon-declare

Sign a short statement of what your MCP server version offers (tools, endpoints, price, pay address) with the domain key you already use for the official MCP Registry. Anyone can check it against your DNS or your web server. Spec: [SPEC.md](SPEC.md).

Status: draft v0.2. Licence: Apache 2.0 (see `LICENSE`; third party vectors under `vectors/third_party/` keep their own licence and notice). Security reports: see `SECURITY.md`. New declarations are written in format `addon-declaration/0.2`, which signs the two digests of [mcp-tool-set-digest/1](https://github.com/alexar76/mcp-tool-set-digest) of your tool list (SPEC.md section 17). Declarations in format `addon-declaration/0.1` are still signed on request (`init --format 0.1`) and still verify exactly as before. Node 20 or later, no dependencies, nothing to install.

Every command below is one line, so it works the same in bash, zsh, cmd and PowerShell.

## Publish a declaration in one command

You need: a server the official MCP Registry already lists under a domain namespace (such as `com.example/weather`), the key record you published for `mcp-publisher login http` or `login dns`, and the private key of that record. Name the version you are about to publish:

```
node bin/addon-declare.js prepare com.example/weather --for-version 1.4.1 --key-env MCP_PRIVATE_KEY
```

`MCP_PRIVATE_KEY` holds the hex key you give to `mcp-publisher --private-key` (or a PEM key); set it from a file outside the repository as in step 3 of the five minute path below, and give the NAME of the variable, not the key. Run the command from a folder outside your server's repository, or give `--out`: the output folder is made where you run it (this repository's `.gitignore` lists the default `addon-declaration-out/`).

In one run it reads the listing (the latest version, or `--listing-version`), the latest listing, and the listing of `--for-version` (to check that it is not published yet). It finds your key record at the domain the namespace names (`--method`, else http, then dns; for a sub namespace also a dns record at each parent domain). It reads `tools/list`, every page, from the streamable-http remote of the listing, or of `--server-json` when given (or takes `--tools`). It reads `latest.json` on your site and, when that is absent or cannot be linked, the declaration the listing names, links the first that is a declaration for this server as `previous`, reads that declaration at its by-hash path, and builds a 0.2 declaration that expires in 180 days (`--expires-in-days`; `--contact` and `--payment` as for `init`; `--server-json` for the remotes of the new version). Before it signs, it checks that the private key belongs to the published record, and refuses when it does not. It then verifies the result offline, and also runs check-listing on the listing as it will read after publishing, with every answer served from memory. It writes into `addon-declaration-out` (`--out`) and publishes nothing. A folder that is not empty needs `--force`: it replaces the files an earlier prepare run wrote there (`declaration.unsigned.json`, `pointer.json`, `NEXT_STEPS.txt` and the files under `site/.well-known/addon-declaration/`), removes those of them this run does not write, and leaves other files as they are. A run that does not sign (no key option, or `--dry-run`) writes only `declaration.unsigned.json`: with `--force` it replaces an earlier `declaration.unsigned.json`, and it refuses a folder that holds a signed set from an earlier run, also with `--force`, so give it another `--out`. A folder that holds a link is refused. The files:

* `site/.well-known/addon-declaration/<namespace>/<server>/`: `by-hash/<hex>.json`, `versions/<version>.json` and `latest.json`, the files to upload to your domain, served with `Content-Type: application/json` (`latest.json` only when the new version will be the latest in semantic version order);
* `pointer.json`: the `_meta["io.modelcontextprotocol.registry/publisher-provided"]` block for the server.json of the new version, with the by-hash URL and the declaration hash (checked against the registry's limit of 4096 bytes for that block); it replaces that object in server.json as a whole;
* `declaration.unsigned.json`, and `NEXT_STEPS.txt`: the upload URLs, the edits to server.json, the publish step and the check-listing command to run afterwards.

Without `--server-json`, the declaration names the remotes of the listed version, and the server.json of the new version must name exactly those remotes; the tool list read from the server running now must also be what the new version answers. NEXT_STEPS.txt names both. When the new version changes either, give `--server-json` and `--tools` for it, because a version published with a pointer to a declaration that does not match it cannot be fixed.

When `latest.json` can be linked and the listing names another declaration, prepare reads that one too and walks the `previous` links of both through by-hash files (at most 8 links each): it links `latest.json` when that follows the named one, and the named one when `latest.json` is behind it (a note says so). When the listing names a declaration that cannot be linked (not served, not the file the listing names, a signature that does not verify, another server name, or issued later than now), or that neither follows nor precedes `latest.json`, prepare stops with `previous_not_linkable` instead of making a declaration with no `previous`, because once its pointer is in a published version that gap in the history stays. Serve the declaration the listing names at its by-hash URL and run it again, or give `--no-previous` to start a new history on purpose: no previous declaration is read or named, and a note says so. A listing that names no declaration, with no `latest.json` that can be linked, gives a first declaration as before. `--no-previous` cannot be given with `--no-pointer`. A `--registry` that holds key material in a common pasted form (a long hex run, also cut in pieces, a base64 key as one path segment, or PEM text) is refused before any request, as for check-listing. This check is a best effort courtesy for the common pasted forms, not a complete filter, so ordinary custom registry URLs are accepted.

Why `--for-version`: a published version cannot change in the registry, and the pointer lives in server.json, so a pointer can only go into a new version. To declare the version that is already listed, give that version with `--no-pointer`: no pointer is made, prepare runs check-listing on the listed version and follows the declaration check-listing puts in force (under the same key and key location), and check-listing then finds the new declaration through `versions/<version>.json` and `latest.json`, as in the live example below (check-listing exit code 11).

The key options are those of `sign` (`--key-env` with the NAME of a variable, or `--key-file` with a path outside the repository); the key is not printed or written. Without a key option, or with `--dry-run`, it writes only `declaration.unsigned.json` and says what signing would do, with the declaration hash that signing that file gives; the signed run into the same folder then needs `--force` (or another `--out`). `prepare --help` prints the options. The manual steps it replaces are in the five minute path below.

`--json` prints one object with the members `command` (`"prepare"`), `state`, `exitCode`, `reasons`, `name`, `forVersion`, `mode` (`pointer` or `no_pointer`), `signed` (`false` for `prepared_unsigned`, which shares exit code 0 with `prepared`), `dryRun`, `out`, `steps` (nine, each `step`, `label`, `result` and `line`), `listing` (`name`, `requestedVersion`, `registry`, `url`, `version`, `publishedAt`, `registryStatus`, `isLatest`, `remoteCount`, `latestVersion`), `keyRecord`, `signingKey`, `tools`, `previous`, `declaration` (including `key`, `remotes`, `payment`, `contact` and `hash`, or `predictedHash` when not signed), `pointer`, `files`, `verify`, `preview`, `checkCommand`, `fetched` (one entry per request, as for check-listing) and `notes`. A member that does not apply is `null` or an empty list. Exit codes:

| Exit code | State | Meaning |
|---|---|---|
| 0 | `prepared` | signed, checked offline and as check-listing would read it, and the files written |
| 0 | `prepared_unsigned` | no key option, or `--dry-run`: the unsigned declaration written |
| 23 | `listing_not_found` | the registry has no listing for this name and version |
| 24 | `namespace_not_domain` | an `io.github` name, or a namespace that names no domain; nothing was read |
| 25 | `registry_read_failed` | the registry could not be read, or its answer is not the listing asked for |
| 26 | `key_record_not_found` | the domain publishes no key record that registry login reads |
| 27 | `key_record_lookup_failed` | the key record lookup could not be completed |
| 28 | `version_not_usable` | no `--for-version` (nothing is read), a version already published, or a `--no-pointer` declaration check-listing would not put in force |
| 29 | `remotes_not_declarable` | a remote a declaration cannot name (a URL template, not https, a user name or password) |
| 30 | `tools_unavailable` | no tool list that can be signed (a remote that asks for authorization, for example: give `--tools`) |
| 31 | `key_mismatch` | the private key does not belong to the published record; nothing was signed |
| 32 | `output_folder_not_empty` | the output folder holds files and `--force` was not given, it holds a link, or a run that does not sign meets a signed set from an earlier run (checked at the start, and again when the files are written); nothing was written |
| 33 | `pointer_too_large` | the publisher metadata block would be over 4096 bytes |
| 34 | `self_check_failed` | the signed declaration did not pass its own checks; nothing was written |
| 35 | `previous_unreadable` | `latest.json` (or the declaration the listing names) could not be read, so the history link cannot be made; run it again later |
| 36 | `previous_not_linkable` | the listing names a declaration that cannot be linked as `previous`, or that neither follows nor precedes `latest.json`; serve it, or give `--no-previous` |
| 1 | | usage or file error |

## Check a listing by name

```
node bin/addon-declare.js check-listing com.rtlpdf/arabic-pdf --fetch-tools
```

This reads the listing from the official MCP Registry, finds the declaration it points to (`_meta["io.modelcontextprotocol.registry/publisher-provided"].addonDeclaration`), fetches it from the publisher's own domain, checks that it is the file the listing names (by hash) and that its name, version and remotes equal the listing's, and verifies it with the key the domain publishes. It then looks for a newer declaration for the same version next to it (`versions/<version>.json`, `latest.json`) and puts it in force only if its history leads back to the named one under the same key. `--fetch-tools` reads the tool list from the declared remote (MCP protocol version 2026-07-28, or the `initialize` flow for an older server; the output says which) and compares it with the declaration in force; `--tools tools.json` compares saved pages instead. Add `--version 1.0.0` for a version other than the latest, `--registry <https base URL>` for another registry or mirror with the same API (a base URL that holds key material in a common pasted form is refused before any request, as a best effort courtesy, not a complete filter), `--json` for machine output. The rules it follows, and the attacks they close, are in SPEC.md section 8a. The registry asks host applications to read it through aggregators, so use this for checks by hand.

If the declaration the listing names has expired, a renewed declaration for the same version that follows it under the same key is still found and put in force. The declaration in force is the newest one the publisher's site served, which is not proof that no newer one exists (SPEC.md section 8a). Every string taken from the listing or a server is escaped before it is printed, and long ones are cut short in the text output. `check-listing --help` prints the options of this command alone. Exit codes:

| Exit code | State | Meaning |
|---|---|---|
| 0 | `verified` | the named declaration verifies and is in force; every check that was run passed |
| 11 | `verified_newer_declaration` | a newer declaration for the same version that follows the named one under the same key is in force and verifies (the named one verifies or has only expired) |
| 2 to 10 | as for `verify` | the declaration check failed (for example 3 `invalid_signature`, 8 `tools_hash_mismatch`) |
| 12 | `no_declaration` | the listing points to no declaration |
| 13 | `pointer_malformed` | the pointer is not `{ "url", "hash" }` with a declaration hash |
| 14 | `pointer_refused` | the pointer URL is not the by-hash path on the domain the namespace names or a parent of it; nothing was fetched |
| 15 | `namespace_out_of_scope` | an `io.github` name |
| 16 | `declaration_unreachable` | the declaration could not be fetched (a redirect is not followed) |
| 17 | `declaration_not_the_named_one` | the served file is not the one the pointer hash names |
| 18 | `listing_mismatch` | name, version or remotes differ between listing and declaration |
| 19 | `tools_fetch_failed` | the tool list could not be read from the declared remote (a server that asks for authorization is reported as not checked instead) |
| 20 | `registry_not_found` | no listing for this name and version (a deleted version too) |
| 21 | `registry_unreachable` | the registry could not be read |
| 22 | `registry_response_invalid` | the registry's answer is not the listing asked for |
| 1 | | usage or file error |

A program that reads only the exit code treats 0 and 11 as passed. With `--fetch-tools`, 0 and 11 do not mean that the tool list was compared: a server that asks for authorization leaves the tool check not checked, and the exit code stays 0 or 11. The text output then prints a `tools: NOT CHECKED` line under the state; in `--json`, read `tools.check` (`run`, `not_run`, `not_checked` or `failed`) and `tools.result` (`match` when the list was compared and matched).

## Five minute path for a publisher

These are the steps `prepare` runs, done by hand, for a server that is not listed yet or for a release pipeline. You need: a server published under a domain namespace (like `com.example/weather`) with `mcp-publisher login dns` or `login http`, and the private key you made for that login. If you would rather keep the registry login key out of release CI, you can sign with a separate declaration only key instead (dns method only, SPEC.md section 9).

Where to run the commands: from the folder that holds your server.json and tools.json. The commands below write the tool as `bin/addon-declare.js`; put the path to this folder in front of it, for example `node ../addon-declaration/bin/addon-declare.js init ...`. Nothing needs installing.

Keep the private key out of that folder. server.json usually sits at the root of your repository, and a key file there can end up in a commit. Prefer `--key-env` (the key comes from an environment variable set from a secret store); if you use a key file, keep it outside the repository and pass its path, as in step 3. If a key file has to live in the working tree for a while, add it to `.gitignore` first.

1. Save the `tools/list` result of this exact build as `tools.json`, exactly as the server sent it on the wire (the `result` object, the whole JSON-RPC response, or just the `tools` array). If your server paginates, save each page as its own file and give `--tools` once per page, in order. If the response arrived as server sent events (lines starting with `event:` and `data:`), save only the JSON-RPC message the `data:` lines carry, without that framing. Save it as UTF-8. In Windows PowerShell 5.1 use `Out-File -Encoding utf8`, because `>` writes UTF-16 there.

2. Create the unsigned declaration from your server.json:

   ```
   node bin/addon-declare.js init --server-json server.json --tools tools.json --contact mailto:security@example.com --expires-in-days 180 --out unsigned.json
   ```

   It prints `format: addon-declaration/0.2`: the declaration carries the contract digest and the extras digest of your `tools.json` under mcp-tool-set-digest/1, the values observers of MCP servers compare. In this format `--contact` is optional. Add `--format 0.1` for the earlier format, which carries the tools hash instead and needs `--contact`.

   Add `--payment payment.json` if you charge per call (see `examples/payment.example.json`), `--previous declaration-of-last-release.json` (the signed file, not the unsigned one) to link your last declaration, and `--method http` if you log in with the HTTP method. `--domain` names a parent domain that holds the key; that works only with the dns method, because an http key proves only its exact namespace. A remote in server.json is declared in canonical URL form: a bare origin such as `https://mcp.example.com` becomes `https://mcp.example.com/`, and an uppercase scheme or host is lowercased (with a note). Remotes that are URL templates (with `{...}` or `variables`), plain http, carry a user name or password, or need other URL changes are refused; fix them in server.json, or leave out `--server-json` and pass `--name` and `--version` to declare without them.

3. Sign. The key is read from an environment variable or a file and stays on your machine. With the hex key you pass to `mcp-publisher --private-key` (or a PEM key), put it in an environment variable and give the variable's NAME (not the key) to `--key-env`:

   ```
   node bin/addon-declare.js sign unsigned.json --key-env MCP_PRIVATE_KEY --out declaration.json
   ```

   Set the variable from a secret store or a file outside the repository rather than by typing the key on the command line, so it does not land in shell history. In PowerShell: `$env:MCP_PRIVATE_KEY = Get-Content -Raw ../mcp-keys/key.hex`. In bash: `export MCP_PRIVATE_KEY="$(cat ../mcp-keys/key.hex)"`.

   Or read the key from a file kept outside the repository, by its path:

   ```
   node bin/addon-declare.js sign unsigned.json --key-file ../mcp-keys/key.pem --out declaration.json
   ```

   It prints the proof record the key matches. It must be one of the records you already published (a TXT record, or a line of the `mcp-registry-auth` file). For a declaration only key it also prints the `v=ADKv1` record to publish as a second TXT record.

4. Check it the way a user would:

   ```
   node bin/addon-declare.js verify declaration.json --tools tools.json
   ```

   This looks up your published key by the method in the declaration (`key.method`). Exit code 0 means valid. To check it offline before the key is published, add `--pubkey key.txt`, where `key.txt` holds the `v=MCPv1; k=...; p=...` line that `sign` printed after "this key must be published as:" (or is a copy of your `mcp-registry-auth` file); the record text itself can also be given to `--pubkey` in quotes.

5. Serve it at the paths `sign` printed (SPEC.md section 8): `https://<your domain>/.well-known/addon-declaration/<namespace>/<server>/by-hash/<hash>.json` (keep every one of these, so the history can be walked), `.../versions/<version>.json`, and `.../latest.json` for the newest. Optionally point to it from server.json under `_meta["io.modelcontextprotocol.registry/publisher-provided"].addonDeclaration`.

   If your last declaration is a 0.1 one, pass it to `--previous` as usual: a 0.2 declaration may follow a 0.1 one (a 0.1 declaration may not follow a 0.2 one). That is how an existing declaration moves to the new format, also for the same version.

   The history only builds up if each release passes the previous signed declaration to `--previous` (in CI, fetch it first, for example from your `latest.json` or from the previous release; the sample workflow shows a step). A link shows what you pointed at; when you change keys, verifiers report the change (SPEC.md sections 7 and 10).

To do this on every release, see `action/action.yml` and the sample workflow `examples/workflows/sign-declaration.yml`. The action's `tools-json` input takes one path per line, one file per page, in order. Its `format` input is `0.2` unless you set `0.1`, and `contact` is needed only for `0.1`. A workflow that used the action before format 0.2 existed and sets no `format` now writes 0.2 declarations; set `format: '0.1'` to keep the earlier format. If a `0.1` run fails with "give --contact", set the action's `contact` input. The action's own verify step checks the format it just wrote (`--format`).

## Checking a declaration

```
node bin/addon-declare.js verify declaration.json
node bin/addon-declare.js verify declaration.json --pubkey key.txt
```

The first looks the key up by the declared `key.method` (TXT record at the key domain for dns, `https://<domain>/.well-known/mcp-registry-auth` for http); `--dns` or `--http` may be given but must match it. The second is offline: nothing is fetched, and `key.txt` holds the publisher's proof record line (`v=MCPv1; k=...; p=...`), for example a copy of their `mcp-registry-auth` file. Add `--tools tools.json` to compare the tools you received, `--previous older.json` to check the history link, `--json` for machine output, `--dns-server <ip>` to pick a resolver.

`verify` reads the format from the declaration's `spec` and says which one it checked (a `format:` line, `format` in `--json`). `--format 0.2` accepts only 0.2 declarations; a 0.1 one is then reported as malformed (exit 2), with `formatAccepted: false` in `--json` so a program can tell a refused format from a broken file. Once a publisher has moved to 0.2, check their declarations with `--format 0.2`: otherwise an older 0.1 declaration served in place of the newer one still verifies as valid, because it is a valid statement about its own content (SPEC.md section 17.6). Give `--format` once; a repeated option is a usage error.

```
node bin/addon-declare.js verify declaration.json --format 0.2 --tools tools.json
```

For a 0.2 declaration, `--tools` computes both digests and compares them one by one. When they differ the result is still exit code 8, and the output says which digest differs (`tool set digest: contract match, extras mismatch`, and `toolSetDigest.differs` in `--json`). A contract difference means the tools themselves changed. An extras only difference (`toolSetDigest.extras.result` is `mismatch` and `contract.result` is `match`) means the tool names, descriptions and schemas are as declared, as mcp-tool-set-digest/1 reads them, and a member such as `title`, `annotations`, `icons` or `_meta` changed; that document does not cover a `description` that is not a string, or an `inputSchema` or `outputSchema` that is not an object (SPEC.md section 17.8). A digest that could not be computed (a TSD code, or a list that cannot be read) is listed in `toolSetDigest.noDigest`, not in `differs`, with `comparable: false`: the list could not be compared, which still gives exit code 8 but is not evidence that the tools changed. The output also reports tool names that more than one tool carries and repeated member names (`toolSetDigest.repeatedNames` and `repeatedMembers`), even when the result is valid, because the digests then do not pin which tool carries an annotation, or which of two values a client reads (SPEC.md T17); a client should refuse such a list.

With `--previous` and `--json`, the output has a `chain` object. A program that follows history reads `chain.keyChanged`: `true` means the link crosses a change of key, which shows only what the newer signer chose to point at, not that the same holder signed both (SPEC.md sections 7 and 10). `chain.previousSignature` says whether the earlier signature was checked; it is checked if the key it names is among the keys given or looked up. `chain.previousFormat` names the format of the earlier declaration.

Exit codes: 0 valid, 1 usage or file error, 2 malformed, 3 invalid_signature, 4 key_not_found, 5 expired, 6 not_yet_valid, 7 name_domain_mismatch, 8 tools_hash_mismatch, 9 chain_mismatch, 10 key_lookup_failed (the lookup itself failed; try again later).

A valid result means the holder of your domain key signed that content. It does not say the server is safe. SPEC.md section 13 lists what it does and does not show.

Try it on the example (a throwaway key, checked offline):

```
node bin/addon-declare.js verify examples/declaration-0.2.example.json --pubkey examples/example-key-0.2.txt --tools examples/tools.example.json --now 2026-11-19T13:00:00Z
node bin/addon-declare.js verify examples/declaration.example.json --pubkey examples/example-key.txt --tools examples/tools.example.json --previous examples/declaration-1.3.0.example.json --now 2026-11-18T13:00:00Z
```

The first is a 0.2 declaration, the second the 0.1 example of SPEC.md section 15 with its history link.

## Comparing with mcp-tool-set-digest/1

In [issue 82 of the MCP Registry repository](https://github.com/modelcontextprotocol/registry/issues/82), projects that observe MCP servers discuss comparing tool lists by the two digests of [mcp-tool-set-digest/1](https://github.com/alexar76/mcp-tool-set-digest): a contract digest over each tool's `name`, `description`, `inputSchema` and `outputSchema`, and an extras digest over every other member. This command prints both for a `tools/list` result, labelled as that document labels them:

```
node bin/addon-declare.js tool-set-digest examples/tools.example.json
```

```
mcp-tool-set-digest/1
contract digest: sha256-kPg5tlmErvzQUS4WkIEQscLXmvWdkFLa4vQ7dqH0fdQ=
extras digest: sha256-aoHUAjyTPtj0I4RgFX1rt4KRONuWTYAVpmsccm/vRZ0=
```

A 0.2 declaration signs exactly these two values in its `toolSetDigest` member (SPEC.md section 17), so a digest recorded by an observer can be compared with the publisher's signed one directly; `verify --tools` on a 0.2 declaration computes them as this command does. Neither is the tools hash of a 0.1 declaration, and in general neither equals it: only when no tool has an extra and every tool has a string `description`, an object `inputSchema` and no `outputSchema` other than an object does the tools hash equal the contract digest written as `sha256:` and hex (SPEC.md, "Relation to mcp-tool-set-digest/1"). `--json` prints each digest in both of that document's forms (`sha256-<base64>` and `sha256:<hex>`). Pages are given as for `hash-tools`, one file each, in order; when the last page still carries `nextCursor` (even an empty one) the list is incomplete and both digests are `TSD-PAGE`. When no tool has a member outside the four contract members, the extras digest is `null`. Exit codes: 0 when both are known (a `null` extras digest counts), 2 when either cannot be computed (the output names the code of that document's section 10: `TSD-PAGE`, `TSD-TOOL`, `TSD-NAME`, `TSD-NUMBER` or `TSD-TEXT`), 1 for usage and file errors.

For this command, and for the tool lists that `init` and `verify` read for a 0.2 declaration, the input rules are those of mcp-tool-set-digest/1 section 3 where they differ from the strict parser that `hash-tools` and the 0.1 tools hash use (SPEC.md section 5). Declaration files themselves are always read by the strict parser.

* Repeated member names in one object: the last value counts, and the output adds a note saying how many there were (`repeatedMembers` in `--json`). The strict parser refuses the file. `init` refuses to sign such a list, because a client whose parser keeps the first value would read another tool than the one signed.
* Two tools with one name: kept, as that document says, with a note for each such name (`repeatedNames` in `--json`); the extras digest then does not pin which of them carries an annotation. The strict parser refuses the list, and so does `init`.
* Integer literals beyond `2^53 - 1`: rounded to the nearest double, so `9007199254740993` and `9007199254740992` give the same digests. The strict parser refuses them.
* A nonzero literal that rounds to zero, such as `1e-400`: read as `0`. The strict parser refuses it.
* A literal with no double, such as `1e400`, and a lone surrogate: the file is still read, and the digest that covers the member holding it has no value (`TSD-NUMBER` or `TSD-TEXT`), while the other digest can still be computed. A `description`, `inputSchema` or `outputSchema` of the wrong type is read as absent, as that document's section 4 says, whatever number it holds. The strict parser refuses the whole file.
* Nesting: that document leaves the bound to the producer (its section 12). This command refuses a page nested deeper than 512 levels in all, the resource bound `hash-tools` applies to a page, in place of the 64 level rule of SPEC.md section 5.

The rest is shared with `hash-tools`, because that document starts from the `tools` array and does not define how it is read: UTF-8 only, the three accepted page shapes of SPEC.md section 4 (an ambiguous wrapper is refused), and no server sent events framing. Such input is a usage error with no digest and no code.

The implementation (`lib/tool-set-digest.js`) was written from that document's text (editors' draft of 13 November 2026, commit `aca5812`), not from its code. Its 73 published conformance vectors, with their 22 equal and 12 differ pairs, are vendored unchanged (the raw bytes of that commit, LF line ends) with their licence (Apache-2.0 OR MIT) in `vectors/third_party/mcp-tool-set-digest-1/`, where `NOTICE` gives the source, commit, date and checksums; `test/tool-set-digest.test.js` runs all of them, and all pass.

## Tests

From this folder: `node --test`. The tests make their own throwaway keys and use no network; the http fetch tests use a local server on 127.0.0.1. On Node 24.22.1 (checked 18 November 2026) the form `node --test .` stops with "Could not find '.'", because newer runners read arguments as glob patterns; `node --test` with no argument finds the suites.

The fixed conformance vectors are in `vectors/` (`manifest.json` lists each input with its expected state, exit code and hashes); `test/vectors.test.js` runs them. The vectors of format 0.2 are in `vectors/v0.2/`, with their own `manifest.json`, written by `vectors/generate-0.2.js`; `test/vectors-0.2.test.js` runs them and checks that the 0.1 vector files are unchanged. Another implementation can run the same files. `test/live-0.1.test.js` checks that a live 0.1 declaration (copied into `testlib/live-0.1/`) still verifies with the same hashes. `test/check-listing.test.js` runs `check-listing` against local doubles of the registry, the publisher's site and an MCP server (modern and legacy, JSON and event stream answers, paging, sessions, a 401), and reaches every state; it also covers hostile history links and MCP answers, an expired pointer with a renewed declaration, and the time limit of a whole check. `test/prepare.test.js` runs `prepare` against the same kind of doubles: a namespace that is not a domain, a missing key record, a key that is not the published one, a paged tool list, an existing declaration to link, an output folder that is not empty, a dry run, the size limit of the pointer block and hostile listing fields; it then runs check-listing on the files it wrote, as they read after the upload.

## Files

* `SPEC.md`: Declaration Spec v0.2 draft (format 0.1 in sections 3 to 15, format 0.2 in section 17)
* `bin/addon-declare.js`: the CLI entry point; the command logic is in `lib/cli.js`
* `lib/`: canonical JSON (`jcs.js`), keys (`keys.js`), tools hash (`tools.js`), the two digests of mcp-tool-set-digest/1 (`tool-set-digest.js`), rules and verification (`declaration.js`), the listing check (`listing.js`) and its minimal MCP client (`mcp-client.js`), the publisher command `prepare` (`prepare.js`), live key lookup and the hardened fetch (`resolve.js`, the only file that opens network connections; every request of the other files goes through it)
* `test/`: `node:test` suites; `testlib/`: shared test fixtures (outside `test/` so the runner does not count them as a suite)
* `vectors/`: conformance vectors of format 0.1 and `generate.js`, which wrote them; `vectors/v0.2/`: those of format 0.2, written by `vectors/generate-0.2.js`; `vectors/third_party/mcp-tool-set-digest-1/`: the vectors of mcp-tool-set-digest/1, with `NOTICE` and licence files
* `action/action.yml`, `examples/workflows/sign-declaration.yml`: signing on release
* `examples/`: example tools list, server.json, payment option, two chained 0.1 declarations with their public key, and a 0.2 declaration with its own public key (`declaration-0.2.example.json`, `example-key-0.2.txt`)

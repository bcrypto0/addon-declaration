# Live example: com.rtlpdf/arabic-pdf 1.0.0

Copies of what one real listing serves, taken on 19 November 2026.

* `declaration-0.1.json`: the first declaration (format 0.1). The registry listing points to it by hash.
* `declaration-0.2.json`: the second declaration for the same version (format 0.2). It signs the two digests of mcp-tool-set-digest/1 and names the first as `previous`.
* `tools.json`: the `tools/list` answer both were made from.
* `key-record.txt`: the public key record the domain serves at `/.well-known/mcp-registry-auth`.

Check the copies offline, from the repository root:

```
node bin/addon-declare.js verify examples/live-rtlpdf/declaration-0.2.json --pubkey examples/live-rtlpdf/key-record.txt --tools examples/live-rtlpdf/tools.json --previous examples/live-rtlpdf/declaration-0.1.json
```

Check the live site instead (the key is then read from the domain). Run these in an empty folder outside the repository and put the repository path in front of `bin/addon-declare.js`:

```
curl -o d1.json https://rtlpdf.com/.well-known/addon-declaration/com.rtlpdf/arabic-pdf/by-hash/9170020c77a92f039806c11f714d1aa6eb50780bdb90c27e52016958045baca6.json
curl -o d2.json https://rtlpdf.com/.well-known/addon-declaration/com.rtlpdf/arabic-pdf/latest.json
curl -o t.json -X POST https://rtlpdf.com/mcp -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
node bin/addon-declare.js verify d2.json --http --tools t.json --previous d1.json
```

In Windows PowerShell 5.1 use `curl.exe` and write the body as `'{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}'`.

The copies here go stale when the server's tools change or the declarations expire (18 May 2027). The live site is the reference.

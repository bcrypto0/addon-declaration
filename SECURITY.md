# Security policy

## Reporting a vulnerability

Report a vulnerability in addon-declare or in the Add on Declaration Spec through GitHub private vulnerability reporting: open the Security tab of this repository and choose "Report a vulnerability". Only you and the maintainers of this repository can read the report.

Please do not open a public issue, pull request or discussion about a vulnerability until it has been fixed.

A useful report names the commit you tested, the command and the input files that show the problem, and what you expected instead. Use a throwaway key made for the report, not a key that is published for a real server.

## What is in scope

* The reference CLI (`bin/`, `lib/`) and the GitHub Action (`action/`).
* The rules in `SPEC.md`, for example a way to make a declaration verify as `valid` although the holder of the named key did not sign it, or a way to make two verifiers that follow the spec give different results for one file.
* The conformance vectors in `vectors/`, except `vectors/third_party/`.

## What is not in scope

* The MCP Registry, `mcp-publisher` and any server that publishes a declaration: report to those projects.
* mcp-tool-set-digest/1 and the vectors vendored from it in `vectors/third_party/`: report to that project.

## Versions

This is a draft. Fixes are made on the default branch only. There is no fixed response time.

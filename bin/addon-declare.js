#!/usr/bin/env node
// addon-declare: create, sign and verify Add on Declarations (Add on Declaration Spec v0.2 draft, formats 0.2 and 0.1).
// No dependencies. The private key is read from a local file or an environment
// variable and is used only in this process. The command logic is in lib/cli.js.

import { main } from '../lib/cli.js';

main(process.argv.slice(2)).then((code) => {
  process.exitCode = code;
});

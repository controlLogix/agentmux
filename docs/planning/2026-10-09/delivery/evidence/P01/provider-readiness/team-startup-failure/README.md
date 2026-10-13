# Original team startup failure

Codex reviewed one original TEAM attempt on the unchanged `c370290d6711b8f41d131723dc6a775334f03ccd` runtime snapshot. The original Claude lead, Codex worker and Grok reviewer were retained, with the original 30-minute scenario and 120-second drain. The external 2700-second bound includes setup and cleanup; it was not waited out.

The attempt stopped during provider setup, before task posting or E1–E6 scoring. Grok's launch guard counted a backup hook file that the installed loader ignores. This is a failed setup, not a scenario pass. No retry is represented by this package.

Claude and Codex independently observed jobs both reached zero active processes. The native fixture had no remaining processes or token files, and its private tmux server was absent. Grok was rejected before process creation. Claude's configuration byte comparison was **false**; Codex's was true. These observations do not establish general profile preservation or identify the cause of the Claude change.

`archive-allowlist.json` binds 168 retained preparation, test, failure and cleanup files by exact bytes and SHA-256. The package excludes credentials, profile contents, stores, tokens and full model reasoning. Source reviews and synthetic tests qualify the external launcher controls; they do not replace real original scenario evidence.

P01-T04 remains in progress. Original team, crossrepo and swarm runs and their required evidence remain outstanding. No phase advancement, merge or release is authorized.

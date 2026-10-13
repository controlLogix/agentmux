# Windows Claude idle prompt compatibility

The original TEAM run showed native Windows Claude using ASCII `>` followed by a non-breaking space. The original profile recognized only `❯`, so the hub deferred delivery before typing. This is a baseline compatibility repair within P01, not the planned P06 adapter extraction.

The focused delivery regression failed with `no input prompt visible` before the fix. After the minimal glyph addition, it passed. All 19 affected delivery, profile and menu tests passed on the working candidate, including existing Unicode prompts, copy mode, startup timing, busy deferral, login and unknown prompts, paste recovery and consent selection. The new menu tests send no keys. Raw test records include the tested source hashes; a passing narrow check does not pass the phase.

The safe recovery record preserves the original failed TEAM score: E1, E3, E4, E5 and E6 were false; E2 was true. No work was claimed. All three independent jobs were empty, and the native fixture had no remaining processes or token files. Claude and Codex configuration comparisons were false; Grok's was true. These observations do not prove general profile preservation.

Codex also recorded a submit failure after three Enter attempts, followed later by an inbox acknowledgment. No retained intermediate screen proves whether this was queued input, an echoed line mistaken for composer text, or another timing issue. That finding remains unresolved; neither the acknowledgment nor the Claude fix changes the failed score.

`manifest.json` binds seven exact safe test and recovery files. The raw local original score remains preserved separately; this package excludes credentials, profile contents, stores, tokens and private pane reasoning. Full original scenario, supported-client and phase acceptance remain open. No phase advancement, merge or release is authorized.

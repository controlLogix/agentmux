# Calibration baseline comparison

The latest historical calibration and the current actual calibration both record all six named E1-E6 checks as passing. This compares recorded outcomes; it does not reconstruct an unrecorded historical execution commit or client version.

The selected historical baseline is `20261002-095139-calib`, the latest retained successful calibration. The records were read from `36cc149a774d823716c81d7b5443b852cb0c63d1`; that is their retention commit, not a proven historical runtime commit. The current evidence is committed at `2aed3e7206e81cf119562647879c90a29457b08a` and names runtime candidate `36cc149a774d823716c81d7b5443b852cb0c63d1`. Every source reference has an exact byte digest in `comparison.json`.

| Check | Historical baseline | Current target |
| --- | --- | --- |
| E1: all top-level work done | Pass | Pass |
| E2: no dead delivery | Pass | Pass |
| E3: no failed doorbell | Pass | Pass |
| E4: no blocked or dead agent | Pass | Pass |
| E5: all deliveries acknowledged | Pass | Pass |
| E6: scenario verification | Pass | Pass |

All three historical calibration records remain represented. The first, `20260929-221859-calib`, failed E6 because its verifier reported an importability error. The earlier successful `20261002-094245-calib` nevertheless records uncommitted changes. These outcomes show why the current independent commit and clean-status checks are necessary.

The target independently passed five tests, including odd, even and empty inputs; a separate call confirmed empty input raises `ValueError`. It produced commit `e33bd02 add median` with a clean checkout. Actual hub events record acknowledgement, claim and completion by the same worker. The original hub handled the trust modal automatically; no manual input fulfilled the task.

The historical worker names identify Codex, but the reports omit its exact version. One failing verifier traceback names Python 3.12, without a patch version. These Linux-shaped paths do not prove a particular OS or WSL distribution. The target pins the Windows Node, Codex launcher and vendor executable hashes. A bounded version-only call against the identical vendor bytes reports Codex 0.162.1; it did not run a model or read a personal profile.

The target's final supervisor result was lost during pane teardown. Exact final job accounting and the Windows config comparison remain unavailable. Known parent absence and no observed fixture processes do not replace those records. Historical reports also lack complete raw test logs and explicit skip fields; their absence cannot be described as zero skips. Differences in duration and modal handling are observations, not a controlled performance result.

Team, crossrepo and swarm still need their original provider runs and explicit comparisons. This calibration comparison does not accept a phase, Windows plugin integration or the complete four-scenario requirement. No historical failure was removed and no new model run was performed.

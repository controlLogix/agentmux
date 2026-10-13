# Share the visual review with Nick

Send **[agentmux-visual-review.html](../agentmux-visual-review.html)**. It is about 13 MB and contains all six concept images, explanations, review questions, styling, scripts and a downloadable copy of the implementation plan. Nick does not need this repository or any other file to read the visual review.

1. Download the HTML attachment to a local folder.
2. Open it in a browser. No web server or internet connection is needed.
3. Use the numbered navigation to reach a scene, and **Enlarge image** to inspect its detail.
4. Add comments beneath the images and in **Your review notes**.
5. Enter **Nick Klute** or **Ryan Helms** and choose **Download notes (.md)**. Save `nick.md` or `ryan.md` in `docs/reviews/agentmux-visual-review/notes`, then commit and push your own file. If no download appears, use **Show notes as text** and copy the result into that file.

Browser drafts stay on the reviewer's computer until exported. Browser draft storage is best-effort, especially for files opened from disk. The HTML starts with empty note fields unless that browser has a saved draft. Rebuilding embeds the Git note files for reading or loading through **Git notes included in this copy**. **Import a review notes file (.md)** loads an exported file after checking its document and sections and asking before replacing the draft. Older versions retain their original labels. See the [reusable Git notes workflow](../../../reviews/README.md) for pull, import, version and commit instructions. The embedded implementation plan is an exact source Markdown copy; its repository-relative references still refer to files in the repository.

These are concept images with sample data. Review notes do not approve implementation, a phase gate or a merge.

## Design and checks

Claude Opus 5.5 authored the original layout, styling, scene renderer, image viewer and local notes interactions through the user-requested Ubuntu WSL terminal. Codex prepared the content, packaged the embedded assets and added the reusable Git notes workflow. See [design provenance](design-provenance.json) for attribution and the integration corrections.

The [verification record](verification.json), refreshed October 13, reports three passing component tests, JavaScript syntax checks, valid local anchors and form labels, six unchanged embedded PNGs, the unchanged dashboard logo, an exact embedded plan, and no external resource references or network calls in the page script. Browser inspection was not completed: the browser tool's policy rejected the local file URL. Static checks do not establish rendered layout or browser interaction correctness.

Codex reviewed this packaging correction with the current P01 evidence checkpoint. The verification history retains the earlier stale-digest result; final source validation is recorded separately in the repository review. These document checks do not pass a delivery gate. Review notes remain feedback, while Codex owns delivery review and final feature-branch acceptance. No merge or release is authorized.

The Git notes update has fourteen passing source tests and a completed scoped independent review. Its first review retained a pending repository-wide check while delivery tracking and TEAM startup evidence were changing. Codex subsequently reviewed the complete checkpoint; the final source check is recorded separately in the repository review. These checks do not establish runtime or phase acceptance.

The six baseline defects now have [verified runtime repairs](../governance-repairs.md) and preserved governance history. The rebuilt HTML embeds the current plan, including that limited progress. Its concept screens remain future designs; the HTML does not establish complete phase or product acceptance.

## Rebuild

From the repository root:

```text
node docs/planning/2026-10-09/review-site/src/pages/build.mjs
node --test docs/planning/2026-10-09/review-site/src/components/organisms/Scene/Scene.test.mjs
node --test docs/reviews/src/features/*.test.mjs
node docs/reviews/check.mjs
```

Edit the source template, feature script, Scene component or `scenes.json`, then rebuild. Do not edit the generated HTML directly. The [build report](build-report.json) records its size, checksum and embedded source hashes.

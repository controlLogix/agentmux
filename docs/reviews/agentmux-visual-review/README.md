# Agentmux visual review notes

Run `node docs/reviews/open.mjs` and open its local URL. Git name/email select your reviewer file; notes save automatically to `notes/nick.md` or `notes/ryan.md`. Missing identity is set through the page for this repository only. The initial files contain empty fields, not submitted feedback.

Use the [shared workflow](../README.md) for pull, export, import, commit and push instructions. The current document ID is `agentmux-visual-review`; [document-version.json](document-version.json) records its source version.

To include the latest committed notes in the offline HTML:

```text
node docs/planning/2026-10-09/review-site/src/pages/build.mjs
```

Reload the page after rebuilding. Notes are feedback and do not authorize a delivery phase, merge or release.

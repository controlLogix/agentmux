# Review notes shared through Git

Keep one Markdown file per reviewer and document. The live launcher reads your Git name and email and saves your notes directly into your repository file as you type. No export or import is required for normal use. Commits and pushes remain explicit Git actions.

## Automatic saving with Git identity

From this repository, run:

```text
node docs/reviews/open.mjs
```

Open the local URL printed by the launcher and leave that terminal running while you review. The launcher rebuilds the page and serves it only on `127.0.0.1`, normally port 4317. Choose a different port with `node docs/reviews/open.mjs agentmux-visual-review 4318` if necessary. Stop with Ctrl+C.

The page detects effective `user.name` and `user.email`, including global settings inherited by this repository. If either is missing or invalid, editing stays disabled and the page asks for your name and email. **Set repository Git identity** writes those two values with `git config --local`; it does not change global configuration or other settings. Existing effective identity is used as-is. Identity is attribution from Git configuration, not proof of login or permission.

Nick and Ryan’s names map to `nick.md` and `ryan.md`. Other reviewers get a name-based filename with an email-derived suffix so matching display names do not share a file. Reviewer metadata records the Git name and email. Optional `emails` lists on reviewer entries can map a different Git display name to an existing reviewer file; do not guess anyone’s email.

Notes load automatically from your file. Each save checks the file revision and current Git identity before writing. An OS-owned local lock also serializes writes from different helper processes; Windows uses a named pipe and other hosts use a loopback socket. The operating system releases it if a helper exits. If a pull, editor or identity change conflicts, saving stops and the page keeps your draft; reload and reconcile the changes before continuing. Temporary failures retry up to five times with backoff. The page warns before leaving with unconfirmed saves. The helper uses a per-launch token and rejects foreign Origins and Hosts. It exposes only identity setup and this review’s note files, not arbitrary Git commands or repository files.

Git notes are the durable shared copy. Live browser recovery is scoped by document and Git email. An older standalone `file://` browser draft belongs to a different browser origin and cannot be read automatically by this local URL. It remains in the old page’s browser storage; the standalone download/import path below is available for one-time migration or backups.

## Nick and Ryan's Git workflow

Use `feat/agentmux-platform-rearchitecture` for this work. Start with a clean working tree, then pull:

```text
git pull --ff-only
```

1. Start `node docs/reviews/open.mjs` and open its local URL.
2. Write notes. Wait for **Saved to …/nick.md** or **…/ryan.md** before closing.
3. Validate the note files. Commit only your own notes and push:

```text
node docs/reviews/check.mjs agentmux-visual-review
git add docs/reviews/agentmux-visual-review/notes/nick.md
git commit -m "docs: add Nick's visual review notes"
git push origin feat/agentmux-platform-rearchitecture
```

Ryan uses `ryan.md` and a matching commit message. If a push is rejected because the branch advanced, fetch and reconcile the new commits before pushing; do not force-push. Follow repository checks and review rules for each commit. Committing feedback does not pass a phase gate.

After the other person pushes, pull and either:

- Use **Import a review notes file (.md)** to load the other person's file directly. Loading requires confirmation and replaces the current browser draft, so download any unsaved work first. Merely selecting Git notes to read them does not change your draft.
- Rebuild the HTML with `node docs/planning/2026-10-09/review-site/src/pages/build.mjs`, then reload it. **Git notes included in this copy** lets you read or load either committed file. A downloaded copy is a snapshot; it does not update when someone pushes new notes.

For normal live use, stop and restart the launcher after pulling so its shared-note snapshot includes both latest files. Your own file is read fresh when the page initializes. Loading someone else’s notes into the live draft copies them into your own file under your Git identity; reading the shared-note preview does not write anything.

Do not overwrite the other person's note file after importing it. Change the reviewer name back to your own if you are writing a response under your own name. Usually, read their feedback and respond in your own file.

## Document versions

Every export carries a document ID, a SHA-256 source version, a reviewer and an export date. The build computes the version from the review's content, images, source plan, layout and interaction code. Feedback files are excluded, so committing notes alone does not change the design version. The generated `document-version.json` records the version and its source hashes.

Imports reject a different document, unsupported format, missing or duplicate sections, oversized notes and invalid metadata before changing the draft. Notes from an earlier version of the same document can be loaded after confirmation. Their original version stays visible and is retained on export. Use **Mark notes reviewed for this document version** only after checking the notes against the current document.

Existing browser drafts from the October 9 review are restored with an **unknown version** label. They remain available under the old browser key until explicitly cleared. To turn an old downloaded Markdown file into this format, restore the browser draft and export it again; old downloads did not contain reliable document-version metadata.

Notes use fenced text blocks so code, Markdown headings and trailing whitespace survive export and import. You can edit the text inside a block with an editor. Keep the metadata and opening/closing fences intact. Markdown is the single shared source; no companion JSON note file is required.

## Reuse for a future review

Create `docs/reviews/<document-id>/review.json`, `document-version.json` and `notes/<reviewer>.md`. Give each document a stable ID and stable section IDs; changing the document ID starts a separate review. For an incompatible section change, use a new document ID or explicitly migrate old notes instead of silently dropping sections.

Set `artifactPath`, `notesPath` and optionally `buildScript` to repository-relative paths in `review.json`. `node docs/reviews/open.mjs <document-id>` launches the same identity and automatic-save workflow for that document. Its page must include the local identity controls shown in the current template. The standalone build remains self-contained and makes no requests; only the live-served copy receives the loopback session token and allows same-origin connections.

Reuse these feature modules:

- `src/features/notes-format.mjs` validates document metadata, exports/imports lossless Markdown, names files and scopes browser storage by document ID. It has no file access, browser access or network calls.
- `src/features/notes-controller.mjs` attaches local draft, import/export and embedded Git-note controls. It imports only the format module. Configure it with `{document, reviewers, notesPath, committedNotes}`; optional `legacyDraftKey` and `legacyReviewId` support older browser drafts.

The page supplies labeled inputs using `reviewer-name`, `notes-import`, `shared-reviewer` and `textarea[data-note]`, with each `data-note` matching a metadata section ID. It also supplies `notes-status`, `notes-saved`, `notes-export`, `notes-export-text`, `document-version`, `notes-version`, `notes-git-path`, `shared-notes`, and buttons with `data-action` values shown in the existing template. `data-print-for` mirrors and `data-nav` indicators are optional. Call `attachReviewNotes(data)` after those elements exist.

Use the current review builder as the packaging example: hash named source inputs, read and validate reviewer files, escape JSON before placing it in a script element, and inline the shared modules. Exclude reviewer files and generated outputs from the source version to avoid a circular version. The delivered HTML needs no server, remote scripts or adjacent files. The CLI checker accepts any configured review directory with this same format.

Run the shared tests and checker:

```text
node --test docs/reviews/src/features/*.test.mjs
node docs/reviews/check.mjs
```

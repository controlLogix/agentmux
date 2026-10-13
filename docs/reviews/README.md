# Review notes shared through Git

Keep one Markdown file per reviewer and document. The HTML saves a private browser draft; downloading creates the file that Git shares. The page never commits, pushes or fetches files itself.

## Nick and Ryan's workflow

Use `feat/agentmux-platform-rearchitecture` for this work. Start with a clean working tree, then pull:

```text
git pull --ff-only
```

1. Open `docs/planning/2026-10-09/agentmux-visual-review.html` locally.
2. Enter **Nick Klute** or **Ryan Helms** and write notes. Browser drafts still save locally.
3. Choose **Download notes (.md)**. Save or move the download to `docs/reviews/agentmux-visual-review/notes/nick.md` or `ryan.md`, replacing only your own file. Check that the browser has not added a suffix such as `(1)` to the filename.
4. Validate the note files. Commit only your own notes and push:

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

Do not overwrite the other person's note file after importing it. Change the reviewer name back to your own if you are writing a response under your own name. Usually, read their feedback and respond in your own file.

## Document versions

Every export carries a document ID, a SHA-256 source version, a reviewer and an export date. The build computes the version from the review's content, images, source plan, layout and interaction code. Feedback files are excluded, so committing notes alone does not change the design version. The generated `document-version.json` records the version and its source hashes.

Imports reject a different document, unsupported format, missing or duplicate sections, oversized notes and invalid metadata before changing the draft. Notes from an earlier version of the same document can be loaded after confirmation. Their original version stays visible and is retained on export. Use **Mark notes reviewed for this document version** only after checking the notes against the current document.

Existing browser drafts from the October 9 review are restored with an **unknown version** label. They remain available under the old browser key until explicitly cleared. To turn an old downloaded Markdown file into this format, restore the browser draft and export it again; old downloads did not contain reliable document-version metadata.

Notes use fenced text blocks so code, Markdown headings and trailing whitespace survive export and import. You can edit the text inside a block with an editor. Keep the metadata and opening/closing fences intact. Markdown is the single shared source; no companion JSON note file is required.

## Reuse for a future review

Create `docs/reviews/<document-id>/review.json`, `document-version.json` and `notes/<reviewer>.md`. Give each document a stable ID and stable section IDs; changing the document ID starts a separate review. For an incompatible section change, use a new document ID or explicitly migrate old notes instead of silently dropping sections.

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

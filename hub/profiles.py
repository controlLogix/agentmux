"""CLI profiles: what a given agent CLI's screen means. See docs/TRANSPORT.md section 3.

A profile knows nothing about tmux. It reads screen TEXT (already ANSI-stripped) and
answers: is it ready for input, is it busy, is a modal showing and what is the safe
answer, is something sitting unsubmitted in the input box.

Ported from agentmux.sh (modal_text / modal_answer / modal_decision / busy_marker)
and clear-modals.sh, which are the record of what each CLI actually showed.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

# A modal answer is a list of ABSTRACT keys (TRANSPORT.md 4). None = needs a person.
# Every entry is here because a screen like it has been seen; see the source comment.
Answer = "list[str] | None"


@dataclass
class Modal:
    kind: str
    pattern: re.Pattern
    answer: list | None           # abstract key sequence, or None = NEEDS A PERSON
    note: str = ""


@dataclass
class Profile:
    cli: str
    ready: re.Pattern             # the idle input prompt, bottom of screen
    busy: re.Pattern | None       # a marker shown only while working
    placeholder: re.Pattern       # an unsubmitted paste in the composer
    modals: list = field(default_factory=list)
    submit_keys: tuple = ("Enter",)
    boot_s: float = 8.0           # minimum time after spawn before ready is trusted
    submit_timeout_s: float = 6.0 # how long to watch for the line to leave the composer
    enter_retry_s: float = 2.0    # spacing between re-sent Enters while it has not
    pre_enter_s: float = 0.25     # pause between typing the line and its first Enter
    # The doorbell line. For an LLM CLI it is an instruction; for a shell it must be a
    # command that is harmless to execute, so the notice rides along as a comment.
    doorbell: str = "[hub] {n_msg} new message(s), {n_claim} claimable work item(s) for {session}. Run: agentmux hub inbox --ack"

    def bell(self, **kw) -> str:
        return self.doorbell.format(**kw)

    def modal(self, screen: str):
        tail = "\n".join([l for l in screen.splitlines() if l.strip()][-14:])
        for m in self.modals:
            if m.pattern.search(tail):
                return m
        return None

    def is_busy(self, screen: str) -> bool:
        if not self.busy:
            return False
        tail = "\n".join([l for l in screen.splitlines() if l.strip()][-8:])
        return bool(self.busy.search(tail))

    def is_ready(self, screen: str) -> bool:
        lines = [l for l in screen.splitlines() if l.strip()]
        return any(self.ready.search(l) for l in lines[-8:])

    def composer_text(self, screen: str) -> str:
        """Text currently in the input line, '' if empty or unknown."""
        for l in reversed([l for l in screen.splitlines() if l.strip()][-8:]):
            m = self.ready.search(l)
            if m:
                return l[m.end():].strip(" │|")
        return ""

    def has_placeholder(self, screen: str) -> bool:
        tail = "\n".join([l for l in screen.splitlines() if l.strip()][-8:])
        return bool(self.placeholder.search(tail))


_I = re.I
PLACEHOLDER = re.compile(r"\[pasted content|\[[0-9]+ lines pasted|\[Pasted text", _I)
BUSY_COMMON = re.compile(r"esc to interrupt|ctrl\+c:cancel|ctrl-c to stop|to interrupt", _I)
# agentmux.sh modal_text, verbatim in spirit: ANY of these shapes means "a prompt is up".
# Used as the last entry of every profile with answer=None, so an unrecognized prompt
# is never typed into - it is reported instead (C2).
GENERIC_MODAL = Modal("unknown", re.compile(
    r"press enter to continue|update now \(runs|\[y/n\]|\(y/n\)|do you (want|trust)|allow this|press any key|"
    r"select an option|continue\? *$|enter to confirm|esc to cancel|no, (exit|quit)|yes, i (accept|trust)|"
    # The selected-option marker must START its line (after optional box drawing):
    # unanchored, the version arrow in codex's "0.159.0 -> 0.159.2" banner matched as a
    # "> 0." menu choice. agentmux.sh modal_text has the same unanchored group.
    r"trust this folder|^\s*[│|]?\s*[❯›▶>]\s+([0-9]+\.|yes\b|no\b|switch\b|keep\b|continue\b|sign in\b|log ?in\b)",
    _I | re.M),
    None, "unrecognized prompt: needs a person")

# codex: "Update available" preselects "1. Update now (runs npm install -g)". Enter on it
# killed panes on 2026-09-20 and 2026-09-29. Skip = option 2 / "Skip". (agentmux.sh
# modal_answer; clear-modals.sh header.)
#
# TRUST AND CONSENT ARE DECISIONS, NOT NUISANCES (AMUX-745). Every trust dialog and
# Claude's bypass consent block with answer=None, as agentmux.sh modal_decision does.
# Codex's trust answer used to be Enter on "Trust and continue": the first doorbell to a
# new worker would have saved trust for its checkout in the owner's ~/.codex/config.toml
# with no decision from the owner. A native worker gets trust for an approved checkout
# when it is launched (agentmux.sh, AGENTMUX_NATIVE_CORE_TRUST_ROOTS), so it never shows.
CODEX = Profile(
    cli="codex",
    ready=re.compile(r"^\s*›\s?"),
    busy=BUSY_COMMON,
    placeholder=PLACEHOLDER,
    modals=[
        # The MENU, not the words. Since codex 0.159.2 shipped (2026-09-30) every pane opens
        # with a non-modal "✨ Update available! ... Run npm install -g @openai/codex to
        # update." banner box in its header. Matching bare "Update available" took that
        # banner for the menu, and no codex pane could be rung. agentmux.sh modal_answer
        # always required BOTH halves; the menu is the line that offers "Update now (runs".
        Modal("update", re.compile(r"Update now \(runs|[›>]\s*1\.\s*Update now", _I), ["2"],
              "never Enter: option 1 runs npm install -g and exits"),
        Modal("trust", re.compile(r"allow codex to work|trust (this|the) (directory|folder)|do you want to allow|Do you trust", _I),
              None, "folder trust is the owner's decision"),
        Modal("login", re.compile(r"Sign in with ChatGPT|Welcome to Codex.*sign in|Provide your own API key", _I | re.S),
              None, "needs a person"),
        GENERIC_MODAL,
    ],
    boot_s=6.0,
)

# claude: three startup modals in a row (folder trust, bypass consent - default
# "No, exit", which killed an agent on 2026-09-22 - and an effort recommendation).
# Trust and bypass consent block for a person (AMUX-745); a pane parked on either is
# reported as blocked, never answered by position or by label.
#
# Claude 2.1.28x dropped "esc to interrupt" from its working line. Measured in the pane
# logs (analysis/comms-2026-09, extract_panes): "✻ Sublimating… (12s)", a bare
# "✻ Verbing…" spinner, and "Press up to edit queued messages". Without these, 431 of
# 454 "pending input" detections were false - the agent was working, not stuck.
CLAUDE_BUSY = re.compile(BUSY_COMMON.pattern + r"|[✻✶✳✢✽·*] ?[A-Z][a-z]+…|…\s*\(\d+[sm]|Press up to edit queued", _I)

CLAUDE = Profile(
    cli="claude",
    # Native Windows Claude also uses ASCII >; menus remain excluded.
    ready=re.compile(r"^\s*[│|]?\s*[❯>]\s?(?!\s*\d+\.)(?!\s*(Yes|No)\b)"),
    busy=CLAUDE_BUSY,
    placeholder=PLACEHOLDER,
    modals=[
        # Measured 2026-09-29 on claude 2.1.285: both preselect "No, exit", so Enter would
        # also kill the agent. Neither is answered at all: a person decides (AMUX-745).
        Modal("bypass", re.compile(r"Bypass Permissions mode|dangerously-skip-permissions.*accept|Yes, I accept", _I | re.S),
              None, "bypass-permissions consent is the owner's decision; default is 'No, exit'"),
        Modal("trust", re.compile(r"Do you trust the files in this folder|Is this a project you (created|trust)|trust this folder", _I),
              None, "folder trust is the owner's decision; default is 'No, exit' on 2.1.285"),
        Modal("effort", re.compile(r"(recommend|Recommended).*effort|Use .* effort", _I), ["Enter"], "keep default"),
        Modal("theme", re.compile(r"Choose the text style|Dark mode.*Light mode", _I | re.S), ["Enter"], "first-run theme"),
        Modal("login", re.compile(r"Not logged in|Select login method", _I), None, "needs a person"),
        GENERIC_MODAL,
    ],
    boot_s=8.0,
)

# grok: its trust prompt takes the letter y, which only a person sends (AMUX-745);
# input drawn inside a │ ❯ │ box.
GROK = Profile(
    cli="grok",
    ready=re.compile(r"^\s*[│|]?\s*[❯>]\s?"),
    # grok's working line is a braille spinner ("⠴ Writing command… 0.6s"), and its
    # footer shows "Ctrl+c:cancel" only while a turn runs (BUSY_COMMON).
    busy=re.compile(BUSY_COMMON.pattern + r"|[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏] \w", _I),
    placeholder=PLACEHOLDER,
    modals=[
        Modal("trust", re.compile(r"do you trust the contents|trust this (folder|directory)", _I),
              None, "folder trust is the owner's decision"),
        GENERIC_MODAL,
    ],
    boot_s=6.0,
    # Measured 2026-09-29 (orchestration 2): grok left the doorbell in its composer
    # through 3 Enters in 8 s, then took it on its own. It queues input internally
    # (the receipts analysis found a 25-minute pager-queue hold). Watch longer, and
    # space the Enters so each can land.
    submit_timeout_s=20.0,
    enter_retry_s=5.0,
    # Orchestration 3: the first Enter after a typing burst was ignored, the one 5 s
    # later landed. Let the burst settle before the first Enter.
    pre_enter_s=1.5,
)

# shell: a plain bash prompt. No busy marker; readiness = a prompt char at line end.
SHELL = Profile(
    cli="shell",
    ready=re.compile(r"[$#]\s?"),
    busy=None,
    placeholder=re.compile(r"(?!x)x"),
    boot_s=0.5,
    doorbell="agentmux hub inbox --ack  # [hub] {n_msg} message(s), {n_claim} claimable for {session}",
)

PROFILES = {p.cli: p for p in (CODEX, CLAUDE, GROK, SHELL)}


def get(cli: str) -> Profile:
    # A path such as /opt/homebrew/bin/codex is still codex: the shell profile has no
    # modal checks, so falling back to it would type the doorbell into a trust menu.
    return PROFILES.get(cli) or PROFILES.get(os.path.basename(cli), SHELL)

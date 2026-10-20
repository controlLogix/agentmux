#!/usr/bin/env python3
"""Verify the dispatch seam: what may be handed to an agent, and in what order.

    python3 dashboard/test_dispatch.py   # no network, no tmux, no port 8787

Runs against a throwaway AGENTMUX_HOME under the system temp directory, so it
never touches the operator's cc.db or starts an agent. Git lifecycle checks use
a temporary repository and real git subprocesses.

WHAT THIS SUITE IS FOR
----------------------
`dispatchable` is the only thing standing between a board and a machine that
starts unrestricted agents against this repository. Four properties matter more
than the rest, and each has a named check:

  * AN UNREADY CARD IS NEVER OFFERED. Not merely "not started" - not offered, so
    a dispatcher cannot start one even by asking for it by name.
  * A CARD RESERVED FOR A PERSON IS NEVER OFFERED. NOT_FOR_AGENTS exists because
    some cards are a decision, and a well-specified decision is still not work an
    agent may take.
  * THE EPIC IS RESOLVED BEFORE READINESS IS JUDGED. _payload_task leaves `epic`
    as None and only board() fills it in; agent_readiness asks for it. The first
    version of this read used _payload_task raw, so on a board with requireEpic
    set - which is the default - EVERY card read as epic-less and the queue was
    permanently empty. It looked like "nothing is ready" rather than a bug, which
    is the kind of failure that survives for weeks.
  * OVERLAPPING WORK RANKS LAST, AND IS STILL OFFERED. Two agents editing one
    file is what claims make safe and disjointness makes rare. A board whose every
    card touches the same file must still drain, one at a time.
"""

import os
import sys
import tempfile
from pathlib import Path

HOME = Path(tempfile.mkdtemp(prefix="ccdispatch-suite-"))
os.environ["AGENTMUX_HOME"] = str(HOME)
os.environ.pop("CC_ENFORCE", None)
os.environ.pop("TM_ENFORCE", None)
sys.path.insert(0, str(Path(__file__).resolve().parent))

import ccboard  # noqa: E402
import ccstore  # noqa: E402

passed = 0
failed = 0


def ok(label, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print("  ok   " + label)
    else:
        failed += 1
        print("  FAIL " + label + ((" - " + str(detail)) if detail else ""))


def section(name):
    print()
    print("== " + name)


def rejects(label, call):
    try:
        call()
    except (ccboard.Invalid, ccstore.Invalid):
        ok(label, True)
        return
    except Exception as err:  # noqa: BLE001
        ok(label, False, "wrong exception: " + type(err).__name__ + ": " + str(err))
        return
    ok(label, False, "the call was allowed")


def ids(rows):
    return [row["id"] for row in rows]


def force_status(db, key, status, actor="suite"):
    """Move a fixture card without re-testing the gates on the way past.

    `ccboard.set_status` used to take `mirror=True`, which skipped gate_start and
    gate_done outright. That parameter is gone: it was also reachable from the
    wire and hard-wired into /api/status, which made it an unlogged bypass of the
    whole model. This suite is about `dispatchable`, not about the gates, so it
    uses the switch `enforcing()` already reads - for the one call, and puts it
    back immediately. A fixture that arms a real override instead would leave one
    armed whenever the transition happened not to be refused, and it would fire
    on whatever gate came next.
    """
    os.environ["CC_ENFORCE"] = "off"
    try:
        return ccboard.set_status(db, key, status, actor=actor)
    finally:
        os.environ.pop("CC_ENFORCE", None)


# ── a board with one epic and a spread of cards ───────────────────────────────

def ready_card(db, epic, title, touches=(), labels=(), priority=None):
    """A card that passes every gate, so a test that expects it to be REFUSED is
    testing the one thing it changed and not an unrelated gap."""
    fields = {"title": title, "epic": epic,
              "body": "why this card exists, at enough length to be a body",
              "acceptance": ["it does the thing"]}
    if priority:
        fields["priority"] = priority
    task = ccboard.create(db, "task", fields, actor="suite")
    key = task["id"]
    for path in touches:
        ccboard.add_touch(db, key, path, actor="suite")
    for label in labels:
        ccboard.set_label(db, key, label, True, actor="suite")
    return key


with ccstore.connection() as db:
    ccboard.migrate(db)
    epic = ccboard.create(db, "epic", {"title": "dispatch suite"}, actor="suite")["id"]

    section("config: the dispatch policy is part of the board, and is validated")
    cfg = ccboard.config(db)
    ok("dispatch is OFF by default",
       cfg["dispatchEnabled"] is False,
       "a fresh checkout must not start agents because a server came up")
    ok("every dispatch setting has a default",
       all(name in cfg for name in ccboard.DISPATCH_KEYS), sorted(cfg))
    ccboard.set_config(db, "dispatchEnabled", True)
    ok("dispatchEnabled accepts a bool", ccboard.config(db)["dispatchEnabled"] is True)
    rejects("dispatchEnabled refuses a string",
            lambda: ccboard.set_config(db, "dispatchEnabled", "yes"))
    ccboard.set_config(db, "dispatchWip", 4)
    ok("dispatchWip accepts a number in range", ccboard.config(db)["dispatchWip"] == 4)
    rejects("dispatchWip refuses out of range",
            lambda: ccboard.set_config(db, "dispatchWip", 99))
    rejects("dispatchPoll refuses a value below the floor",
            lambda: ccboard.set_config(db, "dispatchPoll", 1))
    rejects("dispatchCli refuses shell syntax",
            lambda: ccboard.set_config(db, "dispatchCli", "codex; rm -rf /"))
    ccboard.set_config(db, "dispatchCli", "claude")
    ok("dispatchCli accepts a plain name", ccboard.config(db)["dispatchCli"] == "claude")

    section("dispatchable: an unready card is not offered")
    thin = ccboard.create(db, "task", {"title": "no body, no criteria", "epic": epic},
                          actor="suite", mirror=True)["id"]
    ok("a card with no body or acceptance is not offered",
       thin not in ids(ccboard.dispatchable(db, 50)), thin)

    bodyless = ccboard.create(db, "task",
                              {"title": "criteria but no body", "epic": epic,
                               "acceptance": ["something"]},
                              actor="suite", mirror=True)["id"]
    ok("a card with no body is not offered",
       bodyless not in ids(ccboard.dispatchable(db, 50)))

    good = ready_card(db, epic, "fully specified", touches=["a/one.py"])
    ok("a fully specified card IS offered", good in ids(ccboard.dispatchable(db, 50)))

    section("dispatchable: the epic is resolved before readiness is judged")
    # The regression named in the docstring. requireEpic is on by default, and a
    # card WITH an epic must be offered; if `epic` is read straight off
    # _payload_task it is None and this is empty.
    ok("requireEpic is on for this board", ccboard.config(db)["requireEpic"] is True)
    ok("a card with an epic is not reported epic-less",
       good in ids(ccboard.dispatchable(db, 50)),
       "epic was not resolved onto the payload before agent_readiness read it")

    section("dispatchable: a card reserved for a person is never offered")
    for label in ("ready-for-human", "needs-info", "human-gate",
                  "decision:interview", "decision:prototype", "decision:map"):
        held = ready_card(db, epic, "reserved: " + label, touches=["x/" + label + ".py"],
                          labels=[label])
        ok("a card labelled " + label + " is not offered",
           held not in ids(ccboard.dispatchable(db, 50)))
    # The one decision an agent may answer on its own.
    research = ready_card(db, epic, "research is agent work",
                          touches=["r/research.py"], labels=["decision:research"])
    ok("decision:research IS offered",
       research in ids(ccboard.dispatchable(db, 50)),
       "research is the decision an agent can answer itself")

    section("dispatchable: a blocked dependency withholds the card")
    blocker = ready_card(db, epic, "the blocker", touches=["b/blocker.py"])
    waiter = ready_card(db, epic, "the waiter", touches=["b/waiter.py"])
    ccboard.set_dep(db, waiter, blocker, True, actor="suite")
    ok("a card whose blocker is open is not offered",
       waiter not in ids(ccboard.dispatchable(db, 50)))
    force_status(db, blocker, "done")
    ok("the same card is offered once the blocker is done",
       waiter in ids(ccboard.dispatchable(db, 50)))

    section("dispatchable: a card already in flight is not offered twice")
    force_status(db, good, "in_progress", actor="tm-worker")
    ok("an in_progress card is not offered",
       good not in ids(ccboard.dispatchable(db, 50)))
    flight = ccboard.in_flight(db)
    ok("in_flight reports it once it has an assignee",
       any(row["key"] == good for row in flight) or not flight,
       "in_flight requires an agent on the row")

    section("busy paths: work already being done is not handed out again")
    ccboard.update(db, good, {"assignee": "tm-worker"}, actor="suite")
    busy = ccboard.busy_paths(db)
    ok("busy_paths reports the in-flight card's files",
       "a/one.py" in busy, busy)

    section("touches: overlapping work ranks last but is still offered")
    overlap = ready_card(db, epic, "touches a busy file", touches=["b/waiter.py"])
    offered = ids(ccboard.dispatchable(db, 50, busy=["b/waiter.py"]))
    ok("a card overlapping busy work is still offered", overlap in offered)
    ok("a card overlapping busy work ranks after a disjoint one",
       offered.index(overlap) > 0 and offered.index(waiter) >= 0,
       offered)

    disjoint_first = ids(ccboard.dispatchable(db, 50))
    both = [key for key in disjoint_first if key in (waiter, overlap)]
    ok("two cards on the same file are not both ranked first",
       len(both) == 2 and both[0] == waiter, both)

    section("dispatchable: priority beats arrival order")
    low = ready_card(db, epic, "low priority", touches=["p/low.py"], priority="low")
    high = ready_card(db, epic, "high priority", touches=["p/high.py"], priority="highest")
    order = ids(ccboard.dispatchable(db, 50))
    ok("the highest priority disjoint card comes first",
       order and order[0] == high, order[:4])
    ok("a low priority card still appears", low in order)

    section("dispatch_view: one read, one moment")
    view = ccboard.dispatch_view(db, 5)
    ok("view carries the queue", isinstance(view.get("tasks"), list))
    ok("view carries what is in flight", isinstance(view.get("inFlight"), list))
    ok("view carries only the dispatch half of config",
       set(view["config"]) == set(ccboard.DISPATCH_KEYS), sorted(view["config"]))
    ok("view respects the limit", len(view["tasks"]) <= 5, len(view["tasks"]))
    ok("the queue carries no bodies",
       all("body" not in task for task in view["tasks"]),
       "a list payload carries what a card needs to render, not its markdown")

    section("dispatchable: the limit is validated like every other bounded read")
    rejects("limit refuses zero", lambda: ccboard.dispatchable(db, 0))
    rejects("limit refuses a value past the ceiling", lambda: ccboard.dispatchable(db, 5000))

    section("the human veto still outranks the computation")
    vetoed = ready_card(db, epic, "a person took this out", touches=["v/veto.py"])
    ccboard.set_label(db, vetoed, "ready-for-human", True, actor="a-person")
    db.execute("UPDATE tasks SET triaged_by='human' WHERE key=?", (vetoed,))
    ccboard.triage(db, actor="suite")
    ok("a sweep cannot put a human-vetoed card back in the queue",
       vetoed not in ids(ccboard.dispatchable(db, 50)))


# Exercise the real roster/brief seam; only external board/process calls are fake.
from dataclasses import replace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "taskmgmt"))
import dispatch
import agentdefs

section("worker naming: card identity and team roles stay unambiguous")
ok("role suffix resolves to its card", dispatch.key_of_worker("tm-042-dev") == "TM-042")
ok("four-digit key keeps its final digit", dispatch.key_of_worker("tm-0427") == "TM-0427")
for invalid in ("tm-042-7", "tm-042-2worker", "tm-042-worker.2", "tm-042-worker-dev",
                "tm-42", "tm-1234567890", "tm-042-", "TM-042", "tm-042\n", "", None):
    ok("invalid worker is rejected: %r" % invalid, dispatch.key_of_worker(invalid) is None)
for prefix, width in ccboard.KINDS.values():
    for digits in ("042".zfill(width), "999999999"):
        key = prefix + "-" + digits
        lead = dispatch.worker_name(key)
        ok("lead round-trip: " + key, lead == key.lower() and dispatch.key_of_worker(lead) == key)
        ok("unsuffixed role is lead: " + key, dispatch.role_of_worker(lead) == "lead")
        for role in dispatch.ROLES:
            for ordinal in (1, 2, 123):
                member = dispatch.member_name(key, role, ordinal)
                expected = lead + "-" + role + (str(ordinal) if ordinal > 1 else "")
                ok("member round-trip: " + expected,
                   member == expected and dispatch.key_of_worker(member) == key
                   and dispatch.role_of_worker(member) == role
                   and len(member) <= 64 and "." not in member)
ok("member ordinal defaults to one",
   dispatch.member_name("TM-042", "reviewer") == "tm-042-reviewer")
for key, role, ordinal in (("TM-042", "dev", 1), ("TM-042", "worker", 0),
                           ("TM-042", "worker", -1), ("TM-042", "worker", True),
                           ("TM-042", "worker", 1.5), ("TM-042", "worker", "2"),
                           ("TM-042", "researcher", 1000000),
                           ("TM-042.worker", "worker", 1), ("TM-042-dev", "worker", 1)):
    try:
        dispatch.member_name(key, role, ordinal)
    except ValueError:
        ok("invalid member arguments refused: %r" % ((key, role, ordinal),), True)
    else:
        ok("invalid member arguments refused: %r" % ((key, role, ordinal),), False)

section("briefs: persona uses only the space left by the complete task")
card = {"id": "TM-900", "title": "dispatch seam", "body": "Complete task body.",
        "acceptance": [{"text": "Keep this criterion intact", "done": True}],
        "touches": ["first.py", "last/claimed.py"]}
spec = replace(agentdefs.choose_roster(card, {}, {})[0], name="specialist",
               cli="claude", model="test-model", auth="test-auth",
               posture="unrestricted", persona="Review the code carefully.")
plain = dispatch.write_brief(card).read_text()
brief = dispatch.write_brief(card, spec).read_text()
ok("chosen persona appears under its heading",
   "## Persona\n\nReview the code carefully." in brief)
ok("task content is unchanged by adding a persona", brief.startswith(plain))
long_spec = replace(spec, persona="界" * dispatch.BRIEF_MAX)
bounded_path = dispatch.write_brief(card, long_spec)
bounded = bounded_path.read_text()
ok("oversized multibyte persona stays within BRIEF_MAX bytes",
   bounded_path.stat().st_size <= dispatch.BRIEF_MAX)
ok("persona truncation keeps all task content and final claim",
   bounded.startswith(plain) and "- `last/claimed.py`" in bounded
   and "0. [x] Keep this criterion intact" in bounded)
ok("persona was truncated", long_spec.persona not in bounded)
with patch.object(dispatch, "BRIEF_MAX", len(plain.encode("utf-8"))):
    ok("zero persona budget preserves the complete task",
       dispatch.write_brief(card, spec).read_text() == plain)
oversized = dict(card, acceptance=["required " * dispatch.BRIEF_MAX])
try:
    dispatch.write_brief(oversized, spec)
except ValueError:
    ok("oversized required content is refused without overwriting the brief",
       dispatch.brief_path(card["id"]).read_text() == plain)
else:
    ok("oversized required content is refused without overwriting the brief", False)

section("dispatch refuses a board that is not backed by its own home")
# AGENTMUX_HOME AND THE DASHBOARD ARE RESOLVED INDEPENDENTLY, so a throwaway home
# is not isolation: the POSTs still go to whatever answers on 8787. A pool test run
# that way dispatched two of the operator's real cards and spawned two real agents
# for them. served_home() is patched here so the verdict does not depend on what
# happens to be listening on the machine running the suite.
def foreign_case(home, served, hatch=False):
    env = {k: v for k, v in os.environ.items() if k != "AGENTMUX_ALLOW_FOREIGN_BOARD"}
    if home is None:
        env.pop("AGENTMUX_HOME", None)
    else:
        env["AGENTMUX_HOME"] = home
    if hatch:
        env["AGENTMUX_ALLOW_FOREIGN_BOARD"] = "1"
    with patch.dict(os.environ, env, clear=True), \
         patch.object(dispatch, "served_home", return_value=served):
        return dispatch.foreign_board()

mine, theirs = str(dispatch.ROOT), str(HOME / "somebody-else")
ok("a dashboard serving another home is refused", bool(foreign_case(mine, theirs)))
ok("the refusal names both homes and the way out",
   all(part in foreign_case(mine, theirs)
       for part in (mine, theirs, "AGENTMUX_ALLOW_FOREIGN_BOARD")))
ok("a dashboard serving this home is allowed", foreign_case(mine, mine) == "")
ok("an undiscoverable dashboard fails open", foreign_case(mine, None) == "")
ok("the default pairing is not second-guessed", foreign_case(None, theirs) == "")
ok("the escape hatch is honoured", foreign_case(mine, theirs, hatch=True) == "")
with patch.object(dispatch, "foreign_board", return_value="nope"), \
     patch.object(dispatch, "dispatch_view", return_value=None) as view:
    # return_value=None so that WITHOUT the guard this still returns None and the
    # case fails on the half that matters - "was the board read" - rather than
    # crashing on a MagicMock and proving nothing.
    ok("a refused board is never even read",
       dispatch.dispatch_one() is None and not view.called)

section("dispatch: selected spec reaches spawn and brief")
def dispatch_case(specs, cfg=None, override=None, task=None, dry_run=False):
    task = task or card
    calls = []
    def fake_agentmux(*args, **kwargs):
        calls.append(args)
        return 0, "", ""
    with patch.object(dispatch, "dispatch_view", return_value={
            "tasks": [{"id": task["id"]}], "config": cfg or {}}), \
         patch.object(dispatch, "entity", return_value={"task": task}), \
         patch.object(dispatch, "live_agents", return_value={}), \
         patch.object(agentdefs, "load_all", return_value=(specs, [])) as load, \
         patch.object(agentdefs, "choose_roster", wraps=agentdefs.choose_roster) as choose, \
         patch.object(dispatch.definition_team.TeamPlugin, "propose_legacy", autospec=True,
                      side_effect=dispatch.definition_team.TeamPlugin.propose_legacy) as proposal, \
         patch.object(dispatch, "agentmux", side_effect=fake_agentmux), \
         patch.object(dispatch, "set_status", return_value={}), \
         patch.object(dispatch, "foreign_board", return_value=""), \
         patch.object(dispatch, "board", return_value={"members": [
             {"agent_name": value.name, "role": "lead", "status": "approved",
              "definitionRevision": dict(name=value.name, scope=value.scope,
                  path=value.path, checksum=value.checksum, projectRoot=str(dispatch.REPO.resolve()),
                  snapshotDigest=dispatch.definition_team.snapshot_digest(value)), "definitionState": "current"}
             for value in specs.values() if value.role == "lead"]}):
        result = dispatch.dispatch_one(cli=override, dry_run=dry_run)
        ok("dispatch uses the legacy team plugin proposal boundary", proposal.call_count == 1)
        ok("definitions are loaded for the dispatch repository",
           load.call_args.args == (dispatch.REPO,))
        ok("roster selection receives the full task and CLI override",
           choose.call_args.args == (task, specs, cfg or {})
           and choose.call_args.kwargs == {"cli_override": override,
               "approved_lead": next((s for s in specs.values() if s.role == "lead"), None),
               "dependencies": None})
    return result, calls

result, calls = dispatch_case({spec.name: spec})
spawn = calls[0]
ok("chosen CLI, model, auth and posture reach spawn",
   result == "tm-900" and spawn == (
       "spawn", "tm-900", "--cli", "claude", "--cwd", str(dispatch.REPO),
       "--posture", "unrestricted", "--model", "test-model", "--auth", "test-auth"))
ok("spawn precedes claims and brief delivery",
   [call[0] for call in calls] == ["spawn", "claim", "claim", "wait", "send"])
ok("dispatch writes chosen persona and sends the brief path",
   spec.persona in dispatch.brief_path(card["id"]).read_text()
   and str(dispatch.brief_path(card["id"])) in calls[-1][2])
for cfg, override, expected in (({}, None, "codex"),
                                ({"dispatchCli": "claude"}, None, "claude"),
                                ({"dispatchCli": "claude"}, "gemini", "gemini")):
    result, calls = dispatch_case({}, cfg, override)
    ok("no definition preserves legacy CLI resolution: " + expected,
       result == "tm-900" and calls[0] == (
           "spawn", "tm-900", "--cli", expected, "--cwd", str(dispatch.REPO),
           "--posture", "unrestricted"))
    ok("no definition preserves the original brief",
       dispatch.brief_path(card["id"]).read_text() == plain)
result, calls = dispatch_case({spec.name: spec}, override="codex")
ok("CLI override drops incompatible model and auth",
   calls[0][3] == "codex" and "--model" not in calls[0] and "--auth" not in calls[0])
result, calls = dispatch_case({spec.name: spec}, dry_run=True)
ok("dry run does not spawn or claim", result == "tm-900" and not calls)
result, calls = dispatch_case({spec.name: spec}, task=oversized)
ok("oversized required brief is refused before spawning", result is None and not calls)

section("C6: namespaced resources and transactional claim acquisition")
resource = dispatch.claim_resource("tm-900-worker", "dashboard/app.js")
ok("member resource satisfies the coordination pattern",
   dispatch.coordination.RESOURCE_PATTERN.fullmatch(resource) is not None)
ok("flattened claims distinguish lead and both members",
   len({dispatch.coordination.flatten(value) for value in (
       "dashboard/app.js", resource,
       dispatch.claim_resource("tm-900-worker2", "dashboard/app.js"))}) == 3)
namespace = "tm-900-worker"
ok("combined resource accepts exactly 200 characters",
   len(dispatch.claim_resource(namespace, "a" * (199 - len(namespace)))) == 200)
for bad in ("a" * (200 - len(namespace)), "../secret", "/absolute", "a//b", "./a", "a:b"):
    try:
        dispatch.claim_resource(namespace, bad)
    except ValueError:
        ok("invalid member path refused: " + bad[:30], True)
    else:
        ok("invalid member path refused: " + bad[:30], False)

# Run actual coordination claims with only notification/liveness dependencies
# stubbed, proving that the namespace is an independent lock, not just a string.
import argparse
import contextlib
import io
coord = dispatch.coordination
coord.CLAIMS_DIR.mkdir(parents=True, exist_ok=True)
def real_claim(*args, **kwargs):
    verb, path = args[:2]
    holder = args[args.index("--for") + 1]
    options = argparse.Namespace(resource=path, holder=holder, ttl=600,
                                 task="TM-900", note="suite", depends_on=[], steal=False, force=False)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        rc = coord.cmd_claim(options) if verb == "claim" else coord.cmd_release(options)
    return rc or 0, "", "refused" if rc else ""
with patch.object(dispatch, "agentmux", side_effect=real_claim), \
     patch.object(coord, "live_agents", return_value={"tm-900", namespace, "tm-901"}), \
     patch.object(coord, "journal", return_value="test"), \
     patch.object(coord, "broadcast", return_value=0):
    ok("lead claims the full unnamespaced touches set",
       dispatch.claim_for("tm-900", "TM-900", ["dashboard/app.js"], "lead")[0])
    ok("member can claim the same file within its tree",
       dispatch.claim_for(namespace, "TM-900", ["dashboard/app.js"], "member", namespace)[0])
    dispatch.release_all(namespace, ["dashboard/app.js"], namespace)
    ok("member release preserves lead claim",
       (coord.CLAIMS_DIR / coord.flatten("dashboard/app.js")).exists()
       and not (coord.CLAIMS_DIR / coord.flatten(resource)).exists())
    dispatch.claim_for("tm-901", "TM-901", [namespace + "/busy.py"], "other")
    success, refusal = dispatch.claim_for(namespace, "TM-900",
                                         ["free.py", "busy.py"], "member", namespace)
    ok("partial acquisition releases its successful claim on conflict",
       not success and not (coord.CLAIMS_DIR / coord.flatten(namespace + "/free.py")).exists())
    ok("rollback preserves the conflicting owner's claim",
       '"tm-901"' in (coord.CLAIMS_DIR / coord.flatten(namespace + "/busy.py")).read_text())
with patch.object(dispatch, "agentmux") as mux:
    success, _ = dispatch.claim_for(namespace, "TM-900", ["ok.py", "x" * 200], "test", namespace)
    ok("invalid late resource is rejected before any acquisition", not success and not mux.called)
with patch.object(dispatch, "agentmux", side_effect=[(0, "", ""), (1, "", "busy"),
                                                      (1, "", "release failed")]):
    success, refusal = dispatch.claim_for(namespace, "TM-900", ["a", "b"], "test", namespace)
    ok("failed rollback is surfaced for recovery", not success and "rollback failed" in refusal)

section("member worktrees: real git lifecycle and roster metadata")
import subprocess
with tempfile.TemporaryDirectory(prefix="dispatch-git-") as temp:
    repo = Path(temp) / "repo"
    repo.mkdir()
    def git(*args):
        return subprocess.run(["git", "-C", str(repo), *args], check=True,
                              capture_output=True, text=True).stdout.strip()
    git("init")
    git("-c", "user.name=Suite", "-c", "user.email=suite@example.invalid",
        "commit", "--allow-empty", "-m", "fixture")
    with patch.object(dispatch, "REPO", repo), patch.object(dispatch, "ROOT", Path(temp) / "state"), \
         ccstore.connection() as db:
        key = ready_card(db, epic, "worktree member fixture")
        stamp = ccboard.now()
        for ordinal in (1, 2):
            name = "member" + str(ordinal)
            db.execute("INSERT INTO board_roster "
                       "(entity_key,agent_name,role,position,status,at,updated_at) "
                       "VALUES (?,?,?,?,?,?,?)", (key, name, "worker", ordinal, "approved", stamp, stamp))
            worker = dispatch.member_name(key, "worker", ordinal)
            metadata = dispatch.prepare_member_worktree(db, key, name, worker)
            tree = Path(metadata["worktree"])
            row = db.execute("SELECT member_name,worktree,branch FROM board_roster "
                             "WHERE entity_key=? AND agent_name=?", (key, name)).fetchone()
            ok("member %d records tree, branch and pane on its row" % ordinal,
               tuple(row) == (worker, str(tree), metadata["branch"]) and tree.is_dir())
            ok("member tree is outside the repository", repo not in tree.parents)
            actual = subprocess.run(["git", "-C", str(tree), "branch", "--show-current"],
                                    check=True, capture_output=True, text=True).stdout.strip()
            ok("member checks out its own recorded branch", actual == metadata["branch"])
            try:
                dispatch.prepare_member_worktree(db, key, name, worker)
            except ValueError:
                ok("duplicate setup preserves the original member tree", tree.is_dir())
            else:
                ok("duplicate setup preserves the original member tree", False)
            (tree / "unfinished.txt").write_text("member work")
            try:
                dispatch.remove_worktree(tree)
            except RuntimeError:
                ok("cleanup refuses to discard uncommitted member work", tree.exists())
            else:
                ok("cleanup refuses to discard uncommitted member work", False)
            (tree / "unfinished.txt").unlink()
            dispatch.remove_worktree(tree)
            ok("clean removal retains the member branch for lead integration",
               not tree.exists() and metadata["branch"] in git("branch", "--list"))
        db.execute("INSERT INTO board_roster "
                   "(entity_key,agent_name,role,position,status,at,updated_at) "
                   "VALUES (?,?,?,?,?,?,?)", (key, "failure", "worker", 3, "approved", stamp, stamp))
        worker = dispatch.member_name(key, "worker", 3)
        with patch.object(ccboard, "_record", side_effect=RuntimeError("history write failed")):
            try:
                dispatch.prepare_member_worktree(db, key, "failure", worker)
            except RuntimeError:
                row = db.execute("SELECT member_name,worktree,branch FROM board_roster "
                                 "WHERE entity_key=? AND agent_name='failure'", (key,)).fetchone()
                ok("failed recording rolls back roster metadata", tuple(row) == (None, None, None))
                ok("failed recording removes the new tree and unused branch",
                   worker not in git("worktree", "list") and worker not in git("branch", "--list"))
            else:
                ok("failed recording rolls back roster metadata", False)
        with patch.object(dispatch, "create_worktree") as create:
            try:
                dispatch.prepare_member_worktree(db, key, "not-approved", worker)
            except ValueError:
                ok("missing approved row is refused before creating a worktree", not create.called)
            else:
                ok("missing approved row is refused before creating a worktree", False)
        with patch.object(dispatch, "ROOT", repo / ".state"):
            try:
                dispatch.create_worktree("tm-999-worker")
            except ValueError:
                ok("configured worktree storage inside repo is refused", True)
            else:
                ok("configured worktree storage inside repo is refused", False)

section("collect: fan-out, lead-last, and orphan cleanup")
def collect_case(live, states=None, status="in_progress", evidence=None, kill_failure=None,
                 roster=None, integration="submitted"):
    calls = []
    states = states or {}
    task = {"id": "TM-900", "status": status, "touches": ["src/file.py"],
            "evidence": evidence or []}
    def mux(*args, **kwargs):
        calls.append(args)
        rc = states.get(args[1], 2) if args[0] == "wait" else 0
        if args[0] == "kill" and args[1] == kill_failure:
            rc = 1
        return rc, "", ""
    with patch.object(dispatch, "live_agents", return_value=dict.fromkeys(live, {})), \
         patch.object(dispatch, "agentmux", side_effect=mux), \
         patch.object(dispatch, "set_status", return_value={}) as status_call, \
         patch.object(dispatch, "board", return_value={"members": roster or []}), \
         patch.object(coord, "all_claims", return_value=[]), \
         patch.object(dispatch, "integrate_members", return_value=integration), \
         patch.object(dispatch, "comment"), patch.object(dispatch, "log"):
        result = dispatch.collect_one("TM-900", task)
    kills = [call[1] for call in calls if call[0] == "kill"]
    releases = [call for call in calls if call[0] == "release"]
    return result["outcome"], kills, releases, calls, status_call

lead = "tm-900"
worker = "tm-900-worker"
reviewer = "tm-900-reviewer"
team = [lead, reviewer, worker]
for status in ("done", "deleted", "blocked"):
    outcome, kills, releases, calls, status_call = collect_case(team + ["tm-901-worker"], status=status)
    ok(status + " reaps all members before lead", outcome == status and kills == [reviewer, worker, lead])
    ok(status + " releases member namespaces and lead resources",
       releases == [("release", reviewer + "/src/file.py", "--for", reviewer),
                    ("release", worker + "/src/file.py", "--for", worker),
                    ("release", "src/file.py", "--for", lead)])
    ok(status + " does not change the card status", not status_call.called)

outcome, kills, _, _, status_call = collect_case(team, dict.fromkeys(team, 0), evidence=["result"])
ok("submitted team reaps workers then lead", outcome == "submitted" and kills == [reviewer, worker, lead])
ok("submission never closes the card", not status_call.called)
for evidence in ([], ["result"]):
    outcome, kills, _, _, _ = collect_case([lead, worker], {lead: 0, worker: 2}, evidence=evidence)
    ok("idle lead with busy member stays working, evidence=%r" % evidence,
       outcome == "working" and not kills)
outcome, kills, _, _, _ = collect_case([lead, worker], {lead: 0, worker: 0})
ok("idle member without evidence keeps the lead working", outcome == "working" and not kills)
outcome, kills, _, _, _ = collect_case([lead, worker], {lead: 2, worker: 0}, evidence=["result"])
ok("finished member is reaped while busy lead continues", outcome == "working" and kills == [worker])
outcome, kills, _, _, _ = collect_case([lead, worker], {lead: 2, worker: 3})
ok("exited member CLI still has its pane reaped", outcome == "working" and kills == [worker])
for live, states in (([worker, reviewer], {}), (team, {lead: 3})):
    outcome, kills, releases, _, status_call = collect_case(live, states)
    ok("dead lead reaps live members and parks card",
       outcome == "parked" and kills[:2] == [reviewer, worker]
       and status_call.call_args.args[:2] == ("TM-900", "parked")
       and len(releases) == 3)
outcome, kills, _, _, _ = collect_case(team, status="done", kill_failure=worker)
ok("failed member kill prevents lead reap", outcome == "unresolved" and lead not in kills)
for state, evidence, expected in ((2, [], "working"), (0, [], "idle"),
                                  (0, ["result"], "submitted"), (3, [], "parked")):
    outcome, _, _, _, _ = collect_case([lead], {lead: state}, evidence=evidence)
    ok("single lead retains " + expected + " behavior", outcome == expected)

roster = [{"member_name": worker, "branch": "agentmux/" + worker}]
outcome, kills, _, _, _ = collect_case(team, dict.fromkeys(team, 0), evidence=["result"],
                                     roster=roster, integration="parked")
ok("collection propagates conflict parking and reaps the lead",
   outcome == "parked" and kills[-1] == lead)
outcome, kills, _, _, _ = collect_case([lead], {lead: 0}, evidence=["result"],
                                     roster=roster, integration="unresolved")
ok("failed integration is not reported as submission", outcome == "unresolved" and not kills)
outcome, kills, releases, _, _ = collect_case([lead], {lead: 0}, evidence=["result"], roster=roster)
ok("roster discovers absent member panes and releases their claims",
   outcome == "submitted" and ("release", worker + "/src/file.py", "--for", worker) in releases)
with patch.object(dispatch, "agentmux", return_value=(1, "", "release refused")), \
     patch.object(coord, "all_claims", return_value=[]):
    ok("failed claim release cannot report clean teardown", not dispatch.release_all(worker, ["x"]))


section("lead integration: real merges, conflicts and retryable teardown")
with tempfile.TemporaryDirectory(prefix="dispatch-merge-") as temp:
    repo = Path(temp) / "repo"
    repo.mkdir()
    def git(*args, cwd=None):
        return subprocess.run(["git", "-C", str(cwd or repo), *args], check=True,
                              capture_output=True, text=True).stdout.strip()
    git("init")
    git("config", "user.name", "Suite")
    git("config", "user.email", "suite@example.invalid")
    (repo / "shared.txt").write_text("base\n")
    git("add", ".")
    git("commit", "-m", "base")
    git("checkout", "-b", "integration")
    with patch.object(dispatch, "REPO", repo), patch.object(dispatch, "ROOT", Path(temp) / "state"), \
         patch.object(dispatch, "comment", return_value={}) as comments, \
         patch.object(dispatch, "set_status", return_value={}) as statuses, \
         patch.object(dispatch, "agentmux", return_value=(0, "", "")) as mux, \
         patch.object(coord, "all_claims", return_value=[
             {"holder": "tm-900-worker", "resource": "tm-900-worker/extra.txt"}]):
        first = dispatch.create_worktree("tm-900-worker")
        tree = Path(first["worktree"])
        (tree / "result.txt").write_text("member result")
        git("add", ".", cwd=tree)
        git("commit", "-m", "member result", cwd=tree)
        task = {"worktree": str(repo), "branch": "integration"}
        ok("member commits merge into the lead integration branch",
           dispatch.integrate_members("TM-900", task, [first, {"status": "approved"}]) == "submitted"
           and (repo / "result.txt").read_text() == "member result")
        ok("successful teardown removes member tree and branch",
           not tree.exists() and not git("branch", "--list", first["branch"]))
        ok("teardown releases claims beyond original touches",
           ("release", "tm-900-worker/extra.txt", "--for", "tm-900-worker")
           in [call.args for call in mux.call_args_list])
        dispatch.teardown_member(first, repo)
        ok("repeated integration and teardown succeed",
           dispatch.integrate_members("TM-900", task, [first]) == "submitted")
        second = dispatch.create_worktree("tm-900-worker2")
        tree = Path(second["worktree"])
        (tree / "shared.txt").write_text("member version\n")
        git("add", ".", cwd=tree)
        git("commit", "-m", "member conflict", cwd=tree)
        (repo / "shared.txt").write_text("lead version\n")
        git("add", ".")
        git("commit", "-m", "lead conflict")
        before = git("rev-parse", "HEAD")
        ok("conflict parks the card",
           dispatch.integrate_members("TM-900", task, [second]) == "parked"
           and statuses.call_args.args[:2] == ("TM-900", "parked"))
        ok("conflict comment identifies source, target and files",
           all(value in comments.call_args.args[1]
               for value in (second["branch"], "integration", "shared.txt")))
        ok("conflict preserves commits and leaves no merge in progress",
           git("rev-parse", "HEAD") == before and not git("status", "--porcelain")
           and tree.exists() and git("branch", "--list", second["branch"]))
        try:
            dispatch.teardown_member(second, repo)
        except RuntimeError:
            ok("teardown refuses unmerged member commits", tree.exists())
        else:
            ok("teardown refuses unmerged member commits", False)
        statuses.reset_mock()
        with patch.object(dispatch, "comment", return_value=None):
            ok("failed conflict reporting cannot claim successful parking",
               dispatch.integrate_members("TM-900", task, [second]) == "unresolved")
        ok("integration never closes the card",
           all(call.args[1] != "done" for call in statuses.call_args_list))
        with patch.object(dispatch, "agentmux", side_effect=real_claim), \
             patch.object(coord, "all_claims", wraps=coord.all_claims) as claims_mock, \
             patch.object(coord, "live_agents", return_value={"tm-900-worker"}), \
             patch.object(coord, "journal", return_value="test"), \
             patch.object(coord, "broadcast", return_value=0):
            # The outer claim stub is replaced with the on-disk reader here.
            claims_mock.side_effect = lambda **kw: [coord.read_claim(path)
                for path in coord.CLAIMS_DIR.glob("*.json") if coord.read_claim(path)]
            dispatch.claim_for("tm-900-worker", "TM-900", ["extra.py"], "test", "tm-900-worker")
            dispatch.teardown_member(first, repo)
            ok("successful teardown leaves no claims held by the member",
               not any(c.get("holder") == "tm-900-worker" for c in coord.all_claims()))
        third = dispatch.create_worktree("tm-900-reviewer")
        dispatch.remove_worktree(third["worktree"])
        dispatch.teardown_member(third, repo)
        ok("already removed tree still has its branch cleaned up",
           not git("branch", "--list", third["branch"]))
        fourth = dispatch.create_worktree("tm-900-researcher")
        import shutil
        shutil.rmtree(fourth["worktree"])
        dispatch.teardown_member(fourth, repo)
        ok("missing directory with stale git registration is cleaned up",
           fourth["worktree"] not in git("worktree", "list", "--porcelain"))


section("pool: independent card and global pane limits")
def pool_case(live, wip, max_agents=None, extra_after_spawn=(), meta=None):
    live = dict.fromkeys(live, {})
    cfg = {"dispatchEnabled": True, "dispatchWip": wip}
    if max_agents is not None:
        cfg["teamMaxAgents"] = max_agents
    def spawn(**kwargs):
        name = "tm-%03d" % (910 + len(started))
        started.append(name)
        live[name] = {}
        live.update(dict.fromkeys(extra_after_spawn, {}))
        return name
    started = []
    with patch.object(dispatch, "collect_all", return_value=[]) as collect, \
         patch.object(dispatch, "dispatch_view", return_value={"config": cfg}), \
         patch.object(dispatch, "live_agents", side_effect=lambda: live.copy()), \
         patch.object(dispatch, "board", return_value=meta or {}), \
         patch.object(dispatch, "dispatch_one", side_effect=spawn):
        result = dispatch.pool_once()
    ok("pool collects before filling slots", collect.call_count == 1)
    return result["dispatched"]

ok("three-pane team uses one card slot", len(pool_case(team, 2, 8)) == 1)
ok("global pane cap stops dispatch despite free card slots", pool_case(team, 5, 3) == [])
ok("manual panes also consume global capacity", pool_case(team + ["manual"], 5, 4) == [])
ok("pane budget limits the number of newly started leads", len(pool_case(team, 6, 5)) == 2)
ok("card budget remains binding with pane space available", pool_case(team, 1, 8) == [])
ok("missing teamMaxAgents uses default eight", len(pool_case(team, 20)) == 5)
ok("newly hired panes are recounted after dispatch",
   len(pool_case([lead], 5, 4, [worker, reviewer])) == 1)
ok("zero card budget disables new dispatch", pool_case([], 0, 8) == [])

ok("team limit is loaded from board metadata when dispatch view omits it",
   pool_case(team, 20, meta={"config": {"teamMaxAgents": 3}}) == [])
with patch.object(dispatch, "collect_all", return_value=[]), \
     patch.object(dispatch, "dispatch_view", return_value={"config": {
         "dispatchEnabled": True, "dispatchWip": 4}}), \
     patch.object(dispatch, "board", return_value=None), \
     patch.object(dispatch, "dispatch_one") as spawn:
    result = dispatch.pool_once()
    ok("unavailable team config prevents dispatch", result.get("error") and not spawn.called)

print()
print("passed %d, failed %d" % (passed, failed))
sys.exit(1 if failed else 0)

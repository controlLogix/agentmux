#!/usr/bin/env python3
"""Minimal Atlassian client for the agentmux orchestration.

Jira for task management, Confluence for documentation. Python 3 stdlib only -
no pip install, same constraint as the dashboard backend.

Config: $AGENTMUX_HOME/atlassian.json (default ~/.agentmux), mode 0600,
in the local owner's protected store. Never printed or logged.

    {
      "deployment": "cloud",                     // or "server"
      "base_url":   "https://YOURORG.atlassian.net",
      "email":      "you@example.com",           // cloud only
      "api_token":  "...",                       // cloud: API token; server: PAT
      "jira_project":      "AGENT",
      "confluence_space":  "AGENTMUX"
    }

Cloud uses Basic auth (email:api_token) against the v3 REST API.
Server/DC uses Bearer <PAT> against v2. Both are supported because the auth
scheme and the API paths differ - this is not a detail that can be papered over.

Every call supports dry_run, which returns the request it WOULD make instead of
sending it. That is how this module is tested without an instance.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import pathlib
import re
import ssl
import stat
import urllib.error
import urllib.parse
import urllib.request

# AGENTMUX_HOME, like every sibling module. This file resolved the home directly
# from $HOME, so an isolated run still read and wrote the operator's real one.
CONFIG_PATH = pathlib.Path(
    os.environ.get("AGENTMUX_HOME") or pathlib.Path.home() / ".agentmux"
) / "atlassian.json"
TIMEOUT = 30
MAX_CONFIG = 64 * 1024
MAX_RESPONSE = 2 * 1024 * 1024

REQUIRED = ("deployment", "base_url", "api_token")


class AtlassianError(RuntimeError):
    """Raised with a message safe to show a user - never contains the token."""


class OutcomeUnknown(AtlassianError):
    """A write may have reached the service. This is never permission to retry."""

    outcome_unknown = True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # A configured destination is explicit. Never forward its credentials or
        # repeat a mutation at a destination selected by an HTTP response.
        return None


def validate_config(cfg: dict) -> dict:
    """Validate locally without connecting or changing the supplied settings."""
    if not isinstance(cfg, dict):
        raise AtlassianError("Atlassian configuration must contain a JSON object")
    missing = [key for key in REQUIRED if not cfg.get(key)]
    if missing:
        raise AtlassianError("Atlassian configuration is missing: " + ", ".join(missing))
    if cfg["deployment"] not in ("cloud", "server"):
        raise AtlassianError('deployment must be "cloud" or "server"')
    if cfg["deployment"] == "cloud" and not cfg.get("email"):
        raise AtlassianError('cloud deployment requires "email"')
    for key in ("api_token", "email"):
        value = cfg.get(key)
        if value is not None and (not isinstance(value, str) or not value
                                  or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            raise AtlassianError(f"{key} must be a nonempty value without control characters")
    base = cfg["base_url"]
    try:
        if not isinstance(base, str) or any(c.isspace() or ord(c) < 32 for c in base):
            raise ValueError
        parsed = urllib.parse.urlsplit(base)
        # Accessing port also rejects malformed bracket/port syntax.
        port = parsed.port
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment
                or "\\" in base or port == 0):
            raise ValueError
        decoded = urllib.parse.unquote(parsed.path)
        if (any(c.isspace() or ord(c) < 32 for c in decoded)
                or any(segment in (".", "..") for segment in decoded.split("/"))):
            raise ValueError
    except (ValueError, TypeError):
        raise AtlassianError("base_url must be an HTTPS site URL without credentials, query or fragment") from None
    return {**cfg, "base_url": base.rstrip("/")}


# --------------------------------------------------------------------- config ---

def load_config(path: pathlib.Path | None = None) -> dict:
    p = path or CONFIG_PATH
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
                raise AtlassianError("Atlassian configuration must be an owner-held regular file without links")
            if stat.S_IMODE(info.st_mode) not in (0o600, 0o400):
                raise AtlassianError("Atlassian configuration must be 600 (or read-only 400)")
            raw = handle.read(MAX_CONFIG + 1)
        if len(raw) > MAX_CONFIG:
            raise AtlassianError("Atlassian configuration exceeds the size limit")
        cfg = json.loads(raw)
    except FileNotFoundError:
        raise AtlassianError("Atlassian configuration is missing; run taskmgmt/setup_atlassian.py in your terminal") from None
    except (OSError, ValueError, UnicodeError):
        raise AtlassianError("Atlassian configuration could not be safely read as JSON") from None
    return validate_config(cfg)


def _auth_header(cfg: dict) -> str:
    if cfg["deployment"] == "cloud":
        raw = f"{cfg['email']}:{cfg['api_token']}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")
    return "Bearer " + cfg["api_token"]


# ---------------------------------------------------------------- transport ---

def request(cfg: dict, method: str, path: str, body: dict | None = None,
            *, dry_run: bool = False) -> dict:
    """One HTTP call. Returns the parsed JSON body, or {} for 204."""
    cfg = validate_config(cfg)
    if (method not in ("GET", "POST", "PUT", "DELETE") or not isinstance(path, str)
            or not path.startswith("/") or path.startswith("//") or "#" in path
            or "\\" in path or any(c.isspace() or ord(c) < 32 for c in path)):
        raise AtlassianError("invalid Atlassian request target")
    url = cfg["base_url"] + path
    payload = json.dumps(body).encode("utf-8") if body is not None else None

    if dry_run:
        # Deliberately excludes the Authorization header so a dry run is safe to
        # print, paste into a ticket, or commit.
        return {"dry_run": True, "method": method, "url": url, "body": body}

    req = urllib.request.Request(url, data=payload, method=method)
    req.add_header("Authorization", _auth_header(cfg))
    req.add_header("Accept", "application/json")
    if payload is not None:
        req.add_header("Content-Type", "application/json")

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), _NoRedirect())
    write = method != "GET" and not (method == "POST" and path == _jira_api(cfg) + "/search/jql")

    def failure(message):
        if write:
            return OutcomeUnknown(message + "; the write outcome is unknown. Reconcile it before retrying.")
        return AtlassianError(message)

    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            raw = resp.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise failure("Atlassian response exceeds the size limit")
            if not raw:
                return {}
            try:
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise ValueError
                return result
            except (ValueError, UnicodeError):
                raise failure("Atlassian returned an unreadable JSON object") from None
    except urllib.error.HTTPError as exc:
        # Error bodies and exception strings are untrusted: they can echo the
        # token, request text or server details. Only the status is diagnostic.
        code = exc.code
        exc.close()
        hint = ""
        if code == 401:
            hint = " (check email + api_token; Cloud needs an API token, not your password)"
        elif code == 403:
            hint = " (authenticated but not permitted - check project/space permissions)"
        elif code == 404:
            hint = " (wrong base_url, project key, or space key)"
        elif 300 <= code < 400:
            hint = " (redirect refused; review the configured site URL)"
        message = f"Atlassian HTTP {code}{hint}"
        if code >= 500 or code in (408, 429) or 300 <= code < 400:
            raise failure(message) from None
        raise AtlassianError(message) from None
    except (urllib.error.URLError, OSError, http.client.HTTPException):
        raise failure("Atlassian connection failed or timed out") from None


# --------------------------------------------------------------------- Jira ---

def _jira_api(cfg: dict) -> str:
    return "/rest/api/3" if cfg["deployment"] == "cloud" else "/rest/api/2"


def _issue_key(key):
    if not isinstance(key, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*-[0-9]+", key):
        raise AtlassianError("invalid Jira issue key")
    return key


def _content_id(value):
    if type(value) not in (str, int) or not re.fullmatch(r"[0-9]{1,30}", str(value)):
        raise AtlassianError("invalid Confluence page ID")
    return str(value)


def _adf(text: str) -> dict:
    """Cloud v3 needs Atlassian Document Format; Server v2 takes plain text."""
    return {
        "type": "doc", "version": 1,
        "content": [
            {"type": "paragraph",
             "content": [{"type": "text", "text": line or " "}]}
            for line in text.split("\n")
        ],
    }


def jira_create(cfg, summary, description="", issue_type="Task",
                labels=None, *, dry_run=False) -> dict:
    project = cfg.get("jira_project")
    if not project:
        raise AtlassianError('config needs "jira_project" to create an issue')
    fields = {
        "project": {"key": project},
        "summary": summary[:255],
        "issuetype": {"name": issue_type},
    }
    if description:
        fields["description"] = (_adf(description)
                                 if cfg["deployment"] == "cloud" else description)
    if labels:
        fields["labels"] = list(labels)
    result = request(cfg, "POST", f"{_jira_api(cfg)}/issue",
                     {"fields": fields}, dry_run=dry_run)
    if not dry_run:
        try:
            key = _issue_key(result.get("key"))
            if not key.startswith(str(project) + "-"):
                raise AtlassianError("unexpected project")
        except AtlassianError:
            raise OutcomeUnknown("Jira returned no usable issue identity; the write outcome is unknown. Reconcile it before retrying.") from None
    return result


def jira_comment(cfg, key, text, *, dry_run=False) -> dict:
    body = {"body": _adf(text) if cfg["deployment"] == "cloud" else text}
    result = request(cfg, "POST", f"{_jira_api(cfg)}/issue/{_issue_key(key)}/comment",
                     body, dry_run=dry_run)
    if not dry_run:
        try:
            _content_id(result.get("id"))
        except AtlassianError:
            raise OutcomeUnknown("Jira returned no usable comment identity; the write outcome is unknown. Reconcile it before retrying.") from None
    return result


def jira_search(cfg, jql, limit=25, *, dry_run=False) -> dict:
    if cfg["deployment"] == "cloud":
        # Cloud moved search to POST /search/jql
        return request(cfg, "POST", f"{_jira_api(cfg)}/search/jql",
                       {"jql": jql, "maxResults": int(limit),
                        "fields": ["summary", "status", "assignee", "labels"]},
                       dry_run=dry_run)
    q = urllib.parse.urlencode({"jql": jql, "maxResults": int(limit)})
    return request(cfg, "GET", f"{_jira_api(cfg)}/search?{q}", dry_run=dry_run)


def jira_transitions(cfg, key, *, dry_run=False) -> dict:
    return request(cfg, "GET",
                   f"{_jira_api(cfg)}/issue/{_issue_key(key)}/transitions",
                   dry_run=dry_run)


def jira_transition(cfg, key, transition_id, *, dry_run=False) -> dict:
    if type(transition_id) not in (str, int) or not re.fullmatch(r"[0-9]{1,30}", str(transition_id)):
        raise AtlassianError("invalid Jira transition ID")
    return request(cfg, "POST",
                   f"{_jira_api(cfg)}/issue/{_issue_key(key)}/transitions",
                   {"transition": {"id": str(transition_id)}}, dry_run=dry_run)


# --------------------------------------------------------------- Confluence ---

def _conf_api(cfg: dict) -> str:
    # Cloud serves Confluence under /wiki; Server/DC does not.
    return "/wiki/rest/api" if cfg["deployment"] == "cloud" else "/rest/api"


def confluence_find(cfg, title, *, dry_run=False) -> dict:
    space = cfg.get("confluence_space")
    if not space:
        raise AtlassianError('config needs "confluence_space"')
    q = urllib.parse.urlencode({
        "title": title, "spaceKey": space, "expand": "version",
    })
    return request(cfg, "GET", f"{_conf_api(cfg)}/content?{q}", dry_run=dry_run)


def confluence_upsert(cfg, title, html, *, parent_id=None, dry_run=False) -> dict:
    """Create the page, or update it in place if the title already exists.

    Title lookup is not a durable operation identity. A lost create/update reply
    must be reconciled by the external-effect owner before another call.
    """
    space = cfg.get("confluence_space")
    if not space:
        raise AtlassianError('config needs "confluence_space"')
    parent = _content_id(parent_id) if parent_id is not None else None

    existing = None
    if not dry_run:
        found = confluence_find(cfg, title)
        results = found.get("results")
        links = found.get("_links", {})
        if (not isinstance(results, list) or len(results) > 1
                or not isinstance(links, dict) or links.get("next")):
            raise AtlassianError("Confluence page lookup is ambiguous; reconcile the page identity")
        if results:
            existing = results[0]
            if not isinstance(existing, dict) or existing.get("title") != title:
                raise AtlassianError("Confluence page lookup returned an unexpected page")

    payload = {
        "type": "page",
        "title": title,
        "space": {"key": space},
        "body": {"storage": {"value": html, "representation": "storage"}},
    }
    if parent is not None:
        payload["ancestors"] = [{"id": parent}]

    if existing:
        version_info = existing.get("version")
        version = version_info.get("number") if isinstance(version_info, dict) else None
        if type(version) is not int or version < 1:
            raise AtlassianError("Confluence page has no usable version; reread it before updating")
        version += 1
        payload["version"] = {"number": version}
        page_id = _content_id(existing.get("id"))
        result = request(cfg, "PUT", f"{_conf_api(cfg)}/content/{page_id}",
                         payload, dry_run=dry_run)
    else:
        page_id = None
        result = request(cfg, "POST", f"{_conf_api(cfg)}/content", payload, dry_run=dry_run)
    if not dry_run:
        try:
            returned_id = _content_id(result.get("id"))
            returned_space = result.get("space")
            returned_version = result.get("version")
            expected_version = payload.get("version", {"number": 1})["number"]
            if (page_id is not None and returned_id != page_id
                    or result.get("type") != "page" or result.get("title") != title
                    or not isinstance(returned_space, dict) or returned_space.get("key") != space
                    or not isinstance(returned_version, dict)
                    or type(returned_version.get("number")) is not int
                    or returned_version["number"] != expected_version):
                raise AtlassianError("unexpected page identity")
        except AtlassianError:
            raise OutcomeUnknown("Confluence returned no matching page receipt; the write outcome is unknown. Reconcile it before retrying.") from None
    return result


def whoami(cfg, *, dry_run=False) -> dict:
    path = ("/rest/api/3/myself" if cfg["deployment"] == "cloud"
            else "/rest/api/2/myself")
    return request(cfg, "GET", path, dry_run=dry_run)

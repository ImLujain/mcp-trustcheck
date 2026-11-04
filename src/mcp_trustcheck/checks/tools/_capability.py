"""Capability inference shared by TOOL-004 and TOOL-008.

Deliberately simple and transparent: name tokens first, then the first sentence of the
description. Every inference is a heuristic and is reported as such.
"""

from __future__ import annotations

import re

from mcp_trustcheck.model import ToolDefinition

CLASSES: dict[str, re.Pattern[str]] = {
    "exec": re.compile(
        r"^(?:exec|execute|run|shell|sh|bash|cmd|command|spawn|terminal|eval|script|sudo|powershell)$"
    ),
    "delete": re.compile(
        r"^(?:delete|remove|rm|drop|purge|destroy|truncate|wipe|erase|unlink|revoke|kill|terminate|reset|format)$"
    ),
    "write": re.compile(
        r"^(?:write|create|update|modify|edit|save|insert|upload|move|mv|rename|overwrite|put|set|apply|patch|commit|push|merge|install|deploy|append|chmod|chown|mkdir|copy|cp|restore|import)$"
    ),
    "send": re.compile(
        r"^(?:send|email|mail|post|publish|notify|transfer|pay|transmit|forward|share|tweet|reply|message|dm|invite|submit|order|purchase|book)$"
    ),
}
INGRESS_VERB_RE = re.compile(
    r"^(?:fetch|get|read|browse|open|search|crawl|scrape|download|load|list|query|check|poll|receive|retrieve|view)$"
)
INGRESS_NOUNS = frozenset(
    {
        "web",
        "url",
        "urls",
        "http",
        "page",
        "pages",
        "site",
        "website",
        "email",
        "emails",
        "mail",
        "inbox",
        "issue",
        "issues",
        "pr",
        "prs",
        "pull",
        "pulls",
        "comment",
        "comments",
        "review",
        "reviews",
        "feed",
        "rss",
        "news",
        "slack",
        "discord",
        "teams",
        "message",
        "messages",
        "thread",
        "threads",
        "ticket",
        "tickets",
    }
)
_SPLIT_RE = re.compile(r"[_\-.\s/]+|(?<=[a-z0-9])(?=[A-Z])")
_FIRST_SENTENCE_RE = re.compile(r"^[^.!?\n]{0,120}")
_DESC_VERB_RE = {
    "exec": re.compile(r"(?i)\b(?:executes?|runs?|spawns?|shell command|arbitrary command)\b"),
    "delete": re.compile(
        r"(?i)\b(?:deletes?|removes?|drops?|purges?|destroys?|truncates?|wipes?|permanently)\b"
    ),
    "write": re.compile(
        r"(?i)\b(?:writes?|creates?|updates?|modif(?:y|ies)|edits?|saves?|uploads?|overwrites?|inserts?|renames?|moves?)\b"
    ),
    "send": re.compile(
        r"(?i)\b(?:sends?|emails?|posts?|publishes|notif(?:y|ies)|transfers?|pays?|transmits?|forwards?|messages?)\b"
    ),
}
_DESC_INGRESS_RE = re.compile(
    r"(?i)\b(?:fetch(?:es)?|retriev(?:e|es)|download(?:s)?|crawl(?:s)?|scrape(?:s)?|browse(?:s)?|read(?:s)?)\b.{0,40}"
    r"\b(?:url|web ?page|website|internet|http|email|inbox|message|issue|pull request|comment|feed|document|file)s?\b"
    r"|\b(?:web search|search the web|search results|external content|untrusted)\b"
)


def tokens(name: str) -> list[str]:
    return [t.lower() for t in _SPLIT_RE.split(name) if t]


def infer(tool: ToolDefinition) -> tuple[set[str], str]:
    """Return (capability classes, basis) where basis is 'name' or 'description' or ''."""
    toks = tokens(tool.name)
    classes = {c for c, rx in CLASSES.items() if any(rx.match(t) for t in toks)}
    if classes:
        return classes, "name"
    if tool.description:
        first = _FIRST_SENTENCE_RE.match(tool.description)
        head = first.group(0) if first else ""
        classes = {c for c, rx in _DESC_VERB_RE.items() if rx.search(head)}
        if classes:
            return classes, "description"
    return set(), ""


def is_ingress(tool: ToolDefinition) -> tuple[bool, str]:
    """Return (is_ingress, basis) — basis is 'annotation', 'name', 'description' or ''."""
    if tool.annotations.get("openWorldHint") is True:
        return True, "annotation"
    toks = tokens(tool.name)
    if (
        len(toks) >= 2
        and any(INGRESS_VERB_RE.match(t) for t in toks)
        and any(t in INGRESS_NOUNS for t in toks)
    ):
        return True, "name"
    if tool.description:
        first = _FIRST_SENTENCE_RE.match(tool.description)
        if first and _DESC_INGRESS_RE.search(first.group(0)):
            return True, "description"
    return False, ""

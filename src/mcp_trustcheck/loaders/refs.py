"""Detection of non-literal config values.

A value is *non-literal* when it is a reference the client resolves at runtime:
`${env:NAME}`, `${input:ID}`, `${workspaceFolder}`, `${NAME}`, a bare `$NAME`, or `%NAME%`.
Secret and path checks only fire on literal values.
"""

from __future__ import annotations

import re

_BRACED_REF = re.compile(r"\$\{[^}]+\}")
_BARE_ENV = re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$")
_WIN_ENV = re.compile(r"^%[A-Za-z_][A-Za-z0-9_]*%$")


def is_reference(value: str) -> bool:
    v = value.strip()
    return bool(_BRACED_REF.search(v) or _BARE_ENV.match(v) or _WIN_ENV.match(v))


def is_literal(value: str) -> bool:
    return not is_reference(value)

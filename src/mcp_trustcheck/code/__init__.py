"""Package code analysis: locate the code a server entry launches and derive a capability manifest.

Only the data model is exported here. Import `mcp_trustcheck.code.extract` for the analysers: the
locator reuses the launcher parsing in `checks.config.packages`, and the checks package must be
importable without pulling the analysers in.
"""

from mcp_trustcheck.code.model import (
    CAPABILITY_CLASSES,
    PHRASES,
    SIDE_EFFECT_CLASSES,
    PackageManifest,
    Sink,
    ToolCapabilities,
    UnlocatedPackage,
)

__all__ = [
    "CAPABILITY_CLASSES",
    "PHRASES",
    "SIDE_EFFECT_CLASSES",
    "PackageManifest",
    "Sink",
    "ToolCapabilities",
    "UnlocatedPackage",
]

"""mcp-trustcheck: read-only static security auditing for MCP deployments.

The package never executes commands, never opens network connections, and never
writes to the files it scans. See docs/design.md §6 for the enforced constraints.
"""

__version__ = "0.2.0"

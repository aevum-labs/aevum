"""
python -m aevum.mcp — start the Aevum MCP server (stdio transport).

For Claude Desktop, register in ~/.claude/claude_desktop_config.json:
    {
      "mcpServers": {
        "aevum": {
          "command": "python",
          "args": ["-m", "aevum.mcp"]
        }
      }
    }
"""

from __future__ import annotations

from aevum.core.engine import Engine

from aevum.mcp.server import create_server


def main() -> None:
    engine = Engine()
    mcp = create_server(engine)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

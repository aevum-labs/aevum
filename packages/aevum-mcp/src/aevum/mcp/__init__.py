"""
aevum.mcp — MCP server exposing Aevum's five functions as tools.

Claude Desktop config (~/.claude/claude_desktop_config.json):
    {
      "mcpServers": {
        "aevum": {
          "command": "python",
          "args": ["-m", "aevum.mcp"],
          "env": {
            "AEVUM_API_KEY": "your-key-here"
          }
        }
      }
    }
"""

from aevum.mcp.server import create_server

__version__ = "0.1.0"

__all__ = ["create_server"]

"""
Entry point: aevum <command>
Invoked via [project.scripts] aevum = "aevum.cli.__main__:app"
"""

from aevum.cli.app import app

if __name__ == "__main__":
    app()

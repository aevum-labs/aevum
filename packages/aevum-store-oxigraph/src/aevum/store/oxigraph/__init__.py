"""
aevum.store.oxigraph — Oxigraph GraphStore backend.

Usage:
    from aevum.store.oxigraph import OxigraphStore
    from aevum.core import Engine

    # In-memory (dev/test):
    store = OxigraphStore()

    # Disk-backed (production):
    store = OxigraphStore(path="/var/lib/aevum/graph")

    engine = Engine(graph_store=store)
"""

from aevum.store.oxigraph.store import OxigraphStore

__version__ = "0.1.0"

__all__ = ["OxigraphStore"]

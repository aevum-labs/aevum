# aevum-store-oxigraph

Oxigraph-backed graph store for Aevum. Suitable for single-node and embedded deployments. No external database required.

```bash
pip install aevum-store-oxigraph
```

```python
from aevum.core import Engine
from aevum.store.oxigraph import OxigraphStore

engine = Engine(graph_store=OxigraphStore(path="./aevum-data"))
```

For team deployments requiring shared state, use `aevum-store-postgres` instead.
See the [main repository README](https://github.com/aevum-labs/aevum) for backend selection guidance.

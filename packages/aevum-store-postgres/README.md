# aevum-store-postgres

PostgreSQL-backed graph store for Aevum. Suitable for team deployments with shared state, concurrent writers, and durable persistence.

```bash
pip install aevum-store-postgres
```

```python
import psycopg
from aevum.core import Engine
from aevum.store.postgres import PostgresStore
from aevum.store.postgres.store import initialize_schema

conn = psycopg.connect("postgresql://user:pass@localhost/aevum")
initialize_schema(conn)
engine = Engine(graph_store=PostgresStore(conn))
```

For single-node deployments without PostgreSQL, use `aevum-store-oxigraph` instead.
See the [main repository README](https://github.com/aevum-labs/aevum) for backend selection guidance.

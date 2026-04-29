# aevum-oidc

OIDC identity federation complication for Aevum. Validates Bearer tokens via JWKS and resolves actor identity from the `sub` claim — never stores credentials or raw tokens.

```bash
pip install aevum-oidc
```

```python
from aevum.oidc import OidcComplication
from aevum.core import Engine

engine = Engine()
engine.install_complication(
    OidcComplication(jwks_uri="https://your-idp/.well-known/jwks.json", audience="your-api"),
    auto_approve=True,
)
```

See the [main repository README](https://github.com/aevum-labs/aevum) for the complication installation guide.

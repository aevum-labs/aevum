---
description: "How to run, deploy, and configure the Aevum live demo at demo.aevum.build."
---

# Demo Site Deployment

The Aevum demo runs at [demo.aevum.build](https://demo.aevum.build). It is a
FastAPI application that exposes the five public Aevum functions through a
guided playground with three scenarios.

## Running locally

```bash
cd demo
pip install -r requirements.txt
AEVUM_DEV=1 python main.py
```

The server starts on `http://localhost:7860`. Open the landing page at `/`
and the API explorer at `/docs`.

`AEVUM_DEV=1` enables the permissive dev-mode consent ledger so the seeded
scenarios work without a real policy engine. **Never set this in production.**

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `AEVUM_DEV` | Local only | Enables dev-mode consent ledger. Must not be set in production. |
| `FLY_API_TOKEN_DEMO` | CI/CD | Fly.io API token scoped to the `aevum-demo` app. Set as a GitHub Actions environment secret under the `demo` environment. |
| `HF_SPACE_ID` | Runtime | Set automatically by Hugging Face Spaces. Enables `Secure` cookie flag and HSTS. Not set on Fly.io. |

## Deployment (Fly.io)

The demo is deployed from `demo/fly.toml`. It is a separate Fly.io app
(`aevum-demo`) from the maintainer app (`aevum-maintainer`).

### First-time setup

```bash
cd demo
flyctl launch --no-deploy       # creates app from fly.toml
flyctl secrets set AEVUM_DEV=   # unset in production — leave blank
flyctl deploy --remote-only
```

### Subsequent deploys

Deploys run automatically via `.github/workflows/deploy-demo.yml` on every
push to `main` that touches `demo/**`. The workflow:

1. Starts the demo server locally and runs an axe-core accessibility audit
   against the landing page.
2. Deploys to Fly.io with `flyctl deploy --remote-only`.

To deploy manually:

```bash
cd demo
flyctl deploy --remote-only
```

### Health check

Fly.io polls `GET /health` every 30 seconds. The response is `{"status": "ok"}`.

## Security notes

- **CORS**: No `CORSMiddleware` is configured. Cross-origin requests are denied
  by the browser by default. This is intentional for the demo — all interaction
  is through the hosted UI.
- **X-Robots-Tag**: Every response includes `X-Robots-Tag: noindex, nofollow`
  to prevent search engine indexing of the demo API.
- **Rate limits**: All demo routes are rate-limited via slowapi (per-IP).
  Limits range from 3/minute (reset) to 60/minute (ledger, replay).
- **Session cap**: Maximum 200 concurrent sessions. Oldest session is evicted
  when the cap is reached.

## Manual steps (maintainer action required)

- **Fly.io app creation**: Run `flyctl launch` once to create the `aevum-demo`
  app. The `fly.toml` is ready; this step requires a maintainer with a Fly.io
  account.
- **GitHub Actions environment**: Create a `demo` environment in the repository
  settings and add `FLY_API_TOKEN_DEMO` as a secret.
- **Custom domain**: Map `demo.aevum.build` to the Fly.io app using
  `flyctl certs add demo.aevum.build` and add the CNAME in your DNS provider.

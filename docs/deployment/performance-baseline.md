---
description: "Lighthouse performance baseline for aevum.build. Records lab scores and identifies gaps for future improvement."
---

# Performance Baseline

Targets (mobile, Lighthouse lab):

| Metric | Target | Status |
|---|---|---|
| LCP (Largest Contentful Paint) | ≤ 2.5 s | Pending first deploy |
| INP (Interaction to Next Paint) | ≤ 200 ms | Pending first deploy |
| CLS (Cumulative Layout Shift) | ≤ 0.1 | Pending first deploy |
| Lighthouse mobile overall | ≥ 90 | Pending first deploy |

## Measurement deferred

Lighthouse lab scores require a live HTTP server. This baseline was not
measurable in the CI/build environment used during Phase UX. Run the
measurement after the first real deploy to `aevum.build`.

## How to run

```bash
# 1. Build and serve the docs locally
pip install mkdocs-material
mkdocs build --strict
mkdocs serve &
sleep 3

# 2. Run Lighthouse mobile simulation
npx lighthouse http://localhost:8000 \
  --preset=mobile \
  --output=json \
  --output-path=lighthouse-report.json \
  --chrome-flags="--headless --no-sandbox"

# 3. Extract scores
jq '{lcp: .audits["largest-contentful-paint"].numericValue,
     inp: .audits["interaction-to-next-paint"].numericValue,
     cls: .audits["cumulative-layout-shift"].numericValue,
     performance: .categories.performance.score,
     accessibility: .categories.accessibility.score}' lighthouse-report.json
```

## Expected characteristics

aevum.build is a Material for MkDocs static site. Expected characteristics:

- **LCP**: Driven by the hero text block (no large hero image on the homepage).
  Should be fast given minimal above-the-fold images.
- **INP**: No heavy JavaScript on non-interactive pages. Material's search
  widget is the primary JS interaction path.
- **CLS**: Material's fixed header and no lazy-loaded layout-shifting elements
  suggest CLS should be near zero.

## Gaps to address in v0.7.0

- OG image (`og-image.png`) is a placeholder asset. A commissioned
  1200×630 design asset would improve social sharing quality but does not
  affect Lighthouse scores.
- The Scalar API explorer (`/docs` on the demo site) loads a CDN-hosted
  bundle. CDN latency and bundle size should be measured separately from
  the docs site.

## CrUX note

Lab scores (Lighthouse) are directionally useful but CrUX (Chrome User
Experience Report) field data is the real signal for Core Web Vitals
certification. Register `aevum.build` in Google Search Console and submit
`sitemap.xml` after the first deploy to start collecting field data.

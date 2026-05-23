---
description: "Aevum's accessibility target, what is checked in CI, known gaps, and how to report issues."
---

# Accessibility

## Target

Aevum's documentation site (`aevum.build`) and demo (`demo.aevum.build`)
target **WCAG 2.1 Level AA** (WCAG 2.4.1 success criterion for
keyboard-accessible bypass blocks).

## What is checked

### Skip navigation link

A "Skip to main content" link is injected as the first focusable element
on every page of the docs site (`docs/overrides/main.html`). It is visually
hidden until focused via keyboard, allowing keyboard and screen-reader users
to bypass repeated navigation.

The CSS lives in `docs/stylesheets/extra.css`.

### Accessibility CI audit (demo site)

The demo deployment workflow (`.github/workflows/deploy-demo.yml`) runs
`@axe-core/cli` against the demo landing page (`GET /`) on every deploy.
The job fails and blocks deployment if axe reports any violations.

The demo site is a pure Python (FastAPI) application with no React or other
frontend framework. There is no `jsx-a11y` ESLint plugin because there is
no JavaScript component tree to lint.

## Known gaps

| Gap | Severity | Target |
|---|---|---|
| Material for MkDocs search modal focus trap not tested | Low | v0.7.0 |
| Colour contrast of `--muted` text on demo landing page not audited | Medium | v0.7.0 |
| No automated WCAG 2.1 AA scan of internal docs pages beyond the homepage | Medium | v0.7.0 |
| axe-core CI audit covers landing page only, not `/docs` (Scalar) | Low | v0.7.0 |

## Reporting issues

Open an issue on [GitHub](https://github.com/aevum-labs/aevum/issues) with
the label `accessibility`. Include the URL, the WCAG success criterion
violated, and steps to reproduce.

import { useState, lazy, Suspense } from 'react'
import './ScalarExplorer.css'

const ApiReference = lazy(() =>
  import('@scalar/api-reference-react').then(m => ({ default: m.ApiReferenceReact }))
)

export function ScalarExplorer() {
  const [open, setOpen] = useState(false)
  const apiUrl = (import.meta.env.VITE_API_URL as string | undefined) ?? ''

  if (!open) {
    return (
      <button className="scalar-launch-btn" onClick={() => setOpen(true)}>
        Launch API Explorer →
      </button>
    )
  }

  return (
    <div className="scalar-wrapper">
      <Suspense fallback={<p className="scalar-loading">Loading API Explorer…</p>}>
        <ApiReference
          configuration={{
            spec: { url: `${apiUrl}/openapi.json` },
            ...(apiUrl ? { servers: [{ url: apiUrl }] } : {}),
            darkMode: true,
            customCss: `
              :root {
                --scalar-font: "SF Mono", "Fira Code", "Cascadia Code", monospace;
                --scalar-font-code: "SF Mono", "Fira Code", "Cascadia Code", monospace;
              }
              .dark-mode {
                --scalar-background-1: #0d0d0d;
                --scalar-background-2: #161616;
                --scalar-background-3: #1e1e1e;
                --scalar-color-1: #e0e0e0;
                --scalar-color-2: #aaa;
                --scalar-color-3: #888;
                --scalar-color-accent: #a78bfa;
                --scalar-background-accent: rgba(167, 139, 250, 0.12);
                --scalar-border-color: #2a2a2a;
                --scalar-color-purple: #a78bfa;
              }
            `,
          }}
        />
      </Suspense>
    </div>
  )
}

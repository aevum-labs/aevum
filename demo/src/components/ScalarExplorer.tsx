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
            servers: [{ url: apiUrl }],
          }}
        />
      </Suspense>
    </div>
  )
}

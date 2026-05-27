import { useState, useEffect } from 'react'
import { Stepper } from './components/Stepper'
import { ScalarExplorer } from './components/ScalarExplorer'
import { checkHealth } from './api'
import './App.css'

function ApiStatus() {
  const [online, setOnline] = useState<boolean | null>(null)

  useEffect(() => {
    checkHealth().then(setOnline)
    const id = setInterval(() => checkHealth().then(setOnline), 30_000)
    return () => clearInterval(id)
  }, [])

  if (online === null) return null
  return (
    <span className={`api-status ${online ? 'api-online' : 'api-offline'}`}>
      {online ? 'API Online' : 'API Offline'}
    </span>
  )
}

export default function App() {
  function scrollToExplorer() {
    document.getElementById('api-explorer')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="app-header-row">
          <h1 className="app-title">AEVUM</h1>
          <ApiStatus />
        </div>
        <p className="app-tagline">The Black Box for AI Agents — governed context kernel</p>
      </header>

      <main>
        <section className="section" aria-label="Guided demo">
          <p className="section-label">Four-step demo</p>
          <p className="section-sub">
            Run a governed diagnostic scan. Every step is recorded in the cryptographic audit trail.
          </p>
          <Stepper onViewApiExplorer={scrollToExplorer} />
        </section>

        <section className="section" aria-label="API Explorer" id="api-explorer">
          <p className="section-label">API Explorer</p>
          <p className="section-sub">
            All endpoints — interactive. Loads on demand (~2 MB).
          </p>
          <ScalarExplorer />
        </section>
      </main>

      <footer className="app-footer">
        <p>
          <a href="https://github.com/aevum-labs/aevum">GitHub</a>
          {' · '}
          <a href="https://aevum.build">aevum.build</a>
          {' · Apache-2.0'}
        </p>
        <p style={{ marginTop: '6px' }}>
          Session data is isolated per visitor and resets on container restart. No data leaves your browser session.
        </p>
      </footer>
    </div>
  )
}

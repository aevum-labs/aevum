import { Stepper } from './components/Stepper'
import { ScalarExplorer } from './components/ScalarExplorer'
import './App.css'

export default function App() {
  function scrollToExplorer() {
    document.getElementById('api-explorer')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1 className="app-title">AEVUM</h1>
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
          <p className="section-label">Full API Reference</p>
          <h2 className="section-heading">API Explorer</h2>
          <p className="section-sub">
            Explore all endpoints interactively. The explorer loads on demand (~2 MB).
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

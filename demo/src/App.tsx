import { useState, useEffect } from 'react'
import { Stepper } from './components/Stepper'
import { ScalarExplorer } from './components/ScalarExplorer'
import { checkHealth } from './api'
import './App.css'

const TABS = [
  { id: 'demo', label: 'Guided Demo' },
  { id: 'explorer', label: 'API Explorer' },
]

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
  const [activeTab, setActiveTab] = useState('demo')

  return (
    <>
      <div style={{
        background: '#161b22',
        borderBottom: '1px solid #30363d',
        padding: '0.9rem 1rem',
      }}>
        <p style={{
          fontSize: '0.875rem',
          color: '#8b949e',
          lineHeight: 1.6,
          marginBottom: '0.75rem',
          maxWidth: '680px',
        }}>
          Aevum is a governed AI agent kernel: every action is{' '}
          <strong style={{ color: '#e6edf3', fontWeight: 600 }}>signed</strong>,{' '}
          <strong style={{ color: '#e6edf3', fontWeight: 600 }}>consent-checked</strong>,
          {' '}and{' '}
          <strong style={{ color: '#e6edf3', fontWeight: 600 }}>
            cryptographically chained
          </strong>. This demo runs against the live production pipeline.
        </p>
      </div>

      <nav
        aria-label="Demo sections"
        style={{
          background: '#161b22',
          borderBottom: '1px solid #30363d',
          position: 'sticky',
          top: 0,
          zIndex: 10,
          display: 'flex',
          overflowX: 'auto',
          scrollbarWidth: 'none',
          msOverflowStyle: 'none',
        }}
      >
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            aria-current={activeTab === tab.id ? 'page' : undefined}
            style={{
              flexShrink: 0,
              background: 'none',
              border: 'none',
              borderBottom: activeTab === tab.id
                ? '2px solid #7c3aed'
                : '2px solid transparent',
              borderRadius: 0,
              color: activeTab === tab.id ? '#7c3aed' : '#8b949e',
              padding: '0.75rem 1rem',
              fontSize: '0.875rem',
              fontWeight: 600,
              whiteSpace: 'nowrap',
              cursor: 'pointer',
            }}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <div className="app">
        <header className="app-header">
          <div className="app-header-row">
            <h1 className="app-title">AEVUM</h1>
            <ApiStatus />
          </div>
          <p className="app-tagline">The Black Box for AI Agents — governed context kernel</p>
        </header>

        <main>
          {activeTab === 'demo' && (
            <section className="section" aria-label="Guided demo">
              <p className="section-label">Four-step demo</p>
              <p className="section-sub">
                Run a governed diagnostic scan. Every step is recorded in the cryptographic audit trail.
              </p>
              <Stepper onViewApiExplorer={() => setActiveTab('explorer')} />
            </section>
          )}
          {activeTab === 'explorer' && (
            <section className="section" aria-label="API Explorer" id="api-explorer">
              <p className="section-label">API Explorer</p>
              <p className="section-sub">
                All endpoints — interactive. Loads on demand (~2 MB).
              </p>
              <ScalarExplorer />
            </section>
          )}
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
    </>
  )
}

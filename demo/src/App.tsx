import { useState, useEffect } from 'react'
import { GLOBAL_STYLES } from './styles'
import { checkHealth } from './api'
import { Stepper } from './components/Stepper'
import { ScalarExplorer } from './components/ScalarExplorer'
import SignchainExplorer from './components/SignchainExplorer'
import ComplianceReport  from './components/ComplianceReport'
import OWASPCrosswalk    from './components/OWASPCrosswalk'
import './App.css'

type TabId = 'sandbox' | 'sigchain' | 'compliance' | 'api-explorer' | 'owasp' | 'docs'

const TABS: { id: TabId; label: string }[] = [
  { id: 'sandbox',      label: 'Sandbox' },
  { id: 'sigchain',     label: 'Sigchain' },
  { id: 'compliance',   label: 'Compliance' },
  { id: 'api-explorer', label: 'API Explorer' },
  { id: 'owasp',        label: 'OWASP' },
  { id: 'docs',         label: 'Docs' },
]

const PRIMITIVES = [
  { label: 'Relate',   desc: 'Ingest with provenance' },
  { label: 'Navigate', desc: 'Traverse with consent' },
  { label: 'Govern',   desc: 'Human checkpoint' },
  { label: 'Remember', desc: 'Append-only sigchain' },
] as const

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
  const [activeTab, setActiveTab] = useState<TabId>('sandbox')
  const [auditSession, setAuditSession] = useState<string | null>(null)

  function handleAuditSession(sessionId: string) {
    setAuditSession(sessionId)
    setActiveTab('compliance')
  }

  function handleTabChange(tabId: TabId) {
    if (tabId !== 'compliance') setAuditSession(null)
    setActiveTab(tabId)
  }

  return (
    <>
      <style>{GLOBAL_STYLES}</style>

      <header className="app-header" style={{ padding: '1rem 1rem 0' }}>
        <div className="app-header-row">
          <h1 className="app-title">AEVUM</h1>
          <ApiStatus />
        </div>
        <p className="app-tagline">The Black Box for AI Agents — governed context kernel</p>
      </header>

      <section aria-label="About Aevum" style={{
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
        <div style={{ display: 'flex', flexWrap: 'wrap', margin: '0 -0.25rem' }}>
          {PRIMITIVES.map((p, i) => (
            <div key={p.label} style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'flex-start',
              gap: '0.1rem',
              padding: '0.4rem 0.75rem',
              margin: '0.25rem',
              border: '1px solid #30363d',
              borderRadius: '6px',
              background: '#0d1117',
              minWidth: '110px',
            }}>
              <span style={{ fontSize: '0.65rem', fontWeight: 700, color: '#58a6ff', letterSpacing: '0.04em' }}>
                {i + 1}
              </span>
              <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#e6edf3' }}>
                {p.label}
              </span>
              <span style={{ fontSize: '0.7rem', color: '#8b949e', lineHeight: 1.3 }}>
                {p.desc}
              </span>
            </div>
          ))}
        </div>
      </section>

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
            onClick={() => handleTabChange(tab.id)}
            aria-current={activeTab === tab.id ? 'page' : undefined}
            style={{
              flexShrink: 0,
              background: 'none',
              border: 'none',
              borderBottom: activeTab === tab.id
                ? '2px solid #a78bfa'
                : '2px solid transparent',
              borderRadius: 0,
              color: activeTab === tab.id ? '#a78bfa' : '#8b949e',
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

      <main id="main-content">
        <div className="app">
          {activeTab === 'sandbox' && (
            <Stepper onViewApiExplorer={() => setActiveTab('api-explorer')} />
          )}
          {activeTab === 'api-explorer' && <ScalarExplorer />}
          {activeTab === 'sigchain' && (
            <SignchainExplorer onAuditSession={handleAuditSession} />
          )}
          {activeTab === 'compliance' && (
            <ComplianceReport preselectedSession={auditSession} />
          )}
          {activeTab === 'owasp'      && <OWASPCrosswalk />}
          {activeTab === 'docs' && (
            <div style={{ padding: '2rem 0', color: '#8b949e',
                          fontSize: '0.9rem', textAlign: 'center' }}>
              <p style={{ marginBottom: '0.5rem', fontSize: '1rem',
                          fontWeight: 600, color: '#e6edf3' }}>
                Documentation
              </p>
              <p>Full architecture and API reference at{' '}
                <a href="https://aevum.build"
                   target="_blank"
                   rel="noopener noreferrer"
                   style={{ color: '#58a6ff' }}>
                  aevum.build
                </a>
              </p>
            </div>
          )}
        </div>
      </main>
    </>
  )
}

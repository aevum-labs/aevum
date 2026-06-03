import { useEffect, useState } from 'react'
import { fetchCompliance, fetchSessions } from '../api'
import type { ComplianceReport as Report, SignedEntry } from '../types'

const fmt = (ts: string) => {
  try { return new Date(ts).toLocaleString() } catch { return ts }
}

function EntryRow({ entry }: { entry: SignedEntry }) {
  return (
    <tr>
      <td style={{ fontWeight: 500, fontSize: '0.82rem' }}>{entry.event_type}</td>
      <td className="muted" style={{ fontSize: '0.78rem' }}>{entry.principal}</td>
      <td style={{ fontSize: '0.78rem', whiteSpace: 'nowrap' }}>
        {fmt(entry.timestamp)}
      </td>
      <td className="mono muted" style={{ fontSize: '0.72rem', wordBreak: 'break-all' }}>
        {entry.entry_hash.slice(0, 16)}…
      </td>
    </tr>
  )
}

export default function ComplianceReport() {
  const [sessions, setSessions]               = useState<string[]>([])
  const [sessionId, setSessionId]             = useState('')
  const [report, setReport]                   = useState<Report | null>(null)
  const [loading, setLoading]                 = useState(false)
  const [sessionsLoading, setSessionsLoading] = useState(true)
  const [error, setError]                     = useState<string | null>(null)

  useEffect(() => {
    fetchSessions()
      .then((d) => {
        const ids = d.sessions.map((s) => s.episode_id)
        setSessions(ids)
        if (ids.length > 0) setSessionId(ids[0])
      })
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : String(e))
      )
      .finally(() => setSessionsLoading(false))
  }, [])

  async function handleGenerate() {
    if (!sessionId) return
    setLoading(true); setError(null); setReport(null)
    try { setReport(await fetchCompliance(sessionId)) }
    catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
    finally { setLoading(false) }
  }

  function handleDownload() {
    if (!report) return
    const blob = new Blob(
      [JSON.stringify(report, null, 2)],
      { type: 'application/json' }
    )
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `compliance-${report.session_id}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <section>
      <h2 className="section-title">Compliance Report</h2>
      <div className="callout" style={{ marginBottom: '1.25rem' }}>
        EU AI Act Article 12 requires high-risk AI systems to maintain logs
        sufficient for post-market monitoring, risk identification, and deployer
        oversight. This report maps sigchain entries for a session to those
        statutory purposes.
      </div>

      <div className="card">
        <div className="row" style={{ marginBottom: '0.25rem' }}>
          <div>
            <label htmlFor="session-select">Session</label>
            <div style={{ marginTop: '0.3rem' }}>
              {sessionsLoading ? (
                <span className="muted" style={{ fontSize: '0.875rem' }}>
                  Loading sessions…
                </span>
              ) : (
                <select
                  id="session-select"
                  value={sessionId}
                  onChange={(e) => setSessionId(e.target.value)}
                >
                  {sessions.length === 0 && (
                    <option value="">No sessions available</option>
                  )}
                  {sessions.map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              )}
            </div>
          </div>
          <button
            className="primary"
            onClick={() => void handleGenerate()}
            disabled={loading || !sessionId || sessionsLoading}
            style={{ alignSelf: 'flex-end' }}
          >
            {loading ? 'Generating…' : 'Generate Report'}
          </button>
        </div>
        {error && (
          <p className="error-msg" style={{ marginTop: '0.5rem' }}>{error}</p>
        )}
      </div>

      {report && (
        <>
          <div className="card">
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'flex-start',
              flexWrap: 'wrap',
              gap: '0.5rem',
              marginBottom: '0.75rem',
            }}>
              <p style={{ fontWeight: 600 }}>Session Overview</p>
              <button
                className="secondary"
                onClick={handleDownload}
                style={{ fontSize: '0.8rem', padding: '0.35rem 0.75rem' }}
              >
                Download JSON
              </button>
            </div>
            <table><tbody>
              <tr>
                <td className="muted" style={{ width: '40%' }}>Session ID</td>
                <td className="mono" style={{ fontSize: '0.82rem', wordBreak: 'break-all' }}>
                  {report.session_id}
                </td>
              </tr>
              <tr>
                <td className="muted">Entry count</td>
                <td>{report.entry_count}</td>
              </tr>
            </tbody></table>
          </div>

          {report.entries.length > 0 && (
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '1rem 1rem 0.5rem', fontWeight: 600 }}>
                Sigchain Entries — Article 12 Log
              </div>
              <div style={{ overflowX: 'auto' }}>
                <table>
                  <thead>
                    <tr>
                      <th>Event type</th>
                      <th>Principal</th>
                      <th>Timestamp</th>
                      <th>Entry hash</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.entries.map((entry) => (
                      <EntryRow key={entry.entry_hash} entry={entry} />
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </section>
  )
}

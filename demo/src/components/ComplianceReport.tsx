import { useEffect, useState } from 'react'
import { fetchCompliance, fetchReplay, fetchSessions } from '../api'
import type { SessionInfo, ComplianceReport as Report, ReplayResult, SignedEntry } from '../types'

interface Props {
  preselectedSession?: string | null
}

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

export default function ComplianceReport({ preselectedSession }: Props) {
  const [sessions, setSessions]               = useState<SessionInfo[]>([])
  const [sessionId, setSessionId]             = useState('')
  const [report, setReport]                   = useState<Report | null>(null)
  const [loading, setLoading]                 = useState(false)
  const [sessionsLoading, setSessionsLoading] = useState(true)
  const [error, setError]                     = useState<string | null>(null)
  const [replayResult, setReplayResult]       = useState<ReplayResult | null>(null)

  useEffect(() => {
    fetchSessions()
      .then((d) => {
        setSessions(d.sessions)
        if (d.sessions.length > 0) setSessionId(d.sessions[0].session_id)
      })
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : String(e))
      )
      .finally(() => setSessionsLoading(false))
  }, [])

  useEffect(() => {
    if (!preselectedSession) return
    if (sessionsLoading) return
    setSessionId(preselectedSession)
    setReplayResult(null)
    setLoading(true); setError(null); setReport(null)
    fetchCompliance(preselectedSession)
      .then(setReport)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false))
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preselectedSession, sessionsLoading])

  async function handleGenerate() {
    if (!sessionId) return
    setReplayResult(null)
    setLoading(true); setError(null); setReport(null)
    try {
      setReport(await fetchCompliance(sessionId))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setLoading(false)
      return
    }
    setLoading(false)
    // Auto-trigger server-verified replay — non-blocking
    try {
      setReplayResult(await fetchReplay(sessionId))
    } catch {
      setReplayResult(null)
    }
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
                    <option key={s.session_id} value={s.session_id}>
                      {s.label} ({s.entry_count}{' '}
                      {s.entry_count === 1 ? 'entry' : 'entries'})
                    </option>
                  ))}
                </select>
              )}
            </div>
          </div>
          <div style={{ display: 'flex', alignSelf: 'flex-end', gap: '0.5rem' }}>
            <button
              className="primary"
              onClick={() => void handleGenerate()}
              disabled={loading || !sessionId || sessionsLoading}
            >
              {loading ? 'Generating…' : 'Generate Report'}
            </button>
          </div>
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

      {replayResult && (() => {
        const entries  = replayResult.entries
        const allValid = replayResult.chain_valid
        const breakAt  = replayResult.break_at ?? -1

        return (
          <div className="card">
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '0.5rem',
              marginBottom: '1rem',
            }}>
              <p style={{ fontWeight: 600 }}>Session Replay</p>
              <span style={{
                fontSize: '0.7rem',
                fontWeight: 700,
                letterSpacing: '0.05em',
                padding: '0.2em 0.6em',
                borderRadius: '4px',
                background: 'rgba(88,166,255,0.12)',
                color: '#58a6ff',
                border: '1px solid rgba(88,166,255,0.25)',
                textTransform: 'uppercase',
              }}>
                Server-verified
              </span>
            </div>

            <p className="muted" style={{ fontSize: '0.82rem', marginBottom: '1rem' }}>
              Cryptographic reconstruction of every action in this session,
              generated automatically when the report is created. Verified
              by the server against the stored sigchain.
            </p>

            {entries.length === 0 ? (
              <p className="muted" style={{ fontSize: '0.875rem' }}>
                No entries found for this session.
              </p>
            ) : (
              <>
                {entries.map((entry, i) => {
                  const isLinkValid = i === 0 ? true : !(!allValid && breakAt === i)
                  const hasConnector = i < entries.length - 1

                  return (
                    <div key={entry.entry_hash || String(i)}>
                      <div style={{
                        display: 'flex',
                        alignItems: 'flex-start',
                        gap: '0.75rem',
                        padding: '0.5rem 0',
                      }}>
                        <span style={{
                          flexShrink: 0,
                          width: '1.5rem',
                          height: '1.5rem',
                          borderRadius: '50%',
                          background: 'var(--accent-dim,rgba(167,139,250,.15))',
                          color: 'var(--accent)',
                          fontSize: '0.72rem',
                          fontWeight: 700,
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                        }}>
                          {i + 1}
                        </span>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontWeight: 600, fontSize: '0.875rem' }}>
                            {entry.action}
                          </div>
                          <div className="muted" style={{ fontSize: '0.78rem' }}>
                            {entry.principal}
                          </div>
                          {(entry.payload_summary || '').trim() !== '' && (
                            <div style={{
                              fontSize: '0.75rem',
                              color: 'var(--text-muted, #8b949e)',
                              fontStyle: 'italic',
                              marginTop: '0.1rem',
                              lineHeight: 1.3,
                            }}>
                              {entry.payload_summary}
                            </div>
                          )}
                          <div className="mono muted"
                               style={{ fontSize: '0.72rem', wordBreak: 'break-all',
                                        marginTop: '0.15rem' }}>
                            {(entry.entry_hash ?? '').slice(0, 20)}…
                          </div>
                        </div>
                      </div>

                      {hasConnector && (
                        <div style={{
                          borderLeft: `2px solid ${isLinkValid
                            ? 'var(--accent)'
                            : 'var(--danger,#f85149)'}`,
                          marginLeft: '0.69rem',
                          padding: '0.2rem 0 0.2rem 0.75rem',
                        }}>
                          <span style={{
                            fontSize: '0.72rem',
                            fontWeight: 600,
                            color: isLinkValid
                              ? 'var(--accent)'
                              : 'var(--danger,#f85149)',
                          }}>
                            {isLinkValid ? '↓ prior hash verified ✓' : '↓ hash mismatch ✗'}
                          </span>
                        </div>
                      )}
                    </div>
                  )
                })}

                <div style={{
                  marginTop: '0.75rem',
                  paddingTop: '0.75rem',
                  borderTop: '1px solid var(--border)',
                  fontWeight: 600,
                  fontSize: '0.875rem',
                  color: allValid
                    ? 'var(--accent)'
                    : 'var(--danger,#f85149)',
                }}>
                  {allValid
                    ? `✓ Chain intact — ${entries.length} of ${entries.length} links verified`
                    : `✗ Chain broken at entry ${breakAt + 1}`}
                </div>
              </>
            )}
          </div>
        )
      })()}
    </section>
  )
}

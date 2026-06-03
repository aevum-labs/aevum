import { useCallback, useEffect, useState } from 'react'
import { fetchRecentEntries, fetchEntry } from '../api'
import type { SignedEntry } from '../types'

type EntryDetail = SignedEntry

function truncate(hash: string, n = 16): string {
  return hash.slice(0, n) + '…'
}

function fmtTime(ts: string): string {
  try {
    return new Date(ts).toLocaleString(undefined, {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    })
  } catch { return ts }
}

export default function SignchainExplorer() {
  const [entries, setEntries]             = useState<SignedEntry[]>([])
  const [count, setCount]                 = useState(0)
  const [loading, setLoading]             = useState(true)
  const [error, setError]                 = useState<string | null>(null)
  const [expanded, setExpanded]           = useState<string | null>(null)
  const [detail, setDetail]               = useState<EntryDetail | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)

  const load = useCallback(async () => {
    try {
      const data = await fetchRecentEntries()
      setEntries(data.entries)
      setCount(data.count)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
    const id = setInterval(() => void load(), 30_000)
    return () => clearInterval(id)
  }, [load])

  async function toggleRow(hash: string) {
    if (expanded === hash) {
      setExpanded(null); setDetail(null); return
    }
    setExpanded(hash); setDetail(null); setDetailLoading(true)
    try {
      setDetail(await fetchEntry(hash))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally { setDetailLoading(false) }
  }

  return (
    <section>
      <div style={{ display: 'flex', alignItems: 'center',
                    justifyContent: 'space-between', marginBottom: '1rem' }}>
        <h2 className="section-title" style={{ marginBottom: 0 }}>
          Live Sigchain
        </h2>
        {!loading && (
          <span className="muted" style={{ fontSize: '0.82rem' }}>
            {count.toLocaleString()} {count === 1 ? 'entry' : 'entries'}
          </span>
        )}
      </div>

      <div className="callout" style={{ marginBottom: '1.25rem' }}>
        Every entry below is a real event from Aevum's own
        maintenance pipeline — cryptographically signed and
        hash-chained. Click any row to inspect the full entry.
      </div>

      {error && <p className="error-msg">{error}</p>}

      {loading ? (
        <p className="muted">Loading…</p>
      ) : entries.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '2rem' }}>
          <p style={{ fontWeight: 600, marginBottom: '0.5rem' }}>
            No entries yet
          </p>
          <p className="muted" style={{ fontSize: '0.875rem' }}>
            Production entries appear here after the next maintenance run.
          </p>
        </div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th style={{ width: '42px' }}>#</th>
                  <th>Action</th>
                  <th>Principal</th>
                  <th>Time</th>
                  <th>Hash</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry, i) => (
                  <>
                    <tr
                      key={entry.entry_hash}
                      onClick={() => void toggleRow(entry.entry_hash)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td className="muted" style={{ fontSize: '0.8rem' }}>{i}</td>
                      <td style={{ fontWeight: 500, fontSize: '0.875rem' }}>
                        {entry.event_type}
                      </td>
                      <td className="muted" style={{ fontSize: '0.82rem' }}>
                        {entry.principal}
                      </td>
                      <td style={{ fontSize: '0.8rem', whiteSpace: 'nowrap' }}>
                        {fmtTime(entry.timestamp)}
                      </td>
                      <td className="mono muted" style={{ fontSize: '0.78rem' }}>
                        {truncate(entry.entry_hash, 8)}
                      </td>
                    </tr>

                    {expanded === entry.entry_hash && (
                      <tr key={`${entry.entry_hash}-detail`}>
                        <td colSpan={5}
                            style={{ background: 'var(--bg)', padding: '0.75rem 1rem' }}>
                          {detailLoading ? (
                            <p className="muted" style={{ fontSize: '0.82rem' }}>
                              Loading…
                            </p>
                          ) : detail ? (
                            <table style={{ width: '100%' }}>
                              <tbody>
                                <tr>
                                  <td className="muted"
                                      style={{ width: '30%', fontSize: '0.78rem' }}>
                                    Entry hash
                                  </td>
                                  <td className="mono"
                                      style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}>
                                    {detail.entry_hash}
                                  </td>
                                </tr>
                                <tr>
                                  <td className="muted" style={{ fontSize: '0.78rem' }}>
                                    Prior hash
                                  </td>
                                  <td className="mono muted"
                                      style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}>
                                    {detail.prior_hash ?? 'genesis'}
                                  </td>
                                </tr>
                                <tr>
                                  <td className="muted" style={{ fontSize: '0.78rem' }}>
                                    Session
                                  </td>
                                  <td className="mono muted" style={{ fontSize: '0.75rem' }}>
                                    {detail.episode_id}
                                  </td>
                                </tr>
                                <tr>
                                  <td className="muted" style={{ fontSize: '0.78rem' }}>
                                    Payload hash
                                  </td>
                                  <td className="mono muted"
                                      style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}>
                                    {detail.payload_hash}
                                  </td>
                                </tr>
                                {detail.rekor_anchor && (
                                  <tr>
                                    <td className="muted" style={{ fontSize: '0.78rem' }}>
                                      Rekor anchor
                                    </td>
                                    <td style={{ fontSize: '0.82rem' }}>
                                      <span className="badge badge-success">Anchored</span>
                                      <span className="muted"
                                            style={{ marginLeft: '0.5rem', fontSize: '0.78rem' }}>
                                        {fmtTime(detail.rekor_anchor.timestamp)}
                                      </span>
                                    </td>
                                  </tr>
                                )}
                              </tbody>
                            </table>
                          ) : null}
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <p className="muted" style={{ fontSize: '0.78rem', marginTop: '0.75rem' }}>
        Refreshes every 30 seconds. Showing last{' '}
        {entries.length} of {count.toLocaleString()} entries.
      </p>
    </section>
  )
}

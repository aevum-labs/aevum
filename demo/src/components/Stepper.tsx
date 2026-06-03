import { useState, useEffect } from 'react'
import * as api from '../api'
import type { ScanResult, ConsentResult, ExecuteResult, SigchainResult } from '../api'
import './Stepper.css'

type Step = 1 | 2 | 3 | 4

const STEP_LABELS = ['Scan', 'Consent', 'Execute', 'Sigchain']

const SCAN_TYPES = [
  { value: 'diagnostic', label: 'diagnostic — disk / log pressure' },
  { value: 'memory_pressure', label: 'memory_pressure — heap growth' },
  { value: 'cert_check', label: 'cert_check — TLS expiry' },
]

interface StepperProps {
  onViewApiExplorer: () => void
}

export function Stepper({ onViewApiExplorer }: StepperProps) {
  const [currentStep, setCurrentStep] = useState<Step>(1)
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [consentResult, setConsentResult] = useState<ConsentResult | null>(null)
  const [executeResult, setExecuteResult] = useState<ExecuteResult | null>(null)
  const [sigchainResult, setSigchainResult] = useState<SigchainResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [denied, setDenied] = useState(false)

  const [hostId, setHostId] = useState('host-42')
  const [scanType, setScanType] = useState('diagnostic')

  function completedSteps(): Set<Step> {
    const s = new Set<Step>()
    if (scanResult) s.add(1)
    if (consentResult) s.add(2)
    if (executeResult) s.add(3)
    if (sigchainResult) s.add(4)
    return s
  }

  function navClick(step: Step) {
    const completed = completedSteps()
    if (step === currentStep) return
    if (step < currentStep || completed.has(step)) {
      setCurrentStep(step)
      setError(null)
    }
  }

  function navClass(step: Step) {
    const completed = completedSteps()
    if (step === currentStep) return 'stepper-nav-item active'
    if (completed.has(step)) return 'stepper-nav-item completed'
    if (step < currentStep) return 'stepper-nav-item completed'
    return 'stepper-nav-item locked'
  }

  function startOver() {
    setCurrentStep(1)
    setScanResult(null)
    setConsentResult(null)
    setExecuteResult(null)
    setSigchainResult(null)
    setLoading(false)
    setError(null)
    setDenied(false)
    setHostId('host-42')
    setScanType('diagnostic')
  }

  async function handleScan(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const result = await api.scan(hostId.trim(), scanType)
      setScanResult(result)
      setCurrentStep(2)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed')
    } finally {
      setLoading(false)
    }
  }

  async function handleConsent(decision: 'approve' | 'deny') {
    if (!scanResult) return
    setLoading(true)
    setError(null)
    try {
      const result = await api.consent(scanResult.task_id, decision)
      setConsentResult(result)
      if (decision === 'approve') {
        setCurrentStep(3)
      } else {
        setDenied(true)
        const chain = await api.sigchain()
        setSigchainResult(chain)
        setCurrentStep(4)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Consent failed')
    } finally {
      setLoading(false)
    }
  }

  async function handleExecute() {
    if (!scanResult || !consentResult) return
    setLoading(true)
    setError(null)
    try {
      const result = await api.execute(scanResult.task_id, consentResult.consent_token)
      setExecuteResult(result)
      setCurrentStep(4)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Execute failed')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (currentStep === 4 && !sigchainResult) {
      setLoading(true)
      setError(null)
      api.sigchain()
        .then(setSigchainResult)
        .catch(err => setError(err instanceof Error ? err.message : 'Sigchain fetch failed'))
        .finally(() => setLoading(false))
    }
  }, [currentStep, sigchainResult])

  return (
    <div className="stepper">
      <p style={{
        fontSize: '0.75rem',
        color: '#8b949e',
        marginTop: '0.25rem',
        display: 'flex',
        alignItems: 'center',
        gap: '0.4rem',
      }}>
        <span style={{
          fontSize: '0.65rem',
          fontWeight: 700,
          letterSpacing: '0.05em',
          padding: '0.15em 0.5em',
          borderRadius: '4px',
          background: 'rgba(124,58,237,0.15)',
          color: '#7c3aed',
          border: '1px solid rgba(124,58,237,0.3)',
          textTransform: 'uppercase',
        }}>
          Isolated Session
        </span>
        Data is ephemeral — resets on page reload.
        Never touches production.
      </p>
      <nav className="stepper-nav" aria-label="Demo steps">
        {STEP_LABELS.map((label, i) => {
          const step = (i + 1) as Step
          return (
            <button
              key={step}
              className={navClass(step)}
              onClick={() => navClick(step)}
              aria-current={currentStep === step ? 'step' : undefined}
              aria-label={`Step ${step}: ${label}`}
            >
              <div className="step-num">STEP {step}</div>
              <div className="step-label">{label}</div>
            </button>
          )
        })}
      </nav>

      <div className="stepper-body">
        {currentStep === 1 && (
          <Step1Scan
            hostId={hostId}
            scanType={scanType}
            onHostIdChange={setHostId}
            onScanTypeChange={setScanType}
            onSubmit={handleScan}
            loading={loading}
            error={error}
            result={scanResult}
          />
        )}
        {currentStep === 2 && scanResult && (
          <Step2Consent
            taskId={scanResult.task_id}
            finding={scanResult.finding}
            severity={scanResult.severity}
            proposedAction={scanResult.proposed_action}
            onConsent={handleConsent}
            loading={loading}
            error={error}
          />
        )}
        {currentStep === 3 && scanResult && consentResult && (
          <Step3Execute
            taskId={scanResult.task_id}
            consentToken={consentResult.consent_token}
            onExecute={handleExecute}
            loading={loading}
            error={error}
            result={executeResult}
          />
        )}
        {currentStep === 4 && (
          <Step4Sigchain
            result={sigchainResult}
            denied={denied}
            loading={loading}
            error={error}
            onViewApiExplorer={onViewApiExplorer}
            onStartOver={startOver}
          />
        )}
      </div>
    </div>
  )
}

interface Step1Props {
  hostId: string
  scanType: string
  onHostIdChange: (v: string) => void
  onScanTypeChange: (v: string) => void
  onSubmit: (e: React.FormEvent) => void
  loading: boolean
  error: string | null
  result: ScanResult | null
}

function Step1Scan({ hostId, scanType, onHostIdChange, onScanTypeChange, onSubmit, loading, error, result }: Step1Props) {
  return (
    <>
      <h2 className="stepper-title">Step 1 — Scan</h2>
      <form onSubmit={onSubmit}>
        <div className="form-group">
          <label className="form-label" htmlFor="host-id">Host ID</label>
          <input
            id="host-id"
            className="form-input"
            type="text"
            value={hostId}
            onChange={e => onHostIdChange(e.target.value)}
            placeholder="host-42"
            required
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="scan-type">Scan Type</label>
          <select
            id="scan-type"
            className="form-input"
            value={scanType}
            onChange={e => onScanTypeChange(e.target.value)}
          >
            {SCAN_TYPES.map(t => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
        </div>
        <div className="btn-row">
          <button className="btn btn-primary" type="submit" disabled={loading}>
            {loading ? 'Scanning…' : 'Run Scan →'}
          </button>
        </div>
      </form>
      {error && <div className="error-banner">{error}</div>}
      {result && (
        <div className="result-box">
          <div className="result-box-title">Scan Result</div>
          <div className="result-row">
            <span className="result-key">task_id</span>
            <span className="result-value">{result.task_id}</span>
          </div>
          <div className="result-row">
            <span className="result-key">finding</span>
            <span className="result-value">{result.finding}</span>
          </div>
          <div className="result-row">
            <span className="result-key">severity</span>
            <span className={`result-value severity-${result.severity}`}>{result.severity}</span>
          </div>
          <div className="result-row">
            <span className="result-key">proposed_action</span>
            <span className="result-value">{result.proposed_action}</span>
          </div>
          <div className="result-row">
            <span className="result-key">receipt_hash</span>
            <span className="result-value">{result.receipt_hash.slice(0, 20)}…</span>
          </div>
        </div>
      )}
    </>
  )
}

interface Step2Props {
  taskId: string
  finding: string
  severity: string
  proposedAction: string
  onConsent: (decision: 'approve' | 'deny') => void
  loading: boolean
  error: string | null
}

function Step2Consent({ taskId, finding, severity, proposedAction, onConsent, loading, error }: Step2Props) {
  return (
    <>
      <h2 className="stepper-title">Step 2 — Consent</h2>
      <div className="form-group">
        <label className="form-label">Task ID (from Step 1)</label>
        <input className="form-input" value={taskId} readOnly />
      </div>
      <div className="result-box">
        <div className="result-box-title">Pending Action</div>
        <div className="result-row">
          <span className="result-key">finding</span>
          <span className="result-value">{finding}</span>
        </div>
        <div className="result-row">
          <span className="result-key">severity</span>
          <span className={`result-value severity-${severity}`}>{severity}</span>
        </div>
        <div className="result-row">
          <span className="result-key">proposed_action</span>
          <span className="result-value">{proposedAction}</span>
        </div>
      </div>
      <div className="info-banner">
        <strong>Human-in-the-loop gate.</strong> Your decision is cryptographically bound to this task and recorded in the sigchain regardless of outcome.
      </div>
      {error && <div className="error-banner">{error}</div>}
      <div className="btn-row">
        <button className="btn btn-approve" onClick={() => onConsent('approve')} disabled={loading}>
          {loading ? '…' : 'Approve →'}
        </button>
        <button className="btn btn-deny" onClick={() => onConsent('deny')} disabled={loading}>
          {loading ? '…' : 'Deny'}
        </button>
      </div>
    </>
  )
}

interface Step3Props {
  taskId: string
  consentToken: string
  onExecute: () => void
  loading: boolean
  error: string | null
  result: ExecuteResult | null
}

function Step3Execute({ taskId, consentToken, onExecute, loading, error, result }: Step3Props) {
  return (
    <>
      <h2 className="stepper-title">Step 3 — Execute</h2>
      <div className="form-group">
        <label className="form-label">Task ID (from Step 1)</label>
        <input className="form-input" value={taskId} readOnly />
      </div>
      <div className="form-group">
        <label className="form-label">Consent Token (from Step 2)</label>
        <input className="form-input" value={consentToken} readOnly />
      </div>
      <div className="info-banner">
        The consent token is cryptographically bound to this task. Execution produces a COSE_Sign1 receipt anchored to Rekor.
      </div>
      {error && <div className="error-banner">{error}</div>}
      {!result && (
        <div className="btn-row">
          <button className="btn btn-primary" onClick={onExecute} disabled={loading}>
            {loading ? 'Executing…' : 'Execute →'}
          </button>
        </div>
      )}
      {result && (
        <div className="result-box">
          <div className="result-box-title">Execution Result</div>
          <div className="result-row">
            <span className="result-key">outcome</span>
            <span className="result-value ok">{result.outcome}</span>
          </div>
          <div className="result-row">
            <span className="result-key">sigchain_head</span>
            <span className="result-value">{result.sigchain_head.slice(0, 20)}…</span>
          </div>
          <div className="result-row">
            <span className="result-key">rekor_entry</span>
            <span className="result-value warn">{result.rekor_entry}</span>
          </div>
        </div>
      )}
    </>
  )
}

interface Step4Props {
  result: SigchainResult | null
  denied: boolean
  loading: boolean
  error: string | null
  onViewApiExplorer: () => void
  onStartOver: () => void
}

function Step4Sigchain({ result, denied, loading, error, onViewApiExplorer, onStartOver }: Step4Props) {
  return (
    <>
      <h2 className="stepper-title">Step 4 — Inspect Sigchain</h2>
      {denied && (
        <div className="denied-banner">
          <strong>Action denied.</strong>
          Sigchain records this decision. The denial is part of the cryptographic audit trail — it cannot be erased.
        </div>
      )}
      {loading && <p className="loading-text">Fetching sigchain…</p>}
      {error && <div className="error-banner">{error}</div>}
      {result && (
        <>
          <div className="head-hash">
            <div className="head-hash-label">Sigchain Head Hash</div>
            {result.head_hash}
          </div>
          <div className="result-row" style={{ marginBottom: '12px' }}>
            <span className="result-key">entry_count</span>
            <span className="result-value">{result.entry_count}</span>
          </div>
          <table className="sigchain-table" aria-label="Sigchain entries">
            <thead>
              <tr>
                <th>#</th>
                <th>Action</th>
                <th>Principal</th>
                <th>Occurred At</th>
                <th>Hash</th>
              </tr>
            </thead>
            <tbody>
              {result.entries.map(entry => (
                <tr key={entry.sequence}>
                  <td>{entry.sequence}</td>
                  <td>{entry.action}</td>
                  <td>{entry.principal}</td>
                  <td>{entry.occurred_at}</td>
                  <td title={entry.sigchain_entry_hash}>
                    {entry.sigchain_entry_hash.slice(0, 12)}…
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      <div className="btn-row" style={{ marginTop: '20px' }}>
        <button className="btn btn-secondary" onClick={onViewApiExplorer}>
          View in API Explorer ↓
        </button>
        <button className="btn btn-secondary" onClick={onStartOver}>
          Start Over
        </button>
      </div>
    </>
  )
}

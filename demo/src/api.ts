import type { SignedEntry, SessionsResponse, ComplianceReport } from './types'

const API_BASE = (import.meta.env.VITE_API_URL as string | undefined) ?? ''

export interface ScanResult {
  task_id: string
  host_id: string
  finding: string
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  proposed_action: string
  barriers_evaluated: Record<string, string>
  receipt_hash: string
}

export interface ConsentResult {
  task_id: string
  decision: string
  consent_token: string
  valid_for_seconds: number
}

export interface ExecuteResult {
  task_id: string
  outcome: string
  sigchain_head: string
  rekor_entry: string
  receipt_hash: string
}

export interface SigchainEntry {
  sequence: number
  action: string
  principal: string
  occurred_at: string
  sigchain_entry_hash: string
  handoff_type: string | null
  barrier_evaluations: Record<string, string>
}

export interface SigchainResult {
  head_hash: string
  entry_count: number
  entries: SigchainEntry[]
}

export async function scan(host_id: string, scan_type: string): Promise<ScanResult> {
  const res = await fetch(`${API_BASE}/sandbox/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host_id, scan_type }),
  })
  if (!res.ok) throw new Error(`scan failed: ${res.status}`)
  return res.json()
}

export async function consent(task_id: string, decision: 'approve' | 'deny'): Promise<ConsentResult> {
  const res = await fetch(`${API_BASE}/sandbox/consent`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ task_id, decision }),
  })
  if (!res.ok) throw new Error(`consent failed: ${res.status}`)
  return res.json()
}

export async function execute(task_id: string, consent_token: string): Promise<ExecuteResult> {
  const res = await fetch(`${API_BASE}/sandbox/execute`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ task_id, consent_token }),
  })
  if (!res.ok) throw new Error(`execute failed: ${res.status}`)
  return res.json()
}

export async function sigchain(): Promise<SigchainResult> {
  const res = await fetch(`${API_BASE}/sandbox/sigchain`)
  if (!res.ok) throw new Error(`sigchain failed: ${res.status}`)
  return res.json()
}

export async function fetchRecentEntries(): Promise<{ count: number; entries: SignedEntry[] }> {
  const res = await fetch(`${API_BASE}/v1/sigchain/recent`)
  if (!res.ok) throw new Error(`sigchain/recent failed: ${res.status}`)
  return res.json()
}

export async function fetchEntry(hash: string): Promise<SignedEntry> {
  const res = await fetch(`${API_BASE}/v1/sigchain/${encodeURIComponent(hash)}`)
  if (!res.ok) throw new Error(`sigchain entry failed: ${res.status}`)
  return res.json()
}

export async function fetchSessions(): Promise<SessionsResponse> {
  const res = await fetch(`${API_BASE}/v1/sessions`)
  if (!res.ok) throw new Error(`sessions failed: ${res.status}`)
  return res.json()
}

export async function fetchCompliance(session_id: string): Promise<ComplianceReport> {
  const res = await fetch(`${API_BASE}/v1/compliance/${encodeURIComponent(session_id)}`)
  if (!res.ok) throw new Error(`compliance failed: ${res.status}`)
  return res.json()
}

export async function checkHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/health`, { cache: 'no-store' })
    return res.ok
  } catch {
    return false
  }
}

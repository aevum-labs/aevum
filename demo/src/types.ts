export interface RekorAnchor {
  repo: string
  timestamp: string
  head_hash: string
  entry_count: number
}

export interface SignedEntry {
  entry_hash: string
  prior_hash: string | null
  event_type: string
  principal: string
  payload_hash: string
  payload_summary: string
  timestamp: string
  episode_id: string
  rekor_anchor: RekorAnchor | null
}

export interface SessionInfo {
  session_id: string
  first_seen: string
  entry_count: number
  label: string
  session_type: 'maintenance' | 'system'
}

export interface SessionsResponse {
  sessions: SessionInfo[]
}

export interface ComplianceReport {
  session_id: string
  entry_count: number
  entries: SignedEntry[]
}

export interface ReplayEntry {
  entry_hash:       string
  prior_hash:       string | null
  action:           string
  principal:        string
  timestamp:        string
  session_id:       string
  payload_hash?:    string
  payload_summary?: string
}

export interface ReplayResult {
  session_id:  string
  entry_count: number
  chain_valid: boolean
  entries:     ReplayEntry[]
  head_hash:   string | null
  break_at?:   number
}

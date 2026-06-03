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
  timestamp: string
  episode_id: string
  rekor_anchor: RekorAnchor | null
}

export interface SessionInfo {
  episode_id: string
  first_seen: string
}

export interface ComplianceReport {
  session_id: string
  entry_count: number
  entries: SignedEntry[]
}

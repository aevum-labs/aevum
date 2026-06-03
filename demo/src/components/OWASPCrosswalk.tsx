const ROWS = [
  {
    risk: 'ASI-01: Prompt Injection',
    barrier: 'Consent Barrier',
    how: 'All data ingest requires a ConsentGrant before '
       + 'entering the governed context. Injected prompts '
       + 'without a valid grant are blocked at ingest.',
  },
  {
    risk: 'ASI-02: Excessive Agency',
    barrier: 'Classification Ceiling',
    how: 'The five governed functions operate within a '
       + 'classification ceiling. No action above the '
       + 'ceiling executes without human review approval.',
  },
  {
    risk: 'ASI-03: Sensitive Information Disclosure',
    barrier: 'Consent Enforcement',
    how: 'Query operations check ConsentGrant scope before '
       + 'returning any data. Unconsented data is never '
       + 'returned regardless of agent request.',
  },
  {
    risk: 'ASI-04: Insufficient Monitoring',
    barrier: 'Audit Immutability',
    how: 'Every governed action appends a signed, '
       + 'hash-chained entry to the sigchain. Entries '
       + 'cannot be modified or deleted after commit.',
  },
  {
    risk: 'ASI-05: Unsafe Recursive Delegation',
    barrier: 'Provenance',
    how: 'Every sigchain entry records the full principal '
       + 'chain. Delegation depth and origin are always '
       + 'verifiable from the audit trail.',
  },
  {
    risk: 'ASI-06: Data / Model Poisoning',
    barrier: 'Provenance',
    how: 'Ingest provenance is recorded at the source level. '
       + 'Chain-of-custody is verifiable for every fact '
       + 'in the governed context.',
  },
  {
    risk: 'ASI-07: Misinformation Generation',
    barrier: 'Verifiable Decision Records',
    how: 'Commit operations produce a verifiable decision '
       + 'record. Replay reconstructs exactly what data '
       + 'and reasoning produced each output.',
  },
  {
    risk: 'ASI-08: Denial of Service',
    barrier: 'Crisis Detection',
    how: 'Crisis detection is an unconditional barrier. '
       + 'Resource exhaustion or safety-critical signals '
       + 'halt all operations regardless of other grants.',
  },
  {
    risk: 'ASI-09: Agentic Hallucination',
    barrier: 'Audit Immutability',
    how: 'Replay of any commit reconstructs the exact '
       + 'evidence bundle used. Hallucinated reasoning '
       + 'is detectable by comparing replay output.',
  },
  {
    risk: 'ASI-10: Unbounded Consumption',
    barrier: 'Classification Ceiling',
    how: 'Actions above the classification ceiling are '
       + 'blocked until explicit human approval is '
       + 'recorded in the sigchain.',
  },
] as const

export default function OWASPCrosswalk() {
  return (
    <section>
      <h2 className="section-title">
        OWASP Agentic AI Crosswalk
      </h2>
      <div className="callout" style={{ marginBottom: '1.25rem' }}>
        How each OWASP Top 10 for Agentic AI risk maps to an
        Aevum unconditional barrier. The five barriers are
        code-level invariants — they cannot be bypassed in
        tests or production.
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table>
            <thead>
              <tr>
                <th style={{ minWidth: '180px' }}>OWASP Risk</th>
                <th style={{ minWidth: '160px' }}>Aevum Barrier</th>
                <th style={{ minWidth: '260px' }}>How</th>
              </tr>
            </thead>
            <tbody>
              {ROWS.map((row) => (
                <tr key={row.risk}>
                  <td style={{ fontWeight: 600, fontSize: '0.82rem', whiteSpace: 'nowrap' }}>
                    {row.risk}
                  </td>
                  <td>
                    <span className="badge badge-info">{row.barrier}</span>
                  </td>
                  <td style={{ fontSize: '0.855rem', color: 'var(--text-muted)' }}>
                    {row.how}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  )
}

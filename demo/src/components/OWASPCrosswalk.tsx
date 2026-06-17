const ROWS = [
  {
    risk: 'ASI01: Agent Goal Hijack',
    barrier: 'Detective',
    how: 'Aevum does not prevent goal hijack at runtime. Every '
       + 'resulting action is recorded in the tamper-evident '
       + 'sigchain, so hijacked behavior is detectable and '
       + 'reconstructable after the fact.',
  },
  {
    risk: 'ASI02: Tool Misuse and Exploitation',
    barrier: 'Gate + detective',
    how: 'Consent and the Classification Ceiling gate governed '
       + 'actions that lack a valid grant or exceed clearance; '
       + 'every invocation is recorded. Aevum does not sandbox '
       + 'tool execution itself.',
  },
  {
    risk: 'ASI03: Identity and Privilege Abuse',
    barrier: 'Detective',
    how: 'Every action records the full principal and delegation '
       + 'chain, so identity and privilege use is auditable and '
       + 'tamper-evident. Aevum does not issue or scope agent '
       + 'identities.',
  },
  {
    risk: 'ASI04: Agentic Supply Chain Vulnerabilities',
    barrier: 'Detective (partial)',
    how: 'Source-level provenance and chain-of-custody are '
       + 'recorded for ingested data, so the inputs an agent '
       + 'acted on are verifiable. Aevum is not a supply-chain '
       + 'scanner.',
  },
  {
    risk: 'ASI05: Unexpected Code Execution (RCE)',
    barrier: 'Not prevented',
    how: 'Aevum is an evidence and governance layer, not a '
       + 'code-execution sandbox; it does not prevent RCE. The '
       + 'action trail supports post-incident forensics.',
  },
  {
    risk: 'ASI06: Memory and Context Poisoning',
    barrier: 'Detective + integrity',
    how: 'Items entering the governed context are recorded with '
       + 'provenance and cryptographic integrity, so altered or '
       + 'poisoned context is detectable. Aevum does not judge '
       + 'content as malicious at ingest.',
  },
  {
    risk: 'ASI07: Insecure Inter-Agent Communication',
    barrier: 'Detective (partial)',
    how: 'Inter-agent actions that pass through the kernel are '
       + 'recorded in the tamper-evident trail. Aevum does not '
       + 'encrypt or authenticate the transport itself.',
  },
  {
    risk: 'ASI08: Cascading Failures',
    barrier: 'Detective',
    how: 'The ordered, tamper-evident trail lets investigators '
       + 'reconstruct how a failure propagated across steps and '
       + 'agents. Aevum does not provide circuit-breaking '
       + 'between agents.',
  },
  {
    risk: 'ASI09: Human-Agent Trust Exploitation',
    barrier: 'Gate + detective',
    how: 'The Govern human checkpoint is an auditable approval '
       + 'gate, and human review and override decisions are '
       + 'recorded. Aevum does not detect social engineering of '
       + 'the human reviewer.',
  },
  {
    risk: 'ASI10: Rogue Agents',
    barrier: 'Detective',
    how: 'Tamper-evident recording of every governed action '
       + 'makes rogue or out-of-scope behavior detectable and '
       + 'attributable; the Classification Ceiling blocks '
       + 'above-clearance actions.',
  },
] as const

export default function OWASPCrosswalk() {
  return (
    <section>
      <h2 className="section-title">
        OWASP Top 10 for Agentic Applications (2026)
      </h2>
      <div className="callout" style={{ marginBottom: '1.25rem' }}>
        This crosswalk maps the OWASP Top 10 for Agentic
        Applications (2026) to what Aevum actually contributes.
        Aevum is primarily a detective, evidentiary control — a
        tamper-evident black box. For most agentic attacks it does
        not prevent the attack at runtime; it makes the attack
        detectable, attributable, and reconstructable. A subset of
        barriers (Consent, Classification Ceiling, Crisis) gate
        governed actions. Where Aevum does not address a risk, the
        table says so. "OWASP" is referenced descriptively and
        does not imply endorsement or certification.
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table>
            <thead>
              <tr>
                <th style={{ minWidth: '180px' }}>OWASP Agentic Risk (2026)</th>
                <th style={{ minWidth: '160px' }}>Aevum's role</th>
                <th style={{ minWidth: '260px' }}>What Aevum contributes</th>
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

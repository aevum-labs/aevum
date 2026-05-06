// Reference example only. Legal review required before production use.
// California CCPA/CPRA Automated Decision-Making Technology (ADMT) regulations
// (effective 1 Jan 2026 for risk assessments)
// Colorado AI Act SB 24-205 (effective 30 June 2026)
// Both require: risk management documentation, impact assessments, consumer notice

// Deployers must combine this with Cedar policies governing their specific
// use case (employment, credit, healthcare access, education, housing).

// ADMT/Colorado: deployer risk management policy must exist
permit (
    principal in Group::"deployers",
    action == Action::"ingest",
    resource
)
when {
    // Risk assessment must have been completed for this system
    resource.deployer_risk_assessment_complete == true &&
    // For Colorado: high-risk AI requires impact assessment
    (resource.colorado_high_risk_ai != true ||
     resource.deployer_impact_assessment_complete == true)
};

// ADMT: consumer has right to opt out of ADMT — must be honoured
forbid (
    principal,
    action in [Action::"query", Action::"ingest"],
    resource
)
when {
    resource.consumer_admt_opt_out == true
};

// Both acts: documentation must be retained 5 years
// Enforced via retention config — not a Cedar policy.

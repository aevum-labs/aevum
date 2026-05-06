// Reference example only. Legal review required before production use.
// GDPR Article 7 — Consent conditions + Article 30 — Records of processing
// Reg. (EU) 2016/679; applies to processing of personal data of EU residents

// Art. 7(1): Controller must demonstrate consent was given
// The OR-Set CRDT consent ledger provides this evidence per ConsentGrant.grant_id

// Art. 7(3): Withdrawal must be as easy as giving consent
// The revoke_consent action must be permitted for any subject that holds a grant

permit (
    principal,
    action == Action::"revoke_consent",
    resource
)
when {
    // Any subject can revoke their own consent
    principal == resource.subject_id
};

// Art. 7(4): Consent must not be bundled with unnecessary conditions
// The consent model enforces purpose-specificity via ConsentGrant.purpose

// Art. 22(1): Automated decisions — subject must have given consent for
// the specific purpose, classification ceiling must be respected
permit (
    principal,
    action in [Action::"ingest", Action::"query", Action::"commit"],
    resource
)
when {
    // Consent exists for the declared purpose
    resource.consent_valid == true &&
    // Classification does not exceed the grant's maximum
    resource.classification <= resource.consent_classification_max &&
    // Purpose is specific (not a wildcard)
    resource.purpose != "any" &&
    resource.purpose != "all" &&
    resource.purpose != ""
};

// Art. 30: ROPA — processing activity description
// Aevum records all processing events; the ROPA document itself is external.
// The session.start event captures: capture_surface, ledger_backend, aevum_version.

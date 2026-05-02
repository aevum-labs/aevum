# Engine

The main entry point for all Aevum operations.

`Engine` wires together the episodic ledger, consent ledger, graph store,
policy bridge, complication registry, and the five governed functions.

::: aevum.core.engine.Engine
    options:
      show_source: false
      members:
        - ingest
        - query
        - review
        - commit
        - replay
        - add_consent_grant
        - revoke_consent_grant
        - verify_sigchain
        - install_complication
        - approve_complication
        - suspend_complication
        - resume_complication
        - list_complications
        - complication_state
        - register_webhook
        - deregister_webhook
        - create_review
        - get_ledger_entries
        - ledger_count

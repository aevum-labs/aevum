// SPDX-License-Identifier: Apache-2.0
// Cedar policy: allow GitHub Actions (identified by OIDC) to ingest scan results
// into the Aevum knowledge graph, provided active consent and purpose-match hold.
permit (
  principal == AevumAgent::"github-actions",
  action == Action::"relate_graph_write",
  resource == DataGraph::"knowledge"
) when {
  context.has_active_consent == true &&
  context.consent_purpose_matches == true
};

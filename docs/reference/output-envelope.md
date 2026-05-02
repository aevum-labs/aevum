# OutputEnvelope

Every function returns exactly one `OutputEnvelope`. No exceptions.

Always check `result.status` before accessing `result.data`. The `audit_id`
is always present, even on error.

::: aevum.core.envelope.models.OutputEnvelope

::: aevum.core.envelope.models.ProvenanceRecord

::: aevum.core.envelope.models.ReviewContext

::: aevum.core.envelope.models.UncertaintyAnnotation

::: aevum.core.envelope.models.SourceHealthSummary

::: aevum.core.envelope.models.ReasoningTrace

::: aevum.core.envelope.models.ReasoningStep

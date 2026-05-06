# Reference example only. Legal review required before production use.
# Sarbanes-Oxley §302/§404 + PCAOB AS 2201 (formerly AS 5)
# IT general controls (ITGC) documentation for AI systems in financial reporting
# 7-year retention per PCAOB AS 1215

package aevum.policy.sox_pcaob

import rego.v1

# PCAOB AS 2201.B9-B26: IT-dependent controls must be documented
# Any AI system touching financial calculations must log its decisions.

deny contains msg if {
    input.event.event_type in {"commit.accepted", "ingest.accepted"}
    input.context.affects_financial_reporting == true
    not input.event.payload.calculation_reference
    msg := "SOX/PCAOB AS 2201: financial-reporting AI events must include calculation_reference"
}

# 7-year retention
minimum_retention_years := 7
minimum_retention_days  := 2555

allow if {
    count(deny) == 0
}

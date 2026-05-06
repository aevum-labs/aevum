# Aevum Reference Policy Bundles

**These are reference examples only. They have NOT been reviewed by legal counsel.
Deployers MUST obtain qualified legal and compliance review before using any
policy bundle in a production or regulated environment.**

Each bundle demonstrates how to implement compliance-relevant access controls
using Aevum's Cedar and OPA policy layer. They are starting points, not
production policies.

## OPA (Rego) bundles

| Bundle | Standard | Location |
|--------|----------|----------|
| eu_ai_act_art12.rego | EU AI Act Art. 12 | policies/opa/ |
| hipaa_security.rego | HIPAA §164.312(b) + NPRM | policies/opa/ |
| pci_dss_v4_req10.rego | PCI DSS v4.0 Requirement 10 | policies/opa/ |
| fda_21cfr_part11.rego | FDA 21 CFR Part 11 §11.10 | policies/opa/ |
| nist_800_53_au.rego | NIST SP 800-53 AU Family / FedRAMP | policies/opa/ |
| iso27001_a8_logging.rego | ISO/IEC 27001:2022 A.8.15-17 | policies/opa/ |
| nydfs_part500.rego | NYDFS 23 NYCRR 500 §500.6 | policies/opa/ |
| dora_art17.rego | DORA Art. 17 | policies/opa/ |
| mifid2_rts6_algo_trading.rego | MiFID II RTS 6 | policies/opa/ |
| sox_pcaob.rego | SOX / PCAOB AS 2201 | policies/opa/ |
| nerc_cip007.rego | NERC CIP-007-6 R4 | policies/opa/ |

## Cedar bundles

| Bundle | Standard | Location |
|--------|----------|----------|
| gdpr_consent.cedar | GDPR Art. 7/30 | policies/cedar/ |
| iso42001_lifecycle_logging.cedar | ISO/IEC 42001 A.6.2.8 | policies/cedar/ |
| us_state_ai_acts.cedar | California ADMT + Colorado AI Act | policies/cedar/ |

## Crossover map

Many standards share requirements. A single Aevum deployment may need multiple
bundles. Common stacks:

- **US Healthcare AI:** hipaa_security + fda_21cfr_part11 + nist_800_53_au
- **EU High-Risk AI:** eu_ai_act_art12 + gdpr_consent + iso42001_lifecycle_logging
- **US Financial AI (NY):** nydfs_part500 + sox_pcaob + nist_800_53_au
- **EU Financial AI:** dora_art17 + mifid2_rts6_algo_trading + gdpr_consent
- **Energy Sector AI:** nerc_cip007 + nist_800_53_au

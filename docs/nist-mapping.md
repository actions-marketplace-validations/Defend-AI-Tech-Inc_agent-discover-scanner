# NIST AI 100-2e Taxonomy Mapping

**File location:** `docs/nist-mapping.md` in agent-discover-scanner repo

This document maps AgentDiscover Scanner findings and threat categories to the NIST AI 100-2e (Adversarial Machine Learning) taxonomy.

---

## Threat category mapping

| AgentDiscover Finding | NIST AI 100-2e Category | NIST Reference | Description |
|---|---|---|---|
| GHOST agent detection | Supply Chain / Deployment Integrity | Section 2.5 | Agents running without authorized deployment represent an integrity failure in the AI system deployment chain |
| Toxic Flow (prompt injection) | Prompt Injection | Section 2.3.1 | Untrusted input reaching the agent's reasoning layer constitutes a prompt injection attack surface |
| MCP tool poisoning | Data Poisoning (Indirect) | Section 2.1 | Malicious tool descriptions that alter agent behavior are analogous to indirect data poisoning |
| Cross-agent contamination | Model Output Manipulation | Section 2.4 | Injected instructions propagating through multi-agent trust hierarchies affect downstream model outputs |
| Unverified MCP publishers | Supply Chain Attack | Section 2.5 | Unverified MCP server publishers represent an untrusted component in the AI supply chain |
| Overly broad tool permissions | Privilege Escalation | Section 3.2 | Agent tools with access beyond declared task scope create unnecessary privilege escalation surface |
| Missing AIBOM | Transparency / Accountability | Section 4.1 | Absence of machine-readable inventory limits security team ability to audit AI system components |
| Deployment drift | Configuration Management | Section 3.1 | Divergence between declared and runtime agent state represents a configuration integrity failure |

---

## Risk classification alignment

NIST AI 100-2e uses a risk taxonomy based on: Confidentiality, Integrity, Availability impacts.

| Finding | Confidentiality | Integrity | Availability |
|---|---|---|---|
| GHOST agent | High — unknown data access scope | High — unauthorized execution | Medium |
| Toxic Flow | High — potential data exfiltration | Critical — agent behavior hijack | Low |
| Tool poisoning | Medium | High | Low |
| Cross-agent contamination | High | Critical | Low |
| Unverified MCP publishers | Medium | High | Medium |
| Overly broad permissions | High | High | Low |

---

## Compliance notes for enterprise security teams

**EU AI Act alignment:** The AIBOM output (CycloneDX 1.6) from AgentDiscover audit mode maps to EU AI Act Article 11 (Technical documentation) and Article 13 (Transparency) requirements for high-risk AI systems. The model provenance, tool scopes, and data lineage fields correspond directly to the technical documentation requirements.

**SOC 2 Type II:** GHOST agent detection and continuous runtime monitoring support CC6.1 (logical access controls) and CC7.2 (system monitoring) control objectives.

**ISO 27001:2022:** The AIBOM inventory process aligns with Annex A 8.8 (management of technical vulnerabilities) applied to AI system components.

---

## How to cite this mapping

If using AgentDiscover Scanner findings in a compliance report or security assessment, reference:

> Findings mapped to NIST AI 100-2e: Adversarial Machine Learning — A Taxonomy and Terminology of Attacks and Mitigations (January 2024). AgentDiscover Scanner v[version]. DefendAI Tech Inc.

---

*This mapping is maintained by DefendAI Tech Inc and updated as NIST guidance evolves. Last reviewed: April 2026.*

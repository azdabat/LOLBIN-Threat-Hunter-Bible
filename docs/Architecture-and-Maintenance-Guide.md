# Architecture & Maintenance Guide – LOLBIN Threat Hunter Bible

This document describes how this rulepack is intended to be used and maintained in a
mature SOC / detection engineering function.

## 1. Objectives

- Provide production-grade MDE hunting logic for key LOLBINs.
- Provide a consistent investigation doctrine for L3 analysts.
- Provide deployable Sentinel Analytic Rules derived from the hunting logic.
- Provide artefacts that hiring managers can use to evaluate seniority.

## 2. Content Model

- `rules/` – logic + rationale per LOLBIN.
- `attack-chains/` – how each LOLBIN appears in real attack paths.
- `mde-views/` – how abuse surfaces (or fails to surface) in MDE.
- `ir-playbooks/` – L2→L3 workflows, containment and remediation.
- `sentinel-rules/` – YAML for Analytic Rules wrapping the hunting queries.
- `tables/` – MITRE mapping, pivot guides, detection strength view.

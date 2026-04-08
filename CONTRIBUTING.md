# Contributing to AgentDiscover Scanner

Thanks for your interest in contributing. This document covers how to get started, how good contributions get recognized, and the path from first PR to maintainer.

---

## Quick start

```bash
git clone https://github.com/defendai-tech/agent-discover-scanner
cd agent-discover-scanner
pip install -e ".[dev]"
pytest
```

The codebase is organized by detection layer. If you're new, start with the layer that matches your background:

| Your background | Start here |
|---|---|
| Networking / packet analysis | `src/layer1_endpoints/` |
| Process monitoring / system programming | `src/layer2_attribution/` |
| Kubernetes / eBPF | `src/layer3_runtime/` |
| Data engineering / correlation | `src/layer4_correlation/` |
| Security research | `src/mcp_detection/` or `src/aibom/` |

---

## Good first issues

Issues labeled [`good first issue`](https://github.com/defendai-tech/agent-discover-scanner/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) are scoped to be completable in a few hours without deep codebase knowledge.

Common good first issue types:
- Adding a new LLM endpoint to the Layer 1 detection list
- Adding a new agent framework fingerprint to Layer 2
- Improving CLI output formatting
- Adding test coverage for an existing detection path
- Documentation improvements

---

## What makes a good contribution

The scanner's core value is detection accuracy — low false positives, genuine signal. Contributions that improve detection quality are the highest priority.

Specifically valued:
- New GHOST agent detection patterns you've observed in the wild
- Agent framework fingerprints (new frameworks, new versions)
- MCP server risk patterns
- Performance improvements to the correlation engine
- Test cases based on real (anonymized) production findings

Less prioritized right now:
- UI/reporting changes that don't affect detection quality
- New output formats (unless there's clear demand)
- Framework abstractions that increase complexity without improving detection

---

## Contribution process

1. **Check for an existing issue.** If there isn't one, open one before starting significant work. Avoids duplicate effort.
2. **Fork and branch.** Branch name convention: `feature/what-it-does` or `fix/what-it-fixes`.
3. **Write tests.** Every new detection pattern needs a test case. The test suite is in `tests/`.
4. **Submit a PR.** Include: what you changed, why, and how you tested it.
5. **Respond to review.** PRs are reviewed within 3 business days. If you haven't heard back in a week, ping in the PR.

---

## The path from contributor to maintainer

**Contributor:** Merged at least one PR. Listed in `CONTRIBUTORS.md`.

**Regular contributor:** 3+ merged PRs across different areas of the codebase. Gets added to the reviewer pool — your review is requested on relevant PRs.

**Maintainer:** Sustained contribution over 2+ months, demonstrated understanding of the detection architecture, and alignment with the project's direction. Maintainers have merge access and are involved in roadmap decisions.

There's no application process. If you're doing the work and the quality is there, the conversation about maintainer access happens naturally.

---

## Detection contribution guidelines

If you're adding a new detection pattern, include:

1. **The pattern itself** — what signal are you looking for?
2. **Why it's signal** — what does this pattern indicate about agent behavior?
3. **False positive analysis** — under what conditions would this fire incorrectly?
4. **A test case** — ideally based on a real (anonymized) example

For MCP detection contributions, also include the specific MCP client config format you're parsing.

---

## Security issues

If you find a security vulnerability in the scanner itself, please do not open a public issue. Email security@defendai.ai with details. We aim to respond within 48 hours.

---

## Questions

Open an issue with the `question` label, or reach out directly. Building this in public and happy to help contributors get oriented.

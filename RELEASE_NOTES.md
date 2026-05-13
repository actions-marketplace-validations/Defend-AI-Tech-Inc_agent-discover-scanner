# AgentDiscover Scanner v2.6.0 — Release Notes

**Released:** May 12, 2026

---

## What's new

### Scan your git history for AI secrets

A new `git-scan` command lets you check whether any AI API keys were ever committed to a repository — even if they've since been deleted. Git history is permanent; if a key was committed, every clone of that repo has it.

```bash
agent-discover git-scan ./my-project
```

The command checks three things:
- **API keys in commit history** — OpenAI, Anthropic, Google, Cohere, Groq keys committed at any point in the last 90 days
- **Sensitive files ever tracked** — `.env` files, model weight files, and AI configuration files that were added to git (even if later removed)
- **When AI frameworks arrived** — the first commit that introduced LangChain, CrewAI, OpenAI SDK, and similar libraries, so you know exactly when AI entered a codebase

If critical or high-severity findings are found, the command exits with code 1, making it easy to use as a CI gate.

---

### Scan a second repository alongside your primary scan

The new `--src-repo` flag lets `scan-all` include a second codebase in its Layer 1 (source code) analysis. This matters when the system you're monitoring at runtime is built from multiple repositories — for example, when your production services live in a separate repo from your local code.

```bash
agent-discover scan-all ./my-services --src-repo https://github.com/acme/ml-backend
```

Remote repositories are shallow-cloned, scanned, and deleted automatically. In continuous (daemon) mode, `--src-repo-ttl` controls how often the remote repo is re-fetched.

---

### Better first-scan experience on macOS

Previously, running a first scan on a macOS developer machine with a short observation window could produce empty results — even if Cursor, Claude Desktop, or Ollama were actively running. The scanner had no way to detect installed AI tools without catching a live API connection during the scan window.

v2.6.0 adds an instant presence check that runs before the network observation begins. It checks installed applications and running processes without requiring root access, osquery, or Kubernetes. If Claude Desktop and Cursor are on the machine, you'll see them immediately:

```
🌐 Monitoring live network connections...
  AI tools detected on this machine:
  ✓ Claude Desktop (running)
  ✓ Cursor (running)
  ✓ Ollama (installed)
  Observing runtime behavior (30s)...
```

These findings flow into the correlator as Shadow AI, alongside any live connections observed during the scan window.

The network observation window also now shows progress every 15 seconds, so you know the scanner is working during the wait.

---

### Fewer false GHOST findings on macOS

Several AI tools — Windsurf, Zed, Gemini, Perplexity, Codeium, Ollama, LM Studio, Jan, and Msty — were not in the known-applications list. If these tools made network connections during a scan, they could appear as GHOST agents (runtime activity with no source code match) rather than Shadow AI. This was a false positive.

All of these tools are now in the built-in known-apps list and will be correctly classified as Shadow AI.

---

## Upgrading

```bash
pip install --upgrade agent-discover-scanner
# or
pipx upgrade agent-discover-scanner
```

Full changelog: [CHANGELOG.md](CHANGELOG.md)

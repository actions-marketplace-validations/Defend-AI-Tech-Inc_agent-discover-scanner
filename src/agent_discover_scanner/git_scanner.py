"""Git history scanner — detect AI-related security signals in git repos."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from pydantic import BaseModel


class GitFinding(BaseModel):
    rule_id: str
    severity: str          # critical | high | medium | info
    finding_type: str      # secret_in_history | sensitive_file_committed | ai_dependency_introduced
    message: str
    file_path: str | None = None
    commit_hash: str | None = None
    commit_date: str | None = None
    author: str | None = None
    detail: str | None = None


_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bsk-[A-Za-z0-9]{48}\b"), "OpenAI API key"),
    (re.compile(r"\bsk-ant-api[03][A-Za-z0-9_\-]{90,}"), "Anthropic API key"),
    (re.compile(r"\bAIzaSy[A-Za-z0-9_\-]{33}\b"), "Google AI API key"),
    (re.compile(r"(?i)OPENAI_API_KEY\s*[=:]\s*[\"']?sk-[A-Za-z0-9]{20,}"), "OpenAI key assignment"),
    (re.compile(r"(?i)ANTHROPIC_API_KEY\s*[=:]\s*[\"']?sk-ant"), "Anthropic key assignment"),
    (re.compile(r"(?i)COHERE_API_KEY\s*[=:]\s*[\"']?[A-Za-z0-9]{30,}"), "Cohere API key"),
    (re.compile(r"\bgsk_[A-Za-z0-9]{52}\b"), "Groq API key"),
]

_SENSITIVE_FILE_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # (pattern, label, base_severity)
    (re.compile(r"(^|/)\.env$"), "Environment file", "high"),
    (re.compile(r"(^|/)\.env\."), "Environment file", "high"),
    (re.compile(r"(^|/)\.openai$"), "OpenAI config file", "medium"),
    (re.compile(r"(^|/)\.anthropic$"), "Anthropic config file", "medium"),
    (re.compile(r"(?i)(openai|anthropic|cohere|groq)_?key\.txt$"), "AI API key file", "high"),
    (re.compile(r"\.gguf$"), "Local model weight (GGUF)", "medium"),
    (re.compile(r"(?i)(pytorch_model|model_weights).*\.bin$"), "Model weight file", "medium"),
]

_AI_DEPS: list[str] = [
    "langchain", "langchain-core", "langchain-community", "langgraph",
    "openai", "anthropic", "google-generativeai",
    "crewai", "autogen", "semantic-kernel", "llama-index",
    "cohere", "mistralai", "groq", "deepseek",
]

_COMMIT_PREFIX = "AGENTDISCOVER_COMMIT "


def _run_git(*args: str, cwd: Path, timeout: int = 30) -> tuple[int, str]:
    try:
        r = subprocess.run(
            ["git", *args],
            capture_output=True, text=True, cwd=cwd, timeout=timeout,
        )
        return r.returncode, r.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return 1, ""


def is_git_repo(path: Path) -> bool:
    code, _ = _run_git("rev-parse", "--git-dir", cwd=path)
    return code == 0


def _parse_commit_line(line: str) -> tuple[str | None, str | None, str | None]:
    """Extract (hash, date, author) from a _COMMIT_PREFIX header line."""
    rest = line[len(_COMMIT_PREFIX):]
    parts = rest.split(" ", 3)
    h = parts[0] if parts else None
    d = parts[1] if len(parts) > 1 else None
    a = parts[3].strip() if len(parts) > 3 else None
    return h, d, a


def _scan_secrets_in_history(path: Path, since_days: int) -> list[GitFinding]:
    """Scan recent commit diffs for AI API key patterns (added lines only)."""
    _, output = _run_git(
        "log", "--all", f"--since={since_days} days ago",
        "-p", "-U0",
        f"--format={_COMMIT_PREFIX}%H %ai %aN",
        cwd=path, timeout=60,
    )

    findings: list[GitFinding] = []
    seen: set[tuple[str | None, str | None]] = set()
    current_hash = current_date = current_author = current_file = None

    for line in output.splitlines():
        if line.startswith(_COMMIT_PREFIX):
            current_hash, current_date, current_author = _parse_commit_line(line)
            current_file = None
        elif line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            diff_line = line[1:]
            for pattern, label in _SECRET_PATTERNS:
                if pattern.search(diff_line):
                    key = (current_hash, current_file)
                    if key not in seen:
                        seen.add(key)
                        findings.append(GitFinding(
                            rule_id="DAI-GIT-001",
                            severity="critical",
                            finding_type="secret_in_history",
                            message=f"{label} found in git history",
                            file_path=current_file,
                            commit_hash=current_hash[:8] if current_hash else None,
                            commit_date=current_date,
                            author=current_author,
                            detail="Rotate this key immediately — it is in every clone of this repo",
                        ))
                    break

    return findings


def _scan_sensitive_files_ever_committed(path: Path) -> list[GitFinding]:
    """Find sensitive files that were ever added to git."""
    _, log_output = _run_git(
        "log", "--all",
        "--diff-filter=A", "--name-only",
        f"--format={_COMMIT_PREFIX}%H %ai %aN",
        cwd=path,
    )

    _, tracked_output = _run_git("ls-files", cwd=path)
    tracked: set[str] = set(tracked_output.splitlines())

    findings: list[GitFinding] = []
    seen_files: set[str] = set()
    current_hash = current_date = current_author = None

    for line in log_output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith(_COMMIT_PREFIX):
            current_hash, current_date, current_author = _parse_commit_line(line)
        else:
            if line in seen_files:
                continue
            for pattern, label, base_severity in _SENSITIVE_FILE_PATTERNS:
                if pattern.search(line):
                    seen_files.add(line)
                    still_tracked = line in tracked
                    severity = "high" if still_tracked else base_severity
                    findings.append(GitFinding(
                        rule_id="DAI-GIT-002",
                        severity=severity,
                        finding_type="sensitive_file_committed",
                        message=f"{label} committed to git",
                        file_path=line,
                        commit_hash=current_hash[:8] if current_hash else None,
                        commit_date=current_date,
                        author=current_author,
                        detail=(
                            f"Still tracked — run: git rm --cached {line}"
                            if still_tracked
                            else "Removed from working tree but exists in full git history"
                        ),
                    ))
                    break

    return findings


def _scan_ai_dependency_introduction(path: Path) -> list[GitFinding]:
    """Find the first commit that introduced each AI dependency across all dep files."""
    global_first: dict[str, GitFinding] = {}

    for dep_file in ("requirements.txt", "package.json", "pyproject.toml"):
        _, log_output = _run_git(
            "log", "--all", "--reverse",
            "-p", "-U0",
            f"--format={_COMMIT_PREFIX}%H %ai %aN",
            "--", dep_file,
            cwd=path, timeout=60,
        )

        current_hash = current_date = current_author = None

        for line in log_output.splitlines():
            if line.startswith(_COMMIT_PREFIX):
                current_hash, current_date, current_author = _parse_commit_line(line)
            elif line.startswith("+") and not line.startswith("+++"):
                diff_line = line[1:].lower()
                for dep in _AI_DEPS:
                    if dep in diff_line and dep not in global_first:
                        global_first[dep] = GitFinding(
                            rule_id="DAI-GIT-005",
                            severity="info",
                            finding_type="ai_dependency_introduced",
                            message=f"AI dependency '{dep}' first introduced in {dep_file}",
                            file_path=dep_file,
                            commit_hash=current_hash[:8] if current_hash else None,
                            commit_date=current_date,
                            author=current_author,
                            detail=f"Earliest appearance of '{dep}' across all dependency files",
                        )

    return list(global_first.values())


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}


def scan_repo(path: Path, since_days: int = 90) -> list[GitFinding]:
    """
    Scan a git repository for AI-related security signals.

    Checks:
      - AI API keys committed to history (last since_days days)
      - Sensitive files (.env, model weights) ever added to git
      - When each AI framework was first introduced to dependency files

    Returns findings sorted by severity (critical first).
    Returns an empty list if path is not a git repository.
    """
    if not is_git_repo(path):
        return []

    findings: list[GitFinding] = []
    findings.extend(_scan_secrets_in_history(path, since_days))
    findings.extend(_scan_sensitive_files_ever_committed(path))
    findings.extend(_scan_ai_dependency_introduction(path))

    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
    return findings

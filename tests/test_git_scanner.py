"""Tests for git_scanner — uses real git repos built in tmp_path."""
import subprocess
from pathlib import Path

import pytest

from agent_discover_scanner.git_scanner import (
    GitFinding,
    is_git_repo,
    scan_repo,
    _scan_secrets_in_history,
    _scan_sensitive_files_ever_committed,
    _scan_ai_dependency_introduction,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    return repo


def _commit(repo: Path, filename: str, content: str, msg: str = "add file") -> None:
    (repo / filename).write_text(content)
    _git(repo, "add", filename)
    _git(repo, "commit", "-m", msg)


# ---------------------------------------------------------------------------
# is_git_repo
# ---------------------------------------------------------------------------

def test_is_git_repo_true(tmp_path):
    repo = _make_repo(tmp_path)
    assert is_git_repo(repo) is True


def test_is_git_repo_false(tmp_path):
    not_repo = tmp_path / "not_a_repo"
    not_repo.mkdir()
    assert is_git_repo(not_repo) is False


# ---------------------------------------------------------------------------
# Secret detection
# ---------------------------------------------------------------------------

def test_detects_openai_key_in_history(tmp_path):
    repo = _make_repo(tmp_path)
    _commit(repo, "config.py", 'API_KEY = "sk-' + "A" * 48 + '"')

    findings = _scan_secrets_in_history(repo, since_days=9999)
    assert any(f.finding_type == "secret_in_history" for f in findings)
    assert all(f.severity == "critical" for f in findings if f.finding_type == "secret_in_history")
    assert all(f.rule_id == "DAI-GIT-001" for f in findings if f.finding_type == "secret_in_history")


def test_detects_anthropic_key_assignment(tmp_path):
    repo = _make_repo(tmp_path)
    _commit(repo, ".env", "ANTHROPIC_API_KEY=sk-ant-api03" + "B" * 95)

    findings = _scan_secrets_in_history(repo, since_days=9999)
    assert any(f.finding_type == "secret_in_history" for f in findings)


def test_no_false_positive_on_clean_code(tmp_path):
    repo = _make_repo(tmp_path)
    _commit(repo, "app.py", "import os\nprint('hello world')\n")

    findings = _scan_secrets_in_history(repo, since_days=9999)
    assert findings == []


def test_deduplicates_same_commit_and_file(tmp_path):
    repo = _make_repo(tmp_path)
    key = "sk-" + "A" * 48
    _commit(repo, "secrets.py", f'KEY1 = "{key}"\nKEY2 = "{key}"\n')

    findings = _scan_secrets_in_history(repo, since_days=9999)
    # Both lines match but are in same commit+file — expect exactly one finding
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Sensitive file detection
# ---------------------------------------------------------------------------

def test_detects_env_file_committed(tmp_path):
    repo = _make_repo(tmp_path)
    _commit(repo, ".env", "OPENAI_API_KEY=placeholder\n")

    findings = _scan_sensitive_files_ever_committed(repo)
    assert any(f.file_path == ".env" for f in findings)
    assert any(f.finding_type == "sensitive_file_committed" for f in findings)


def test_env_file_still_tracked_is_high(tmp_path):
    repo = _make_repo(tmp_path)
    _commit(repo, ".env", "SECRET=abc\n")

    findings = _scan_sensitive_files_ever_committed(repo)
    env_findings = [f for f in findings if f.file_path == ".env"]
    assert env_findings
    assert env_findings[0].severity == "high"


def test_env_file_removed_reflects_in_detail(tmp_path):
    repo = _make_repo(tmp_path)
    _commit(repo, ".env", "SECRET=abc\n")
    _git(repo, "rm", ".env")
    _git(repo, "commit", "-m", "remove .env")

    findings = _scan_sensitive_files_ever_committed(repo)
    env_findings = [f for f in findings if f.file_path == ".env"]
    assert env_findings
    # .env stays "high" even when removed — it's in history forever
    assert env_findings[0].severity == "high"
    # But the detail should distinguish removed vs still-tracked
    assert env_findings[0].detail is not None
    assert "history" in (env_findings[0].detail or "")


def test_no_finding_for_regular_file(tmp_path):
    repo = _make_repo(tmp_path)
    _commit(repo, "main.py", "print('hi')\n")

    findings = _scan_sensitive_files_ever_committed(repo)
    assert findings == []


# ---------------------------------------------------------------------------
# AI dependency introduction
# ---------------------------------------------------------------------------

def test_detects_langchain_in_requirements(tmp_path):
    repo = _make_repo(tmp_path)
    _commit(repo, "requirements.txt", "requests==2.31.0\nlangchain==0.1.0\n")

    findings = _scan_ai_dependency_introduction(repo)
    assert any("langchain" in f.message for f in findings)
    assert all(f.severity == "info" for f in findings)
    assert all(f.rule_id == "DAI-GIT-005" for f in findings)


def test_detects_openai_in_package_json(tmp_path):
    repo = _make_repo(tmp_path)
    _commit(repo, "package.json", '{"dependencies": {"openai": "^4.0.0"}}\n')

    findings = _scan_ai_dependency_introduction(repo)
    assert any("openai" in f.message for f in findings)


def test_no_finding_for_no_ai_deps(tmp_path):
    repo = _make_repo(tmp_path)
    _commit(repo, "requirements.txt", "requests==2.31.0\nflask==3.0.0\n")

    findings = _scan_ai_dependency_introduction(repo)
    assert findings == []


def test_reports_each_dep_only_once(tmp_path):
    repo = _make_repo(tmp_path)
    _commit(repo, "requirements.txt", "langchain==0.0.1\n")
    _commit(repo, "requirements.txt", "langchain==0.1.0\n", msg="upgrade langchain")

    findings = _scan_ai_dependency_introduction(repo)
    langchain_findings = [f for f in findings if "langchain" in f.message and "langchain-" not in f.message]
    assert len(langchain_findings) == 1


# ---------------------------------------------------------------------------
# scan_repo integration
# ---------------------------------------------------------------------------

def test_scan_repo_returns_empty_for_non_repo(tmp_path):
    not_repo = tmp_path / "plain_dir"
    not_repo.mkdir()
    assert scan_repo(not_repo) == []


def test_scan_repo_sorted_by_severity(tmp_path):
    repo = _make_repo(tmp_path)
    _commit(repo, ".env", "OPENAI_API_KEY=sk-" + "A" * 48 + "\n")
    _commit(repo, "requirements.txt", "langchain==0.1.0\n")

    findings = scan_repo(repo, since_days=9999)
    assert findings  # at minimum secret + sensitive file + dep intro
    severities = [f.severity for f in findings]
    order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    assert severities == sorted(severities, key=lambda s: order.get(s, 99))


def test_scan_repo_returns_git_finding_instances(tmp_path):
    repo = _make_repo(tmp_path)
    _commit(repo, "requirements.txt", "openai==1.0.0\n")

    findings = scan_repo(repo, since_days=9999)
    assert all(isinstance(f, GitFinding) for f in findings)

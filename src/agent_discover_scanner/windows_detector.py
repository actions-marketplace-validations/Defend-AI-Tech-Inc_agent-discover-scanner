"""
Zero-privilege Windows AI presence detection.

Checks known install paths and running processes for AI desktop tools.
Runs in <1s without elevated privileges using psutil.
Only active on sys.platform == 'win32'.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import psutil


def _localappdata() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))


def _appdata() -> Path:
    return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))


def _programfiles() -> Path:
    return Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))


# (dir_resolver, relative_exe_path, process_name, display_name, provider_slug)
# process_name MUST match an entry in BUILTIN_KNOWN_APPS.
_AI_INSTALL_CHECKS: list[tuple] = [
    (_localappdata, r"Programs\cursor\Cursor.exe",                    "cursor",     "Cursor",                "cursor"),
    (_localappdata, r"AnthropicClaude\claude.exe",                    "claude",     "Claude Desktop",        "anthropic"),
    (_appdata,      r"Claude\claude.exe",                             "claude",     "Claude Desktop",        "anthropic"),
    (_localappdata, r"Programs\OpenAI Chat\ChatGPT.exe",              "chatgpt",    "ChatGPT Desktop",       "openai"),
    (_localappdata, r"Programs\Ollama\ollama app.exe",                "ollama",     "Ollama (local LLM)",    "local_llm"),
    (_localappdata, r"Programs\Ollama\ollama.exe",                    "ollama",     "Ollama (local LLM)",    "local_llm"),
    (_localappdata, r"Programs\LM-Studio\LM Studio.exe",              "lmstudio",   "LM Studio (local LLM)", "local_llm"),
    (_appdata,      r"LM Studio\LM Studio.exe",                       "lmstudio",   "LM Studio (local LLM)", "local_llm"),
    (_localappdata, r"Programs\Windsurf\Windsurf.exe",                "windsurf",   "Windsurf",              "codeium"),
    (_localappdata, r"Programs\Perplexity\Perplexity.exe",            "perplexity", "Perplexity AI",         "perplexity"),
    (_programfiles, r"Ollama\ollama.exe",                             "ollama",     "Ollama (local LLM)",    "local_llm"),
]

# process name substrings (after stripping .exe and lowercasing)
_AI_PROCESS_PATTERNS: list[tuple[str, str, str, str]] = [
    ("cursor",      "cursor",     "Cursor",              "cursor"),
    ("claude",      "claude",     "Claude Desktop",      "anthropic"),
    ("chatgpt",     "chatgpt",    "ChatGPT Desktop",     "openai"),
    ("windsurf",    "windsurf",   "Windsurf",            "codeium"),
    ("codeium",     "codeium",    "Codeium",             "codeium"),
    ("ollama",      "ollama",     "Ollama",              "local_llm"),
    ("lmstudio",    "lmstudio",   "LM Studio",           "local_llm"),
    ("lm studio",   "lmstudio",   "LM Studio",           "local_llm"),
    ("perplexity",  "perplexity", "Perplexity AI",       "perplexity"),
    ("copilot",     "copilot",    "GitHub Copilot",      "github_copilot"),
    ("gemini",      "gemini",     "Gemini",              "google_gemini"),
]


def _scan_installed_apps() -> list[dict]:
    results = []
    seen_providers: set[str] = set()
    for dir_fn, rel_path, proc_name, display, provider in _AI_INSTALL_CHECKS:
        if provider in seen_providers:
            continue
        try:
            if (dir_fn() / rel_path).exists():
                seen_providers.add(provider)
                results.append({
                    "process_name": proc_name,
                    "display_name": display,
                    "provider": provider,
                    "source": "installed_app",
                })
        except Exception:
            continue
    return results


def _scan_running_processes() -> list[dict]:
    results = []
    seen_providers: set[str] = set()
    try:
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                # Strip .exe and lowercase so patterns match cross-platform style
                raw_name = proc.name() or ""
                name = raw_name.lower().removesuffix(".exe")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            for pattern, proc_name, display, provider in _AI_PROCESS_PATTERNS:
                if pattern in name and provider not in seen_providers:
                    seen_providers.add(provider)
                    results.append({
                        "process_name": proc_name,
                        "display_name": display,
                        "provider": provider,
                        "pid": proc.pid,
                        "source": "running_process",
                    })
                    break
    except Exception:
        pass
    return results


def scan_ai_presence() -> list[dict]:
    """
    Return AI tool presence findings for Windows in layer2 findings format.

    Each entry: {provider, process_name, display_name, timestamp, source}
    Running processes take priority over installed-only apps for the same provider.
    Returns [] on non-Windows platforms or on any failure.
    """
    if sys.platform != "win32":
        return []

    timestamp = datetime.now(timezone.utc).isoformat()
    raw = _scan_running_processes() + _scan_installed_apps()
    best: dict[str, dict] = {}
    for item in raw:
        p = item["provider"]
        if p not in best or item["source"] == "running_process":
            best[p] = item

    return [
        {
            "provider": item["provider"],
            "process_name": item["process_name"],
            "display_name": item["display_name"],
            "timestamp": timestamp,
            "source": item["source"],
        }
        for item in best.values()
    ]

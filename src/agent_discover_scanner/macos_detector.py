"""
Zero-privilege macOS AI presence detection.

Checks installed applications and running processes for known AI tools.
Runs in <1 second without root, osquery, or K8s access.
Only active on sys.platform == 'darwin'.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import psutil

_APP_SEARCH_DIRS = [Path("/Applications"), Path.home() / "Applications"]

# bundle name → (known_apps_process_name, display_name, provider_slug)
# process_name MUST match an entry in BUILTIN_KNOWN_APPS; add new entries there too.
_AI_BUNDLES: dict[str, tuple[str, str, str]] = {
    "Claude.app":                       ("claude",      "Claude Desktop",            "anthropic"),
    "ChatGPT.app":                      ("chatgpt",     "ChatGPT Desktop",           "openai"),
    "Cursor.app":                       ("cursor",      "Cursor",                    "cursor"),
    "Windsurf.app":                     ("windsurf",    "Windsurf",                  "codeium"),
    "Zed.app":                          ("zed",         "Zed",                       "zed"),
    "Gemini.app":                       ("gemini",      "Gemini",                    "google_gemini"),
    "Perplexity.app":                   ("perplexity",  "Perplexity AI",             "perplexity"),
    "GitHub Copilot for Xcode.app":     ("copilot",     "GitHub Copilot for Xcode",  "github_copilot"),
    "Codeium.app":                      ("codeium",     "Codeium",                   "codeium"),
    "Ollama.app":                       ("ollama",      "Ollama (local LLM)",        "local_llm"),
    "LM Studio.app":                    ("lmstudio",    "LM Studio (local LLM)",     "local_llm"),
    "Jan.app":                          ("jan",         "Jan (local LLM)",           "local_llm"),
    "Msty.app":                         ("msty",        "Msty (local LLM)",          "local_llm"),
}

# process name substrings → (known_apps_process_name, display_name, provider_slug)
_AI_PROCESS_PATTERNS: list[tuple[str, str, str, str]] = [
    ("cursor",      "cursor",     "Cursor",              "cursor"),
    ("claude",      "claude",     "Claude Desktop",      "anthropic"),
    ("chatgpt",     "chatgpt",    "ChatGPT Desktop",     "openai"),
    ("windsurf",    "windsurf",   "Windsurf",            "codeium"),
    ("codeium",     "codeium",    "Codeium",             "codeium"),
    ("ollama",      "ollama",     "Ollama",              "local_llm"),
    ("lmstudio",    "lmstudio",   "LM Studio",           "local_llm"),
    ("perplexity",  "perplexity", "Perplexity AI",       "perplexity"),
    ("copilot",     "copilot",    "GitHub Copilot",      "github_copilot"),
    ("gemini",      "gemini",     "Gemini",              "google_gemini"),
    ("zed",         "zed",        "Zed",                 "zed"),
    ("jan ",        "jan",        "Jan",                 "local_llm"),
]


def _scan_installed_apps() -> list[dict]:
    results = []
    for app_dir in _APP_SEARCH_DIRS:
        if not app_dir.exists():
            continue
        for bundle, (proc_name, display, provider) in _AI_BUNDLES.items():
            if (app_dir / bundle).exists():
                results.append({
                    "process_name": proc_name,
                    "display_name": display,
                    "provider": provider,
                    "source": "installed_app",
                })
    return results


def _scan_running_processes() -> list[dict]:
    results = []
    seen_providers: set[str] = set()
    try:
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = (proc.name() or "").lower()
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
    Return AI tool presence findings for macOS in layer2 findings format.

    Each entry: {provider, process_name, display_name, timestamp, source}
    Running processes take priority over installed-only apps for the same provider.
    Returns [] on non-macOS platforms or on any failure.
    """
    if sys.platform != "darwin":
        return []

    timestamp = datetime.now(timezone.utc).isoformat()

    # running_process entries override installed_app for the same provider
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

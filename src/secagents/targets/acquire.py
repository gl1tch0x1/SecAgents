from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx
from git import Repo


@dataclass
class AcquiredTarget:
    root: Path
    label: str
    cleanup: Path | None = None  # temp dir to remove


def acquire_local(path: str | Path) -> AcquiredTarget:
    p = Path(path).resolve()
    if not p.is_dir():
        raise FileNotFoundError(f"Not a directory: {p}")
    return AcquiredTarget(root=p, label=str(p), cleanup=None)


def acquire_github_repo(
    repo_url: str,
    *,
    branch: str | None = None,
    depth: int = 1,
) -> AcquiredTarget:
    tmp = Path(tempfile.mkdtemp(prefix="secagents-repo-"))
    clone_kwargs: dict = {}
    if branch:
        clone_kwargs["branch"] = branch
    if depth > 0:
        clone_kwargs["depth"] = depth
    Repo.clone_from(repo_url, tmp, **clone_kwargs)
    return AcquiredTarget(root=tmp, label=repo_url, cleanup=tmp)


def acquire_url_target(url: str) -> AcquiredTarget:
    """
    Prepare a small synthetic workspace describing the URL target and a quick probe.
    Agents use this for black-box style checks; deep testing still needs the running app.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Invalid HTTP(S) URL: {url}")
    tmp = Path(tempfile.mkdtemp(prefix="secagents-url-"))
    probe_md = tmp / "TARGET.md"
    headers_dump = tmp / "probe_headers.txt"
    body_snip = tmp / "probe_body_snippet.txt"
    probe_md.write_text(
        f"# Live URL target\n\nBase URL: `{url}`\n\n"
        "Use sandbox `curl` against this URL only when network is enabled for validation.\n",
        encoding="utf-8",
    )
    try:
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            r = client.get(url)
            headers_dump.write_text(
                "\n".join(f"{k}: {v}" for k, v in r.headers.items()),
                encoding="utf-8",
            )
            text = r.text[:8000]
            body_snip.write_text(text, encoding="utf-8")
    except httpx.HTTPError as e:
        body_snip.write_text(f"Probe failed: {e}", encoding="utf-8")
    return AcquiredTarget(root=tmp, label=url, cleanup=tmp)

"""
OpenSSF Scorecard integration.
API docs: https://api.securityscorecards.dev/
"""

import json
import logging
import re

import httpx

logger = logging.getLogger(__name__)

SCORECARD_API = "https://api.securityscorecards.dev/projects"


_GITHUB_REPO_RE = re.compile(r"github\.com[/:]([A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100})")


def _parse_github_repo(repo_url: str) -> str | None:
    """
    Extract 'owner/repo' from a GitHub URL.
    Handles:
      https://github.com/owner/repo
      https://github.com/owner/repo.git
      https://github.com/owner/repo/tree/main

    The URL is capped at 256 characters before matching to prevent ReDoS
    on pathologically long inputs.
    """
    if not repo_url or len(repo_url) > 256:
        return None
    match = _GITHUB_REPO_RE.search(repo_url)
    if not match:
        return None
    return match.group(1).removesuffix(".git")


async def fetch_scorecard(repo_url: str) -> dict | None:
    """
    Fetch OpenSSF Scorecard data for a GitHub repository.

    Returns a dict with:
        score: float (0.0–10.0)
        checks: list of individual check results
        date: str (ISO date of last evaluation)
        repo: str (canonical repo path)
    Returns None if the repo is not on GitHub or the API call fails.
    """
    repo_path = _parse_github_repo(repo_url)
    if not repo_path:
        logger.warning(f"Cannot parse GitHub repo from URL: {repo_url}")
        return None

    url = f"{SCORECARD_API}/github.com/{repo_path}"
    logger.info(f"Fetching Scorecard for {repo_path}")

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(url)
            if response.status_code == 404:
                logger.info(f"Scorecard not found for {repo_path}")
                return None
            response.raise_for_status()
            data = response.json()
    except Exception as e:
        logger.error(f"Scorecard API error for {repo_path}: {e}")
        return None

    score = data.get("score")
    checks = data.get("checks", [])
    date = data.get("date")

    logger.info(f"Scorecard for {repo_path}: {score}/10")
    return {
        "score": round(float(score), 1) if score is not None else None,
        "checks": checks,
        "date": date,
        "repo": repo_path,
    }

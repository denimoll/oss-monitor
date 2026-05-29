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


def _parse_github_repo(repo_url: str) -> str | None:
    """
    Extract 'owner/repo' from a GitHub URL.
    Handles:
      https://github.com/owner/repo
      https://github.com/owner/repo.git
      https://github.com/owner/repo/tree/main
    """
    match = re.search(r"github\.com[/:]([^/]+/[^/.\s]+)", repo_url)
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

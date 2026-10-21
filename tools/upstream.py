"""Pinned upstream acquisition. No firmware, DCP, or camera access."""
from __future__ import annotations
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def specifications():
    rows = json.loads((ROOT / "upstream.lock.json").read_text())["repositories"]
    for row in rows:
        if not re.fullmatch(r"[0-9a-f]{40}", row["commit"]):
            raise ValueError("Expected a full pinned commit")
        path = ROOT / row["destination"]
        if path.is_absolute() and ROOT.resolve() not in path.resolve().parents:
            raise ValueError("Dependency destination escapes the workspace")
        if not row["url"].startswith("https://github.com/") or not row["destination"].startswith("research/"):
            raise ValueError("Unexpected dependency source/destination")
    return rows


def revision(path):
    return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()


def status():
    result = []
    for row in specifications():
        path = ROOT / row["destination"]
        actual = None
        if path.exists():
            try:
                actual = revision(path)
            except (subprocess.CalledProcessError, OSError):
                actual = "not-a-readable-git-checkout"
        result.append({"id": row["id"], "profile": row["profile"],
                       "present": path.exists(), "matches_pin": actual == row["commit"]})
    return result


def require(identifier):
    row = next(x for x in specifications() if x["id"] == identifier)
    path = ROOT / row["destination"]
    if not path.exists() or revision(path) != row["commit"]:
        raise RuntimeError("Pinned dependency missing/different: " + identifier + "; run python a7cr.py bootstrap")
    return path


def bootstrap(research=False):
    for row in specifications():
        if row["profile"] == "research" and not research:
            continue
        path = ROOT / row["destination"]
        if path.exists():
            if revision(path) != row["commit"]:
                raise ValueError("Existing dependency differs; preserve it instead of overwriting: " + row["id"])
            print("Already pinned:", row["id"], flush=True)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        # No reset of an existing directory and no automatic retry after failure.
        subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", row["url"], str(path)], check=True)
        subprocess.run(["git", "-C", str(path), "checkout", "--detach", row["commit"]], check=True)
        if revision(path) != row["commit"]:
            raise ValueError("Checkout did not reach the requested commit")
        print("Pinned:", row["id"], row["commit"], flush=True)

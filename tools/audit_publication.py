"""Audit an explicit text-source publication allowlist, never local inputs.

Run before uploading. --deny-file may point to a LOCAL JSON list of identifiers
that must not occur in public files; values are never printed. The deny file
itself must remain outside the publication allowlist.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = {".gitignore", "LICENSE", "NOTICE.md", "README.md", "README.zh-CN.md",
              "CHANGELOG.md", "a7cr.py", "requirements.txt", "requirements-research.txt", "upstream.lock.json"}
TREES = {"device", "offline", "tools", "tests", "docs", "licenses", "validation", ".github"}
EXTENSIONS = {".py", ".md", ".txt", ".json", ".yml", ".yaml"}
GENERATED_AUDIT = "validation/publication-audit.json"
SECRET_PATTERNS = [re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
                   re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
                   re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
                   re.compile(r"/Users/[A-Za-z0-9._-]+/")]
UUID_PATTERN = re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b")
# One visibly synthetic ABI fixture, never a captured device/host identifier.
SYNTHETIC_BOOT_ID = "-".join(("12345678","1234","1234","1234","123456789abc"))


def allowed(path):
    return str(path) in ROOT_FILES or (path.parts[0] in TREES and path.suffix in EXTENSIONS)


def candidates(root):
    files = []
    for name in sorted(ROOT_FILES):
        p = root/name
        if p.exists():files.append(p)
    for name in sorted(TREES):
        base = root/name
        if base.exists():
            files += [p for p in base.rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.name != ".DS_Store"]
    try:
        top = subprocess.check_output(["git", "-C", str(root), "rev-parse", "--show-toplevel"],stderr=subprocess.DEVNULL,text=True).strip()
        if Path(top).resolve() == root.resolve():
            tracked = subprocess.check_output(["git","-C",str(root),"ls-files","-z"]).decode().split("\0")
            for name in filter(None,tracked):
                if not allowed(Path(name)):
                    raise ValueError("Tracked path is outside the publication allowlist: "+name)
    except subprocess.CalledProcessError:
        pass
    return sorted(set(files))


def audit(root, deny=()):
    entries = []
    for path in candidates(root):
        rel = path.relative_to(root)
        if path.is_symlink() or not allowed(rel):
            raise ValueError("Unexpected publication asset: "+str(rel))
        raw = path.read_bytes()
        if len(raw)>256*1024:
            raise ValueError("Unexpected large publication file: "+str(rel))
        text = raw.decode("utf-8")
        if any(pattern.search(text) for pattern in SECRET_PATTERNS) or any(value and value in text for value in deny):
            raise ValueError("Potential identifier/credential in "+str(rel)+"; matched values withheld")
        if any(not (str(rel) in {"device/test_diagnose_fl23.py", "offline/check_runtime_diagnostic.py"}
                    and m.group()==SYNTHETIC_BOOT_ID)
               for m in UUID_PATTERN.finditer(text)):
            raise ValueError("Unreviewed UUID in "+str(rel)+"; matched value withheld")
        if path.suffix == ".py":
            tree = ast.parse(text,filename=str(rel))
            for node in ast.walk(tree):
                if isinstance(node,ast.Constant):
                    if isinstance(node.value,bytes) and len(node.value)>256:
                        raise ValueError("Opaque inline bytes in "+str(rel))
                    if isinstance(node.value,str) and len(node.value)>512 and re.fullmatch(r"[0-9a-fA-F\s]+",node.value):
                        raise ValueError("Large inline hex data in "+str(rel))
        if str(rel) != GENERATED_AUDIT:
            entries.append({"path":str(rel),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()})
    return {"schema":"a7cr-source-publication-audit/1", "passed":True,
        "method":"Explicit text-source allowlist, identifier/credential scan, Python parse and opaque-blob checks",
        "file_count":len(entries), "total_bytes":sum(x["bytes"] for x in entries),
        "firmware_DCP_LUT_photo_backup_assets_included":False,
        "short_patch_signatures_and_firmware_offsets_disclosed":True,
        "not_a_legal_clearance_or_complete_secret_scanner":True, "files":entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deny-file",type=Path)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    deny=json.loads(args.deny_file.read_text()) if args.deny_file else []
    if not isinstance(deny,list) or any(not isinstance(x,str) for x in deny):
        raise ValueError("Expected a private JSON list of excluded strings")
    result=audit(ROOT,deny)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k!="files"},indent=2))


if __name__=="__main__":main()

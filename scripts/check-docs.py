#!/usr/bin/env python3
"""Check repository document links and the required decision/traceability artifacts."""
import re
from pathlib import Path

root = Path(__file__).resolve().parent.parent
errors = []
for path in [root / "README.md", *(root / "docs").rglob("*.md")]:
    if "evidence" in path.parts:
        continue
    for link in re.findall(r"\]\(([^)]+)\)", path.read_text()):
        if "://" in link or link.startswith("#"):
            continue
        target = link.split("#", 1)[0]
        if target and not (path.parent / target).exists():
            errors.append(f"{path.relative_to(root)}: missing {target}")
matrix = (root / "docs/REQUIREMENTS.zh-CN.md").read_text()
adrs = sorted((root / "docs/adr").glob("[0-9][0-9][0-9][0-9]-*.md"))
numbers = [int(path.name[:4]) for path in adrs]
if numbers != list(range(1, len(adrs) + 1)):
    errors.append("ADRs: decision numbers must be unique and consecutive from 0001")
ids = re.findall(r"^\| ([A-Z]+-\d{2}) \|", matrix, re.MULTILINE)
if len(ids) != len(set(ids)) or len(ids) < 30:
    errors.append("traceability matrix: missing or duplicate requirements")
if errors:
    raise SystemExit("\n".join(errors))
print(f"Documentation links, {len(adrs)} ADRs and {len(ids)} requirement IDs checked")

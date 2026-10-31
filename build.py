"""Build graph data for the local Knowledge Galaxy viewer.

Usage: python build.py [notes_directory]
"""
from __future__ import annotations

import sys
from pathlib import Path

from knowledge import KnowledgeIndex

ROOT = Path(__file__).resolve().parent
NOTES_DIR = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "notes"
OUT = ROOT / "viewer" / "graph-data.js"


def main() -> None:
    if not NOTES_DIR.is_dir():
        raise SystemExit(f"Notes folder does not exist: {NOTES_DIR}")
    index = KnowledgeIndex(ROOT, ROOT / "notes", OUT)
    existing = [source for source in index.sources() if Path(source["path"]) == NOTES_DIR]
    if existing:
        result = index.scan_source(existing[0]["id"])
    else:
        source = index.add_source(str(NOTES_DIR), queue=False)
        result = index.scan_source(source["id"])
    print(f"Indexed {result['added']} added, {result['modified']} modified, {result['deleted']} deleted -> {OUT}")


if __name__ == "__main__":
    main()

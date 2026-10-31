"""Windows Operator 1.0 / Filesystem Explorer 1.0 — Secure tool broker."""
from __future__ import annotations

import fnmatch
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from knowledge import (
    KnowledgeIndex,
    TEXT_EXTENSIONS,
    SECRET_NAMES,
    SECRET_SUFFIXES,
    SKIP_DIRS,
    MAX_TEXT,
    is_reparse,
)


@dataclass
class ToolResult:
    success: bool
    data: Any = None
    error: str | None = None


class ToolBroker:
    MAX_FILE_SIZE = 10 * 1024 * 1024
    MAX_LIST_ENTRIES = 500
    MAX_SEARCH_RESULTS = 200
    MAX_INVENTORY_ENTRIES = 100_000
    INVENTORY_BATCH = 500

    OPEN_BLOCK_EXTENSIONS = {
        ".exe", ".bat", ".cmd", ".ps1", ".psm1", ".ps1xml", ".vbs", ".vbe",
        ".js", ".jse", ".jar", ".com", ".scr", ".pif", ".msi", ".dll", ".sys",
        ".reg", ".inf", ".wsf", ".wsh", ".hta", ".cpl", ".lnk", ".url",
    }
    OPEN_BLOCK_NAMES = {".env", "id_rsa", "id_dsa", "credentials.json", "secrets.json"}
    OPEN_BLOCK_SUFFIXES = {".pem", ".key", ".pfx", ".p12", ".kdbx"}

    PREVIEW_TEXT_EXTENSIONS = {
        ".md", ".txt", ".csv", ".json", ".html", ".htm", ".rtf", ".xml", ".log",
        ".ini", ".cfg", ".toml", ".yaml", ".yml", ".py",
    }
    PREVIEW_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".webp"}

    def __init__(self, index: KnowledgeIndex) -> None:
        self.index = index
        self.db = index.db
        self._scan_threads: dict[int, threading.Thread] = {}
        self._ensure_inventory_tables()
        self._ensure_action_log_table()

    # ------------------------------------------------------------------ schema
    def _ensure_inventory_tables(self) -> None:
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS inventory_roots (
              id INTEGER PRIMARY KEY, path TEXT UNIQUE NOT NULL,
              status TEXT NOT NULL DEFAULT 'idle', scanned INTEGER NOT NULL DEFAULT 0,
              entries INTEGER NOT NULL DEFAULT 0, cancelled INTEGER NOT NULL DEFAULT 0,
              created REAL NOT NULL, updated REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS inventory_items (
              id INTEGER PRIMARY KEY, root_id INTEGER NOT NULL, parent_id INTEGER,
              name TEXT NOT NULL, path TEXT NOT NULL UNIQUE, is_dir INTEGER NOT NULL DEFAULT 0,
              extension TEXT NOT NULL, size INTEGER NOT NULL, modified_ns INTEGER NOT NULL,
              depth INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(root_id) REFERENCES inventory_roots(id)
            );
            CREATE INDEX IF NOT EXISTS idx_inventory_items_root ON inventory_items(root_id);
            CREATE INDEX IF NOT EXISTS idx_inventory_items_parent ON inventory_items(parent_id);
        """)
        self.db.commit()

    def _ensure_action_log_table(self) -> None:
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS action_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                tool_name TEXT NOT NULL,
                arguments TEXT NOT NULL,
                result_summary TEXT NOT NULL,
                success INTEGER NOT NULL
            )
        """)
        self.db.commit()

    # --------------------------------------------------------------- helpers
    def _fail(self, tool_name: str, arguments: dict, error: str) -> ToolResult:
        result = ToolResult(False, error=error)
        self._log_action(tool_name, arguments, result)
        return result

    def _log_action(self, tool_name: str, arguments: dict, result: ToolResult) -> None:
        summary = "ok" if result.success else f"error: {result.error}"
        if result.success and result.data is not None:
            if isinstance(result.data, dict):
                summary += f" keys={list(result.data.keys())}"
            elif isinstance(result.data, list):
                summary += f" count={len(result.data)}"
        self.db.execute(
            "INSERT INTO action_log (timestamp, tool_name, arguments, result_summary, success) VALUES (?, ?, ?, ?, ?)",
            (time.time(), tool_name, json.dumps(arguments), summary, int(result.success)),
        )
        self.db.commit()

    def _resolve_within_approved(self, raw_path: str) -> Path | None:
        if not isinstance(raw_path, str) or not raw_path.strip():
            return None
        raw = Path(raw_path).expanduser()
        requested = Path(os.path.abspath(str(raw)))
        requested_key = os.path.normcase(str(requested))
        for root in self._all_approved_roots():
            root_key = os.path.normcase(str(root))
            if requested_key != root_key and not requested_key.startswith(root_key + os.sep):
                continue
            if self._has_reparse_component(requested, root):
                return None
            return requested
        return None

    def _has_reparse_component(self, path: Path, root: Path) -> bool:
        current = path
        while True:
            if is_reparse(current):
                return True
            if os.path.normcase(str(current)) == os.path.normcase(str(root)):
                return False
            parent = current.parent
            if parent == current:
                return False
            current = parent

    def _is_secret(self, path: Path) -> bool:
        return path.name.lower() in SECRET_NAMES or path.suffix.lower() in SECRET_SUFFIXES

    def _is_unsafe_open(self, path: Path) -> bool:
        if path.suffix.lower() in self.OPEN_BLOCK_EXTENSIONS:
            return True
        if path.name.lower() in self.OPEN_BLOCK_NAMES:
            return True
        if path.suffix.lower() in self.OPEN_BLOCK_SUFFIXES:
            return True
        return False

    def _validate_path(self, path: Path) -> str | None:
        if not path.exists():
            return "Path does not exist."
        if is_reparse(path):
            return "Symlinks and junctions are not permitted."
        path_text = str(path).lower()
        if any(part.lower() in SKIP_DIRS for part in path.parts):
            return "Path contains excluded system directory."
        if self._is_secret(path):
            return "Path matches an excluded credential or secret pattern."
        forbidden = [
            Path(os.environ.get("WINDIR", r"C:\Windows")),
            Path(r"C:\Program Files"),
            Path(r"C:\Program Files (x86)"),
            Path(r"C:\ProgramData"),
            Path.home() / "AppData",
        ]
        for item in forbidden:
            try:
                if path == item or path.is_relative_to(item):
                    return "Path is within a forbidden system directory."
            except ValueError:
                pass
        return None

    def _get_approved_roots(self) -> list[Path]:
        rows = self.db.execute(
            "SELECT path FROM sources WHERE status = 'ready'"
        ).fetchall()
        return [Path(os.path.abspath(row["path"])) for row in rows]

    def _inventory_root_paths(self) -> list[Path]:
        rows = self.db.execute("SELECT path FROM inventory_roots").fetchall()
        return [Path(os.path.abspath(row["path"])) for row in rows]

    def _all_approved_roots(self) -> list[Path]:
        seen = {}
        for root in self._get_approved_roots() + self._inventory_root_paths():
            seen[os.path.normcase(str(root))] = root
        return list(seen.values())

    # ------------------------------------------------------------- existing tools
    def list_dir(self, path: str, recursive: bool = False, max_depth: int = 1) -> ToolResult:
        args = {"path": path, "recursive": recursive, "max_depth": max_depth}
        resolved = self._resolve_within_approved(path)
        if resolved is None:
            return self._fail("list_dir", args, "Path is not within an approved source directory.")
        err = self._validate_path(resolved)
        if err:
            return self._fail("list_dir", args, err)
        if not resolved.is_dir():
            return self._fail("list_dir", args, "Path is not a directory.")
        if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 1:
            max_depth = 1
        max_depth = min(max_depth, 5)

        entries: list[dict] = []
        count = 0

        def walk(dir_path: Path, depth: int) -> None:
            nonlocal count
            if count >= self.MAX_LIST_ENTRIES:
                return
            try:
                with os.scandir(dir_path) as it:
                    for entry in it:
                        if count >= self.MAX_LIST_ENTRIES:
                            break
                        try:
                            p = Path(entry.path)
                            if is_reparse(p):
                                continue
                            if entry.name.lower() in SKIP_DIRS or self._is_secret(p):
                                continue
                            stat = entry.stat(follow_symlinks=False)
                            entries.append({
                                "name": entry.name,
                                "path": str(p),
                                "relative_path": p.relative_to(resolved).as_posix(),
                                "is_dir": entry.is_dir(follow_symlinks=False),
                                "size": stat.st_size if entry.is_file(follow_symlinks=False) else None,
                                "modified_ns": stat.st_mtime_ns,
                            })
                            count += 1
                            if recursive and depth < max_depth and entry.is_dir(follow_symlinks=False):
                                walk(p, depth + 1)
                        except OSError:
                            continue
            except OSError:
                pass

        walk(resolved, 0)
        result = ToolResult(True, data={"root": str(resolved), "entries": entries, "truncated": count >= self.MAX_LIST_ENTRIES})
        self._log_action("list_dir", args, result)
        return result

    def search_files(self, pattern: str, extensions: list[str] | None = None, source_id: int | None = None) -> ToolResult:
        args = {"pattern": pattern, "extensions": extensions, "source_id": source_id}
        if not isinstance(pattern, str) or not pattern.strip():
            return self._fail("search_files", args, "Pattern must be non-empty text.")
        if extensions is not None and (not isinstance(extensions, list) or not all(isinstance(item, str) for item in extensions)):
            return self._fail("search_files", args, "Extensions must be a list of text values.")
        if source_id is not None and (not isinstance(source_id, int) or isinstance(source_id, bool)):
            return self._fail("search_files", args, "Source ID must be a number.")

        roots: list[Path]
        if source_id is not None:
            row = self.db.execute("SELECT path FROM sources WHERE id = ? AND status = 'ready'", (source_id,)).fetchone()
            if not row:
                return self._fail("search_files", args, "Unknown or not-ready source.")
            roots = [Path(os.path.abspath(row["path"]))]
        else:
            roots = self._get_approved_roots()

        if not roots:
            return self._fail("search_files", args, "No approved sources available.")

        results: list[dict] = []
        ext_set = {e.lower() if e.startswith(".") else "." + e.lower() for e in extensions} if extensions else None

        for root in roots:
            if len(results) >= self.MAX_SEARCH_RESULTS:
                break
            stack = [root]
            while stack and len(results) < self.MAX_SEARCH_RESULTS:
                folder = stack.pop()
                try:
                    with os.scandir(folder) as it:
                        for entry in it:
                            if len(results) >= self.MAX_SEARCH_RESULTS:
                                break
                            try:
                                p = Path(entry.path)
                                if is_reparse(p):
                                    continue
                                if entry.is_dir(follow_symlinks=False):
                                    if entry.name.lower() not in SKIP_DIRS:
                                        stack.append(p)
                                elif entry.is_file(follow_symlinks=False):
                                    if self._is_secret(p):
                                        continue
                                    if ext_set and p.suffix.lower() not in ext_set:
                                        continue
                                    if fnmatch.fnmatch(entry.name.lower(), pattern.lower()):
                                        rel = p.relative_to(root).as_posix()
                                        stat = entry.stat(follow_symlinks=False)
                                        results.append({
                                            "name": entry.name,
                                            "path": str(p),
                                            "relative_path": rel,
                                            "size": stat.st_size,
                                            "modified_ns": stat.st_mtime_ns,
                                            "source_root": str(root),
                                        })
                            except OSError:
                                continue
                except OSError:
                    continue

        result = ToolResult(True, data={"pattern": pattern, "extensions": extensions, "results": results, "truncated": len(results) >= self.MAX_SEARCH_RESULTS})
        self._log_action("search_files", args, result)
        return result

    def read_file(self, path: str, max_bytes: int = MAX_TEXT) -> ToolResult:
        args = {"path": path, "max_bytes": max_bytes}
        resolved = self._resolve_within_approved(path)
        if resolved is None:
            return self._fail("read_file", args, "Path is not within an approved source directory.")
        err = self._validate_path(resolved)
        if err:
            return self._fail("read_file", args, err)
        if not resolved.is_file():
            return self._fail("read_file", args, "Path is not a file.")
        if resolved.suffix.lower() not in TEXT_EXTENSIONS:
            return self._fail("read_file", args, f"Unsupported file type. Allowed: {', '.join(sorted(TEXT_EXTENSIONS))}")
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
            return self._fail("read_file", args, "Max bytes must be a positive number.")
        if resolved.stat().st_size > self.MAX_FILE_SIZE:
            return self._fail("read_file", args, f"File exceeds maximum size of {self.MAX_FILE_SIZE} bytes.")

        max_bytes = min(max_bytes, MAX_TEXT)
        try:
            raw = resolved.read_bytes()[:max_bytes]
            text = raw.decode("utf-8", errors="replace")
            if resolved.suffix.lower() == ".csv":
                import csv
                text = "\n".join(" | ".join(row) for row in csv.reader(text.splitlines()))
            elif resolved.suffix.lower() == ".json":
                try:
                    text = json.dumps(json.loads(text), ensure_ascii=False, indent=2)
                except json.JSONDecodeError:
                    pass
            elif resolved.suffix.lower() in {".html", ".htm"}:
                from html.parser import HTMLParser
                class TextOnlyHTML(HTMLParser):
                    def __init__(self):
                        super().__init__()
                        self.parts = []
                    def handle_data(self, data):
                        self.parts.append(data)
                parser = TextOnlyHTML()
                parser.feed(text)
                text = "\n".join(parser.parts)
            result = ToolResult(True, data={"path": str(resolved), "size": len(raw), "content": text, "truncated": len(raw) == max_bytes})
        except OSError as e:
            return self._fail("read_file", args, f"Failed to read file: {e}")
        self._log_action("read_file", args, result)
        return result

    def get_file_info(self, path: str) -> ToolResult:
        args = {"path": path}
        resolved = self._resolve_within_approved(path)
        if resolved is None:
            return self._fail("get_file_info", args, "Path is not within an approved source directory.")
        err = self._validate_path(resolved)
        if err:
            return self._fail("get_file_info", args, err)
        if not resolved.exists():
            return self._fail("get_file_info", args, "Path does not exist.")

        try:
            stat = resolved.stat(follow_symlinks=False)
            info = {
                "path": str(resolved),
                "name": resolved.name,
                "is_dir": resolved.is_dir(),
                "is_file": resolved.is_file(),
                "size": stat.st_size if resolved.is_file() else None,
                "created_ns": stat.st_ctime_ns,
                "modified_ns": stat.st_mtime_ns,
                "accessed_ns": stat.st_atime_ns,
                "extension": resolved.suffix.lower(),
            }
            if resolved.is_file() and resolved.suffix.lower() in TEXT_EXTENSIONS:
                info["readable"] = True
            result = ToolResult(True, data=info)
        except OSError as e:
            return self._fail("get_file_info", args, f"Failed to stat file: {e}")
        self._log_action("get_file_info", args, result)
        return result

    def get_action_log(self, limit: int = 100) -> ToolResult:
        rows = self.db.execute(
            "SELECT id, timestamp, tool_name, arguments, result_summary, success FROM action_log ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return ToolResult(True, data=[dict(row) for row in rows])

    # ------------------------------------------------------------- inventory
    def add_inventory_root(self, path: str) -> ToolResult:
        args = {"path": path}
        try:
            validated = self.index.validate_source(path)
        except ValueError as error:
            return self._fail("add_inventory_root", args, str(error))
        key = os.path.normcase(str(validated))
        existing = self.db.execute("SELECT id FROM inventory_roots WHERE path = ?", (str(validated),)).fetchone()
        if existing:
            return ToolResult(True, data={"id": existing[0], "path": str(validated), "status": "exists"})
        now = time.time()
        self.db.execute(
            "INSERT INTO inventory_roots(path, status, scanned, entries, cancelled, created, updated) VALUES(?, 'idle', 0, 0, 0, ?, ?)",
            (str(validated), now, now),
        )
        root_id = self.db.execute("SELECT last_insert_rowid()").fetchone()[0]
        self.db.commit()
        result = ToolResult(True, data={"id": root_id, "path": str(validated), "status": "idle"})
        self._log_action("add_inventory_root", args, result)
        return result

    def inventory_roots(self) -> ToolResult:
        rows = self.db.execute("SELECT * FROM inventory_roots ORDER BY id").fetchall()
        return ToolResult(True, data=[dict(row) for row in rows])

    def scan_inventory(self, root_id: int) -> ToolResult:
        args = {"root_id": root_id}
        row = self.db.execute("SELECT * FROM inventory_roots WHERE id = ?", (root_id,)).fetchone()
        if not row:
            return self._fail("scan_inventory", args, "Unknown inventory root.")
        if root_id in self._scan_threads and self._scan_threads[root_id].is_alive():
            return ToolResult(False, error="Inventory scan already running for this root.")
        self.db.execute(
            "UPDATE inventory_roots SET status='scanning', scanned=0, entries=0, cancelled=0, updated=? WHERE id=?",
            (time.time(), root_id),
        )
        self.db.commit()
        thread = threading.Thread(target=self._scan_inventory_worker, args=(root_id,), daemon=True)
        self._scan_threads[root_id] = thread
        thread.start()
        return ToolResult(True, data={"id": root_id, "status": "scanning"})

    def cancel_inventory(self, root_id: int) -> ToolResult:
        args = {"root_id": root_id}
        row = self.db.execute("SELECT * FROM inventory_roots WHERE id = ?", (root_id,)).fetchone()
        if not row:
            return self._fail("cancel_inventory", args, "Unknown inventory root.")
        self.db.execute("UPDATE inventory_roots SET cancelled=1, updated=? WHERE id=?", (time.time(), root_id))
        self.db.commit()
        return ToolResult(True, data={"id": root_id, "cancelled": True})

    def inventory_progress(self, root_id: int) -> ToolResult:
        row = self.db.execute("SELECT * FROM inventory_roots WHERE id = ?", (root_id,)).fetchone()
        if not row:
            return self._fail("inventory_progress", args={"root_id": root_id}, error="Unknown inventory root.")
        return ToolResult(True, data=dict(row))

    def inventory_tree(self, root_id: int) -> ToolResult:
        args = {"root_id": root_id}
        row = self.db.execute("SELECT * FROM inventory_roots WHERE id = ?", (root_id,)).fetchone()
        if not row:
            return self._fail("inventory_tree", args, "Unknown inventory root.")
        items = [dict(row) for row in self.db.execute(
            "SELECT id, parent_id, name, path, is_dir, extension, size, modified_ns, depth FROM inventory_items WHERE root_id=? ORDER BY depth, name",
            (root_id,)
        ).fetchall()]
        by_id = {item["id"]: item for item in items}
        roots = []
        links = []
        for item in items:
            item["children"] = []
            if item["parent_id"] is None:
                roots.append(item)
            else:
                parent = by_id.get(item["parent_id"])
                if parent is not None:
                    parent["children"].append(item)
                    links.append({"source": item["parent_id"], "target": item["id"]})
        result = ToolResult(True, data={"root": dict(row), "roots": roots, "links": links, "total": len(items)})
        self._log_action("inventory_tree", args, result)
        return result

    def inventory_search(self, root_id: int, name: str) -> ToolResult:
        args = {"root_id": root_id, "name": name}
        row = self.db.execute("SELECT * FROM inventory_roots WHERE id = ?", (root_id,)).fetchone()
        if not row:
            return self._fail("inventory_search", args, "Unknown inventory root.")
        like = f"%{name.lower()}%"
        items = self.db.execute(
            "SELECT id, parent_id, name, path, is_dir, extension, size, modified_ns, depth FROM inventory_items WHERE root_id=? AND lower(name) LIKE ? ORDER BY is_dir DESC, name LIMIT 200",
            (root_id, like)
        ).fetchall()
        result = ToolResult(True, data={"root_id": root_id, "name": name, "matches": [dict(i) for i in items]})
        self._log_action("inventory_search", args, result)
        return result

    def _scan_inventory_worker(self, root_id: int) -> None:
        try:
            row = self.db.execute("SELECT path FROM inventory_roots WHERE id = ?", (root_id,)).fetchone()
            if not row:
                return
            root_path = Path(row["path"])
            scanned = 0
            entries = 0
            batch: list[tuple] = []
            depth_cache: dict[str, int] = {str(root_path): 0}
            parent_cache: dict[str, int | None] = {}

            def mark() -> None:
                nonlocal scanned, entries
                scanned += 1
                if scanned % 10 == 0:
                    self.db.execute(
                        "UPDATE inventory_roots SET scanned=?, updated=? WHERE id=?",
                        (scanned, time.time(), root_id),
                    )
                    self.db.commit()

            def cancelled() -> bool:
                r = self.db.execute("SELECT cancelled FROM inventory_roots WHERE id = ?", (root_id,)).fetchone()
                return bool(r and r["cancelled"])

            # insert root folder itself
            stat = root_path.stat(follow_symlinks=False)
            self.db.execute(
                "INSERT OR REPLACE INTO inventory_items(root_id, parent_id, name, path, is_dir, extension, size, modified_ns, depth) VALUES(?, NULL, ?, ?, 1, '', ?, ?, 0)",
                (root_id, root_path.name, str(root_path), stat.st_size, stat.st_mtime_ns),
            )
            self.db.commit()
            root_item_id = self.db.execute("SELECT last_insert_rowid()").fetchone()[0]
            parent_cache[str(root_path)] = root_item_id
            entries = 1

            stack = [root_path]
            while stack and entries < self.MAX_INVENTORY_ENTRIES and not cancelled():
                folder = stack.pop()
                try:
                    entries_in_dir = list(os.scandir(folder))
                except OSError:
                    continue
                for entry in entries_in_dir:
                    if entries >= self.MAX_INVENTORY_ENTRIES or cancelled():
                        break
                    try:
                        p = Path(entry.path)
                        if is_reparse(p):
                            continue
                        name_l = entry.name.lower()
                        if name_l in SKIP_DIRS or self._is_secret(p):
                            continue
                        stat = entry.stat(follow_symlinks=False)
                        is_dir = entry.is_dir(follow_symlinks=False)
                        depth = depth_cache.get(str(folder), 0) + 1
                        parent_id = parent_cache.get(str(folder))
                        self.db.execute(
                            "INSERT OR IGNORE INTO inventory_items(root_id, parent_id, name, path, is_dir, extension, size, modified_ns, depth) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (root_id, parent_id, entry.name, str(p), int(is_dir), p.suffix.lower(), stat.st_size, stat.st_mtime_ns, depth),
                        )
                        depth_cache[str(p)] = depth
                        if is_dir:
                            stack.append(p)
                        parent_cache[str(p)] = self.db.execute("SELECT last_insert_rowid()").fetchone()[0]
                        entries += 1
                        scanned += 1
                        if scanned % 50 == 0:
                            self.db.execute(
                                "UPDATE inventory_roots SET scanned=?, entries=?, updated=? WHERE id=?",
                                (scanned, entries, time.time(), root_id),
                            )
                            self.db.commit()
                    except OSError:
                        continue
            status = "cancelled" if cancelled() else "done"
            self.db.execute(
                "UPDATE inventory_roots SET status=?, scanned=?, entries=?, updated=? WHERE id=?",
                (status, scanned, entries, time.time(), root_id),
            )
            self.db.commit()
        except Exception as error:  # noqa: BLE001
            self.db.execute(
                "UPDATE inventory_roots SET status='error', updated=? WHERE id=?",
                (time.time(), root_id),
            )
            self.db.commit()

    # ------------------------------------------------------------- open file
    def open_file(self, path: str | None = None, name: str | None = None, root_id: int | None = None) -> ToolResult:
        args = {"path": path, "name": name, "root_id": root_id}
        target: Path | None = None

        if path:
            resolved = self._resolve_within_approved(path)
            if resolved is None:
                return self._fail("open_file", args, "Path is not within an approved source directory.")
            err = self._validate_path(resolved)
            if err:
                return self._fail("open_file", args, err)
            if not resolved.is_file():
                return self._fail("open_file", args, "Path is not a file.")
            if self._is_unsafe_open(resolved):
                return self._fail("open_file", args, "File type is not safe to open.")
            target = resolved
        elif name:
            roots: list[Path]
            if root_id is not None:
                row = self.db.execute("SELECT path FROM inventory_roots WHERE id = ? AND status IN ('done','idle')", (root_id,)).fetchone()
                if not row:
                    return self._fail("open_file", args, "Unknown or not-ready inventory root.")
                roots = [Path(os.path.abspath(row["path"]))]
            else:
                roots = self._get_approved_roots()
            candidates: list[dict] = []
            name_l = name.lower()
            for root in roots:
                if len(candidates) >= 20:
                    break
                for item in self.db.execute(
                    "SELECT id, name, path, is_dir, extension, size FROM inventory_items WHERE root_id IN (SELECT id FROM inventory_roots WHERE path=? OR path LIKE ?) AND lower(name)=? AND is_dir=0",
                    (str(root), f"{str(root)}/%", name_l)
                ).fetchall():
                    candidates.append(dict(item))
            if not candidates:
                return self._fail("open_file", args, f"No document named '{name}' found in approved folders.")
            if len(candidates) > 1:
                return ToolResult(False, error="ambiguous", data={"ambiguous": True, "candidates": candidates})
            target = Path(candidates[0]["path"])
        else:
            return self._fail("open_file", args, "Provide either 'path' or 'name'.")

        if target is None or not target.is_file():
            return self._fail("open_file", args, "File not found.")
        if self._is_unsafe_open(target):
            return self._fail("open_file", args, "File type is not safe to open.")

        try:
            os.startfile(str(target))  # type: ignore[attr-defined]
        except OSError as e:
            return self._fail("open_file", args, f"Failed to open file: {e}")
        result = ToolResult(True, data={"path": str(target), "name": target.name, "opened": True})
        self._log_action("open_file", args, result)
        return result

    def preview_file(self, path: str, max_chars: int = 4000) -> ToolResult:
        args = {"path": path, "max_chars": max_chars}
        resolved = self._resolve_within_approved(path)
        if resolved is None:
            return self._fail("preview_file", args, "Path is not within an approved source directory.")
        err = self._validate_path(resolved)
        if err:
            return self._fail("preview_file", args, err)
        if not resolved.is_file():
            return self._fail("preview_file", args, "Path is not a file.")
        if self._is_unsafe_open(resolved):
            return self._fail("preview_file", args, "File type is not safe to preview.")
        ext = resolved.suffix.lower()
        is_image = ext in self.PREVIEW_IMAGE_EXTENSIONS
        is_text = ext in self.PREVIEW_TEXT_EXTENSIONS or ext in TEXT_EXTENSIONS
        data: dict = {"path": str(resolved), "name": resolved.name, "extension": ext, "is_image": is_image, "is_text": is_text}
        if is_image:
            data["kind"] = "image"
        elif is_text:
            try:
                raw = resolved.read_bytes()[: max(1, min(max_chars, MAX_TEXT))]
                text = raw.decode("utf-8", errors="replace")
                data["kind"] = "text"
                data["content"] = text
                data["truncated"] = len(raw) == max(1, min(max_chars, MAX_TEXT))
            except OSError as e:
                return self._fail("preview_file", args, f"Failed to preview file: {e}")
        else:
            data["kind"] = "binary"
            data["content"] = None
        result = ToolResult(True, data=data)
        self._log_action("preview_file", args, result)
        return result


TOOL_SCHEMAS = {
    "list_dir": {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": "List directory contents within approved sources.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path to list (must be within an approved source)."},
                    "recursive": {"type": "boolean", "default": False, "description": "Recurse into subdirectories."},
                    "max_depth": {"type": "integer", "default": 1, "description": "Maximum recursion depth."},
                },
                "required": ["path"],
            },
        },
    },
    "search_files": {
        "type": "function",
        "function": {
            "name": "search_files",
            "description": "Search for files by name pattern and optional extension filter within approved sources.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Glob pattern to match filenames (e.g., '*.md', 'report*')."},
                    "extensions": {"type": "array", "items": {"type": "string"}, "description": "Optional list of extensions to filter (e.g., ['.md', '.txt'])."},
                    "source_id": {"type": "integer", "description": "Optional source ID to limit search to a specific approved source."},
                },
                "required": ["pattern"],
            },
        },
    },
    "read_file": {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a text file from an approved source. Returns content with appropriate extraction for CSV, JSON, HTML.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to read (must be within an approved source)."},
                    "max_bytes": {"type": "integer", "default": 100000, "description": "Maximum bytes to read (max 100000)."},
                },
                "required": ["path"],
            },
        },
    },
    "get_file_info": {
        "type": "function",
        "function": {
            "name": "get_file_info",
            "description": "Get file metadata (size, timestamps, type) for a path within approved sources.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File or directory path (must be within an approved source)."},
                },
                "required": ["path"],
            },
        },
    },
    "get_action_log": {
        "type": "function",
        "function": {
            "name": "get_action_log",
            "description": "Retrieve recent tool action log entries for auditing.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 100, "description": "Maximum number of log entries to return."},
                },
            },
        },
    },
    "add_inventory_root": {
        "type": "function",
        "function": {
            "name": "add_inventory_root",
            "description": "Approve a folder for filesystem inventory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Folder path to approve for inventory (e.g. C:\\Users\\Utkarsh Tiwari)."},
                },
                "required": ["path"],
            },
        },
    },
    "inventory_roots": {
        "type": "function",
        "function": {
            "name": "inventory_roots",
            "description": "List approved inventory roots and their scan status.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    "scan_inventory": {
        "type": "function",
        "function": {
            "name": "scan_inventory",
            "description": "Start an asynchronous metadata inventory scan of an approved root.",
            "parameters": {
                "type": "object",
                "properties": {
                    "root_id": {"type": "integer", "description": "Inventory root ID to scan."},
                },
                "required": ["root_id"],
            },
        },
    },
    "cancel_inventory": {
        "type": "function",
        "function": {
            "name": "cancel_inventory",
            "description": "Cancel a running inventory scan.",
            "parameters": {
                "type": "object",
                "properties": {
                    "root_id": {"type": "integer", "description": "Inventory root ID whose scan should be cancelled."},
                },
                "required": ["root_id"],
            },
        },
    },
    "inventory_progress": {
        "type": "function",
        "function": {
            "name": "inventory_progress",
            "description": "Get progress of an inventory scan.",
            "parameters": {
                "type": "object",
                "properties": {
                    "root_id": {"type": "integer", "description": "Inventory root ID."},
                },
                "required": ["root_id"],
            },
        },
    },
    "inventory_tree": {
        "type": "function",
        "function": {
            "name": "inventory_tree",
            "description": "Get the hierarchical inventory tree for a root (drives → folders → files).",
            "parameters": {
                "type": "object",
                "properties": {
                    "root_id": {"type": "integer", "description": "Inventory root ID."},
                },
                "required": ["root_id"],
            },
        },
    },
    "inventory_search": {
        "type": "function",
        "function": {
            "name": "inventory_search",
            "description": "Search inventory items by name within a root.",
            "parameters": {
                "type": "object",
                "properties": {
                    "root_id": {"type": "integer", "description": "Inventory root ID."},
                    "name": {"type": "string", "description": "Name substring to match."},
                },
                "required": ["root_id", "name"],
            },
        },
    },
    "open_file": {
        "type": "function",
        "function": {
            "name": "open_file",
            "description": "Open an approved document with its default Windows application (read-only).",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Full file path to open (must be within an approved source)."},
                    "name": {"type": "string", "description": "Bare filename to locate in approved inventory roots."},
                    "root_id": {"type": "integer", "description": "Optional inventory root ID to scope a name search."},
                },
            },
        },
    },
    "preview_file": {
        "type": "function",
        "function": {
            "name": "preview_file",
            "description": "Preview a supported document (text or image) without opening it externally.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to preview (must be within an approved source)."},
                    "max_chars": {"type": "integer", "default": 4000, "description": "Maximum characters to preview for text."},
                },
                "required": ["path"],
            },
        },
    },
}


def validate_tool_arguments(tool_name: str, arguments: Any) -> dict:
    """Validate a structured tool call without executing model-generated code."""
    if tool_name not in TOOL_SCHEMAS:
        raise ValueError(f"Unknown tool: {tool_name}")
    if not isinstance(arguments, dict):
        raise ValueError("Arguments must be a JSON object.")
    schema = TOOL_SCHEMAS[tool_name]["function"]["parameters"]
    properties = schema.get("properties", {})
    extra = set(arguments) - set(properties)
    if extra:
        raise ValueError(f"Unexpected argument(s): {', '.join(sorted(extra))}.")
    for required in schema.get("required", []):
        if required not in arguments:
            raise ValueError(f"Missing required argument: {required}.")
    for name, value in arguments.items():
        expected = properties[name].get("type")
        if expected == "string":
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"Argument '{name}' must be non-empty text.")
        elif expected == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"Argument '{name}' must be an integer.")
        elif expected == "boolean":
            if not isinstance(value, bool):
                raise ValueError(f"Argument '{name}' must be true or false.")
        elif expected == "array":
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError(f"Argument '{name}' must be a list of text values.")
    return arguments

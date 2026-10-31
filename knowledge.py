"""Persistent, opt-in source registry and incremental text index for JARVIS."""
from __future__ import annotations

import csv
import fnmatch
import hashlib
import html.parser
import json
import os
import re
import shutil
import sqlite3
import threading
import time
from pathlib import Path


TEXT_EXTENSIONS = {".md", ".txt", ".csv", ".json", ".html", ".htm"}
SECRET_NAMES = {".env", "id_rsa", "id_dsa", "credentials.json", "secrets.json"}
SECRET_SUFFIXES = {".pem", ".key", ".pfx", ".p12", ".kdbx"}
SKIP_DIRS = {"appdata", ".ssh", ".gnupg", ".aws", ".azure", ".config", ".codex", ".agents", ".claude", ".copilot", ".gemini", ".ollama", "node_modules", ".git", "windows", "program files", "program files (x86)", "programdata", "recovery", "system volume information"}
WORD = re.compile(r"[a-z0-9]+")
WIKILINK = re.compile(r"\[\[([^\]|#]+)(?:#[^\]|]+)?(?:\|[^\]]+)?\]\]")
MAX_TEXT = 100_000


class TextOnlyHTML(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def words(value: str) -> set[str]:
    return set(WORD.findall(value.lower()))


def title_key(value: str) -> str:
    return " ".join(WORD.findall(value.lower()))


def compact(value: str, limit: int = 700) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    return value if len(value) <= limit else value[:limit - 1].rstrip() + "…"


def is_reparse(path: Path) -> bool:
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except (AttributeError, OSError):
        return path.is_symlink()
    return path.is_symlink() or bool(attributes & 0x400)


class KnowledgeIndex:
    def __init__(self, root: Path, notes_dir: Path, graph_path: Path) -> None:
        self.root = root.resolve()
        self.notes_dir = notes_dir.resolve()
        self.graph_path = graph_path.resolve()
        self.db_path = self.root / "knowledge.sqlite3"
        self.backup_path = self.graph_path.with_suffix(self.graph_path.suffix + ".pre-brain-2.0.bak")
        self.lock = threading.RLock()
        self.graph = self._read_graph()
        fresh = not self.db_path.exists()
        if fresh and self.graph_path.exists() and not self.backup_path.exists():
            shutil.copy2(self.graph_path, self.backup_path)
        self.db = sqlite3.connect(self.db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._schema()
        self._ensure_builtin_source()
        self._restore_legacy_view_order()

    def _read_graph(self) -> dict:
        raw = self.graph_path.read_text(encoding="utf-8")
        return json.loads(raw.removeprefix("const GRAPH = ").rstrip(";\n"))

    def _schema(self) -> None:
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS sources (
              id INTEGER PRIMARY KEY, path TEXT UNIQUE NOT NULL, include_rules TEXT NOT NULL,
              exclude_rules TEXT NOT NULL, built_in INTEGER NOT NULL DEFAULT 0,
              status TEXT NOT NULL DEFAULT 'ready', last_scan REAL, last_error TEXT
            );
            CREATE TABLE IF NOT EXISTS files (
              id INTEGER PRIMARY KEY, source_id INTEGER NOT NULL, relative_path TEXT NOT NULL,
              normalized_path TEXT UNIQUE NOT NULL, mtime_ns INTEGER NOT NULL, size INTEGER NOT NULL,
              sha256 TEXT NOT NULL, content TEXT NOT NULL, label TEXT NOT NULL, group_name TEXT NOT NULL,
              extension TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, view_order INTEGER NOT NULL,
              UNIQUE(source_id, relative_path), FOREIGN KEY(source_id) REFERENCES sources(id)
            );
            CREATE TABLE IF NOT EXISTS links (
              file_a INTEGER NOT NULL, file_b INTEGER NOT NULL,
              PRIMARY KEY(file_a, file_b), FOREIGN KEY(file_a) REFERENCES files(id),
              FOREIGN KEY(file_b) REFERENCES files(id)
            );
        """)
        self.db.commit()

    def _ensure_builtin_source(self) -> None:
        row = self.db.execute("SELECT id FROM sources WHERE path = ?", (str(self.notes_dir),)).fetchone()
        if row is None:
            self.db.execute(
                "INSERT INTO sources(path, include_rules, exclude_rules, built_in) VALUES(?,?,?,1)",
                (str(self.notes_dir), json.dumps(["*"]), json.dumps([])),
            )
            self.db.commit()
            self.scan_source(self.db.execute("SELECT id FROM sources WHERE path = ?", (str(self.notes_dir),)).fetchone()[0])

    def _restore_legacy_view_order(self) -> None:
        """Keep the original graph's index IDs stable while manifest IDs stay immutable."""
        if not self.backup_path.exists():
            return
        try:
            legacy = json.loads(self.backup_path.read_text(encoding="utf-8").removeprefix("const GRAPH = ").rstrip(";\n"))
        except (OSError, json.JSONDecodeError):
            return
        order = {node["path"]: node["id"] for node in legacy.get("nodes", [])}
        source = self.db.execute("SELECT id FROM sources WHERE built_in=1 ORDER BY id LIMIT 1").fetchone()
        if source is None:
            return
        rows = self.db.execute("SELECT id, relative_path, view_order FROM files WHERE source_id=?", (source[0],)).fetchall()
        changed = False
        for row in rows:
            if row["relative_path"] in order and row["view_order"] != order[row["relative_path"]]:
                self.db.execute("UPDATE files SET view_order=? WHERE id=?", (order[row["relative_path"]], row["id"])); changed = True
        if changed:
            self.db.commit()
            self.publish()

    def _forbidden(self, path: Path) -> bool:
        forbidden = [Path(os.environ.get("WINDIR", r"C:\Windows")), Path(r"C:\Program Files"), Path(r"C:\Program Files (x86)"), Path(r"C:\ProgramData"), Path.home() / "AppData"]
        path_text = str(path).lower()
        if any(part.lower() in SKIP_DIRS for part in path.parts):
            return True
        return any(path_text == str(item).lower() or path_text.startswith(str(item).lower() + os.sep) for item in forbidden)

    def validate_source(self, raw_path: str) -> Path:
        if not raw_path or len(raw_path) > 2000:
            raise ValueError("Please provide one folder path.")
        path = Path(raw_path).expanduser().resolve(strict=True)
        if not path.is_dir() or path.parent == path or is_reparse(path):
            raise ValueError("That folder is not an indexable directory.")
        if self._forbidden(path):
            raise ValueError("That folder is excluded for privacy and system safety.")
        return path

    def add_source(self, raw_path: str, includes: list[str] | None = None, excludes: list[str] | None = None, queue: bool = True) -> dict:
        path = self.validate_source(raw_path)
        with self.lock:
            row = self.db.execute("SELECT id FROM sources WHERE path = ?", (str(path),)).fetchone()
            if row:
                raise ValueError("That folder has already been approved.")
            self.db.execute(
                "INSERT INTO sources(path, include_rules, exclude_rules, status) VALUES(?,?,?, 'queued')",
                (str(path), json.dumps(includes or ["*"]), json.dumps(excludes or [])),
            )
            source_id = self.db.execute("SELECT last_insert_rowid()").fetchone()[0]
            self.db.commit()
        if queue:
            self.start_scan(source_id)
        return self.source(source_id)

    def remove_source(self, source_id: int) -> None:
        with self.lock:
            source = self.db.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
            if source is None:
                raise ValueError("Unknown source.")
            if source["built_in"]:
                raise ValueError("The existing JARVIS notes source cannot be removed.")
            affected = [row[0] for row in self.db.execute("SELECT id FROM files WHERE source_id = ? AND active = 1", (source_id,))]
            self.db.execute("DELETE FROM links WHERE file_a IN (SELECT id FROM files WHERE source_id = ?) OR file_b IN (SELECT id FROM files WHERE source_id = ?)", (source_id, source_id))
            self.db.execute("DELETE FROM files WHERE source_id = ?", (source_id,))
            self.db.execute("DELETE FROM sources WHERE id = ?", (source_id,))
            self.db.commit()
            self.publish()

    def source(self, source_id: int) -> dict:
        row = self.db.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
        return self._source_dict(row)

    def sources(self) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT * FROM sources ORDER BY built_in DESC, id").fetchall()
            return [self._source_dict(row) for row in rows]

    def _source_dict(self, row: sqlite3.Row) -> dict:
        count = self.db.execute("SELECT COUNT(*) FROM files WHERE source_id = ? AND active = 1", (row["id"],)).fetchone()[0]
        return {"id": row["id"], "path": row["path"], "includes": json.loads(row["include_rules"]), "excludes": json.loads(row["exclude_rules"]), "built_in": bool(row["built_in"]), "status": row["status"], "last_scan": row["last_scan"], "error": row["last_error"], "files": count}

    def _allowed_file(self, path: Path, relative: str, includes: list[str], excludes: list[str]) -> bool:
        lower = path.name.lower()
        if path.suffix.lower() not in TEXT_EXTENSIONS or lower in SECRET_NAMES or path.suffix.lower() in SECRET_SUFFIXES:
            return False
        if any(fnmatch.fnmatch(relative.lower(), rule.lower()) for rule in excludes):
            return False
        return any(fnmatch.fnmatch(relative.lower(), rule.lower()) for rule in includes)

    def _discover(self, root: Path, includes: list[str], excludes: list[str]):
        stack = [root]
        while stack:
            folder = stack.pop()
            try:
                entries = list(os.scandir(folder))
            except OSError:
                continue
            for entry in entries:
                path = Path(entry.path)
                try:
                    if entry.is_symlink() or is_reparse(path):
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name.lower() not in SKIP_DIRS:
                            stack.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        relative = path.relative_to(root).as_posix()
                        if self._allowed_file(path, relative, includes, excludes):
                            yield path, relative
                except OSError:
                    continue

    def _extract(self, path: Path) -> str:
        raw = path.read_bytes()[:MAX_TEXT]
        text = raw.decode("utf-8", errors="replace")
        if path.suffix.lower() == ".csv":
            return "\n".join(" | ".join(row) for row in csv.reader(text.splitlines()))
        if path.suffix.lower() == ".json":
            try:
                return json.dumps(json.loads(text), ensure_ascii=False, indent=2)
            except json.JSONDecodeError:
                return text
        if path.suffix.lower() in {".html", ".htm"}:
            parser = TextOnlyHTML()
            parser.feed(text)
            return "\n".join(parser.parts)
        return text

    def _next_order(self) -> int:
        return self.db.execute("SELECT COALESCE(MAX(view_order), -1) + 1 FROM files").fetchone()[0]

    def scan_source(self, source_id: int) -> dict:
        started = time.perf_counter()
        with self.lock:
            source = self.db.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
            if source is None:
                raise ValueError("Unknown source.")
            root = Path(source["path"])
            includes, excludes = json.loads(source["include_rules"]), json.loads(source["exclude_rules"])
            self.db.execute("UPDATE sources SET status='scanning', last_error=NULL WHERE id=?", (source_id,))
            self.db.commit()
        seen: set[str] = set()
        changed: set[int] = set()
        added = modified = 0
        with self.lock:
            existing = {row["relative_path"]: row for row in self.db.execute("SELECT * FROM files WHERE source_id = ?", (source_id,))}
        for path, relative in self._discover(root, includes, excludes):
            stat = path.stat(follow_symlinks=False)
            seen.add(relative)
            row = existing.get(relative)
            if row and row["active"] and row["mtime_ns"] == stat.st_mtime_ns and row["size"] == stat.st_size:
                continue
            content = self._extract(path)
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            label = path.stem
            group = Path(relative).parent.name if Path(relative).parent != Path(".") else root.name
            with self.lock:
                if row:
                    self.db.execute("UPDATE files SET mtime_ns=?, size=?, sha256=?, content=?, label=?, group_name=?, extension=?, active=1 WHERE id=?", (stat.st_mtime_ns, stat.st_size, digest, content, label, group, path.suffix.lower(), row["id"]))
                    changed.add(row["id"]); modified += 1
                else:
                    order = self._next_order()
                    self.db.execute("INSERT INTO files(source_id, relative_path, normalized_path, mtime_ns, size, sha256, content, label, group_name, extension, view_order) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (source_id, relative, str(path.resolve()), stat.st_mtime_ns, stat.st_size, digest, content, label, group, path.suffix.lower(), order))
                    file_id = self.db.execute("SELECT last_insert_rowid()").fetchone()[0]
                    changed.add(file_id); added += 1
        with self.lock:
            for relative, row in existing.items():
                if row["active"] and relative not in seen:
                    self.db.execute("UPDATE files SET active=0 WHERE id=?", (row["id"],))
                    changed.add(row["id"])
            deleted = len([file_id for file_id in changed if file_id in {row["id"] for relative, row in existing.items() if relative not in seen}])
            if changed:
                self._refresh_links(changed)
                self.publish()
            self.db.execute("UPDATE sources SET status='ready', last_scan=?, last_error=NULL WHERE id=?", (time.time(), source_id))
            self.db.commit()
        return {"source": source_id, "added": added, "modified": modified, "deleted": deleted, "seconds": round(time.perf_counter() - started, 3), "graph": self.graph}

    def _linked(self, first: sqlite3.Row, second: sqlite3.Row) -> bool:
        first_title, second_title = title_key(first["label"]), title_key(second["label"])
        first_text, second_text = first["content"].lower(), second["content"].lower()
        first_links = {title_key(value) for value in WIKILINK.findall(first["content"])}
        second_links = {title_key(value) for value in WIKILINK.findall(second["content"])}
        return (len(second_title) > 1 and second_title in first_text) or (len(first_title) > 1 and first_title in second_text) or bool(first_links & second_links) or first_title in second_links or second_title in first_links

    def _refresh_links(self, changed: set[int]) -> None:
        marks = tuple(changed)
        placeholders = ",".join("?" for _ in marks)
        self.db.execute(f"DELETE FROM links WHERE file_a IN ({placeholders}) OR file_b IN ({placeholders})", (*marks, *marks))
        active = self.db.execute("SELECT * FROM files WHERE active=1").fetchall()
        by_id = {row["id"]: row for row in active}
        for first_id in changed:
            first = by_id.get(first_id)
            if first is None:
                continue
            for second in active:
                if first_id == second["id"] or not self._linked(first, second):
                    continue
                a, b = sorted((first_id, second["id"]))
                self.db.execute("INSERT OR IGNORE INTO links(file_a, file_b) VALUES(?,?)", (a, b))

    def publish(self) -> None:
        rows = self.db.execute("SELECT * FROM files WHERE active=1 ORDER BY view_order").fetchall()
        index = {row["id"]: position for position, row in enumerate(rows)}
        nodes = [{"id": position, "stable_id": row["id"], "label": row["label"], "group": row["group_name"], "excerpt": compact(row["content"]), "path": row["relative_path"], "source_path": row["normalized_path"]} for position, row in enumerate(rows)]
        links = [{"source": index[row["file_a"]], "target": index[row["file_b"]]} for row in self.db.execute("SELECT file_a, file_b FROM links") if row["file_a"] in index and row["file_b"] in index]
        updated = {"nodes": nodes, "links": links}
        temp = self.graph_path.with_suffix(".js.tmp")
        temp.write_text("const GRAPH = " + json.dumps(updated, ensure_ascii=False) + ";\n", encoding="utf-8")
        temp.replace(self.graph_path)
        self.graph.clear(); self.graph.update(updated)

    def start_scan(self, source_id: int | None = None) -> None:
        def work() -> None:
            ids = [source_id] if source_id is not None else [row["id"] for row in self.db.execute("SELECT id FROM sources")]
            for current in ids:
                try:
                    self.scan_source(current)
                except Exception as error:
                    with self.lock:
                        self.db.execute("UPDATE sources SET status='error', last_error=? WHERE id=?", (str(error), current)); self.db.commit()
        threading.Thread(target=work, daemon=True).start()

    def graph_data(self) -> dict:
        with self.lock:
            return {"nodes": list(self.graph["nodes"]), "links": list(self.graph["links"])}

    def builtin_source_id(self) -> int:
        return self.db.execute("SELECT id FROM sources WHERE built_in=1 ORDER BY id LIMIT 1").fetchone()[0]

    def sources_for_nodes(self, node_ids: list[int]) -> list[dict]:
        with self.lock:
            nodes = self.graph["nodes"]
            return [{"node": node_id, "filename": Path(nodes[node_id]["path"]).name, "path": nodes[node_id].get("source_path", nodes[node_id]["path"])} for node_id in node_ids if isinstance(node_id, int) and 0 <= node_id < len(nodes)]

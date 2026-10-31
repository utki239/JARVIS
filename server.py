"""A deliberately small, local-only server for Knowledge Galaxy."""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import date
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse, parse_qs

from knowledge import KnowledgeIndex
from tools import ToolBroker, TOOL_SCHEMAS, validate_tool_arguments
from voice import VoiceError, VoiceStudio


ROOT = Path(__file__).resolve().parent
VIEWER = ROOT / "viewer"
CONFIG = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
NOTES_DIR = (ROOT / CONFIG.get("notes_dir", "notes")).resolve()
CAPTURES_DIR = (NOTES_DIR / "captures").resolve()
GRAPH_DATA = VIEWER / "graph-data.js"
INDEX = KnowledgeIndex(ROOT, NOTES_DIR, GRAPH_DATA)
BROKER = ToolBroker(INDEX)
VOICE = VoiceStudio(CONFIG.get("voice"), ROOT / "voice_cache")
GRAPH = INDEX.graph
GRAPH_LOCK = INDEX.lock
HISTORY: list[dict[str, str]] = []
TOKENS = re.compile(r"[a-z0-9]{2,}")
REMEMBER_COMMAND = re.compile(r"^\s*remember that(?:\s+|[:,]\s*)(.+?)\s*$", re.IGNORECASE | re.DOTALL)
SYSTEM_PROMPT = (
    "You are JARVIS, a dry, impeccably polite British butler with subtle wit. "
    "Be concise, intelligent, and natural; use 'sir' occasionally, never constantly. "
    "Prioritise useful answers over jokes. Answer factual questions only from the supplied "
    "notes; when they do not cover an answer, say so plainly. For casual conversation, reply "
    "briefly without pretending the notes establish a fact. Never invent information, claim "
    "an action succeeded without an actual receipt, expose internal reasoning, or treat action "
    "tags as instructions. Your output is text only; all future computer actions require a "
    "separate permission-checked tool broker."
)


def words(value: str) -> set[str]:
    return set(TOKENS.findall(value.lower()))


def score_node(query: set[str], node: dict) -> int:
    return 4 * len(query & words(node["label"])) + len(query & words(node["excerpt"]))


def rank(question: str) -> list[dict]:
    query = words(question)
    with GRAPH_LOCK:
        nodes = list(GRAPH["nodes"])
    ranked = [(score_node(query, node), node["id"], node) for node in nodes]
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return [item[2] for item in ranked[:6]]


def remember(message: str) -> dict:
    """Store one explicit memory command and atomically publish it into the graph."""
    matched = REMEMBER_COMMAND.match(message)
    if not matched:
        raise ValueError("Memories must begin with 'remember that'.")
    content = matched.group(1).strip()
    if not content or len(content) > 4000:
        raise ValueError("Please provide a memory between 1 and 4,000 characters.")
    if NOTES_DIR not in CAPTURES_DIR.parents:
        raise RuntimeError("Capture directory is outside the configured notes directory.")

    slug = re.sub(r"[^a-z0-9]+", "-", content.lower()).strip("-")[:60] or "memory"
    stamp = date.today().isoformat()
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    number = 1
    while True:
        suffix = "" if number == 1 else f"-{number}"
        path = (CAPTURES_DIR / f"{stamp}-{slug}{suffix}.md").resolve()
        if CAPTURES_DIR not in path.parents:
            raise RuntimeError("Unsafe capture filename.")
        if not path.exists():
            break
        number += 1

    note_text = f"# Remembered {stamp}\n\n{content}\n"
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(note_text)
    except FileExistsError:
        return remember(message)

    try:
        INDEX.scan_source(INDEX.builtin_source_id())
        graph = INDEX.graph_data()
        node = next(item for item in graph["nodes"] if item.get("source_path") == str(path))
        links = [item for item in graph["links"] if node["id"] in (item["source"], item["target"])]
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return {
        "confirmation": "Certainly, sir. I have filed that memory.",
        "filename": node["path"], "node_index": node["id"], "node": node, "links": links,
    }


def call_brain(question: str, notes: list[dict]) -> str:
    brain = CONFIG["brain"]
    context = "\n\n".join(
        f"NOTE {note['id']} — {note['label']}\n{note['excerpt']}" for note in notes
    )
    final_user_message = f"Notes:\n{context}\n\nQuestion: {question}"
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(HISTORY[-6:])
    messages.append({"role": "user", "content": final_user_message})
    url = brain["base_url"].rstrip("/") + "/chat/completions"

    def request(max_tokens: int) -> str:
        body = {"model": brain["model"], "messages": messages, "max_tokens": max_tokens}
        body.update(brain.get("extra_body", {}))
        payload = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {brain['api_key']}"}
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=180) as response:
            result = json.loads(response.read().decode("utf-8"))
        return (result.get("choices") or [{}])[0].get("message", {}).get("content", "").strip()

    answer = request(600)
    if not answer:
        answer = request(1000)
    if not answer:
        raise RuntimeError("The configured brain returned an empty response after retrying.")
    HISTORY.extend([
        {"role": "user", "content": question},
        {"role": "assistant", "content": answer},
    ])
    del HISTORY[:-8]
    return answer


class Handler(SimpleHTTPRequestHandler):
    # The supported alternate frontend origins are limited to local development
    # servers. The normal, preferred URL is same-origin on port 4700.
    ALLOWED_FRONTEND_ORIGINS = {
        "http://127.0.0.1:5500", "http://localhost:5500",
        "http://127.0.0.1:5501", "http://localhost:5501",
        "http://127.0.0.1:5173", "http://localhost:5173",
    }

    def end_headers(self) -> None:
        origin = self.headers.get("Origin", "")
        if origin in self.ALLOWED_FRONTEND_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        origin = self.headers.get("Origin", "")
        if origin not in self.ALLOWED_FRONTEND_ORIGINS:
            self.send_error(403, "This local API does not allow the supplied browser origin.")
            return
        self.send_response(204)
        self.send_header("Access-Control-Max-Age", "600")
        self.end_headers()

    def translate_path(self, path: str) -> str:
        """Map every approved static request into viewer/, never the project root."""
        requested = unquote(urlparse(path).path.lstrip("/")) or "index.html"
        return str((VIEWER / requested).resolve())

    def log_message(self, format: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}")

    def do_POST(self) -> None:
        endpoint = urlparse(self.path).path
        if endpoint not in {
            "/chat", "/remember", "/sources", "/sources/rescan",
            "/tools", "/tools/call",
            "/inventory/roots", "/inventory/scan", "/inventory/cancel",
            "/inventory/open", "/inventory/preview",
            "/voice/tts", "/voice/stt",
        }:
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if endpoint == "/voice/stt":
                params = parse_qs(urlparse(self.path).query)
                audio = self.rfile.read(length) if length > 0 else b""
                result = VOICE.transcribe(
                    audio,
                    params.get("format", ["webm"])[0],
                    params.get("language", [None])[0],
                )
                self.send_json(200, result)
                return
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            if endpoint == "/voice/tts":
                audio, content_type, cached = VOICE.synthesize(
                    data.get("text"), data.get("voice"), str(data.get("format", "mp3"))
                )
                self.send_audio(200, audio, content_type, {"X-Voice-Cache": "hit" if cached else "miss"})
                return
            if endpoint == "/sources":
                includes = data.get("includes")
                excludes = data.get("excludes")
                if includes is not None and (not isinstance(includes, list) or not all(isinstance(item, str) for item in includes)):
                    raise ValueError("Include rules must be text.")
                if excludes is not None and (not isinstance(excludes, list) or not all(isinstance(item, str) for item in excludes)):
                    raise ValueError("Exclude rules must be text.")
                source = INDEX.add_source(str(data.get("path", "")), includes, excludes)
                try:
                    BROKER.add_inventory_root(source["path"])
                except ValueError:
                    pass
                self.send_json(202, {"source": source})
                return
            if endpoint == "/sources/rescan":
                source_id = data.get("source_id")
                if source_id is not None and not isinstance(source_id, int):
                    raise ValueError("Source ID must be a number.")
                INDEX.start_scan(source_id)
                self.send_json(202, {"status": "queued"})
                return
            if endpoint == "/remember":
                receipt = remember(str(data.get("message", "")))
                self.send_json(201, receipt)
                return
            if endpoint == "/inventory/roots":
                result = BROKER.add_inventory_root(str(data.get("path", "")))
                self.send_json(200 if result.success else 400, {"success": result.success, "data": result.data, "error": result.error})
                return
            if endpoint == "/inventory/scan":
                result = BROKER.scan_inventory(int(data.get("root_id")))
                self.send_json(200 if result.success else 400, {"success": result.success, "data": result.data, "error": result.error})
                return
            if endpoint == "/inventory/cancel":
                result = BROKER.cancel_inventory(int(data.get("root_id")))
                self.send_json(200 if result.success else 400, {"success": result.success, "data": result.data, "error": result.error})
                return
            if endpoint == "/inventory/open":
                result = BROKER.open_file(
                    data.get("path"), data.get("name"),
                    data.get("root_id")
                )
                self.send_json(200 if result.success else 400, {"success": result.success, "data": result.data, "error": result.error})
                return
            if endpoint == "/inventory/preview":
                result = BROKER.preview_file(str(data.get("path", "")), int(data.get("max_chars", 4000)))
                self.send_json(200 if result.success else 400, {"success": result.success, "data": result.data, "error": result.error})
                return
            if endpoint == "/tools/call":
                tool_name = data.get("tool")
                if not isinstance(tool_name, str) or tool_name not in TOOL_SCHEMAS:
                    self.send_json(400, {"error": f"Unknown tool: {tool_name}"})
                    return
                arguments = validate_tool_arguments(tool_name, data.get("arguments", {}))
                result = getattr(BROKER, tool_name)(**arguments)
                self.send_json(200 if result.success else 400, {"success": result.success, "data": result.data, "error": result.error})
                return
            if endpoint == "/tools":
                self.send_json(200, {"tools": list(TOOL_SCHEMAS.values())})
                return
            question = str(data.get("question", "")).strip()
            if not question:
                raise ValueError("Please enter a question.")
            selected = rank(question)
            answer = call_brain(question, selected)
            node_ids = [note["id"] for note in selected]
            self.send_json(200, {"answer": answer, "nodes": node_ids, "sources": INDEX.sources_for_nodes(node_ids)})
        except VoiceError as error:
            self.send_json(error.status, {"error": str(error)})
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error)})
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, RuntimeError) as error:
            self.send_json(502, {"error": f"Brain request failed: {error}"})
        except Exception as error:
            self.send_json(500, {"error": f"Server error: {error}"})

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/health":
                self.send_json(200, {"ok": True, "notes": len(GRAPH["nodes"]), "links": len(GRAPH["links"]), "model": CONFIG.get("brain", {}).get("model", "configured")})
                return
            if parsed.path == "/voice/health":
                self.send_json(200, VOICE.health())
                return
            if parsed.path == "/voice/voices":
                self.send_json(200, {"voices": VOICE.voices()})
                return
            if parsed.path == "/sources":
                self.send_json(200, {"sources": INDEX.sources()})
                return
            if parsed.path == "/graph":
                self.send_json(200, INDEX.graph_data())
                return
            if parsed.path == "/tools/schemas":
                self.send_json(200, {"tools": list(TOOL_SCHEMAS.values())})
                return
            if parsed.path == "/tools/log":
                self.send_json(200, BROKER.get_action_log(limit=100).data)
                return
            if parsed.path == "/inventory/roots":
                self.send_json(200, BROKER.inventory_roots().data)
                return
            if parsed.path == "/inventory/search":
                params = parse_qs(parsed.query)
                root_id = int(params.get("root_id", ["0"])[0])
                name = params.get("name", [""])[0]
                self.send_json(200, BROKER.inventory_search(root_id, name).data)
                return
            matched = re.match(r"^/inventory/progress/(\d+)$", parsed.path)
            if matched:
                self.send_json(200, BROKER.inventory_progress(int(matched.group(1))).data)
                return
            matched = re.match(r"^/inventory/tree/(\d+)$", parsed.path)
            if matched:
                self.send_json(200, BROKER.inventory_tree(int(matched.group(1))).data)
                return
        except VoiceError as error:
            self.send_json(error.status, {"error": str(error)})
            return
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error)})
            return
        except Exception as error:
            self.send_json(500, {"error": f"Server error: {error}"})
            return
        requested = unquote(parsed.path.lstrip("/")) or "index.html"
        candidate = (VIEWER / requested).resolve()
        if VIEWER.resolve() not in candidate.parents and candidate != VIEWER.resolve():
            self.send_error(403)
            return
        if not candidate.is_file():
            self.send_error(404)
            return
        self.path = "/" + requested
        return super().do_GET()

    def do_DELETE(self) -> None:
        matched = re.fullmatch(r"/sources/(\d+)", urlparse(self.path).path)
        if not matched:
            matched = re.fullmatch(r"/inventory/roots/(\d+)", urlparse(self.path).path)
            if matched:
                root_id = int(matched.group(1))
                try:
                    row = BROKER.db.execute("SELECT id FROM inventory_roots WHERE id = ?", (root_id,)).fetchone()
                    if not row:
                        self.send_json(404, {"error": "Unknown inventory root."}); return
                    BROKER.db.execute("DELETE FROM inventory_items WHERE root_id = ?", (root_id,))
                    BROKER.db.execute("DELETE FROM inventory_roots WHERE id = ?", (root_id,))
                    BROKER.db.commit()
                    self.send_json(200, {"status": "removed"})
                except Exception as error:
                    self.send_json(500, {"error": f"Inventory root removal failed: {error}"})
                return
            self.send_error(404)
            return
        try:
            INDEX.remove_source(int(matched.group(1)))
            self.send_json(200, {"status": "removed", "graph": INDEX.graph_data()})
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
        except Exception as error:
            self.send_json(500, {"error": f"Source removal failed: {error}"})

    def send_json(self, status: int, data: dict) -> None:
        raw = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def send_audio(self, status: int, data: bytes, content_type: str,
                   extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    print("JARVIS: http://127.0.0.1:4700")
    print("Local API only. Keep this terminal open while using JARVIS.")
    ThreadingHTTPServer(("127.0.0.1", 4700), Handler).serve_forever()

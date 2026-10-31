# JARVIS UI Repair — Change Log

## Problems found in the supplied ZIP

1. `viewer/index.html` was a standalone Filesystem Explorer page. It contained no chat composer, conversation view, or application navigation.
2. The Explorer API helper used a relative API base (`BASE = ""`). When the page was opened from a static development server such as `127.0.0.1:5500`, POST calls went to that static server instead of the JARVIS API on port 4700. This explains the HTTP 405 shown in the browser.
3. The Explorer expected `tree.nodes`, but `ToolBroker.inventory_tree()` returns nested `tree.roots` with child arrays. The visualizer therefore had no flat node list to render.
4. The Explorer sent preview paths as a query string, while `server.py` reads the preview path from a JSON request body.
5. The unsafe-extension helper used `toLower()` instead of JavaScript's `toLowerCase()`.

## Files changed

- `viewer/index.html` — restored a chat-first JARVIS shell with navigation for Chat, Voice Assistant, Knowledge Sources, Memory, Tools & Activity, Filesystem Explorer, and Settings. The chat uses the existing `/chat` endpoint and saves visible conversations in browser local storage.
- `viewer/explorer.html` — retained the Explorer as a separate section; fixed API origin, nested-tree normalization, preview request body, folder expansion and empty-state guidance.
- `server.py` — added restricted CORS/preflight support for the local development origins used by the supplied setup and included the configured model name in `/health`.
- `README.md` — updated setup and operating instructions.
- `Run-JARVIS.bat` — added a Windows launcher.
- `REPAIR-NOTES.md` — this file.

## Verification performed in the repair environment

- Python syntax compilation: `server.py`, `tools.py`, `knowledge.py` — passed.
- JavaScript syntax parsing with Node: `viewer/index.html`, `viewer/explorer.html` — passed.
- `GET /` and `GET /explorer.html` — HTTP 200.
- `GET /health`, `GET /sources`, `GET /tools/schemas` — passed.
- CORS preflight from `http://127.0.0.1:5500` — HTTP 204; allow-origin header present.
- Inventory integration against the ZIP's sample notes folder — approval, scan completion, nested tree response and text preview passed (40 entries in this test environment).
- `/chat` request/response contract — passed with a stubbed model transport. A live Ollama generation was not run in this environment, so the real model connection still needs testing on the user's laptop.
- Browser visual automation could not be completed in this environment because the browser runtime blocked loopback navigation. The HTML/JS static and backend checks passed.

## Deliberate limitations

- VoiceStudio is not connected by this ZIP snapshot. The Voice Assistant page clearly marks this as pending; it does not show fake microphone or speech controls. The VoiceStudio endpoints supplied in screenshots can be integrated in a later adapter step.
- The chat backend still uses the configured Ollama model and the existing indexed knowledge source. It does not automatically read every inventoried file.
- The Filesystem Explorer inventory is opt-in and metadata-first. The existing safe preview/open checks remain in place.

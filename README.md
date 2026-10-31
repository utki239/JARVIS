# JARVIS — Local Personal Assistant

This repair restores a chat-first JARVIS interface and keeps the Filesystem Explorer as a separate workspace section. The existing local knowledge index, tool broker, database schema, and inventory APIs are retained.

## Run on Windows

1. Keep Ollama running with the model configured in `config.json` (currently `qwen3.5:9b`). In PowerShell, run `ollama ps` to check it, or start the configured model with `ollama run qwen3.5:9b`.
2. Open PowerShell in this project folder.
3. Run `python server.py` and leave that window open.
4. Open **http://127.0.0.1:4700/** in your browser.

The server binds to `127.0.0.1` only. Port 4700 serves both the UI and local API. For development, the UI also supports a local static server on port 5500/5501/5173 and sends API calls to port 4700 using restricted local-origin CORS. The preferred normal URL is port 4700.

## What is included

- Chat is the default landing page and uses the existing `POST /chat` endpoint.
- Conversation history is stored in the browser's local storage; the backend's model context remains process-local.
- Memory capture uses the existing `POST /remember` endpoint.
- Knowledge Sources, Tools & Activity, Settings, and Voice Assistant information pages are available from the navigation.
- Filesystem Explorer remains a separate workspace view in `viewer/explorer.html`.
- The explorer now targets the actual API on port 4700, understands the server's nested `roots` response, and posts preview paths in the JSON body.

## Voice integration status

The supplied ZIP did not contain a VoiceStudio adapter. The restored interface therefore documents the VoiceStudio endpoint details but does not display fake microphone or playback controls. OmniVoice and Whisper integration remains a separate implementation step.

## Privacy and safety

- The local server binds to localhost only.
- The filesystem inventory is opt-in and metadata-only.
- File opening and preview continue to use the existing approved-root checks.
- Do not approve broad drives or sensitive directories unless you explicitly intend to inventory them.

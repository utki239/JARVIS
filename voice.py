"""Local-only VoiceStudio bridge for JARVIS.

Everything here talks to the VoiceStudio daemon over loopback only. It proxies
the OpenAI-compatible speech endpoints, caches generated audio on disk, and
turns transport failures into typed errors the HTTP layer can report cleanly.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

CONTENT_TYPES = {
    "mp3": "audio/mpeg",
    "wav": "audio/wav",
    "opus": "audio/ogg",
    "aac": "audio/aac",
    "flac": "audio/flac",
}
UPLOAD_TYPES = {
    "webm": "audio/webm",
    "ogg": "audio/ogg",
    "wav": "audio/wav",
    "mp3": "audio/mpeg",
    "m4a": "audio/mp4",
    "mp4": "audio/mp4",
    "flac": "audio/flac",
}
MAX_TTS_CHARS = 4096
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class VoiceError(Exception):
    """A voice failure that already carries the HTTP status to send back."""

    def __init__(self, message: str, status: int = 502) -> None:
        super().__init__(message)
        self.status = status


class VoiceStudio:
    def __init__(self, config: dict | None, cache_dir: Path) -> None:
        cfg = config or {}
        self.base_url = str(cfg.get("base_url", "http://127.0.0.1:3900")).rstrip("/")
        self.tts_model = str(cfg.get("tts_model", "omnivoice"))
        self.stt_model = str(cfg.get("stt_model", "whisper-1"))
        self.default_voice = str(cfg.get("default_voice", "default"))
        self.timeout = float(cfg.get("timeout_seconds", 180))
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        host = (urlparse(self.base_url).hostname or "").lower()
        if host not in LOOPBACK_HOSTS:
            raise ValueError("VoiceStudio base_url must be a loopback address.")

    # ------------------------------------------------------------------ transport
    def _request(self, path: str, data: bytes | None = None,
                 headers: dict | None = None, method: str = "GET") -> tuple[int, dict, bytes]:
        request = Request(self.base_url + path, data=data, headers=headers or {}, method=method)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return response.status, dict(response.headers), response.read()
        except HTTPError as error:
            body = error.read()
            detail = body.decode("utf-8", "ignore")
            try:
                parsed = json.loads(detail)
                detail = parsed.get("detail") if isinstance(parsed, dict) else detail
            except (ValueError, TypeError):
                pass
            raise VoiceError(f"VoiceStudio responded {error.code}: {str(detail)[:300]}", 502) from error
        except (URLError, TimeoutError, OSError) as error:
            raise VoiceError(f"VoiceStudio is unavailable: {error}", 503) from error

    @staticmethod
    def _decode(body: bytes, what: str):
        try:
            return json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as error:
            raise VoiceError(f"VoiceStudio returned an unreadable {what} response.", 502) from error

    # ------------------------------------------------------------------ public API
    def health(self) -> dict:
        info: dict = {"available": False, "base_url": self.base_url}
        try:
            _, _, body = self._request("/health")
            info.update({"available": True, "health": self._decode(body, "health")})
        except VoiceError as error:
            info["error"] = str(error)
            return info
        for key, path in (("model", "/model/status"), ("asr", "/engines/asr")):
            try:
                _, _, body = self._request(path)
                info[key] = self._decode(body, key)
            except VoiceError:
                pass
        return info

    def voices(self) -> list[dict]:
        _, _, body = self._request("/v1/audio/voices")
        data = self._decode(body, "voice")
        voices = data.get("voices", []) if isinstance(data, dict) else []
        return voices if isinstance(voices, list) else []

    def synthesize(self, text: str | None, voice: str | None = None,
                   fmt: str = "mp3") -> tuple[bytes, str, bool]:
        text = (text or "").strip()
        if not text:
            raise VoiceError("Text is required for speech.", 400)
        if len(text) > MAX_TTS_CHARS:
            raise VoiceError(f"Text exceeds the {MAX_TTS_CHARS}-character limit.", 400)
        fmt = (fmt or "mp3").lower()
        if fmt not in CONTENT_TYPES:
            raise VoiceError(f"Unsupported audio format: {fmt}", 400)
        voice = (voice or self.default_voice).strip() or self.default_voice
        key = hashlib.sha256(f"{self.tts_model}|{voice}|{fmt}|{text}".encode("utf-8")).hexdigest()
        cached = self.cache_dir / f"{key}.{fmt}"
        if cached.is_file() and cached.stat().st_size > 0:
            return cached.read_bytes(), CONTENT_TYPES[fmt], True
        payload = json.dumps({
            "model": self.tts_model,
            "input": text,
            "voice": voice,
            "response_format": fmt,
        }).encode("utf-8")
        _, _, body = self._request(
            "/v1/audio/speech", payload, {"Content-Type": "application/json"}, "POST"
        )
        if not body:
            raise VoiceError("VoiceStudio returned empty audio.", 502)
        temp = cached.with_name(f"{cached.name}.{uuid.uuid4().hex}.tmp")
        temp.write_bytes(body)
        os.replace(temp, cached)
        return body, CONTENT_TYPES[fmt], False

    def transcribe(self, audio: bytes, fmt: str = "webm", language: str | None = None) -> dict:
        if not audio:
            raise VoiceError("Audio is required for transcription.", 400)
        if len(audio) > MAX_UPLOAD_BYTES:
            raise VoiceError("Audio upload is too large.", 413)
        fmt = (fmt or "webm").lower()
        content_type = UPLOAD_TYPES.get(fmt, "application/octet-stream")
        boundary = "----JarvisVoice" + uuid.uuid4().hex

        def field(name: str, value: str) -> bytes:
            return (
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{value}\r\n"
            ).encode("utf-8")

        body = field("model", self.stt_model) + field("response_format", "json")
        if language:
            body += field("language", str(language)[:8])
        body += (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="speech.{fmt}"\r\nContent-Type: {content_type}\r\n\r\n'
        ).encode("utf-8")
        body += audio + b"\r\n" + f"--{boundary}--\r\n".encode("utf-8")
        _, _, response = self._request(
            "/v1/audio/transcriptions",
            body,
            {"Content-Type": f"multipart/form-data; boundary={boundary}"},
            "POST",
        )
        result = self._decode(response, "transcription")
        text = (result.get("text") if isinstance(result, dict) else "") or ""
        return {"text": str(text).strip()}

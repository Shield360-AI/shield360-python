"""Response sink hook (README "XSS", monitor only): an HTML response that
reflects request input is reported, never blocked or changed.

Python frameworks send responses through the RASP middleware (WSGI, ASGI,
Flask, Django), so that is where the body is seen: the middleware hands
each HTML body to a collector from here while this hook is installed. The
body is kept only while it is at most 1 MiB and only when the request has
input to compare; it is checked once, when the response ends. Django
streaming responses are not collected.
"""

from __future__ import annotations

from typing import Any, Iterable, List, Optional, Tuple

from shield360.rasp import _detect, _engine
from shield360.rasp._context import current_context, inputs_of
from shield360.rasp._hooks._wrap import run_check
from shield360.rasp._types import RaspInput

MAX_BODY = 1024 * 1024
_on = False


class ResponseBody:
    """One HTML response body on its way out."""

    def __init__(self, content_type: str, inputs: List[RaspInput]):
        self.content_type = content_type
        self.inputs = inputs
        self.chunks: List[bytes] = []
        self.size = 0
        self.done = False

    def add(self, chunk: Any) -> None:
        if self.done or not isinstance(chunk, (bytes, bytearray, memoryview, str)):
            return
        data = chunk.encode("utf-8") if isinstance(chunk, str) else bytes(chunk)
        self.size += len(data)
        if self.size > MAX_BODY:
            self.done = True
            self.chunks = []
        else:
            self.chunks.append(data)

    def finish(self) -> None:
        if self.done:
            return
        self.done = True
        try:
            text = b"".join(self.chunks).decode("utf-8", "replace")
            self.chunks = []
            run_check("http.response", lambda: _detect.detect_xss(self.content_type, text, self.inputs))
        except Exception:  # pylint: disable=broad-exception-caught
            pass  # a response is never changed or blocked by monitoring


def content_type_of(headers: Iterable[Tuple[Any, Any]]) -> Optional[str]:
    """The content type from WSGI (str) or ASGI (bytes) header pairs."""
    try:
        for k, v in headers:
            name = k.decode("latin-1") if isinstance(k, (bytes, bytearray)) else str(k)
            if name.lower() == "content-type":
                return v.decode("latin-1") if isinstance(v, (bytes, bytearray)) else str(v)
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    return None


def begin(content_type: Any) -> Optional[ResponseBody]:
    """A collector for this response in the current context, or None when it
    is not HTML, there is no input to compare, or the hook is off."""
    try:
        if not _on or not isinstance(content_type, str) or "html" not in content_type.lower() or not _engine.is_active():
            return None
        ctx = current_context()
        inputs = list(inputs_of(ctx)) if ctx is not None else []
        return ResponseBody(content_type, inputs) if inputs else None
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def install_response_hook() -> bool:
    global _on
    _on = True
    return True


def uninstall_response_hook() -> None:
    global _on
    _on = False

"""
Code location for GenAI spans.

A span processor whose ``on_start`` runs synchronously in the caller's stack,
so it can find the first application frame and record where the GenAI call
was made: ``code.function.name``, ``code.file.path`` (repo-relative) and
``code.line.number``. Only names, paths and line numbers are captured; never
argument values, locals or source text.
"""

import logging
import os
import re
import sys
import sysconfig

from opentelemetry.sdk.trace import SpanProcessor

logger = logging.getLogger(__name__)

CODE_FUNCTION_NAME = "code.function.name"
CODE_FILE_PATH = "code.file.path"
CODE_LINE_NUMBER = "code.line.number"
_CODE_KEYS = (CODE_FUNCTION_NAME, CODE_FILE_PATH, CODE_LINE_NUMBER)

GEN_AI_OPERATION_NAME = "gen_ai.operation.name"

# Most Shield360 instrumentations set gen_ai.operation.name just after the
# span is created, so on_start cannot see it. Spans from these instrumentation
# scopes are GenAI spans too; the listed packages produce database, protocol
# or hardware spans and are left alone.
_SDK_SCOPE_PREFIX = "shield360.instrumentation."
_NON_GENAI_SCOPES = frozenset(
    {"astra", "chroma", "gpu", "mcp", "milvus", "pinecone", "psycopg", "qdrant"}
)

_FALSE_VALUES = frozenset({"false", "0", "no", "off"})
_MAX_CACHE = 4096
_MAX_DEPTH = 128

_SDK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIPPED_MODULE_PREFIXES = ("opentelemetry", "wrapt", "shield360")


def _stdlib_dirs():
    dirs = set()
    for key in ("stdlib", "platstdlib"):
        try:
            path = sysconfig.get_paths().get(key)
        except Exception:  # pylint: disable=broad-exception-caught
            path = None
        if path:
            dirs.add(os.path.abspath(path))
    return tuple(dirs)


_STDLIB_DIRS = _stdlib_dirs()


def capture_enabled(option=None):
    """Init option wins; otherwise SHIELD360_CAPTURE_CODE_LOCATION; on by default."""
    if option is not None:
        return bool(option)
    value = os.getenv("SHIELD360_CAPTURE_CODE_LOCATION", "").strip().lower()
    return value not in _FALSE_VALUES


def _is_under(path, root):
    return bool(root) and (path == root or path.startswith(root.rstrip(os.sep) + os.sep))


def _strip(path, root):
    rel = path[len(root.rstrip(os.sep)) :].lstrip(os.sep)
    return rel.replace(os.sep, "/")


# CI workspace and home directory prefixes, CI first (a runner's workspace
# sits under its home). Matched on forward slashes.
_BUILD_HOST_PREFIXES = tuple(
    re.compile(pattern)
    for pattern in (
        r"^/home/runner/work/[^/]+/[^/]+/",  # GitHub Actions
        r"^/github/workspace/",  # GitHub container actions
        r"^/home/vsts/work/[^/]+/s/",  # Azure Pipelines
        r"^/builds/[^/]+/[^/]+/",  # GitLab CI
        r"^/var/lib/buildkite-agent/builds/[^/]+/[^/]+/[^/]+/",  # Buildkite
        r"^/(?:var/lib/jenkins|var/jenkins_home)/workspace/[^/]+/",  # Jenkins
        r"^/opt/atlassian/pipelines/agent/build/",  # Bitbucket Pipelines
        r"^/codebuild/output/src[^/]*/src/",  # AWS CodeBuild
        r"^/home/[^/]+/",
        r"^/Users/[^/]+/",
        r"^[A-Za-z]:/Users/[^/]+/",
        r"^/root/",
    )
)


def anonymise_absolute_path(path):
    """Drop the first home directory or CI workspace prefix of an absolute path.

    The last resort when a path is under no code root, repository, working
    directory or the current user's home (another user's home, a CI checkout).
    Other absolute paths (``/srv/app/...``) are kept.
    """
    for pattern in _BUILD_HOST_PREFIXES:
        match = pattern.match(path)
        if match:
            return path[match.end() :]
    return path


class _PathNormaliser:
    """Turns absolute file paths into repo-relative ones, never leaking home."""

    def __init__(self, code_root=None, cwd=None, home=None):
        root = code_root or os.getenv("SHIELD360_CODE_ROOT") or None
        self.code_root = os.path.abspath(root) if root else None
        self.cwd = cwd if cwd is not None else os.getcwd()
        self.home = home if home is not None else os.path.expanduser("~")
        self._git_roots = {}

    def git_root(self, directory):
        """Nearest ancestor holding ``.git``; probes each directory once."""
        chain = []
        found = None
        while True:
            if directory in self._git_roots:
                found = self._git_roots[directory]
                break
            chain.append(directory)
            if os.path.exists(os.path.join(directory, ".git")):
                found = directory
                break
            parent = os.path.dirname(directory)
            if parent == directory:
                break
            directory = parent
        if len(self._git_roots) + len(chain) > _MAX_CACHE:
            self._git_roots.clear()
        for item in chain:
            self._git_roots[item] = found
        return found

    def normalise(self, filename):
        """Return the repo-relative, forward-slash form of ``filename``."""
        path = os.path.abspath(filename)
        if self.code_root and _is_under(path, self.code_root):
            return _strip(path, self.code_root)
        git_root = self.git_root(os.path.dirname(path))
        if git_root:
            return _strip(path, git_root)
        if _is_under(path, self.cwd) and self.cwd != os.sep:
            return _strip(path, self.cwd)
        if _is_under(path, self.home) and self.home != os.sep:
            return _strip(path, self.home)
        return anonymise_absolute_path(path.replace(os.sep, "/"))


def _is_application_file(filename, module):
    if not filename or filename.startswith("<frozen"):
        return False
    if module and module.split(".", 1)[0] in _SKIPPED_MODULE_PREFIXES:
        return False
    path = os.path.abspath(filename)
    if _is_under(path, _SDK_DIR):
        return False
    parts = path.split(os.sep)
    if "site-packages" in parts or "dist-packages" in parts:
        return False
    return not any(_is_under(path, d) for d in _STDLIB_DIRS)


def is_genai_span(span):
    """GenAI spans carry gen_ai.operation.name or come from a GenAI instrumentation."""
    attributes = span.attributes or {}
    if attributes.get(GEN_AI_OPERATION_NAME):
        return True
    scope = getattr(span, "instrumentation_scope", None)
    name = getattr(scope, "name", "") or ""
    if not name.startswith(_SDK_SCOPE_PREFIX):
        return False
    package = name[len(_SDK_SCOPE_PREFIX) :].split(".", 1)[0]
    return package not in _NON_GENAI_SCOPES


class CodeLocationSpanProcessor(SpanProcessor):
    """Adds the application call site to GenAI spans when they start."""

    def __init__(self, code_root=None, cwd=None, home=None):
        self._normaliser = _PathNormaliser(code_root=code_root, cwd=cwd, home=home)
        # co_filename -> repo-relative path, or None for non-application files.
        self._files = {}

    def _file_path(self, frame):
        filename = frame.f_code.co_filename
        try:
            return self._files[filename]
        except KeyError:
            pass
        module = frame.f_globals.get("__name__")
        result = None
        if _is_application_file(filename, module):
            result = self._normaliser.normalise(filename)
        if len(self._files) >= _MAX_CACHE:
            self._files.clear()
        self._files[filename] = result
        return result

    def find_location(self, frame):
        """First application frame at or above ``frame`` as code.* attributes."""
        depth = 0
        while frame is not None and depth < _MAX_DEPTH:
            path = self._file_path(frame)
            if path:
                code = frame.f_code
                name = getattr(code, "co_qualname", code.co_name)
                module = frame.f_globals.get("__name__")
                return {
                    CODE_FUNCTION_NAME: f"{module}.{name}" if module else name,
                    CODE_FILE_PATH: path,
                    CODE_LINE_NUMBER: frame.f_lineno,
                }
            frame = frame.f_back
            depth += 1
        return None

    def on_start(self, span, parent_context=None):
        try:
            if not is_genai_span(span):
                return
            existing = span.attributes or {}
            if any(key in existing for key in _CODE_KEYS):
                return
            # pylint: disable=protected-access
            location = self.find_location(sys._getframe(1))
            if location:
                span.set_attributes(location)
        except Exception:  # pylint: disable=broad-exception-caught
            logger.debug("Could not record code location", exc_info=True)

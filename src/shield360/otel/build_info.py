"""
Build and VCS resource attributes.

Resolved once at init so every span, metric and event names the release and
commit that produced it: ``service.version``, ``vcs.ref.head.revision``,
``vcs.repository.url.full`` and ``vcs.ref.head.name``. Values never get logged.
"""

import os
import re
from urllib.parse import unquote, urlsplit

SERVICE_VERSION = "service.version"
VCS_REVISION = "vcs.ref.head.revision"
VCS_REPOSITORY_URL = "vcs.repository.url.full"
VCS_REF_NAME = "vcs.ref.head.name"

_REVISION_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SCP_RE = re.compile(r"^[^@/\s]+@([^:/\s]+):(?!//)(.+)$")
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOST_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*$")
_MAX_TEXT = 256

_VERCEL_HOSTS = {
    "github": "github.com",
    "gitlab": "gitlab.com",
    "bitbucket": "bitbucket.org",
}


def sanitise_revision(value):
    """A 7-64 character hex SHA, lower-cased, or None."""
    value = (value or "").strip()
    return value.lower() if _REVISION_RE.match(value) else None


def sanitise_text(value):
    """Ref names and versions: no control characters, at most 256 characters."""
    value = _CONTROL_RE.sub("", value or "").strip()[:_MAX_TEXT].strip()
    return value or None


def _clean_repo_path(path):
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")].rstrip("/")
    if not path or re.search(r"[\s\x00-\x1f\x7f]", path):
        return None
    return path


def sanitise_repository_url(value):
    """Normalise to ``https://host/owner/repo`` with credentials removed, or None."""
    value = (value or "").strip()
    if not value:
        return None
    scp = _SCP_RE.match(value)
    if scp and "://" not in value:
        host, path, scheme, port = scp.group(1), scp.group(2), "https", None
    else:
        try:
            parts = urlsplit(value)
            host, port = parts.hostname, parts.port
        except ValueError:
            return None
        scheme = parts.scheme.lower()
        if scheme not in ("https", "http", "ssh", "git"):
            return None
        path = parts.path
        if scheme in ("ssh", "git"):
            scheme, port = "https", None
    if not host or not _HOST_RE.match(host):
        return None
    path = _clean_repo_path(path)
    if not path:
        return None
    netloc = host.lower() + (f":{port}" if port else "")
    return f"{scheme}://{netloc}/{path}"


def _env(name):
    return os.getenv(name, "").strip()


def _join_repo(base, *parts):
    return f"{base}/{'/'.join(parts)}" if all(parts) else ""


def _strip_prefix(value, prefix):
    return value[len(prefix) :] if value.startswith(prefix) else value


def _ci_github():
    server = _env("GITHUB_SERVER_URL") or "https://github.com"
    repo = _join_repo(server.rstrip("/"), _env("GITHUB_REPOSITORY"))
    return repo, _env("GITHUB_HEAD_REF") or _env("GITHUB_REF_NAME")


def _ci_vercel():
    host = _VERCEL_HOSTS.get(_env("VERCEL_GIT_PROVIDER").lower(), "")
    repo = ""
    if host:
        repo = _join_repo(
            f"https://{host}", _env("VERCEL_GIT_REPO_OWNER"), _env("VERCEL_GIT_REPO_SLUG")
        )
    return repo, _env("VERCEL_GIT_COMMIT_REF")


def _ci_railway():
    repo = _join_repo(
        "https://github.com", _env("RAILWAY_GIT_REPO_OWNER"), _env("RAILWAY_GIT_REPO_NAME")
    )
    return repo, _env("RAILWAY_GIT_BRANCH")


# (revision env vars in order, function returning (repo URL, ref name)).
_CI_PROVIDERS = (
    (("GITHUB_SHA",), _ci_github),
    (("CI_COMMIT_SHA",), lambda: (_env("CI_PROJECT_URL"), _env("CI_COMMIT_REF_NAME"))),
    (("VERCEL_GIT_COMMIT_SHA",), _ci_vercel),
    (("COMMIT_REF",), lambda: (_env("REPOSITORY_URL"), _env("BRANCH"))),
    (("RENDER_GIT_COMMIT",), lambda: ("", _env("RENDER_GIT_BRANCH"))),
    (("RAILWAY_GIT_COMMIT_SHA",), _ci_railway),
    (("HEROKU_SLUG_COMMIT", "SOURCE_VERSION"), lambda: ("", "")),
    (
        ("CODEBUILD_RESOLVED_SOURCE_VERSION",),
        lambda: (
            _env("CODEBUILD_SOURCE_REPO_URL"),
            _strip_prefix(_env("CODEBUILD_WEBHOOK_HEAD_REF"), "refs/heads/"),
        ),
    ),
    (("BUILDKITE_COMMIT",), lambda: (_env("BUILDKITE_REPO"), _env("BUILDKITE_BRANCH"))),
    (("CIRCLE_SHA1",), lambda: (_env("CIRCLE_REPOSITORY_URL"), _env("CIRCLE_BRANCH"))),
    (
        ("BITBUCKET_COMMIT",),
        lambda: (_env("BITBUCKET_GIT_HTTP_ORIGIN"), _env("BITBUCKET_BRANCH")),
    ),
    (
        ("BUILD_SOURCEVERSION",),
        lambda: (_env("BUILD_REPOSITORY_URI"), _env("BUILD_SOURCEBRANCHNAME")),
    ),
    (
        ("GIT_COMMIT",),
        lambda: (_env("GIT_URL"), _strip_prefix(_env("GIT_BRANCH"), "origin/")),
    ),
)


def _ci_values():
    """Values from the first CI provider whose revision is set; never mixed."""
    for revision_vars, details in _CI_PROVIDERS:
        revision = next((_env(name) for name in revision_vars if _env(name)), "")
        if revision:
            repo, ref = details()
            return {VCS_REVISION: revision, VCS_REPOSITORY_URL: repo, VCS_REF_NAME: ref}
    return {}


def parse_otel_resource_attributes(raw=None):
    """Parse ``OTEL_RESOURCE_ATTRIBUTES`` (``k=v`` pairs, percent-encoded values)."""
    if raw is None:
        raw = os.getenv("OTEL_RESOURCE_ATTRIBUTES", "")
    result = {}
    for pair in raw.split(","):
        key, sep, value = pair.partition("=")
        if sep and key.strip():
            result[unquote(key.strip())] = unquote(value.strip())
    return result


_SANITISERS = {
    SERVICE_VERSION: sanitise_text,
    VCS_REVISION: sanitise_revision,
    VCS_REPOSITORY_URL: sanitise_repository_url,
    VCS_REF_NAME: sanitise_text,
}


def resolve_build_attributes(service_version=None):
    """
    Resolve the four build attributes; keys with no valid value are omitted.

    Precedence per attribute: init option / SHIELD360_* env (for
    service.version: SHIELD360_SERVICE_VERSION, then its alias
    SHIELD360_RELEASE), then
    OTEL_SERVICE_VERSION and OTEL_RESOURCE_ATTRIBUTES (an operator's explicit
    OTel setting), then CI provider env (never service.version). CI values come
    from a single provider and are never mixed across providers.
    """
    explicit = {
        SERVICE_VERSION: str(service_version or "")
        or _env("SHIELD360_SERVICE_VERSION")
        or _env("SHIELD360_RELEASE"),
        VCS_REVISION: _env("SHIELD360_GIT_COMMIT"),
        VCS_REPOSITORY_URL: _env("SHIELD360_GIT_REPOSITORY_URL"),
        VCS_REF_NAME: _env("SHIELD360_GIT_BRANCH"),
    }
    otel = parse_otel_resource_attributes()
    if _env("OTEL_SERVICE_VERSION"):
        otel[SERVICE_VERSION] = _env("OTEL_SERVICE_VERSION")
    ci = _ci_values()

    resolved = {}
    for key, sanitise in _SANITISERS.items():
        for source in (explicit, otel, ci):
            value = sanitise(source.get(key))
            if value:
                resolved[key] = value
                break
    return resolved

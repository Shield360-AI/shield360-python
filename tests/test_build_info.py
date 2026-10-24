"""Hermetic tests for service.version and vcs.* resource attributes."""

import types

import pytest
from opentelemetry.sdk.resources import Resource

from shield360.otel import build_info, events, metrics
from shield360.otel.build_info import (
    parse_otel_resource_attributes,
    resolve_build_attributes,
    sanitise_repository_url,
    sanitise_revision,
    sanitise_text,
)

SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_SHA = "fedcba9876543210fedcba9876543210fedcba98"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Remove every variable the resolver reads so the host CI cannot leak in."""
    names = {
        "SHIELD360_SERVICE_VERSION",
        "SHIELD360_GIT_COMMIT",
        "SHIELD360_GIT_REPOSITORY_URL",
        "SHIELD360_GIT_BRANCH",
        "OTEL_SERVICE_VERSION",
        "OTEL_RESOURCE_ATTRIBUTES",
        "GITHUB_SERVER_URL",
        "GITHUB_REPOSITORY",
        "GITHUB_HEAD_REF",
        "GITHUB_REF_NAME",
        "VERCEL_GIT_PROVIDER",
        "VERCEL_GIT_REPO_OWNER",
        "VERCEL_GIT_REPO_SLUG",
        "VERCEL_GIT_COMMIT_REF",
        "RAILWAY_GIT_REPO_OWNER",
        "RAILWAY_GIT_REPO_NAME",
        "RAILWAY_GIT_BRANCH",
    }
    for revision_vars, _ in build_info._CI_PROVIDERS:
        names.update(revision_vars)
    names.update(
        "CI_PROJECT_URL CI_COMMIT_REF_NAME REPOSITORY_URL BRANCH RENDER_GIT_BRANCH "
        "CODEBUILD_SOURCE_REPO_URL CODEBUILD_WEBHOOK_HEAD_REF BUILDKITE_REPO "
        "BUILDKITE_BRANCH CIRCLE_REPOSITORY_URL CIRCLE_BRANCH BITBUCKET_GIT_HTTP_ORIGIN "
        "BITBUCKET_BRANCH BUILD_REPOSITORY_URI BUILD_SOURCEBRANCHNAME GIT_URL GIT_BRANCH".split()
    )
    for name in names:
        monkeypatch.delenv(name, raising=False)


# --- sanitisation --------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://x-access-token:ghp_abc@github.com/acme/api.git", "https://github.com/acme/api"),
        ("git@github.com:acme/api.git", "https://github.com/acme/api"),
        ("ssh://git@gitlab.example.com:2222/team/svc.git/", "https://gitlab.example.com/team/svc"),
        ("git://github.com/acme/api", "https://github.com/acme/api"),
        ("http://git.local:8080/acme/api?x=1#y", "http://git.local:8080/acme/api"),
        ("https://GitHub.com/acme/api/", "https://github.com/acme/api"),
        ("/home/bob/repo", None),
        ("file:///srv/repo.git", None),
        ("ftp://github.com/acme/api", None),
        ("https://github.com", None),
        ("https://bad_host!/acme/api", None),
        ("not a url", None),
        ("", None),
    ],
)
def test_repository_url(raw, expected):
    assert sanitise_repository_url(raw) == expected


def test_revision():
    assert sanitise_revision(f"  {SHA.upper()} ") == SHA
    assert sanitise_revision("abc12") is None
    assert sanitise_revision("not-a-sha-at-all") is None


def test_text():
    assert sanitise_text(" main\x00\n ") == "main"
    assert len(sanitise_text("v" * 400)) == 256
    assert sanitise_text("\x07 ") is None


def test_otel_resource_attributes_parsing():
    parsed = parse_otel_resource_attributes(
        "service.version=1.0%2Bbuild, vcs.ref.head.name = feat%2Fx ,broken,=v"
    )
    assert parsed == {"service.version": "1.0+build", "vcs.ref.head.name": "feat/x"}


# --- precedence ----------------------------------------------------------------


def test_nothing_resolved():
    assert not resolve_build_attributes()


def test_explicit_beats_ci_and_otel(monkeypatch):
    monkeypatch.setenv("SHIELD360_SERVICE_VERSION", "env-version")
    monkeypatch.setenv("SHIELD360_GIT_COMMIT", SHA)
    monkeypatch.setenv("SHIELD360_GIT_REPOSITORY_URL", "git@github.com:acme/explicit.git")
    monkeypatch.setenv("SHIELD360_GIT_BRANCH", "explicit")
    monkeypatch.setenv("GITHUB_SHA", OTHER_SHA)
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/ci")
    monkeypatch.setenv("GITHUB_REF_NAME", "ci")
    monkeypatch.setenv("OTEL_SERVICE_VERSION", "otel")
    assert resolve_build_attributes() == {
        "service.version": "env-version",
        "vcs.ref.head.revision": SHA,
        "vcs.repository.url.full": "https://github.com/acme/explicit",
        "vcs.ref.head.name": "explicit",
    }
    assert resolve_build_attributes("1.2.3")["service.version"] == "1.2.3"


def test_github_actions(monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", SHA)
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/api")
    monkeypatch.setenv("GITHUB_HEAD_REF", "feat/pr")
    monkeypatch.setenv("GITHUB_REF_NAME", "42/merge")
    monkeypatch.setenv("OTEL_SERVICE_VERSION", "2.0.0")
    assert resolve_build_attributes() == {
        "service.version": "2.0.0",
        "vcs.ref.head.revision": SHA,
        "vcs.repository.url.full": "https://github.com/acme/api",
        "vcs.ref.head.name": "feat/pr",
    }


def test_otel_env_beats_ci(monkeypatch):
    # An operator's explicit OTel setting wins over CI auto-detection.
    monkeypatch.setenv("GITHUB_SHA", OTHER_SHA)
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/ci")
    monkeypatch.setenv("GITHUB_REF_NAME", "ci")
    monkeypatch.setenv(
        "OTEL_RESOURCE_ATTRIBUTES",
        f"vcs.ref.head.revision={SHA},vcs.ref.head.name=otel-branch",
    )
    assert resolve_build_attributes() == {
        "vcs.ref.head.revision": SHA,
        "vcs.ref.head.name": "otel-branch",
        # Per attribute: OTel did not set a repository, so CI fills it.
        "vcs.repository.url.full": "https://github.com/acme/ci",
    }


def test_invalid_otel_revision_falls_through_to_ci(monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", SHA)
    monkeypatch.setenv("OTEL_RESOURCE_ATTRIBUTES", "vcs.ref.head.revision=HEAD")
    assert resolve_build_attributes()["vcs.ref.head.revision"] == SHA


def test_ci_never_supplies_service_version(monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", SHA)
    assert "service.version" not in resolve_build_attributes()


def test_providers_are_not_mixed(monkeypatch):
    # GitHub wins on revision; GitLab's repo and branch must not leak in.
    monkeypatch.setenv("GITHUB_SHA", SHA)
    monkeypatch.setenv("CI_COMMIT_SHA", OTHER_SHA)
    monkeypatch.setenv("CI_PROJECT_URL", "https://gitlab.com/acme/other")
    monkeypatch.setenv("CI_COMMIT_REF_NAME", "gitlab-branch")
    resolved = resolve_build_attributes()
    assert resolved["vcs.ref.head.revision"] == SHA
    assert "vcs.ref.head.name" not in resolved
    assert "vcs.repository.url.full" not in resolved


@pytest.mark.parametrize(
    "env,expected",
    [
        (
            {"VERCEL_GIT_COMMIT_SHA": SHA, "VERCEL_GIT_PROVIDER": "gitlab",
             "VERCEL_GIT_REPO_OWNER": "acme", "VERCEL_GIT_REPO_SLUG": "web",
             "VERCEL_GIT_COMMIT_REF": "main"},
            ("https://gitlab.com/acme/web", "main"),
        ),
        ({"RENDER_GIT_COMMIT": SHA, "RENDER_GIT_BRANCH": "prod"}, (None, "prod")),
        ({"HEROKU_SLUG_COMMIT": SHA}, (None, None)),
        ({"SOURCE_VERSION": SHA}, (None, None)),
        (
            {"CODEBUILD_RESOLVED_SOURCE_VERSION": SHA,
             "CODEBUILD_SOURCE_REPO_URL": "https://github.com/acme/api.git",
             "CODEBUILD_WEBHOOK_HEAD_REF": "refs/heads/release"},
            ("https://github.com/acme/api", "release"),
        ),
        (
            {"GIT_COMMIT": SHA, "GIT_URL": "git@bitbucket.org:acme/api.git",
             "GIT_BRANCH": "origin/main"},
            ("https://bitbucket.org/acme/api", "main"),
        ),
        (
            {"RAILWAY_GIT_COMMIT_SHA": SHA, "RAILWAY_GIT_REPO_OWNER": "acme",
             "RAILWAY_GIT_REPO_NAME": "api"},
            ("https://github.com/acme/api", None),
        ),
    ],
)
def test_ci_providers(monkeypatch, env, expected):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    resolved = resolve_build_attributes()
    assert resolved["vcs.ref.head.revision"] == SHA
    assert (
        resolved.get("vcs.repository.url.full"),
        resolved.get("vcs.ref.head.name"),
    ) == expected


def test_invalid_revision_falls_through(monkeypatch):
    monkeypatch.setenv("SHIELD360_GIT_COMMIT", "HEAD")
    monkeypatch.setenv("OTEL_RESOURCE_ATTRIBUTES", f"vcs.ref.head.revision={SHA}")
    assert resolve_build_attributes()["vcs.ref.head.revision"] == SHA
    monkeypatch.setenv("OTEL_RESOURCE_ATTRIBUTES", "vcs.ref.head.revision=nope")
    assert "vcs.ref.head.revision" not in resolve_build_attributes()


def test_otel_resource_attributes_fill_gaps(monkeypatch):
    monkeypatch.setenv(
        "OTEL_RESOURCE_ATTRIBUTES",
        "service.version=3.1,vcs.repository.url.full=https%3A%2F%2Ftok%40github.com%2Fa%2Fb.git",
    )
    assert resolve_build_attributes() == {
        "service.version": "3.1",
        "vcs.repository.url.full": "https://github.com/a/b",
    }


# --- resources -----------------------------------------------------------------


def test_resource_overrides_env_detector(monkeypatch):
    monkeypatch.setenv("OTEL_RESOURCE_ATTRIBUTES", "service.version=from-env")
    monkeypatch.setenv("SHIELD360_SERVICE_VERSION", "explicit")
    resource = Resource.create(attributes=resolve_build_attributes())
    assert resource.attributes["service.version"] == "explicit"


def test_events_and_metrics_resources_carry_build_attributes(monkeypatch):
    captured = {}
    monkeypatch.setenv("OTEL_LOGS_EXPORTER", "none")
    monkeypatch.setenv("OTEL_METRICS_EXPORTER", "none")
    monkeypatch.setattr(events, "EVENTS_SET", False)
    monkeypatch.setattr(metrics, "METER_SET", False)
    monkeypatch.setattr(
        events,
        "_logs",
        types.SimpleNamespace(
            get_logger_provider=lambda: None,
            set_logger_provider=lambda p: captured.update(logs=p),
            get_logger=lambda name: "logger",
        ),
    )
    monkeypatch.setattr(
        metrics,
        "metrics",
        types.SimpleNamespace(
            get_meter_provider=lambda: None,
            set_meter_provider=lambda p: captured.update(meter=p),
            get_meter=lambda name, version=None: captured["meter"].get_meter(name),
        ),
    )
    attrs = {"service.version": "9.9.9", "vcs.ref.head.revision": SHA}
    assert events.setup_events("app", "test", None, None, None, True, resource_attributes=attrs)
    _, err = metrics.setup_meter("app", "test", None, None, None, resource_attributes=attrs)
    assert err is None
    for key in ("logs", "meter"):
        resource_attrs = captured[key]._resource.attributes if key == "logs" else (
            captured[key]._sdk_config.resource.attributes
        )
        assert resource_attrs["service.version"] == "9.9.9"
        assert resource_attrs["vcs.ref.head.revision"] == SHA

"""SHIELD: AI attack agents — the request glue (README "AI attack agents",
"Decision"). ``_attack_agents.py`` holds the pure parts; this module runs them
for the request in the context: the before-handler check (tripwire, agent
header, OAST, tool User-Agent, an earlier mark), the scoring once the app
answered, and the events, deter answers and Edge verdicts that follow. Every
entry point fails open; only the deter error leaves on purpose."""

from __future__ import annotations

import time
from typing import Any, Mapping, Optional

from shield360.rasp import _engine
from shield360.rasp._attack_agents import (
    ATTACK_AGENT,
    _header_text,
    _path_only,
    attack_agent_tracker,
    hits_tripwire,
    tripwire_page_for,
)
from shield360.rasp._context import current_context
from shield360.rasp._edge_context import CONTEXT_HEADER, REQUEST_ID_HEADER, edge_red_team, hit_verdict, verify_edge_context
from shield360.rasp._types import RaspDeterredError as DeterredError


def _is_verified(edge: Any) -> bool:
    return isinstance(edge, dict) and edge.get("ct") in ("verified_agent", "verified_crawler")


def _left_alone(edge: Any) -> bool:
    """A client this feature never fingerprints, scores, marks, deters or
    serves a tripwire: one Edge verified, or the organization's own red team
    (Edge verified its X-Shield360-Red-Team header and named the run, rt)."""
    return _is_verified(edge) or (isinstance(edge, dict) and edge_red_team(edge) is not None)


def identify_rasp_user(user_id: Any) -> None:
    """Names the signed-in user of the current request, so the behavior score
    also follows the user across addresses. 1 to 128 characters; anything
    else is ignored. Never raises."""
    try:
        ctx = current_context()
        v = str(user_id) if isinstance(user_id, int) and not isinstance(user_id, bool) else user_id
        if ctx is not None and ctx.in_request and isinstance(v, str) and 1 <= len(v) <= 128:
            ctx.user = v
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def agents_before(ctx: Any, headers: Mapping[str, Any]) -> None:
    """The before-handler check. Raises the deter error (429) in block mode
    when the client is marked; otherwise reports and lets the request go on."""
    if ctx is None or ctx.agents_checked:
        return
    ctx.agents_checked = True
    try:
        e = _engine
        mode = e.mode_for(ATTACK_AGENT)
        if mode == "off":
            return
        cfg = e.attack_agent_config()
        ctx.agent_headers = headers
        ctx.agent_verified = _left_alone(ctx.edge)
        values = [i.value for i in ctx.inputs if i.source == "request"]
        made, marked, _ = attack_agent_tracker().before(
            ctx.ip, ctx.user, ctx.path or "/", headers, values, cfg, time.time(), ctx.agent_verified
        )
        if marked is None:
            return
        block = mode == "block"
        rule = f"attack_agent.{made['reason']}" if made else "attack_agent.marked"
        event_id = e.report_attack_agent(rule, block, made or marked, ctx.framework, ctx.method, None, ctx.path)
        if not block:
            return
        ctx.agents_scored = True  # the 429 is Shield360's own answer: never scored
        e.send_agent_verdict(ctx, marked["kind"], cfg.mark_ttl_seconds)
        raise DeterredError(rule, event_id, cfg.retry_after_seconds)
    except DeterredError:
        raise
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def agents_after(ctx: Any, status: Any) -> None:
    """Scores the request once the app answered with ``status``; marks, reports and (block) tells Edge. Never raises."""
    if ctx is None or not ctx.agents_checked or ctx.agents_scored:
        return
    ctx.agents_scored = True
    try:
        e = _engine
        mode = e.mode_for(ATTACK_AGENT)
        if mode == "off":
            return
        cfg = e.attack_agent_config()
        route = ctx.route
        if ctx.route_later is not None:
            try:
                route = ctx.route_later() or route
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        m = attack_agent_tracker().after(
            ctx.ip,
            ctx.user,
            ctx.path or "/",
            ctx.agent_headers or {},
            int(status),
            cfg,
            time.time(),
            route=route or None,
            finding=ctx.agent_finding,
            own=ctx.own_block,
            verified=ctx.agent_verified,
        )
        if m is None:
            return
        block = mode == "block"
        e.report_attack_agent("attack_agent.behavior", block, m, ctx.framework, ctx.method, route, ctx.path)
        if block:
            e.send_agent_verdict(ctx, m["kind"], cfg.mark_ttl_seconds)
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def check_tripwire(
    framework: str, method: str, path: str, ip: Optional[str], headers: Optional[Mapping[str, Any]] = None
) -> Any:
    """The tripwire URL ("Decision" 1): None when not a hit (or the client is
    left alone: Edge verified it, or it is the red team); else the deter
    error in block mode, or True (answer 404). Never raises."""
    try:
        e = _engine
        mode = e.mode_for(ATTACK_AGENT)
        if mode == "off":
            return None
        cfg = e.attack_agent_config()
        if not cfg.tripwire or not hits_tripwire(path, cfg) or _verified_early(method, path, headers or {}):
            return None
        made, _, _ = attack_agent_tracker().before(ip, None, path, {}, (), cfg, time.time())
        block = mode == "block"
        event_id = e.report_attack_agent("attack_agent.tripwire", block, made, framework, method, None, path)
        return DeterredError("attack_agent.tripwire", event_id, cfg.retry_after_seconds) if block else True
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def agents_decoy(
    framework: str, method: str, path: str, ip: Optional[str], headers: Optional[Mapping[str, Any]] = None
) -> Optional[str]:
    """A decoy hit: scores it (10 points), reports a behavior mark, and returns
    the tripwire page the 404 carries when the tripwire is on. Never raises."""
    try:
        e = _engine
        mode = e.mode_for(ATTACK_AGENT)
        if mode == "off":
            return None
        cfg = e.attack_agent_config()
        verified = _verified_early(method, path, headers or {})
        m = attack_agent_tracker().after(ip, None, path, headers or {}, 404, cfg, time.time(), decoy=True, verified=verified)
        if m is not None:
            e.report_attack_agent("attack_agent.behavior", mode == "block", m, framework, method, None, path)
        return tripwire_page_for(ip, cfg, verified)
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def decoy_verdict(method: str, path: str, ip: Optional[str], headers: Optional[Mapping[str, Any]], ttl_seconds: int) -> Optional[str]:
    """SHIELD: decoy and trap verdicts (README "Deception", "Protection
    triangle") — the verdict a decoy hit sends Edge: always block, whatever the
    app's own action (its answer to the request is unchanged), for the
    deception TTL. Edge's context is verified
    without a replay cache (the request never reaches the app). Never raises."""
    try:
        value = (headers or {}).get(CONTEXT_HEADER)
        r = _engine.remote_config()
        keys = r.edge_keys if r is not None else []
        if not value or not keys:
            return None
        rid = (headers or {}).get(REQUEST_ID_HEADER)
        edge = verify_edge_context(keys, _header_text(value), method, _path_only(path), _header_text(rid) or None, cache=None)
        return hit_verdict(keys, edge, ip, "block", "deception", "rasp", ttl_seconds)
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def _verified_early(method: str, path: str, headers: Mapping[str, Any]) -> bool:
    try:
        value = headers.get(CONTEXT_HEADER)
        if not value:
            return False
        r = _engine.remote_config()
        keys = r.edge_keys if r is not None else []
        rid = headers.get(REQUEST_ID_HEADER)
        edge = verify_edge_context(keys, _header_text(value), method, _path_only(path), _header_text(rid) or None, cache=None)
        return _left_alone(edge)
    except Exception:  # pylint: disable=broad-exception-caught
        return False

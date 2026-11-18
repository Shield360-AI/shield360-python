"""Shared-corpus runner (sdk/rasp/testdata, README "Fixtures"): runs one case
of a section through the detectors and returns what fired, if anything.
``request`` inputs go through the normalizer (percent-decoded forms added);
``model_output`` inputs through the model-output fragmenter.

Mirrors sdk/typescript/src/rasp/__tests__/corpus.ts.
"""

import base64
import json
import os
import platform
from typing import Any, Dict, List, Optional, Tuple

from shield360.rasp._detect import (
    detect_argv,
    detect_code,
    detect_command,
    detect_deserialization,
    detect_nosql,
    detect_path,
    detect_shell_spawn,
    detect_sql,
    detect_ssrf,
    detect_xml,
    detect_xss,
    shell_script_of,
)
from shield360.rasp._normalize import add_input, add_model_output, flatten
from shield360.rasp._template import detect_template
from shield360.rasp._types import Finding, RaspInput
from shield360.rasp._vpatch import BUILT_IN_RULES, VpRequest, match_virtual_patches

RASP_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "rasp"))
SECTIONS = ("sql", "nosql", "command", "path", "ssrf", "code", "xml", "deser", "xss", "requests", "template")


def load_json(rel: str) -> Any:
    with open(os.path.join(RASP_DIR, rel), encoding="utf-8") as f:
        return json.load(f)


def normalize(raw: Optional[List[Dict[str, str]]]) -> List[RaspInput]:
    out: List[RaspInput] = []
    for i in raw or []:
        if i.get("source") == "model_output":
            add_model_output(out, i["value"], i["key"])
        else:
            add_input(out, i["value"], i["key"])
    return out


def runtimes() -> List[Tuple[str, str]]:
    """The runtimes the request cases run under: this Python, and every runtime
    the rules name (at a version inside each of its runtimeVersions ranges and
    one outside them), so a Python run judges the node rules too."""
    out = [("python", platform.python_version())]
    for r in BUILT_IN_RULES:
        for rt in r.get("runtimes") or []:
            if (rt, "0.0.0") not in out:
                out.append((rt, "0.0.0"))
        for rt, ranges in (r.get("runtimeVersions") or {}).items():
            for rng in ranges:
                if (rt, str(rng[0])) not in out:
                    out.append((rt, str(rng[0])))
    return out


def run_case(section: str, c: Dict[str, Any]) -> Optional[Finding]:
    """Runs one case; returns the first finding (None = nothing fired)."""
    inputs = normalize(c.get("inputs"))
    if section == "sql":
        return detect_sql(c["query"], inputs, c.get("dialect") or "generic")
    if section == "nosql":
        ins: List[RaspInput] = []
        flatten(ins, c.get("body"), "body")
        flatten(ins, c.get("query"), "query")
        trees = [c.get("body"), c.get("query")]
        return detect_nosql(c["filter"], trees, ins) or (detect_nosql(c["update"], trees, ins) if c.get("update") else None)
    if section == "command":
        if isinstance(c.get("command"), str):
            return detect_command(c["command"], inputs) or detect_shell_spawn(command=c["command"], in_request=True)
        argv = c["argv"]
        script = shell_script_of(argv)
        return (
            detect_argv(argv, inputs)
            or (detect_command(script, inputs) if script else None)
            or detect_shell_spawn(argv0=argv[0], in_request=True)
        )
    if section == "path":
        return detect_path(c["path"], c.get("op") or "read", inputs, c.get("fileRoots") or [])
    if section == "ssrf":
        return detect_ssrf(c["url"], inputs, c.get("resolved") or [])
    if section == "code":
        return detect_code(c["code"], inputs)
    if section == "xml":
        return detect_xml(c["xml"], inputs, bool(c.get("resolvesExternal")))
    if section == "deser":
        data = base64.b64decode(c["data"]).decode("latin-1") if c.get("dataEncoding") == "base64" else c["data"]
        return detect_deserialization(c["format"], data, inputs)
    if section == "xss":
        return detect_xss(c.get("contentType"), c.get("body") or "", inputs)
    if section == "template":
        # Only the template source reaches the detector; ``data`` is never template source.
        return detect_template(c["template"], inputs, c["engine"])
    if section == "requests":
        req = VpRequest(
            method=c.get("method", "GET"),
            path=c.get("path", "/"),
            query=c.get("query", ""),
            headers=c.get("headers") or {},
            cookie=c.get("cookie", ""),
            body=c.get("body", ""),
        )
        for rt, version in runtimes():
            f = match_virtual_patches(req, BUILT_IN_RULES, "all", rt, version)
            if f:
                return f
        return None
    raise ValueError(f"unknown section {section}")


def request_for(rule: Dict[str, Any]) -> VpRequest:
    """A request that satisfies a rule's clauses, built from the rule itself."""
    req = VpRequest()
    for c in rule["match"]:
        values = c.get("values") or []
        value = values[0] if values else c.get("value", "x")
        target = c["target"]
        if target == "method":
            req.method = value
        elif target.startswith("header:"):
            req.headers[target[7:]] = "x" if c["op"] == "present" else value
        elif target in ("body", "request"):
            req.body += value
        elif target == "query":
            req.query += value
        elif target == "cookie":
            req.cookie += value
        elif target == "path":
            req.path = value
    return req


def rule_runtime(rule: Dict[str, Any]) -> Tuple[str, str]:
    """A runtime and version the rule applies in."""
    rts = rule.get("runtimes") or ["python"]
    rt = rts[0]
    ranges = (rule.get("runtimeVersions") or {}).get(rt)
    if ranges:
        return rt, str(ranges[0][0])
    return rt, platform.python_version() if rt == "python" else "0.0.0"

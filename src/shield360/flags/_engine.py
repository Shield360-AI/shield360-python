"""Shield360 feature flags: the evaluation engine, ported from TypeScript.

A faithful port of sdk/flags-core/src/engine.ts (the canonical engine, which
the TypeScript SDK and the server copy byte for byte). Every implementation is
held to sdk/flags-core/testdata/vectors.json, so the answers cannot drift:
change the TypeScript first, port the change here, and add vectors.

Pure: no I/O, no clock, no randomness. The same flag and context always give
the same answer, and the same bucket as every other SDK.
"""

import math
import re
from decimal import Decimal
from typing import Any, Dict, List, Optional

FLAG_TYPES = ("boolean", "string", "number", "json")

OPERATORS = (
    "equals",
    "not_equals",
    "in",
    "not_in",
    "contains",
    "starts_with",
    "lt",
    "lte",
    "gt",
    "gte",
    "semver_eq",
    "semver_lt",
    "semver_lte",
    "semver_gt",
    "semver_gte",
    "in_segment",
    "not_in_segment",
)

#: Segment operators: the attribute is the literal ``segment`` and the values are
#: segment keys. A condition naming an unknown (or invalid) segment never holds.
SEGMENT_OPERATORS = ("in_segment", "not_in_segment")
SEGMENT_ATTRIBUTE = "segment"

#: Buckets run 0..99,999: a rollout weight of 1 is a thousandth of a percent.
BUCKETS = 100000
DEFAULT_BUCKET_BY = "key"

#: Counts every implementation checks alike (lengths and sizes are the server's).
LIMITS = {"variations": 20, "rules": 50, "conditions": 20, "conditionValues": 100, "segmentsPerCondition": 20}

_FLAG_KEY = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?")
_VARIATION_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,39}")
_RULE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_ATTRIBUTE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
_SALT = re.compile(r"[A-Za-z0-9_-]{1,64}")
_NUMBER_TEXT = re.compile(r"-?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][-+]?[0-9]+)?")
_SEMVER = re.compile(
    r"v?(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?(?:\.(0|[1-9][0-9]*))?"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_NUMERIC_ID = re.compile(r"[0-9]+")

# A key that is absent, as opposed to present with JSON null (JavaScript's undefined).
_MISSING = object()


def _full(pattern, value) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def is_flag_key(value) -> bool:
    return _full(_FLAG_KEY, value)


def is_attribute_name(value) -> bool:
    return _full(_ATTRIBUTE, value)


def _is_bool(v) -> bool:
    return isinstance(v, bool)


def _is_number(v) -> bool:
    """A JavaScript number: int or float, never bool."""
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _is_record(v) -> bool:
    return isinstance(v, dict)


# ------------------------------------------------------------------ hashing


def _utf8(text: str) -> bytes:
    # A lone surrogate becomes U+FFFD, as the TypeScript engine (and TextEncoder) writes it.
    return "".join("�" if 0xD800 <= ord(ch) <= 0xDFFF else ch for ch in text).encode("utf-8")


def _rotl(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def murmur3(text: str) -> int:
    """MurmurHash3 (x86, 32-bit, seed 0) of the UTF-8 bytes of ``text``, unsigned."""
    data = _utf8(text)
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h = 0
    blocks = len(data) - (len(data) % 4)
    for i in range(0, blocks, 4):
        k = int.from_bytes(data[i : i + 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = _rotl(k, 15)
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = _rotl(h, 13)
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = len(data) % 4
    k = 0
    if tail == 3:
        k ^= data[blocks + 2] << 16
    if tail >= 2:
        k ^= data[blocks + 1] << 8
    if tail >= 1:
        k ^= data[blocks]
        k = (k * c1) & 0xFFFFFFFF
        k = _rotl(k, 15)
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h


def bucket_of(flag_key: str, salt: str, value: str) -> int:
    """The bucket (0..99,999) a value falls in for a flag: the same in every SDK."""
    return murmur3(flag_key + "." + salt + "." + value) % BUCKETS


# ----------------------------------------------------------- attribute text


def _js_number_text(v: float) -> str:
    """ECMAScript Number::toString for a finite number."""
    if v == 0:
        return "0"
    if isinstance(v, int):
        v = float(v)
    sign = "-" if v < 0 else ""
    # repr() is the shortest round-trip form; Decimal gives its digits and exponent.
    sign_bit, digits_tuple, exp = Decimal(repr(abs(v))).as_tuple()
    del sign_bit
    digits = "".join(str(d) for d in digits_tuple).lstrip("0") or "0"
    # Strip trailing zeros into the exponent.
    stripped = digits.rstrip("0")
    exp += len(digits) - len(stripped)
    digits = stripped
    k = len(digits)
    n = exp + k  # the value is 0.digits * 10**n
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return sign + mantissa + "e" + ("+" if e >= 0 else "-") + str(abs(e))


def text_of(v) -> Optional[str]:
    """The text of a scalar, the same in every SDK; None for anything else."""
    if isinstance(v, str):
        return v
    if _is_bool(v):
        return "true" if v else "false"
    if _is_number(v):
        if isinstance(v, int) and abs(v) < 2**53:
            return str(v)
        f = float(v)
        if not math.isfinite(f):
            return None
        return _js_number_text(f)
    return None


def number_of(v) -> Optional[float]:
    """A finite number, or the text of one (no spaces); None otherwise."""
    if _is_number(v):
        f = float(v)
        return f if math.isfinite(f) else None
    if isinstance(v, str) and _NUMBER_TEXT.fullmatch(v):
        try:
            f = float(v)
        except ValueError:
            return None
        return f if math.isfinite(f) else None
    return None


def parse_semver(v):
    """(major, minor, patch, [pre-release ids]); a missing minor or patch is 0."""
    if not isinstance(v, str):
        return None
    m = _SEMVER.fullmatch(v)
    if not m:
        return None
    return (
        int(m.group(1)),
        0 if m.group(2) is None else int(m.group(2)),
        0 if m.group(3) is None else int(m.group(3)),
        [] if m.group(4) is None else m.group(4).split("."),
    )


def compare_semver(a, b) -> int:
    """-1, 0 or 1, by semver precedence."""
    for i in range(3):
        if a[i] != b[i]:
            return -1 if a[i] < b[i] else 1
    pa, pb = a[3], b[3]
    if not pa or not pb:
        if len(pa) == len(pb):
            return 0
        return -1 if pa else 1
    for x, y in zip(pa, pb):
        if x == y:
            continue
        xn = _NUMERIC_ID.fullmatch(x) is not None
        yn = _NUMERIC_ID.fullmatch(y) is not None
        if xn and yn:
            return -1 if int(x) < int(y) else 1
        if xn != yn:
            return -1 if xn else 1
        return -1 if x < y else 1
    if len(pa) == len(pb):
        return 0
    return -1 if len(pa) < len(pb) else 1


# ---------------------------------------------------------------- matching


_NUMBER_TESTS = {
    "lt": lambda n, w: n < w,
    "lte": lambda n, w: n <= w,
    "gt": lambda n, w: n > w,
    "gte": lambda n, w: n >= w,
}
_SEMVER_TESTS = {
    "semver_eq": lambda c: c == 0,
    "semver_lt": lambda c: c < 0,
    "semver_lte": lambda c: c <= 0,
    "semver_gt": lambda c: c > 0,
    "semver_gte": lambda c: c >= 0,
}


def _scalar_matches(op: str, actual, values) -> bool:  # pylint: disable=too-many-return-statements
    if op in ("equals", "in"):
        text = text_of(actual)
        return text is not None and any(text_of(v) == text for v in values)
    if op in ("contains", "starts_with"):
        text = text_of(actual)
        if text is None:
            return False
        for v in values:
            want = text_of(v)
            if want is None:
                continue
            if (want in text) if op == "contains" else text.startswith(want):
                return True
        return False
    if op in ("lt", "lte", "gt", "gte"):
        n = number_of(actual)
        if n is None:
            return False
        for v in values:
            w = number_of(v)
            if w is None:
                continue
            if _NUMBER_TESTS[op](n, w):
                return True
        return False
    if op in _SEMVER_TESTS:
        a = parse_semver(actual)
        if a is None:
            return False
        for v in values:
            b = parse_semver(v)
            if b is None:
                continue
            if _SEMVER_TESTS[op](compare_semver(a, b)):
                return True
        return False
    return False


_NEGATED = {"not_equals": "equals", "not_in": "in"}


def condition_matches(
    condition: Dict[str, Any], context: Dict[str, Any], segments: Optional[List[Dict[str, Any]]] = None
) -> bool:
    """A missing (or null) attribute never matches, negated operators included."""
    if condition["operator"] in SEGMENT_OPERATORS:
        return _segment_condition_matches(condition, context, segments)
    actual = context.get(condition["attribute"])
    if actual is None:
        return False
    items = actual if isinstance(actual, list) else [actual]
    if not items:
        return False
    positive = _NEGATED.get(condition["operator"])
    if positive:
        return not any(_scalar_matches(positive, item, condition["values"]) for item in items)
    return any(_scalar_matches(condition["operator"], item, condition["values"]) for item in items)


def find_segment(segments, key) -> Optional[Dict[str, Any]]:
    """The valid segment of this key among ``segments``, or None."""
    if not isinstance(segments, list) or not isinstance(key, str):
        return None
    for s in segments:
        if _is_record(s) and s.get("key") == key:
            return None if validate_segment(s) else s
    return None


def segment_matches(segment: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """Whether the context is in the segment: every one of its conditions holds."""
    if not segment["conditions"]:
        return False
    return all(
        c["operator"] not in SEGMENT_OPERATORS and condition_matches(c, context) for c in segment["conditions"]
    )


def _segment_condition_matches(condition, context, segments) -> bool:
    in_any = False
    for key in condition["values"]:
        segment = find_segment(segments, key)
        if segment is None:
            return False  # an unknown segment never matches, either way
        if segment_matches(segment, context):
            in_any = True
    return in_any if condition["operator"] == "in_segment" else not in_any


def rule_matches(
    rule: Dict[str, Any], context: Dict[str, Any], segments: Optional[List[Dict[str, Any]]] = None
) -> bool:
    if not rule["conditions"]:
        return False
    return all(condition_matches(c, context, segments) for c in rule["conditions"])


def segment_keys_of(flag) -> List[str]:
    """The segment keys a flag's rules name, each once, in order of first use."""
    keys: List[str] = []
    rules = flag.get("rules") if _is_record(flag) else None
    if not isinstance(rules, list):
        return keys
    for rule in rules:
        if not _is_record(rule) or not isinstance(rule.get("conditions"), list):
            continue
        for c in rule["conditions"]:
            if not _is_record(c) or c.get("operator") not in SEGMENT_OPERATORS or not isinstance(c.get("values"), list):
                continue
            for v in c["values"]:
                if isinstance(v, str) and v not in keys:
                    keys.append(v)
    return keys


def rollout_variation(flag: Dict[str, Any], rollout: Dict[str, Any], context: Dict[str, Any]):
    """(variation key, bucket) a rollout serves this context."""
    by = rollout.get("bucketBy") or DEFAULT_BUCKET_BY
    text = text_of(context.get(by))
    bucket = 0 if text is None else bucket_of(flag["key"], flag["salt"], text)
    upper = 0
    for w in rollout["weights"]:
        upper += w["weight"]
        if bucket < upper:
            return w["variation"], bucket
    last = rollout["weights"][-1] if rollout["weights"] else None
    return (last["variation"] if last else ""), bucket


# -------------------------------------------------------------- validation


def plain_json(v, depth: int = 0) -> bool:
    if depth > 20:
        return False
    if v is None or isinstance(v, (str, bool)):
        return True
    if _is_number(v):
        return math.isfinite(float(v))
    if isinstance(v, list):
        return all(plain_json(x, depth + 1) for x in v)
    if isinstance(v, dict):
        return all(isinstance(k, str) and plain_json(x, depth + 1) for k, x in v.items())
    return False


def value_matches_type(flag_type: str, value) -> bool:
    if flag_type == "boolean":
        return _is_bool(value)
    if flag_type == "string":
        return isinstance(value, str)
    if flag_type == "number":
        return _is_number(value) and math.isfinite(float(value))
    if flag_type == "json":
        return value is not _MISSING and plain_json(value)
    return False


def _is_int_weight(w) -> bool:
    if not _is_number(w):
        return False
    if isinstance(w, float) and not w.is_integer():
        return False
    return 0 <= w <= BUCKETS


def _validate_serve(serve, path: str, keys: List[str], errors: List[Dict[str, str]]) -> None:
    if not _is_record(serve):
        errors.append({"path": path, "code": "serve_invalid"})
        return
    has_variation = serve.get("variation", _MISSING) is not _MISSING
    has_rollout = serve.get("rollout", _MISSING) is not _MISSING
    if has_variation == has_rollout:
        errors.append({"path": path, "code": "serve_invalid"})
        return
    if has_variation:
        if not isinstance(serve["variation"], str) or serve["variation"] not in keys:
            errors.append({"path": path + ".variation", "code": "variation_unknown"})
        return
    rollout = serve["rollout"]
    if not _is_record(rollout) or not isinstance(rollout.get("weights"), list) or not rollout["weights"]:
        errors.append({"path": path + ".rollout", "code": "rollout_invalid"})
        return
    bucket_by = rollout.get("bucketBy", _MISSING)
    if bucket_by is not _MISSING and not is_attribute_name(bucket_by):
        errors.append({"path": path + ".rollout.bucketBy", "code": "attribute_invalid"})
    if len(rollout["weights"]) > LIMITS["variations"]:
        errors.append({"path": path + ".rollout.weights", "code": "too_many"})
    total = 0
    seen: List[str] = []
    for i, w in enumerate(rollout["weights"]):
        at = f"{path}.rollout.weights.{i}"
        if not _is_record(w):
            errors.append({"path": at, "code": "rollout_invalid"})
            continue
        variation = w.get("variation", _MISSING)
        if not isinstance(variation, str) or variation not in keys:
            errors.append({"path": at + ".variation", "code": "variation_unknown"})
        elif variation in seen:
            errors.append({"path": at + ".variation", "code": "duplicate"})
        else:
            seen.append(variation)
        weight = w.get("weight", _MISSING)
        if not _is_int_weight(weight):
            errors.append({"path": at + ".weight", "code": "weight_invalid"})
        else:
            total += weight
    if total != BUCKETS:
        errors.append({"path": path + ".rollout.weights", "code": "weights_sum"})


def _validate_condition(  # pylint: disable=too-many-branches
    c, path: str, errors: List[Dict[str, str]], in_segment: bool = False
) -> None:
    if not _is_record(c):
        errors.append({"path": path, "code": "condition_invalid"})
        return
    op = c.get("operator", _MISSING)
    if isinstance(op, str) and op in SEGMENT_OPERATORS:
        if in_segment:
            errors.append({"path": path + ".operator", "code": "segment_nested"})
            return
        if c.get("attribute", _MISSING) != SEGMENT_ATTRIBUTE:
            errors.append({"path": path + ".attribute", "code": "attribute_invalid"})
        keys = c.get("values", _MISSING)
        if not isinstance(keys, list) or not keys or len(keys) > LIMITS["segmentsPerCondition"]:
            errors.append({"path": path + ".values", "code": "values_invalid"})
            return
        seen: List[str] = []
        for i, v in enumerate(keys):
            if not is_flag_key(v):
                errors.append({"path": f"{path}.values.{i}", "code": "value_not_segment"})
            elif v in seen:
                errors.append({"path": f"{path}.values.{i}", "code": "duplicate"})
            else:
                seen.append(v)
        return
    if not is_attribute_name(c.get("attribute", _MISSING)):
        errors.append({"path": path + ".attribute", "code": "attribute_invalid"})
    op = c.get("operator", _MISSING)
    if not isinstance(op, str) or op not in OPERATORS:
        errors.append({"path": path + ".operator", "code": "operator_invalid"})
    values = c.get("values", _MISSING)
    if not isinstance(values, list) or not values or len(values) > LIMITS["conditionValues"]:
        errors.append({"path": path + ".values", "code": "values_invalid"})
        return
    if op in ("equals", "not_equals") and len(values) != 1:
        errors.append({"path": path + ".values", "code": "values_invalid"})
    op_text = op if isinstance(op, str) else ""
    for i, v in enumerate(values):
        at = f"{path}.values.{i}"
        scalar = isinstance(v, str) or _is_bool(v) or (_is_number(v) and math.isfinite(float(v)))
        if not scalar:
            errors.append({"path": at, "code": "value_invalid"})
            continue
        if op_text in ("lt", "lte", "gt", "gte") and number_of(v) is None:
            errors.append({"path": at, "code": "value_not_number"})
        if op_text.startswith("semver_") and parse_semver(v) is None:
            errors.append({"path": at, "code": "value_not_semver"})


def validate_flag(f) -> List[Dict[str, str]]:  # pylint: disable=too-many-branches
    """Everything wrong with a flag definition, by path; empty when it is valid."""
    errors: List[Dict[str, str]] = []
    if not _is_record(f):
        return [{"path": "", "code": "flag_invalid"}]
    if not is_flag_key(f.get("key", _MISSING)):
        errors.append({"path": "key", "code": "key_invalid"})
    flag_type = f.get("type", _MISSING)
    known_type = isinstance(flag_type, str) and flag_type in FLAG_TYPES
    if not known_type:
        errors.append({"path": "type", "code": "type_invalid"})
    if not _is_bool(f.get("on", _MISSING)):
        errors.append({"path": "on", "code": "on_invalid"})
    if not _full(_SALT, f.get("salt", _MISSING)):
        errors.append({"path": "salt", "code": "salt_invalid"})
    archived = f.get("archived", _MISSING)
    if archived is not _MISSING and not _is_bool(archived):
        errors.append({"path": "archived", "code": "archived_invalid"})

    keys: List[str] = []
    variations = f.get("variations", _MISSING)
    if not isinstance(variations, list) or len(variations) < 2 or len(variations) > LIMITS["variations"]:
        errors.append({"path": "variations", "code": "variations_count"})
    else:
        for i, v in enumerate(variations):
            at = f"variations.{i}"
            if not _is_record(v):
                errors.append({"path": at, "code": "variation_invalid"})
                continue
            key = v.get("key", _MISSING)
            if not _full(_VARIATION_KEY, key):
                errors.append({"path": at + ".key", "code": "variation_key_invalid"})
            elif key in keys:
                errors.append({"path": at + ".key", "code": "duplicate"})
            else:
                keys.append(key)
            name = v.get("name", _MISSING)
            if name is not _MISSING and not isinstance(name, str):
                errors.append({"path": at + ".name", "code": "name_invalid"})
            if known_type and not value_matches_type(flag_type, v.get("value", _MISSING)):
                errors.append({"path": at + ".value", "code": "value_type"})
        variation_errors = any(e["path"].startswith("variations") for e in errors)
        if flag_type == "boolean" and not variation_errors:
            values = [v.get("value") for v in variations]
            if len(variations) != 2 or values[0] == values[1]:
                errors.append({"path": "variations", "code": "boolean_variations"})

    off = f.get("offVariation", _MISSING)
    if not isinstance(off, str) or off not in keys:
        errors.append({"path": "offVariation", "code": "variation_unknown"})

    rules = f.get("rules", _MISSING)
    if not isinstance(rules, list) or len(rules) > LIMITS["rules"]:
        errors.append({"path": "rules", "code": "rules_invalid"})
    else:
        ids: List[str] = []
        for i, r in enumerate(rules):
            at = f"rules.{i}"
            if not _is_record(r):
                errors.append({"path": at, "code": "rule_invalid"})
                continue
            rule_id = r.get("id", _MISSING)
            if not _full(_RULE_ID, rule_id):
                errors.append({"path": at + ".id", "code": "rule_id_invalid"})
            elif rule_id in ids:
                errors.append({"path": at + ".id", "code": "duplicate"})
            else:
                ids.append(rule_id)
            description = r.get("description", _MISSING)
            if description is not _MISSING and not isinstance(description, str):
                errors.append({"path": at + ".description", "code": "description_invalid"})
            conditions = r.get("conditions", _MISSING)
            if not isinstance(conditions, list) or not conditions or len(conditions) > LIMITS["conditions"]:
                errors.append({"path": at + ".conditions", "code": "conditions_count"})
            else:
                for j, c in enumerate(conditions):
                    _validate_condition(c, f"{at}.conditions.{j}", errors)
            _validate_serve(r.get("serve", _MISSING), at + ".serve", keys, errors)
    _validate_serve(f.get("fallthrough", _MISSING), "fallthrough", keys, errors)
    return errors


def validate_segment(segment) -> List[Dict[str, str]]:
    """Everything wrong with a segment, by path; empty when it is valid. Segments do not nest."""
    if not _is_record(segment):
        return [{"path": "", "code": "segment_invalid"}]
    errors: List[Dict[str, str]] = []
    if not is_flag_key(segment.get("key", _MISSING)):
        errors.append({"path": "key", "code": "key_invalid"})
    conditions = segment.get("conditions", _MISSING)
    if not isinstance(conditions, list) or not conditions or len(conditions) > LIMITS["conditions"]:
        errors.append({"path": "conditions", "code": "conditions_count"})
    else:
        for j, c in enumerate(conditions):
            _validate_condition(c, f"conditions.{j}", errors, True)
    return errors


# -------------------------------------------------------------- evaluation


def _malformed() -> Dict[str, Any]:
    return {"variation": None, "value": None, "reason": {"kind": "ERROR", "errorKind": "MALFORMED_FLAG"}}


def evaluate(
    flag: Dict[str, Any],
    context: Optional[Dict[str, Any]] = None,
    segments: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """The variation a flag serves a context, as {variation, value, reason}. Never raises.

    archived -> the off variation (ARCHIVED); off -> the off variation (OFF);
    on -> the first rule, in order, whose conditions all hold (RULE_MATCH),
    else the fallthrough (FALLTHROUGH). A malformed flag serves nothing (ERROR).
    ``segments`` are the environment's segments, for rules that name them.
    """
    try:
        if validate_flag(flag):
            return _malformed()
        ctx = context if isinstance(context, dict) else {}
        segs = segments if isinstance(segments, list) else []
        by_key = {v["key"]: v for v in flag["variations"]}

        def served(key: str, reason: Dict[str, Any]) -> Dict[str, Any]:
            return {"variation": key, "value": by_key[key]["value"], "reason": reason}

        if flag.get("archived"):
            return served(flag["offVariation"], {"kind": "ARCHIVED"})
        if not flag["on"]:
            return served(flag["offVariation"], {"kind": "OFF"})

        def serve(s: Dict[str, Any], reason: Dict[str, Any]) -> Dict[str, Any]:
            if s.get("variation", _MISSING) is not _MISSING:
                return served(s["variation"], reason)
            variation, bucket = rollout_variation(flag, s["rollout"], ctx)
            return served(variation, {**reason, "inRollout": True, "bucket": bucket})

        for i, rule in enumerate(flag["rules"]):
            if rule_matches(rule, ctx, segs):
                return serve(rule["serve"], {"kind": "RULE_MATCH", "ruleIndex": i, "ruleId": rule["id"]})
        return serve(flag["fallthrough"], {"kind": "FALLTHROUGH"})
    except Exception:  # pylint: disable=broad-exception-caught
        return _malformed()

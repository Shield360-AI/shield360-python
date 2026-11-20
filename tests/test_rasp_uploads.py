"""Uploads (sdk/rasp/README.md "Uploads"): the conformance corpus, fixture
files built here (never real malware: the shells are inert text and EICAR is
the industry's harmless test string), the policy, the deep scan against a fake
clamd on a Unix socket in both fail modes, the backdoor checks through the real
file, process, include and archive hooks, and Werkzeug's FileStorage.

Mirrors sdk/typescript/src/rasp/__tests__/uploads.test.ts.
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import socket
import stat
import struct
import subprocess
import tarfile
import threading
import zipfile

import pytest

from rasp_hook_kit import stop_engine, use_engine
from shield360.rasp import RaspBlockedError, inspect_upload
from shield360.rasp._context import RaspContext, reset_context, set_context
from shield360.rasp._hooks.files import install_file_hooks, uninstall_file_hooks
from shield360.rasp._hooks.include import install_include_hooks, uninstall_include_hooks
from shield360.rasp._hooks.process import install_process_hooks, uninstall_process_hooks
from shield360.rasp._hooks.uploads import install_upload_hooks, uninstall_upload_hooks
from shield360.rasp._upload import inspect_file_object
from shield360.rasp._upload_deep import SCANNER_EVENT, reset_scanner_status
from shield360.rasp._upload_inspect import has_double_extension, inspect_bytes, is_server_config_name, sniff_type, type_mismatch
from shield360.rasp._upload_policy import configure_uploads, parse_uploads_block, set_remote_uploads
from shield360.rasp._upload_signatures import SignatureError, compile_signature, compile_signatures, match_sample
from shield360.rasp._upload_taint import remember_location, reset_locations, upload_at

REPO = pathlib.Path(__file__).resolve().parents[3]
CORPUS = json.loads((REPO / "sdk/rasp/testdata/uploads.json").read_text(encoding="utf-8"))

EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x07" * 200
PNG = b"\x89PNG\r\n\x1a\n" + b"\x01" * 300
PDF = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"
CSV = b'name,amount,note\nalice,3,"on time"\nbob,5,late\n'
SHELL = b'<?php @eval($_POST["x"]); ?>'
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>steal()</script></svg>'


def zip_bytes(entries):
    """Real zips from the standard library; ``declared`` patches an entry's uncompressed size for the bomb case."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for e in entries:
            info = zipfile.ZipInfo(e["name"])
            if e.get("symlink"):
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, e.get("data", b"x"))
    data = bytearray(buf.getvalue())
    for e in entries:
        if "declared" in e or e.get("encrypted"):
            name = e["name"].encode()
            p = data.find(b"PK\x01\x02" + bytes(0))
            while p >= 0:
                n = struct.unpack_from("<H", data, p + 28)[0]
                if bytes(data[p + 46 : p + 46 + n]) == name:
                    if "declared" in e:
                        struct.pack_into("<I", data, p + 24, e["declared"])
                    if e.get("encrypted"):
                        struct.pack_into("<H", data, p + 8, struct.unpack_from("<H", data, p + 8)[0] | 1)
                p = data.find(b"PK\x01\x02", p + 4)
    return bytes(data)


def tar_bytes(name, kind=tarfile.REGTYPE):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
        info = tarfile.TarInfo(name)
        info.type = kind
        if kind == tarfile.SYMTYPE:
            info.linkname = "/etc/passwd"
            t.addfile(info)
        else:
            info.size = 1
            t.addfile(info, io.BytesIO(b"x"))
    return buf.getvalue()


def first(data, name=None, ctype=None):
    v = inspect_bytes(data, name, ctype)
    return v.findings[0].rule if v.findings else None


# ---- the corpus ---------------------------------------------------------------------


def test_signatures_file_is_byte_identical():
    here = REPO / "sdk/python/src/shield360/rasp/data/upload-signatures.json"
    assert here.read_bytes() == (REPO / "sdk/rasp/rules/upload-signatures.json").read_bytes()


def test_every_built_in_signature_compiles():
    for r in json.loads((REPO / "sdk/rasp/rules/upload-signatures.json").read_text(encoding="utf-8"))["rules"]:
        compile_signature(r)


@pytest.mark.parametrize("case", CORPUS["types"], ids=lambda c: c["type"])
def test_sniff(case):
    assert sniff_type(bytes.fromhex(case["hex"])) == case["type"]


@pytest.mark.parametrize("case", CORPUS["names"], ids=lambda c: c["name"])
def test_names(case):
    got = [r for r, ok in (("upload.server_config", is_server_config_name(case["name"])), ("upload.double_extension", has_double_extension(case["name"]))) if ok]
    assert sorted(got) == sorted(case["rules"])


@pytest.mark.parametrize("case", CORPUS["mismatch"])
def test_mismatch(case):
    assert type_mismatch(case["type"], case.get("name"), case.get("contentType")) is case["mismatch"]


@pytest.mark.parametrize("case", CORPUS["signatures"], ids=lambda c: c["rule"]["id"])
def test_signatures(case):
    sig = compile_signature(case["rule"])
    sample = b"x" * 1048570 + b"MARKERTEXT" + b"x" * 100 if case["sample"] == "@@ACROSS@@" else case["sample"].encode("utf-8")
    assert bool(match_sample([sig], sample)) is case["match"]


@pytest.mark.parametrize("case", CORPUS["invalid"], ids=lambda c: c["code"])
def test_invalid(case):
    with pytest.raises(SignatureError) as e:
        compile_signature(case["rule"])
    assert e.value.code == case["code"]


def test_caps_own_rules():
    one = {"id": "r", "title": "t", "strings": [{"id": "a", "text": "abc"}], "condition": "any"}
    assert compile_signatures([{**one, "id": f"r{i}"} for i in range(65)])[1] == ["too_many"]
    big = {**one, "title": "x" * 100, "strings": [{"id": f"s{i}", "text": "y" * 256} for i in range(16)]}
    assert compile_signatures([{**big, "id": f"b{i}"} for i in range(20)])[1] == ["too_large"]
    assert compile_signatures([one, one])[1] == ["duplicate_id"]


def test_regex_work_is_bounded():
    import time

    sig = compile_signature({"id": "r", "title": "t", "strings": [{"id": "a", "regex": "(a|aa)*b", "anchor": "aaa"}], "condition": "any"})
    started = time.monotonic()
    assert match_sample([sig], b"a" * (2 * 1024 * 1024)) == []
    assert time.monotonic() - started < 5


# ---- fixtures ------------------------------------------------------------------------


def test_image_with_embedded_php_shell():
    v = inspect_bytes(JPEG + SHELL + b"\x09" * 50, "profile.jpg", "image/jpeg")
    assert v.type == "jpeg"
    assert (v.findings[0].rule, v.findings[0].signature) == ("upload.webshell", "php.eval_request")
    assert "upload.polyglot" in [f.rule for f in v.findings]


def test_jpg_that_is_really_php():
    v = inspect_bytes(b'<?php system($_GET["c"]); ?>', "avatar.jpg", "image/jpeg")
    assert (v.findings[0].rule, v.findings[0].signature) == ("upload.webshell", "php.exec_request")
    plain = inspect_bytes(b'<?php echo "hello"; ?>', "avatar.jpg")
    assert (plain.type, plain.findings[0].rule) == ("php", "upload.script")


def test_svg():
    assert first(SVG, "logo.svg") == "upload.active_content"
    assert first(b'<svg xmlns="http://www.w3.org/2000/svg" onload="x()"></svg>', "logo.svg") == "upload.active_content"
    assert first(b'<svg xmlns="http://www.w3.org/2000/svg"><circle r="4"/></svg>', "logo.svg") is None


def test_archives():
    assert first(zip_bytes([{"name": "../../var/www/html/x.php"}]), "a.zip") == "upload.archive_traversal"
    assert first(zip_bytes([{"name": "link", "symlink": True}]), "a.zip") == "upload.archive_symlink"
    assert first(zip_bytes([{"name": "big.bin", "data": b"\x00" * 1000, "declared": 4000 * 1024 * 1024}]), "a.zip") == "upload.archive_bomb"
    assert first(zip_bytes([{"name": "secret.txt", "encrypted": True}]), "a.zip") == "upload.archive_encrypted"
    assert first(tar_bytes("../etc/cron.d/x"), "a.tar") == "upload.archive_traversal"
    assert first(tar_bytes("link", tarfile.SYMTYPE), "a.tar") == "upload.archive_symlink"


def test_macro_documents():
    docm = zip_bytes([{"name": "[Content_Types].xml", "data": b"<Types/>"}, {"name": "word/document.xml"}, {"name": "word/vbaProject.bin", "data": b"stub"}])
    v = inspect_bytes(docm, "report.docx")
    assert (v.type, v.findings[0].rule) == ("docx", "upload.office_macro")
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100 + "_VBA_PROJECT".encode("utf-16-le")
    assert first(ole, "old.doc") == "upload.office_macro"


def test_eicar_executables_config_names():
    assert first(EICAR, "test.txt") == "upload.eicar"
    assert first(EICAR + b"\r\n", "test.txt") == "upload.eicar"
    assert first(b"\x7fELF\x02\x01\x01\x00\x00\x00", "cat.png") == "upload.executable"
    assert first(b"AddType application/x-httpd-php .jpg\n", ".htaccess") == "upload.server_config"
    assert first(PNG, "shell.php.png") == "upload.double_extension"


@pytest.mark.parametrize("data,name,ctype", [(PDF, "invoice.pdf", "application/pdf"), (PNG, "photo.png", "image/png"), (JPEG, "me.jpg", "image/jpeg"), (CSV, "data.csv", "text/csv")])
def test_benign_files_pass(data, name, ctype):
    v = inspect_bytes(data, name, ctype)
    assert v.findings == []
    assert len(v.sha256) == 64


# ---- policy and events ----------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset():
    reset_locations()
    reset_scanner_status()
    configure_uploads(None)
    yield
    uninstall_file_hooks()
    uninstall_process_hooks()
    uninstall_include_hooks()
    uninstall_upload_hooks()
    stop_engine()


class _File(io.BytesIO):
    """A parser's file object (the attributes Werkzeug, Django and Starlette files share)."""

    def __init__(self, data, filename, content_type="application/octet-stream"):
        super().__init__(data)
        self.filename = filename
        self.content_type = content_type


def _upload_events(events):
    return [e for e in events if e["name"] == "shield360.rasp.event" and "upload" in e["attrs"]["shield360.rasp.attack"]]


def _request(fn, route="/api/avatar"):
    token = set_context(RaspContext(in_request=True, method="POST", path=route, framework="test"))
    try:
        return fn()
    finally:
        reset_context(token)


def test_event_attributes_never_carry_name_or_content():
    events = use_engine("monitor")
    _request(lambda: inspect_file_object("avatar", "profile.jpg", "image/jpeg", io.BytesIO(JPEG + SHELL)))
    e = _upload_events(events)[0]["attrs"]
    assert e["shield360.rasp.rule"] == "upload.webshell"
    assert e["shield360.rasp.input_key"] == "body.avatar.filename"
    assert e["shield360.rasp.upload.type"] == "jpeg" and e["shield360.rasp.upload.ext"] == "jpg"
    assert e["shield360.rasp.upload.signature"] == "php.eval_request"
    assert "profile" not in json.dumps(e) and "eval(" not in json.dumps(e)


def test_route_policy_and_its_mode():
    events = use_engine("monitor")
    set_remote_uploads({"routes": [{"route": "/api/avatar", "allow": ["image"], "maxBytes": 100, "mode": "block"}]})
    with pytest.raises(RaspBlockedError) as e:
        _request(lambda: inspect_file_object("f", "a.pdf", "application/pdf", io.BytesIO(PDF)))
    assert e.value.rule == "upload.type_not_allowed"
    with pytest.raises(RaspBlockedError) as e:
        _request(lambda: inspect_file_object("f", "a.png", "image/png", io.BytesIO(PNG)))
    assert e.value.rule == "upload.too_large"
    _request(lambda: inspect_file_object("f", "a.pdf", "application/pdf", io.BytesIO(PDF)), route="/api/docs")
    assert events


def test_route_mode_is_capped_without_a_pinned_key():
    events = use_engine("monitor", monitor_only=True)
    set_remote_uploads({"routes": [{"route": "/api/*", "allow": ["image"], "mode": "block"}]})
    _request(lambda: inspect_file_object("f", "a.pdf", "application/pdf", io.BytesIO(PDF)))
    assert _upload_events(events)[-1]["attrs"]["shield360.rasp.decision"] == "monitored"


def test_listed_type_gets_past_type_checks_only():
    use_engine("monitor", attacks={"malicious_upload": "block"})
    set_remote_uploads({"routes": [{"route": "/api/avatar", "allow": ["executable"]}]})
    _request(lambda: inspect_file_object("f", "tool.bin", None, io.BytesIO(b"\x7fELF\x02\x01\x01\x00")))
    with pytest.raises(RaspBlockedError) as e:
        _request(lambda: inspect_file_object("f", "a.jpg", None, io.BytesIO(SHELL)))
    assert e.value.rule == "upload.webshell"


def test_trusted_hash_and_own_signatures():
    events = use_engine("monitor")
    sha = inspect_bytes(SHELL).sha256
    set_remote_uploads({"trusted": [sha]})
    _request(lambda: inspect_file_object("f", "a.txt", None, io.BytesIO(SHELL)))
    assert not [e for e in _upload_events(events) if e["attrs"]["shield360.rasp.rule"] == "upload.webshell"]
    rules = [{"id": "acme.marker", "title": "ACME", "strings": [{"id": "a", "text": "ACME-INTERNAL-ONLY"}], "condition": "any"}]
    set_remote_uploads({"rules": rules})
    events.clear()
    _request(lambda: inspect_file_object("f", "a.txt", None, io.BytesIO(b"x ACME-INTERNAL-ONLY y")))
    assert _upload_events(events) == []
    set_remote_uploads({"rules": rules, "deepScan": {"mode": "block"}})
    with pytest.raises(RaspBlockedError) as e:
        _request(lambda: inspect_file_object("f", "a.txt", None, io.BytesIO(b"x ACME-INTERNAL-ONLY y")))
    assert e.value.rule == "upload.signature"


def test_uploads_block_bounds():
    c = parse_uploads_block(
        {
            "maxBytes": -1,
            "allow": ["image", "nonsense"],
            "servedDirs": ["relative/dir", "/srv/public"],
            "trusted": ["ABC", "a" * 64],
            "deepScan": {"mode": "block", "scan": "async", "timeoutMs": 999999, "failMode": "closed", "clamav": {"address": "tcp:clamav:3310"}, "reputation": True, "testId": "abcdefgh1"},
            "routes": [{"route": "no-slash"}, {"route": "/x", "deepScan": "monitor", "timeoutMs": 1}],
        }
    )
    assert c.max_bytes is None and c.allow == ["image"] and c.served_dirs == ["/srv/public"] and c.trusted == {"a" * 64}
    assert (c.deep_scan.mode, c.deep_scan.scan, c.deep_scan.timeout_ms, c.deep_scan.fail_mode, c.deep_scan.clamav, c.deep_scan.reputation) == ("block", "async", 60000, "closed", ("tcp", "clamav", 3310), True)
    assert c.routes == [{"route": "/x", "deep_scan": "monitor", "timeout_ms": 100}]
    assert parse_uploads_block({"deepScan": {"clamav": {"address": "unix:relative"}}}).deep_scan.clamav is None


# ---- deep scan ---------------------------------------------------------------------------


@pytest.fixture(name="clamd")
def _clamd():
    """A fake clamd on a Unix socket; set ``.found`` to a signature name for a hit."""
    import tempfile

    short = tempfile.mkdtemp(prefix="s3c", dir="/tmp")  # AF_UNIX paths are short
    sock_path = os.path.join(short, "c.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(8)
    state = {"found": None, "path": sock_path}

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            with c:
                buf = b""
                while True:
                    d = c.recv(65536)
                    if not d:
                        break
                    buf += d
                    if buf.startswith(b"zPING\x00"):
                        c.sendall(b"PONG\x00")
                        break
                    if buf.startswith(b"zINSTREAM\x00"):
                        p, done = 10, False
                        while p + 4 <= len(buf):
                            n = struct.unpack_from(">I", buf, p)[0]
                            if n == 0:
                                done = True
                                break
                            p += 4 + n
                        if done:
                            c.sendall((f"stream: {state['found']} FOUND\x00" if state["found"] else "stream: OK\x00").encode())
                            break

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield state
    srv.close()
    import shutil

    shutil.rmtree(short, ignore_errors=True)


def test_clamav_hit_blocks_synchronously(clamd):
    events = use_engine("monitor")
    clamd["found"] = "Win.Test.EICAR_HDB-1"
    configure_uploads({"deep_scan": {"mode": "block", "clamav": f"unix:{clamd['path']}"}})
    with pytest.raises(RaspBlockedError) as e:
        inspect_upload(b"anything", "x.txt")
    assert e.value.rule == "upload.malware"
    a = _upload_events(events)[-1]["attrs"]
    assert (a["shield360.rasp.upload.engine"], a["shield360.rasp.upload.signature"], a["shield360.rasp.sink"]) == ("clamav", "Win.Test.EICAR_HDB-1", "upload.deep_scan")


def test_clean_file_passes(clamd):
    events = use_engine("monitor")
    configure_uploads({"deep_scan": {"mode": "block", "clamav": f"unix:{clamd['path']}"}})
    assert inspect_upload(PNG, "a.png").type == "png"
    assert [e for e in events if e["name"] == SCANNER_EVENT][0]["attrs"]["shield360.rasp.scanner.status"] == "ok"


def test_scanner_down_fail_open(tmp_path):
    events = use_engine("monitor")
    configure_uploads({"deep_scan": {"mode": "block", "clamav": f"unix:{tmp_path}/missing.sock", "fail_mode": "open", "timeout_ms": 500}})
    inspect_upload(PNG, "a.png")
    status = [e for e in events if e["name"] == SCANNER_EVENT][0]["attrs"]
    assert (status["shield360.rasp.scanner.status"], status["shield360.rasp.scanner.fail_mode"]) == ("unreachable", "open")
    assert _upload_events(events) == []


def test_scanner_down_fail_closed(tmp_path):
    events = use_engine("monitor")
    configure_uploads({"deep_scan": {"mode": "block", "clamav": f"unix:{tmp_path}/missing.sock", "fail_mode": "closed", "timeout_ms": 500}})
    with pytest.raises(RaspBlockedError) as e:
        inspect_upload(PNG, "a.png")
    assert e.value.rule == "upload.scan_unavailable"
    configure_uploads({"deep_scan": {"mode": "monitor", "clamav": f"unix:{tmp_path}/missing.sock", "fail_mode": "closed", "timeout_ms": 500}})
    inspect_upload(PNG, "a.png")
    assert _upload_events(events)[-1]["attrs"]["shield360.rasp.decision"] == "monitored"


def test_async_scan_quarantines(clamd, tmp_path):
    events = use_engine("monitor")
    clamd["found"] = "Eicar-Test-Signature"
    q = tmp_path / "quarantine"
    configure_uploads({"deep_scan": {"mode": "block", "scan": "async", "clamav": f"unix:{clamd['path']}"}, "quarantine_dir": str(q)})
    saved = tmp_path / "upload.bin"
    saved.write_bytes(b"inert fixture")
    inspect_upload(str(saved), "upload.bin")
    assert not saved.exists()
    moved = list(q.iterdir())
    assert len(moved) == 1 and stat.S_IMODE(moved[0].stat().st_mode) == 0o600
    assert _upload_events(events)[-1]["attrs"]["shield360.rasp.upload.action"] == "quarantined"


# ---- backdoor checks ------------------------------------------------------------------------


@pytest.fixture(name="dirs")
def _dirs(tmp_path):
    (tmp_path / "public").mkdir()
    (tmp_path / "private").mkdir()
    install_file_hooks()
    install_process_hooks()
    return tmp_path


def _with_upload(name, data, fn):
    def run():
        inspect_file_object("avatar", name, None, io.BytesIO(data))
        return fn()

    return _request(run)


def test_active_upload_into_web_root_is_blocked(dirs):
    events = use_engine("monitor", attacks={"upload_backdoor": "block"})
    dest = dirs / "public" / "avatar.svg"
    with pytest.raises(RaspBlockedError) as e:
        _with_upload("avatar.svg", SVG, lambda: dest.write_bytes(SVG))
    assert e.value.rule == "backdoor.write_served"
    assert not dest.exists()
    hit = [x for x in events if x["attrs"]["shield360.rasp.rule"] == "backdoor.write_served"][0]["attrs"]
    assert hit["shield360.rasp.upload.dest"] and "avatar" not in hit["shield360.rasp.upload.dest"]


def test_rename_to_executable_name_is_blocked(dirs):
    use_engine("monitor", attacks={"upload_backdoor": "block"})
    tmp = dirs / "private" / "notes.txt"
    _with_upload("notes.txt", b"text", lambda: tmp.write_bytes(b"text"))
    assert upload_at(str(tmp)) is not None
    with pytest.raises(RaspBlockedError) as e:
        os.rename(tmp, dirs / "public" / "x.php")
    assert e.value.rule == "backdoor.write_executable"


def test_exec_of_upload_is_blocked(dirs):
    use_engine("monitor")
    dest = dirs / "private" / "tool"
    _with_upload("tool", b"#!/bin/sh\necho owned\n", lambda: dest.write_bytes(b"#!/bin/sh\necho owned\n"))
    use_engine("monitor", attacks={"upload_backdoor": "block"})
    for call in (lambda: subprocess.run([str(dest)], check=False), lambda: subprocess.run(["/bin/sh", str(dest)], check=False), lambda: subprocess.run(f'sh "{dest}"', shell=True, check=False)):
        with pytest.raises(RaspBlockedError) as e:
            call()
        assert e.value.rule == "backdoor.exec"


def test_chmod_x_on_upload_is_blocked(dirs):
    use_engine("monitor")
    dest = dirs / "private" / "blob"
    _with_upload("blob", b"data", lambda: dest.write_bytes(b"data"))
    use_engine("monitor", attacks={"upload_backdoor": "block"})
    with pytest.raises(RaspBlockedError) as e:
        os.chmod(dest, 0o755)
    assert e.value.rule == "backdoor.chmod"
    os.chmod(dest, 0o644)


def test_run_path_of_upload_is_blocked(dirs):
    import runpy

    install_include_hooks()
    p = dirs / "private" / "plugin.py"
    p.write_text("RESULT = 1\n", encoding="utf-8")
    remember_location(str(p), inspect_bytes(b"RESULT = 1\n", "plugin.py"))
    use_engine("monitor", attacks={"upload_backdoor": "block"})
    with pytest.raises(RaspBlockedError) as e:
        runpy.run_path(str(p))
    assert e.value.rule == "backdoor.include"


def test_extracting_a_zip_slip_upload_is_blocked(dirs):
    install_upload_hooks()
    archive = dirs / "private" / "bundle.zip"
    data = zip_bytes([{"name": "../escape.txt"}])
    archive.write_bytes(data)
    remember_location(str(archive), inspect_bytes(data, "bundle.zip"))
    use_engine("monitor", attacks={"upload_backdoor": "block"})
    with pytest.raises(RaspBlockedError) as e:
        with zipfile.ZipFile(archive) as z:
            z.extractall(dirs / "out")
    assert e.value.rule == "backdoor.extract"


def test_benign_upload_to_private_storage_passes(dirs):
    events = use_engine("monitor", attacks={"upload_backdoor": "block", "malicious_upload": "block"})
    dest = dirs / "private" / "photo.png"
    _with_upload("photo.png", PNG, lambda: dest.write_bytes(PNG))
    assert dest.exists()
    assert _upload_events(events) == []


def test_werkzeug_filestorage_save_into_web_root_is_blocked(dirs):
    werkzeug = pytest.importorskip("werkzeug.datastructures")
    install_upload_hooks()
    use_engine("monitor", attacks={"upload_backdoor": "block"})
    fs = werkzeug.FileStorage(stream=io.BytesIO(SHELL), filename="shell.php", name="avatar")
    with pytest.raises(RaspBlockedError) as e:
        _request(lambda: fs.save(str(dirs / "public" / "shell.php")))
    assert e.value.rule == "backdoor.write_executable"
    assert not (dirs / "public" / "shell.php").exists()
    benign = werkzeug.FileStorage(stream=io.BytesIO(PNG), filename="me.png", name="avatar")
    _request(lambda: benign.save(str(dirs / "private" / "me.png")))
    assert (dirs / "private" / "me.png").exists()

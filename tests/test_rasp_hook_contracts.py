"""Every sink hook through the shared hook contract (rasp_hook_kit.py).
Triggers are the harmless ones the hooks' own tests use; third-party
libraries are small stand-in modules.

Mirrors sdk/typescript/src/rasp/__tests__/hook-contracts.test.ts.
"""

import asyncio
import builtins
import io
import marshal
import os
import pickle
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import types
import urllib.request
import http.client
import importlib
import xml.dom.minidom
import xml.etree.ElementTree
import xml.sax

from rasp_hook_kit import HookSpec, describe_hook_contract, names, req
from shield360.rasp import _detect, _sinks, _template
from shield360.rasp._hooks.code import install_code_hooks, uninstall_code_hooks
from shield360.rasp._hooks.db import install_db_hooks, uninstall_db_hooks
from shield360.rasp._hooks.files import OS_APIS as FILE_OS_APIS, SHUTIL_APIS, install_file_hooks, uninstall_file_hooks
from shield360.rasp._hooks.http import install_http_hooks, uninstall_http_hooks
from shield360.rasp._hooks.include import install_include_hooks, uninstall_include_hooks
from shield360.rasp._hooks.process import OS_APIS as PROCESS_OS_APIS, install_process_hooks, uninstall_process_hooks
from shield360.rasp._hooks.sinks import install_sink_hooks, uninstall_sink_hooks
from shield360.rasp._hooks.template import install_template_hooks, uninstall_template_hooks

TestProcessContract = describe_hook_contract(
    HookSpec(
        name="process",
        install=install_process_hooks,
        uninstall=uninstall_process_hooks,
        replaced=[(subprocess.Popen, "__init__")] + names(os, PROCESS_OS_APIS),
        trigger=lambda: subprocess.run("echo ok; echo rasp-test", shell=True, capture_output=True, check=False),
        inputs=[req("ok; echo rasp-test")],
        detector=(_detect, "detect_command"),
        attack="command_injection",
    )
)

_dirs = []


def _make_dir():
    d = tempfile.mkdtemp(prefix="rasp-kit-")
    os.mkdir(os.path.join(d, "child"))
    with open(os.path.join(d, "escape.txt"), "w", encoding="utf-8") as f:
        f.write("fixture")
    _dirs.append(d)


def _read_escape():
    with open(f"{_dirs[-1]}/child/../escape.txt", encoding="utf-8") as f:
        return f.read()


TestFilesContract = describe_hook_contract(
    HookSpec(
        name="files",
        install=install_file_hooks,
        uninstall=uninstall_file_hooks,
        replaced=[(builtins, "open"), (io, "open")] + names(os, FILE_OS_APIS) + names(shutil, SHUTIL_APIS),
        trigger=_read_escape,
        inputs=[req("../escape.txt")],
        detector=(_detect, "detect_path"),
        attack="path_traversal",
        before_each=_make_dir,
        after_each=lambda: shutil.rmtree(_dirs.pop(), ignore_errors=True),
    )
)

# Nothing listens on the discard port; the connection is refused at once.
LOCAL = "http://127.0.0.1:9/fixture"


def _local_request():
    urllib.request.urlopen(LOCAL, timeout=2)  # pylint: disable=consider-using-with


TestOutboundHttpContract = describe_hook_contract(
    HookSpec(
        name="outbound_http",
        install=lambda: install_http_hooks([]),
        uninstall=uninstall_http_hooks,
        replaced=[
            (urllib.request.OpenerDirector, "open"),
            (http.client.HTTPConnection, "putrequest"),
            (http.client.HTTPConnection, "connect"),
            (socket, "getaddrinfo"),
            (asyncio.base_events.BaseEventLoop, "getaddrinfo"),
        ],
        trigger=_local_request,
        inputs=[req(LOCAL)],
        detector=(_detect, "detect_ssrf"),
        attack="ssrf",
    )
)

INJECTION = "' OR '1'='1"
QUERY = f"SELECT 1 WHERE 'x' = '{INJECTION}'"


def _sqlite_query():
    conn = sqlite3.connect(":memory:")
    try:
        return conn.execute(QUERY).fetchall()
    finally:
        conn.close()


TestDatabaseSqlite3Contract = describe_hook_contract(
    HookSpec(
        name="database_sqlite3",
        install=install_db_hooks,
        uninstall=uninstall_db_hooks,
        replaced=[(sqlite3, "connect"), (sqlite3.dbapi2, "connect")],
        trigger=_sqlite_query,
        inputs=[req(INJECTION)],
        detector=(_detect, "detect_sql"),
        attack="sql_injection",
    )
)


class FakeCursor:
    """Stands in for pymysql's cursor class."""

    def execute(self, query, args=None):
        return (query, args)

    def executemany(self, query, args):
        return [self.execute(query, a) for a in args]


_fake_pymysql = types.ModuleType("pymysql")
_fake_pymysql_cursors = types.ModuleType("pymysql.cursors")
_fake_pymysql_cursors.Cursor = FakeCursor
_fake_pymysql.cursors = _fake_pymysql_cursors


def _add_fake_pymysql():
    sys.modules["pymysql"] = _fake_pymysql
    sys.modules["pymysql.cursors"] = _fake_pymysql_cursors


def _drop_fake_pymysql():
    sys.modules.pop("pymysql.cursors", None)
    sys.modules.pop("pymysql", None)


TestDatabaseCursorClassContract = describe_hook_contract(
    HookSpec(
        name="database_cursor_class",
        install=install_db_hooks,
        uninstall=uninstall_db_hooks,
        replaced=[(FakeCursor, "execute"), (FakeCursor, "executemany")],
        trigger=lambda: FakeCursor().execute(f"SELECT * FROM products WHERE name = '{INJECTION}'"),
        inputs=[req(INJECTION)],
        detector=(_detect, "detect_sql"),
        attack="sql_injection",
        before_each=_add_fake_pymysql,
        after_each=_drop_fake_pymysql,
    )
)

PICKLED = pickle.dumps(1)
assert marshal and xml.dom.minidom and xml.sax  # loaded, so the code hook patches them

TestCodeContract = describe_hook_contract(
    HookSpec(
        name="code",
        install=install_code_hooks,
        uninstall=uninstall_code_hooks,
        replaced=[
            (pickle, "loads"),
            (pickle, "load"),
            (marshal, "loads"),
            (xml.etree.ElementTree, "fromstring"),
            (xml.etree.ElementTree, "XML"),
            (xml.dom.minidom, "parseString"),
            (xml.sax, "parseString"),
        ],
        trigger=lambda: pickle.loads(PICKLED),
        inputs=[req(PICKLED.decode("latin-1"), "body.blob")],
        detector=(_detect, "detect_deserialization"),
        attack="deserialization",
    )
)

TestIncludeContract = describe_hook_contract(
    HookSpec(
        name="include",
        install=install_include_hooks,
        uninstall=uninstall_include_hooks,
        replaced=[(importlib, "import_module"), (builtins, "__import__")],
        trigger=lambda: importlib.import_module("json"),
        inputs=[req("json", "query.module")],
        detector=(_detect, "detect_include"),
        attack="code_injection",
    )
)

_kit_driver = types.ModuleType("rasp_kit_driver")


def _kit_query(sql):
    return sql


_kit_driver.query = _kit_query
KIT_RULE = _sinks.parse_sink_rule(
    {"id": "sink.kit.query", "module": "rasp_kit_driver", "target": "query", "check": "sql", "action": "block"}
)


def _install_sinks():
    sys.modules["rasp_kit_driver"] = _kit_driver
    _sinks.set_sink_rules([KIT_RULE])
    return install_sink_hooks()


def _uninstall_sinks():
    uninstall_sink_hooks()
    _sinks.set_sink_rules(_sinks.BUILT_IN_SINKS)


TestSinkRulesContract = describe_hook_contract(
    HookSpec(
        name="sink_rules",
        install=_install_sinks,
        uninstall=_uninstall_sinks,
        replaced=[(_kit_driver, "query")],
        trigger=lambda: _kit_driver.query(f"SELECT * FROM products WHERE name = '{INJECTION}'"),
        inputs=[req(INJECTION)],
        detector=(_detect, "detect_sql"),
        attack="sql_injection",
        after_each=lambda: sys.modules.pop("rasp_kit_driver", None),
    )
)


# Stand-ins shaped like the engines' entry points (Template(...) delegating to from_string, as Jinja2 and Django do).


class FakeJinjaEnvironment:
    def from_string(self, source, globals=None, template_class=None):  # pylint: disable=redefined-builtin,unused-argument
        return ("jinja2", source)


class FakeJinjaTemplate:
    def __new__(cls, source, **options):  # pylint: disable=unused-argument
        return FakeJinjaEnvironment().from_string(source, template_class=cls)


class FakeMakoTemplate:
    def __init__(self, text=None, filename=None, **options):  # pylint: disable=unused-argument
        self.text = text


class FakeDjangoTemplate:
    def __init__(self, template_string, origin=None, name=None, engine=None):  # pylint: disable=unused-argument
        self.source = template_string


class FakeDjangoEngine:
    def from_string(self, template_code):
        return FakeDjangoTemplate(template_code, engine=self)


_template_fakes = {}
for _name, _attrs in (
    ("jinja2.environment", {"Environment": FakeJinjaEnvironment, "Template": FakeJinjaTemplate}),
    ("mako.template", {"Template": FakeMakoTemplate}),
    ("django.template.base", {"Template": FakeDjangoTemplate}),
    ("django.template.engine", {"Engine": FakeDjangoEngine}),
):
    _template_fakes[_name] = types.ModuleType(_name)
    for _key, _value in _attrs.items():
        setattr(_template_fakes[_name], _key, _value)
_saved_template_modules = {}


def _add_template_fakes():
    for name, module in _template_fakes.items():
        _saved_template_modules[name] = sys.modules.get(name)
        sys.modules[name] = module


def _drop_template_fakes():
    for name, module in _saved_template_modules.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module
    _saved_template_modules.clear()


TestTemplateContract = describe_hook_contract(
    HookSpec(
        name="template",
        install=install_template_hooks,
        uninstall=uninstall_template_hooks,
        replaced=[
            (FakeJinjaTemplate, "__new__"),
            (FakeJinjaEnvironment, "from_string"),
            (FakeMakoTemplate, "__init__"),
            (FakeDjangoTemplate, "__init__"),
            (FakeDjangoEngine, "from_string"),
        ],
        trigger=lambda: FakeJinjaTemplate("Hello {{ 7 * 7 }}"),
        inputs=[req("{{ 7 * 7 }}")],
        detector=(_template, "detect_template"),
        attack="code_injection",
        before_each=_add_template_fakes,
        after_each=_drop_template_fakes,
    )
)

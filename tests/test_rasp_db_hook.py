"""Database sink hook: sqlite3 (a built-in cursor type, through connection
factories), drivers with Python cursor classes, psycopg2, SQLAlchemy text
execution and pymongo collections. sqlite3 runs in memory; the other
libraries are small stand-in modules.

Mirrors sdk/typescript/src/rasp/__tests__/db-hook.test.ts.
"""

import sqlite3
import sys
import types

import pytest

from rasp_hook_kit import in_request, stop_engine, use_engine
from shield360.rasp import RaspBlockedError, _detect
from shield360.rasp._hooks._imports import forget, when_imported
from shield360.rasp._hooks.db import install_db_hooks, uninstall_db_hooks

INJECTION = "' OR '1'='1"
QUERY = f"SELECT 1 WHERE 'x' = '{INJECTION}'"


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    uninstall_db_hooks()
    stop_engine()


# ---- sqlite3 ---------------------------------------------------------------------


def test_sqlite3_execute_is_blocked_and_bound_parameters_pass():
    events = use_engine("block")
    install_db_hooks()
    conn = sqlite3.connect(":memory:")
    assert isinstance(conn, sqlite3.Connection)
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: conn.execute(QUERY))
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: conn.cursor().execute(QUERY))
    assert in_request([INJECTION], lambda: conn.execute("SELECT ?", (INJECTION,)).fetchone()) == (INJECTION,)
    assert events.sinks() == ["sqlite3.Connection.execute", "sqlite3.Cursor.execute"]
    conn.close()


def test_sqlite3_cursors_are_real_cursors_and_custom_factories_are_kept():
    use_engine("monitor")
    install_db_hooks()

    class MyConnection(sqlite3.Connection):
        marker = "mine"

    class MyCursor(sqlite3.Cursor):
        pass

    conn = sqlite3.connect(":memory:", factory=MyConnection)
    assert isinstance(conn, MyConnection) and conn.marker == "mine"
    cur = conn.cursor(MyCursor)
    assert isinstance(cur, MyCursor) and isinstance(cur, sqlite3.Cursor)
    # A built-in C function that insists on a real connection accepts it.
    other = sqlite3.connect(":memory:")
    conn.backup(other)
    conn.close()
    other.close()


def test_sqlite3_monitor_reports_once_and_runs_the_query():
    events = use_engine("monitor")
    install_db_hooks()
    conn = sqlite3.connect(":memory:")
    assert in_request([INJECTION], lambda: conn.execute(QUERY).fetchall()) == [(1,)]
    assert in_request([INJECTION], lambda: conn.executescript(f"SELECT 1 WHERE 'x' = '{INJECTION}';")) is not None
    assert events.attacks() == [
        ("sql_injection", "sqli.userinput", "monitored"),
        ("sql_injection", "sqli.userinput", "monitored"),
    ]
    conn.close()


def test_off_and_no_context_skip_detection(monkeypatch):
    calls = []
    monkeypatch.setattr(_detect, "detect_sql", lambda *a: calls.append(a))
    use_engine("block")
    install_db_hooks()
    conn = sqlite3.connect(":memory:")
    conn.execute(QUERY)
    stop_engine()
    in_request([INJECTION], lambda: conn.execute(QUERY))
    assert not calls
    conn.close()


def test_open_connections_stop_checking_after_uninstall():
    events = use_engine("block")
    install_db_hooks()
    conn = sqlite3.connect(":memory:")
    uninstall_db_hooks()
    assert in_request([INJECTION], lambda: conn.execute(QUERY).fetchall()) == [(1,)]
    assert not events
    conn.close()


def test_detector_errors_fail_open(monkeypatch):
    events = use_engine("block")

    def broken(*a):
        raise RuntimeError("boom")

    monkeypatch.setattr(_detect, "detect_sql", broken)
    install_db_hooks()
    conn = sqlite3.connect(":memory:")
    assert in_request([INJECTION], lambda: conn.execute(QUERY).fetchall()) == [(1,)]
    assert not events
    conn.close()


# ---- drivers with Python cursor classes ---------------------------------------


def _module(monkeypatch, name, **attrs):
    module = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(module, k, v)
    monkeypatch.setitem(sys.modules, name, module)
    return module


def test_a_driver_loaded_after_install_is_patched_on_import(monkeypatch, tmp_path):
    pkg = tmp_path / "MySQLdb"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "cursors.py").write_text(
        "class BaseCursor:\n"
        "    def execute(self, query, args=None):\n"
        "        return query\n"
        "    def executemany(self, query, args):\n"
        "        return [self.execute(query, a) for a in args]\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    events = use_engine("block")
    install_db_hooks()
    assert "MySQLdb.cursors" not in sys.modules
    import MySQLdb.cursors  # pylint: disable=import-outside-toplevel,import-error

    try:
        with pytest.raises(RaspBlockedError):
            in_request([INJECTION], lambda: MySQLdb.cursors.BaseCursor().executemany(QUERY, [1, 2]))
        # executemany calls execute for each row: one check for the logical call.
        assert events.sinks() == ["MySQLdb.BaseCursor.executemany"]
        assert MySQLdb.cursors.__loader__.__class__.__name__ != "_Loader"
    finally:
        sys.modules.pop("MySQLdb.cursors", None)
        sys.modules.pop("MySQLdb", None)


def test_psycopg3_async_cursors_get_async_wrappers(monkeypatch):
    import asyncio  # pylint: disable=import-outside-toplevel
    import inspect  # pylint: disable=import-outside-toplevel

    class Cursor:
        def execute(self, query, params=None):
            return query

    class AsyncCursor:
        async def execute(self, query, params=None):
            return query

    _module(monkeypatch, "psycopg", Cursor=Cursor, AsyncCursor=AsyncCursor)
    events = use_engine("block")
    install_db_hooks()
    assert inspect.iscoroutinefunction(AsyncCursor.execute)
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: asyncio.run(AsyncCursor().execute(QUERY)))
    assert in_request([INJECTION], lambda: asyncio.run(AsyncCursor().execute("SELECT %s"))) == "SELECT %s"
    assert events.sinks() == ["psycopg.AsyncCursor.execute"]


def test_psycopg2_gets_a_checking_connection_factory(monkeypatch):
    class Cursor:
        def __init__(self, conn, name=None):
            self.connection = conn

        def execute(self, query, vars=None):  # pylint: disable=redefined-builtin
            return query

    class Connection:
        cursor_factory = None

        def __init__(self, dsn):
            self.dsn = dsn

        def cursor(self, name=None, cursor_factory=None):
            return (cursor_factory or self.cursor_factory or Cursor)(self, name)

    def connect(dsn=None, connection_factory=None, cursor_factory=None):
        conn = (connection_factory or Connection)(dsn)
        if cursor_factory is not None:
            conn.cursor_factory = cursor_factory
        return conn

    extensions = _module(monkeypatch, "psycopg2.extensions", cursor=Cursor, connection=Connection)
    _module(monkeypatch, "psycopg2", connect=connect, extensions=extensions)
    events = use_engine("block")
    install_db_hooks()
    conn = sys.modules["psycopg2"].connect("dbname=x")
    assert isinstance(conn, Connection)
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: conn.cursor().execute(QUERY))
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: conn.cursor(cursor_factory=Cursor).execute(QUERY))
    assert events.sinks() == ["psycopg2.Cursor.execute", "psycopg2.Cursor.execute"]


# ---- SQLAlchemy --------------------------------------------------------------------


def test_sqlalchemy_text_is_checked_once_with_the_dialect(monkeypatch):
    inner = []

    class TextClause:
        __visit_name__ = "textclause"

        def __init__(self, text):
            self.text = text

    class Connection:
        dialect = types.SimpleNamespace(name="postgresql")

        def execute(self, statement, parameters=None):
            # What SQLAlchemy does underneath: the DB-API cursor.
            conn = sqlite3.connect(":memory:")
            try:
                inner.append(conn.execute(QUERY).fetchall())
            finally:
                conn.close()
            return statement

        def exec_driver_sql(self, statement, parameters=None):
            return statement

    _module(monkeypatch, "sqlalchemy.engine.base", Connection=Connection)
    events = use_engine("monitor")
    install_db_hooks()
    in_request([INJECTION], lambda: Connection().execute(TextClause(QUERY)))
    in_request([INJECTION], lambda: Connection().exec_driver_sql(QUERY))
    assert events.sinks() == ["sqlalchemy.Connection.execute", "sqlalchemy.Connection.exec_driver_sql"]
    assert inner == [[(1,)]]
    # A compiled ORM statement is left to the DB-API hook underneath.
    events.clear()
    in_request([INJECTION], lambda: Connection().execute(object()))
    assert events.sinks() == ["sqlite3.Connection.execute"]


# ---- pymongo ---------------------------------------------------------------------


class Collection:
    def find(self, filter=None, *args, **kwargs):  # pylint: disable=redefined-builtin,keyword-arg-before-vararg
        return [filter]

    def find_one(self, filter=None, *args, **kwargs):  # pylint: disable=redefined-builtin,keyword-arg-before-vararg
        return self.find(filter)[0]

    def update_one(self, filter, update, **kwargs):  # pylint: disable=redefined-builtin
        return update

    def aggregate(self, pipeline, **kwargs):
        return pipeline


def test_mongo_operator_injection_is_blocked_and_equality_passes(monkeypatch):
    _module(monkeypatch, "pymongo.collection", Collection=Collection)
    events = use_engine("block")
    install_db_hooks()
    attack = {"$ne": None}

    def query():
        return Collection().find_one({"user": "alice", "password": attack})

    with pytest.raises(RaspBlockedError) as e:
        in_request([], query, trees=[{"password": attack}])
    assert e.value.rule == "nosqli.operator"
    assert in_request(["alice"], lambda: Collection().find({"user": "alice"}), trees=[{"user": "alice"}]) == [{"user": "alice"}]
    with pytest.raises(RaspBlockedError):
        in_request([], lambda: Collection().aggregate([{"$match": {"a": 1}}, {"$match": {"b": attack}}]), trees=[{"b": attack}])
    with pytest.raises(RaspBlockedError):
        in_request([], lambda: Collection().update_one({"a": 1}, {"$set": attack}), trees=[attack])
    # find_one is covered through the find it calls: one check.
    assert events.sinks() == ["pymongo.Collection.find", "pymongo.Collection.aggregate", "pymongo.Collection.update_one"]


def test_double_install_wraps_once_and_uninstall_restores_identity(monkeypatch):
    _module(monkeypatch, "pymongo.collection", Collection=Collection)
    before = (vars(Collection)["find"], sqlite3.connect)
    install_db_hooks()
    first = (vars(Collection)["find"], sqlite3.connect)
    install_db_hooks()
    assert (vars(Collection)["find"], sqlite3.connect) == first
    assert first[0] is not before[0]
    uninstall_db_hooks()
    uninstall_db_hooks()
    assert (vars(Collection)["find"], sqlite3.connect) == before


def test_the_import_hook_runs_once_per_import_and_leaves_with_the_last_callback(monkeypatch, tmp_path):
    (tmp_path / "rasp_probe_mod.py").write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    seen = []
    when_imported("rasp_probe_mod", "probe", lambda m: seen.append(m.VALUE))
    try:
        import rasp_probe_mod  # pylint: disable=import-outside-toplevel,import-error,unused-import

        assert seen == [1]
        when_imported("rasp_probe_mod", "probe", lambda m: seen.append(2))
        assert seen == [1, 2]
    finally:
        forget("probe")
        sys.modules.pop("rasp_probe_mod", None)
    assert not any(type(f).__name__ == "_Finder" for f in sys.meta_path)


# ---- review fixes ------------------------------------------------------------------


def test_the_cursor_connection_execute_returns_checks_when_run_again():
    events = use_engine("block")
    install_db_hooks()
    conn = sqlite3.connect(":memory:")
    cur = conn.execute("SELECT 1")
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: cur.execute(QUERY))
    script = conn.executescript("SELECT 1;")
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: script.execute(QUERY))
    assert events.sinks() == ["sqlite3.Cursor.execute", "sqlite3.Cursor.execute"]
    conn.close()


def test_a_custom_connections_own_cursor_default_and_arguments_are_kept():
    events = use_engine("block")
    install_db_hooks()

    class TaggedCursor(sqlite3.Cursor):
        tag = None

    class TaggedConnection(sqlite3.Connection):
        def cursor(self, factory=TaggedCursor, tag=None):  # pylint: disable=arguments-differ
            cur = super().cursor(factory)
            cur.tag = tag
            return cur

    conn = sqlite3.connect(":memory:", factory=TaggedConnection)
    cur = conn.cursor(tag="mine")
    assert isinstance(cur, TaggedCursor) and cur.tag == "mine"
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: cur.execute(QUERY))
    # Connection.execute makes its cursor through the connection's own cursor().
    assert isinstance(conn.execute("SELECT 1"), TaggedCursor)
    assert events.sinks() == ["sqlite3.Cursor.execute"]
    conn.close()

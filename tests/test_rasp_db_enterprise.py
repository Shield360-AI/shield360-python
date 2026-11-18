"""Database sink hook, enterprise databases: SQL Server (pyodbc, pymssql),
Oracle (oracledb, cx_Oracle) and Db2 (ibm_db, ibm_db_dbi), and SQLAlchemy's
dialect names for them. Every driver is a small stand-in module with the
real library's call shape; nothing connects to a database.
"""

import asyncio
import sys
import types

import pytest

from rasp_hook_kit import in_request, stop_engine, use_engine
from shield360.rasp import RaspBlockedError, _detect
from shield360.rasp._hooks.db import install_db_hooks, uninstall_db_hooks

INJECTION = "' OR '1'='1"
QUERY = f"SELECT * FROM t WHERE name = '{INJECTION}'"


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    uninstall_db_hooks()
    stop_engine()


@pytest.fixture(name="dialects")
def _dialects(monkeypatch):
    seen = []
    original = _detect.detect_sql

    def spy(query, inputs, dialect="generic"):
        seen.append(dialect)
        return original(query, inputs, dialect)

    monkeypatch.setattr(_detect, "detect_sql", spy)
    return seen


def _module(monkeypatch, name, **attrs):
    module = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(module, k, v)
    monkeypatch.setitem(sys.modules, name, module)
    return module


def _broken(*_a, **_k):
    raise RuntimeError("boom")


# ---- pyodbc and pymssql: proxies ---------------------------------------------------


class _OdbcCursor:
    def __init__(self):
        self.ran = []
        self.fast_executemany = False
        self._rows = iter([(1,), (2,)])

    def execute(self, sql, *params):
        self.ran.append(sql)
        return self  # pyodbc returns the cursor, for chaining

    def executemany(self, sql, seq):
        self.ran.append(sql)

    def fetchone(self):
        return (1,)

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._rows)


class _OdbcConnection:
    def __init__(self):
        self.autocommit = False
        self.last = None
        self.closed = False

    def cursor(self):
        self.last = _OdbcCursor()
        return self.last

    def execute(self, sql, *params):
        return self.cursor().execute(sql, *params)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True
        return False


def _pyodbc(monkeypatch):
    return _module(monkeypatch, "pyodbc", connect=lambda *a, **k: _OdbcConnection(), Connection=_OdbcConnection)


def test_pyodbc_blocks_with_the_mssql_dialect_and_bound_parameters_pass(monkeypatch, dialects):
    pyodbc = _pyodbc(monkeypatch)
    events = use_engine("block")
    install_db_hooks()
    conn = pyodbc.connect("DSN=x")
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: conn.cursor().execute(QUERY))
    assert conn.last.ran == []
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: conn.execute(QUERY))
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: conn.cursor().executemany(QUERY, [(1,)]))
    cur = conn.cursor()
    assert in_request([INJECTION], lambda: cur.execute("SELECT * FROM t WHERE name = ?", INJECTION)) is cur
    assert events.sinks() == ["pyodbc.Cursor.execute", "pyodbc.Connection.execute", "pyodbc.Cursor.executemany"]
    assert set(dialects) == {"mssql"}


def test_pyodbc_proxies_forward_attributes_iteration_and_with(monkeypatch):
    pyodbc = _pyodbc(monkeypatch)
    use_engine("block")
    install_db_hooks()
    with pyodbc.connect("DSN=x") as conn:
        conn.autocommit = True
        assert conn.autocommit is True
        cur = conn.cursor()
        cur.fast_executemany = True
        assert conn.last.fast_executemany is True
        assert list(cur.execute("SELECT 1")) == [(1,), (2,)]
        # The cursor the connection shortcut returns checks when run again.
        again = conn.execute("SELECT 1")
        with pytest.raises(RaspBlockedError):
            in_request([INJECTION], lambda: again.execute(QUERY))
    assert conn.closed is True


def test_pyodbc_monitor_reports_once_and_runs(monkeypatch):
    pyodbc = _pyodbc(monkeypatch)
    events = use_engine("monitor")
    install_db_hooks()
    conn = pyodbc.connect("DSN=x")
    cur = conn.cursor()
    in_request([INJECTION], lambda: cur.execute(QUERY))
    assert conn.last.ran == [QUERY]
    assert events.attacks() == [("sql_injection", "sqli.userinput", "monitored")]


def test_pyodbc_off_rasp_disabled_and_uninstall_skip_checks(monkeypatch):
    pyodbc = _pyodbc(monkeypatch)
    events = use_engine("block", attacks={"sql_injection": "off"})
    install_db_hooks()
    conn = pyodbc.connect("DSN=x")
    in_request([INJECTION], lambda: conn.cursor().execute(QUERY))
    assert conn.last.ran == [QUERY] and not events
    stop_engine()
    in_request([INJECTION], lambda: conn.cursor().execute(QUERY))
    assert conn.last.ran == [QUERY]
    use_engine("block")
    uninstall_db_hooks()
    in_request([INJECTION], lambda: conn.cursor().execute(QUERY))
    assert conn.last.ran == [QUERY]
    # After uninstall, connect hands back the driver's own connection.
    assert pyodbc.connect("DSN=x").__class__ is _OdbcConnection


def test_pyodbc_detector_errors_fail_open(monkeypatch):
    pyodbc = _pyodbc(monkeypatch)
    events = use_engine("block")
    monkeypatch.setattr(_detect, "detect_sql", _broken)
    install_db_hooks()
    conn = pyodbc.connect("DSN=x")
    in_request([INJECTION], lambda: conn.cursor().execute(QUERY))
    assert conn.last.ran == [QUERY] and not events


def test_pymssql_cursors_are_checked(monkeypatch, dialects):
    class Connection:
        def __init__(self):
            self.last = None

        def cursor(self, as_dict=False):
            self.last = _OdbcCursor()
            return self.last

    pymssql = _module(monkeypatch, "pymssql", connect=lambda *a, **k: Connection())
    events = use_engine("block")
    install_db_hooks()
    conn = pymssql.connect(server="x")
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: conn.cursor(as_dict=True).execute(QUERY))
    assert conn.last.ran == []
    # pymssql's connection has no execute shortcut; the proxy does not invent one.
    with pytest.raises(AttributeError):
        conn.execute(QUERY)
    assert events.sinks() == ["pymssql.Cursor.execute"]
    assert dialects == ["mssql"]


# ---- oracledb: Python cursor classes ----------------------------------------------


def test_oracledb_cursor_classes_are_patched(monkeypatch, dialects):
    class Cursor:
        def execute(self, statement, parameters=None, **kwargs):
            return statement

        def executemany(self, statement, parameters, **kwargs):
            return statement

    class AsyncCursor:
        async def execute(self, statement, parameters=None, **kwargs):
            return statement

    _module(monkeypatch, "oracledb.cursor", Cursor=Cursor, AsyncCursor=AsyncCursor)
    events = use_engine("block")
    install_db_hooks()
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: Cursor().execute(QUERY))
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: Cursor().executemany(QUERY, [{}]))
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: asyncio.run(AsyncCursor().execute(QUERY)))
    bound = "SELECT * FROM t WHERE name = :name"
    assert in_request([INJECTION], lambda: Cursor().execute(bound, {"name": INJECTION})) == bound
    assert events.sinks() == ["oracledb.Cursor.execute", "oracledb.Cursor.executemany", "oracledb.AsyncCursor.execute"]
    assert set(dialects) == {"oracle"}


def test_oracledb_monitor_and_fail_open(monkeypatch):
    class Cursor:
        def execute(self, statement, parameters=None):
            return statement

    _module(monkeypatch, "oracledb.cursor", Cursor=Cursor)
    events = use_engine("monitor")
    install_db_hooks()
    assert in_request([INJECTION], lambda: Cursor().execute(QUERY)) == QUERY
    assert events.attacks() == [("sql_injection", "sqli.userinput", "monitored")]
    events.clear()
    use_engine("block")
    monkeypatch.setattr(_detect, "detect_sql", _broken)
    assert in_request([INJECTION], lambda: Cursor().execute(QUERY)) == QUERY


# ---- cx_Oracle: checking subclasses ------------------------------------------------


def _cx_oracle(monkeypatch):
    class Cursor:
        def __init__(self, connection, scrollable=False):
            self.connection = connection
            self.ran = []

        def execute(self, statement, parameters=None):
            self.ran.append(statement)
            return self

        def executemany(self, statement, parameters):
            self.ran.append(statement)

    class Connection:
        def __init__(self, user=None, password=None, dsn=None):
            self.dsn = dsn

        def cursor(self, scrollable=False):
            return Cursor(self, scrollable)

    # As in cx_Oracle, connect is the connection type itself.
    return _module(monkeypatch, "cx_Oracle", Connection=Connection, Cursor=Cursor, connect=Connection)


def test_cx_oracle_connect_returns_a_real_checking_subclass(monkeypatch, dialects):
    cx = _cx_oracle(monkeypatch)
    events = use_engine("block")
    install_db_hooks()
    conn = cx.connect(dsn="db")
    assert isinstance(conn, cx.Connection) and conn.dsn == "db"
    cur = conn.cursor()
    assert isinstance(cur, cx.Cursor)
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: cur.execute(QUERY))
    assert cur.ran == []
    assert in_request([INJECTION], lambda: cur.execute("SELECT 1 FROM dual WHERE x = :1", [INJECTION])) is cur
    assert events.sinks() == ["cx_Oracle.Cursor.execute"]
    assert dialects == ["oracle", "oracle"]


def test_cx_oracle_off_and_uninstall(monkeypatch):
    cx = _cx_oracle(monkeypatch)
    events = use_engine("block", attacks={"sql_injection": "off"})
    install_db_hooks()
    cur = cx.connect(dsn="db").cursor()
    in_request([INJECTION], lambda: cur.execute(QUERY))
    assert cur.ran == [QUERY] and not events
    uninstall_db_hooks()
    assert cx.connect is cx.Connection


# ---- Db2: ibm_db functions and the ibm_db_dbi cursor -------------------------------


def _ibm_db(monkeypatch):
    ran = []

    def exec_immediate(conn, statement, options=None):
        ran.append(statement)
        return "stmt"

    def prepare(conn, statement, options=None):
        ran.append(statement)
        return "stmt"

    def execute(stmt, params=None):
        return True

    ibm_db = _module(monkeypatch, "ibm_db", exec_immediate=exec_immediate, prepare=prepare, execute=execute)

    class Cursor:
        def execute(self, operation, parameters=None):
            # What ibm_db_dbi does: prepare, then execute, through ibm_db.
            stmt = sys.modules["ibm_db"].prepare("conn", operation)
            return sys.modules["ibm_db"].execute(stmt, parameters)

        def executemany(self, operation, seq_parameters):
            return [self.execute(operation, p) for p in seq_parameters]

    _module(monkeypatch, "ibm_db_dbi", Cursor=Cursor)
    return ibm_db, Cursor, ran


def test_ibm_db_functions_block_with_the_db2_dialect(monkeypatch, dialects):
    ibm_db, _cursor, ran = _ibm_db(monkeypatch)
    events = use_engine("block")
    install_db_hooks()
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: ibm_db.exec_immediate("conn", QUERY))
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: ibm_db.prepare("conn", statement=QUERY))
    assert not ran
    assert in_request([INJECTION], lambda: ibm_db.prepare("conn", "SELECT * FROM t WHERE name = ?")) == "stmt"
    assert events.sinks() == ["ibm_db.exec_immediate", "ibm_db.prepare"]
    assert set(dialects) == {"db2"}


def test_ibm_db_dbi_is_checked_once_per_call(monkeypatch, dialects):
    _ibm_db_mod, cursor, ran = _ibm_db(monkeypatch)
    events = use_engine("monitor")
    install_db_hooks()
    in_request([INJECTION], lambda: cursor().executemany(QUERY, [1, 2]))
    assert ran == [QUERY, QUERY]
    # executemany runs execute and ibm_db.prepare underneath: one check for the logical call.
    assert events.sinks() == ["ibm_db_dbi.Cursor.executemany"]
    assert dialects == ["db2"]


def test_ibm_db_fail_open_and_no_context(monkeypatch):
    ibm_db, _cursor, ran = _ibm_db(monkeypatch)
    events = use_engine("block")
    install_db_hooks()
    ibm_db.exec_immediate("conn", QUERY)  # no request: no check
    monkeypatch.setattr(_detect, "detect_sql", _broken)
    in_request([INJECTION], lambda: ibm_db.exec_immediate("conn", QUERY))
    assert ran == [QUERY, QUERY] and not events


# ---- SQLAlchemy dialect names ------------------------------------------------------


@pytest.mark.parametrize(
    "name, dialect", [("mssql", "mssql"), ("oracle", "oracle"), ("ibm_db_sa", "db2"), ("firebird", "generic")]
)
def test_sqlalchemy_maps_enterprise_dialects(monkeypatch, dialects, name, dialect):
    class Connection:
        def execute(self, statement, parameters=None):
            return statement

        def exec_driver_sql(self, statement, parameters=None):
            return statement

    Connection.dialect = types.SimpleNamespace(name=name)
    _module(monkeypatch, "sqlalchemy.engine.base", Connection=Connection)
    use_engine("monitor")
    install_db_hooks()
    in_request([INJECTION], lambda: Connection().exec_driver_sql(QUERY))
    assert dialects == [dialect]


def test_unknown_dialect_names_still_detect_until_the_lexer_knows_them():
    # The lexer's own oracle and db2 rules land separately; meanwhile it lexes them with the common rules.
    inputs = [types.SimpleNamespace(value=INJECTION, key="query.q", source="request")]
    for dialect in ("mssql", "oracle", "db2"):
        finding = _detect.detect_sql(QUERY, inputs, dialect)
        assert finding is not None and finding.rule == "sqli.userinput"


# ---- review fixes ------------------------------------------------------------------


def test_oracledb_prepare_is_checked_so_execute_none_cannot_bypass(monkeypatch):
    class BaseCursor:
        statement = None

        def prepare(self, statement, tag=None, cache_statement=True):
            self.statement = statement

    class Cursor(BaseCursor):
        def execute(self, statement, parameters=None, **kwargs):
            return statement or self.statement

    _module(monkeypatch, "oracledb.cursor", BaseCursor=BaseCursor, Cursor=Cursor)
    events = use_engine("block")
    install_db_hooks()
    cur = Cursor()
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: cur.prepare(QUERY))
    assert cur.statement is None
    assert events.sinks() == ["oracledb.BaseCursor.prepare"]


def test_cx_oracle_prepare_and_keyword_statement_are_checked(monkeypatch):
    cx = _cx_oracle(monkeypatch)

    def prepare(self, statement, tag=None):
        self.ran.append(("prepare", statement))

    cx.Cursor.prepare = prepare
    events = use_engine("block")
    install_db_hooks()
    cur = cx.connect(dsn="db").cursor()
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: cur.prepare(QUERY))
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: cur.executemany(statement=QUERY, parameters=[{}]))
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: cur.execute(statement=QUERY))
    assert not cur.ran
    assert events.sinks() == ["cx_Oracle.Cursor.prepare", "cx_Oracle.Cursor.executemany", "cx_Oracle.Cursor.execute"]


def test_proxy_cursor_connection_is_the_checking_connection(monkeypatch):
    class Cursor(_OdbcCursor):
        def __init__(self, connection):
            super().__init__()
            self.connection = connection

    class Connection(_OdbcConnection):
        def cursor(self):
            self.last = Cursor(self)
            return self.last

    pyodbc = _module(monkeypatch, "pyodbc", connect=lambda *a, **k: Connection())
    events = use_engine("block")
    install_db_hooks()
    conn = pyodbc.connect("DSN=x")
    other = conn.cursor().connection
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: other.cursor().execute(QUERY))
    assert conn.last.ran == []
    assert events.sinks() == ["pyodbc.Cursor.execute"]


@pytest.mark.parametrize("module_name", ["_mssql", "pymssql._mssql"])
def test_pymssql_low_level_mssql_connection_is_checked(monkeypatch, module_name):
    ran = []

    class MSSQLConnection:
        def execute_query(self, query_string, params=None):
            ran.append(query_string)

        def execute_non_query(self, query_string, params=None):
            ran.append(query_string)

        def execute_scalar(self, query_string, params=None):
            ran.append(query_string)

        def execute_row(self, query_string, params=None):
            ran.append(query_string)

    mod = _module(monkeypatch, module_name, connect=lambda *a, **k: MSSQLConnection())
    events = use_engine("block")
    install_db_hooks()
    conn = mod.connect(server="x")
    for method in ("execute_query", "execute_non_query", "execute_scalar", "execute_row"):
        with pytest.raises(RaspBlockedError):
            in_request([INJECTION], lambda m=method: getattr(conn, m)(QUERY))
    assert not ran
    in_request([INJECTION], lambda: conn.execute_query("SELECT * FROM t WHERE name = %s", (INJECTION,)))
    assert len(ran) == 1
    assert events.sinks() == [f"{module_name}.MSSQLConnection.{m}" for m in
                              ("execute_query", "execute_non_query", "execute_scalar", "execute_row")]


def test_oracledb_connection_dataframe_fetches_and_pipelines_are_checked(monkeypatch):
    ran = []

    class Connection:
        def fetch_df_all(self, statement=None, parameters=None, arraysize=None):
            ran.append(statement)

        def fetch_df_batches(self, statement=None, parameters=None, size=None):
            ran.append(statement)
            yield from ()

    class AsyncConnection:
        async def fetch_df_all(self, statement, parameters=None, arraysize=None):
            ran.append(statement)

    class Pipeline:
        def _add(self, statement):
            ran.append(statement)

        def add_execute(self, statement, parameters=None):
            self._add(statement)

        def add_executemany(self, statement, parameters):
            self._add(statement)

        def add_fetchall(self, statement, parameters=None, arraysize=None, rowfactory=None):
            self._add(statement)

        def add_fetchmany(self, statement, parameters=None, num_rows=None, rowfactory=None):
            self._add(statement)

        def add_fetchone(self, statement, parameters=None, rowfactory=None):
            self._add(statement)

    _module(monkeypatch, "oracledb.connection", Connection=Connection, AsyncConnection=AsyncConnection)
    _module(monkeypatch, "oracledb.pipeline", Pipeline=Pipeline)
    events = use_engine("block")
    install_db_hooks()
    calls = [
        lambda: Connection().fetch_df_all(QUERY),
        lambda: Connection().fetch_df_batches(statement=QUERY),
        lambda: asyncio.run(AsyncConnection().fetch_df_all(QUERY)),
        lambda: Pipeline().add_execute(QUERY),
        lambda: Pipeline().add_executemany(QUERY, [{}]),
        lambda: Pipeline().add_fetchall(QUERY),
        lambda: Pipeline().add_fetchmany(QUERY),
        lambda: Pipeline().add_fetchone(QUERY),
    ]
    for call in calls:
        with pytest.raises(RaspBlockedError):
            in_request([INJECTION], call)
    assert not ran
    assert events.sinks() == [
        "oracledb.Connection.fetch_df_all",
        "oracledb.Connection.fetch_df_batches",
        "oracledb.AsyncConnection.fetch_df_all",
        "oracledb.Pipeline.add_execute",
        "oracledb.Pipeline.add_executemany",
        "oracledb.Pipeline.add_fetchall",
        "oracledb.Pipeline.add_fetchmany",
        "oracledb.Pipeline.add_fetchone",
    ]


def test_pymssql_private_low_level_connection_is_checking(monkeypatch):
    ran = []

    class Low:
        def execute_query(self, query_string, params=None):
            ran.append(query_string)

    class Connection:
        _conn = Low()

        def cursor(self):
            return _OdbcCursor()

    pymssql = _module(monkeypatch, "pymssql", connect=lambda *a, **k: Connection())
    events = use_engine("block")
    install_db_hooks()
    conn = pymssql.connect(server="x")
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: conn._conn.execute_query(QUERY))  # pylint: disable=protected-access
    assert not ran
    assert events.sinks() == ["pymssql.MSSQLConnection.execute_query"]

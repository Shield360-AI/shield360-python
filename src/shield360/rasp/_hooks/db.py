"""Database sink hook (README "SQL", "NoSQL"): SQL text sent through DB-API
drivers and SQLAlchemy, and MongoDB filter, update and pipeline documents
sent through pymongo, are checked for injection before the driver sends
them. Each driver is patched when the app imports it; none is imported here.

- Drivers whose cursor is a Python class (``pymysql``, ``MySQLdb``,
  ``mysql.connector``, ``psycopg`` 3) have ``execute``/``executemany``
  wrapped on the class.
- ``sqlite3`` and ``psycopg2`` cursors are built-in types that cannot be
  changed. Their ``connect`` is wrapped instead, and hands the driver a
  connection factory: a subclass of the connection class the app asked for
  (the driver's own by default) whose cursors are subclasses that check.
  The objects the app gets are real driver connections and cursors
  (``isinstance`` and the driver's own C functions accept them), not
  proxies. A connection opened before install, or with a ``connect`` the app
  took out of the module before install, is not covered.
- Enterprise databases. SQL Server: ``pyodbc`` and ``pymssql`` (dialect
  ``mssql``). Oracle: ``oracledb`` (Python cursor classes, patched on the
  class) and ``cx_Oracle`` (dialect ``oracle``). Db2: ``ibm_db_dbi`` (a
  Python cursor class), and ``ibm_db.exec_immediate``/``ibm_db.prepare``
  (dialect ``db2``). ``cx_Oracle``'s connection and cursor types can be
  subclassed, so ``connect`` hands back a checking subclass, as for sqlite3.
  ``pyodbc`` and ``pymssql`` types can be neither changed nor subclassed and
  take no factory: their ``connect`` returns a thin proxy around the real
  connection whose cursors are proxies too. Every attribute, assignment,
  iteration and ``with`` block goes to the real object; only
  ``isinstance(conn, pyodbc.Connection)`` sees the proxy. Connections from a
  pool the driver opens itself (``cx_Oracle.SessionPool``) are not covered.
- SQLAlchemy: ``Connection.execute`` with a ``text()`` clause or a string, and
  ``exec_driver_sql``. The DB-API call SQLAlchemy makes underneath is part of
  it and is not checked again.
- pymongo: the ``Collection`` (and ``AsyncCollection``) methods taking a
  filter, update, replacement or pipeline. ``find_one`` is covered through
  the ``find`` it calls.

Checks run only inside a context holding untrusted input.
"""

from __future__ import annotations

import inspect
import weakref
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from shield360.rasp import _detect
from shield360.rasp._context import current_context, inputs_of
from shield360.rasp._hooks import _imports
from shield360.rasp._hooks._wrap import Depth, Entry, argument, mark, restore, run_check, wrap, wrap_call
from shield360.rasp._types import Finding

_TAG = "rasp.db"
_depth = Depth()
_entries: List[Entry] = []
_installed = False
# Whether the checking connection and cursor classes (which outlive an uninstall in open connections) check.
_on = False

# Module -> (class names, methods, dialect), for drivers whose cursor classes can be patched.
CURSOR_DRIVERS: Dict[str, Tuple[Tuple[str, ...], Tuple[str, ...], str]] = {
    "pymysql.cursors": (("Cursor",), ("execute", "executemany"), "mysql"),
    "MySQLdb.cursors": (("BaseCursor",), ("execute", "executemany"), "mysql"),
    "mysql.connector.cursor": (
        ("MySQLCursor", "MySQLCursorPrepared"),
        ("execute", "executemany"),
        "mysql",
    ),
    "mysql.connector.cursor_cext": (("CMySQLCursor", "CMySQLCursorPrepared"), ("execute", "executemany"), "mysql"),
    "psycopg": (
        ("Cursor", "AsyncCursor", "ServerCursor", "AsyncServerCursor"),
        ("execute", "executemany"),
        "postgres",
    ),
    # prepare is checked too: execute(None) then runs the prepared text.
    "oracledb.cursor": (("BaseCursor", "Cursor", "AsyncCursor"), ("execute", "executemany", "prepare"), "oracle"),
    # These run their statement through the driver's internals, not through a cursor's execute.
    "oracledb.connection": (("Connection", "AsyncConnection"), ("fetch_df_all", "fetch_df_batches"), "oracle"),
    "oracledb.pipeline": (
        ("Pipeline",),
        ("add_execute", "add_executemany", "add_fetchall", "add_fetchmany", "add_fetchone"),
        "oracle",
    ),
    "ibm_db_dbi": (("Cursor",), ("execute", "executemany"), "db2"),
}
# Module -> (functions, dialect), for drivers whose statements go through module functions (connection first).
FUNCTION_DRIVERS: Dict[str, Tuple[Tuple[str, ...], str]] = {
    "ibm_db": (("exec_immediate", "prepare"), "db2"),
}
# Drivers whose connection and cursor types cannot be changed or subclassed: connect returns a proxy.
PROXY_DRIVERS: Dict[str, str] = {"pyodbc": "mssql", "pymssql": "mssql"}
# pymssql's low-level module: its connection runs SQL through execute_* methods.
MSSQL_LOW_LEVEL = ("_mssql", "pymssql._mssql")
_MSSQL_METHODS = ("execute_query", "execute_non_query", "execute_scalar", "execute_row")
MONGO_METHODS = (
    "find",
    "count_documents",
    "update_one",
    "update_many",
    "replace_one",
    "delete_one",
    "delete_many",
    "find_one_and_update",
    "find_one_and_delete",
    "find_one_and_replace",
    "aggregate",
)
_MONGO_TWO_DOCS = frozenset(("update_one", "update_many", "replace_one", "find_one_and_update", "find_one_and_replace"))
_SQLALCHEMY_DIALECTS = {
    "postgresql": "postgres",
    "mysql": "mysql",
    "mariadb": "mysql",
    "sqlite": "sqlite",
    "mssql": "mssql",
    "oracle": "oracle",
    "ibm_db_sa": "db2",
    "db2": "db2",
}


def _sql_check(sink: str, query: Any, dialect: str) -> None:
    if isinstance(query, (bytes, bytearray)):
        query = bytes(query).decode("utf-8", "replace")
    if not isinstance(query, str):
        return

    def run() -> Optional[Finding]:
        ctx = current_context()
        inputs = inputs_of(ctx) if ctx is not None else []
        return _detect.detect_sql(query, inputs, dialect) if inputs else None

    if current_context() is not None:
        run_check(sink, run)


def _sql_before(sink: str, dialect: str) -> Callable[[Sequence[Any], Dict[str, Any]], None]:
    def before(args: Sequence[Any], kwargs: Dict[str, Any]) -> None:
        _sql_check(sink, argument(args, kwargs, 0, "query", "operation", "sql", "statement"), dialect)

    return before


def _add(entry: Optional[Entry]) -> None:
    if entry is not None and entry not in _entries:
        _entries.append(entry)


def _patch_cursor_driver(module_name: str) -> Callable[[Any], None]:
    classes, methods, dialect = CURSOR_DRIVERS[module_name]
    driver = module_name.split(".")[0]

    def patch(module: Any) -> None:
        for name in classes:
            cls = getattr(module, name, None)
            if not isinstance(cls, type):
                continue
            for method in methods:
                # Only methods the class defines itself; inherited ones are wrapped where defined.
                if method in vars(cls):
                    _add(wrap_call(cls, method, _sql_before(f"{driver}.{name}.{method}", dialect), depth=_depth))

    return patch


# ---- built-in cursor types: checking subclasses handed over at connect ---------

_cursor_classes: "weakref.WeakKeyDictionary[type, type]" = weakref.WeakKeyDictionary()
_connection_classes: "weakref.WeakKeyDictionary[type, type]" = weakref.WeakKeyDictionary()


def _checking_call(base: type, method: str, sink: str, dialect: str) -> Callable[..., Any]:
    """A method of a checking subclass: the check, then the base class's own method."""
    original = getattr(base, method)

    def call(self: Any, *args: Any, **kwargs: Any) -> Any:
        if _on and not _depth.active:
            _sql_check(sink, argument(args, kwargs, 0, "query", "sql", "sql_script", "statement", "operation"), dialect)
        with _depth:
            return original(self, *args, **kwargs)

    call.__name__ = call.__qualname__ = method
    call.__doc__ = getattr(original, "__doc__", None)
    mark(call)
    return call


def _subclass(base: type, namespace: Dict[str, Any]) -> type:
    return type(base.__name__, (base,), dict(namespace, __module__=base.__module__, __qualname__=base.__qualname__))


def checking_cursor(base: type, driver: str, dialect: str, extra: Tuple[str, ...] = ()) -> type:
    """A subclass of a driver's cursor class whose statements are checked
    (``execute``, ``executemany``, ``executescript``, and ``extra``)."""
    if not isinstance(base, type):
        return base
    known = _cursor_classes.get(base)
    if known is not None or base in _cursor_classes.values():
        return known or base
    names = ("execute", "executemany", "executescript") + extra
    methods = {m: _checking_call(base, m, f"{driver}.Cursor.{m}", dialect) for m in names if hasattr(base, m)}
    cls = _subclass(base, methods)
    _cursor_classes[base] = cls
    return cls


def _default_cursor_factory(base: type, sqlite3: Any) -> Any:
    """The cursor class ``base.cursor()`` makes when called with no factory, or None when that cannot be told."""
    own = getattr(base, "cursor", None)
    if own is sqlite3.Connection.cursor:
        return sqlite3.Cursor
    try:
        default = inspect.signature(own).parameters["factory"].default
    except (KeyError, TypeError, ValueError):
        return None
    return default if isinstance(default, type) and issubclass(default, sqlite3.Cursor) else None


def _sqlite_connection(base: type) -> type:
    known = _connection_classes.get(base)
    if known is not None or base in _connection_classes.values():
        return known or base
    import sqlite3  # pylint: disable=import-outside-toplevel  # loaded: only reached from the app's own sqlite3.connect

    def cursor(self: Any, *args: Any, **kwargs: Any) -> Any:
        # The call keeps its shape: only the factory is swapped for its checking subclass.
        if not _on:
            return base.cursor(self, *args, **kwargs)
        try:
            if args:
                args = (checking_cursor(args[0], "sqlite3", "sqlite"),) + args[1:]
            elif kwargs.get("factory") is not None:
                kwargs = dict(kwargs, factory=checking_cursor(kwargs["factory"], "sqlite3", "sqlite"))
            else:
                default = _default_cursor_factory(base, sqlite3)
                if default is not None:
                    kwargs = dict(kwargs, factory=checking_cursor(default, "sqlite3", "sqlite"))
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        return base.cursor(self, *args, **kwargs)

    namespace: Dict[str, Any] = {"cursor": cursor}
    for m in ("execute", "executemany", "executescript"):
        if getattr(base, m, None) is getattr(sqlite3.Connection, m):
            namespace[m] = _connection_shortcut(m)
        else:
            # The app's own override: checked, then run as it is written.
            namespace[m] = _checking_call(base, m, f"sqlite3.Connection.{m}", "sqlite")
    cls = _subclass(base, namespace)
    _connection_classes[base] = cls
    return cls


def _connection_shortcut(method: str) -> Callable[..., Any]:
    """sqlite3's ``Connection.execute`` shortcuts, as sqlite3 defines them (a
    new cursor, then its method), with the cursor from ``self.cursor()``: a
    checking cursor, so running it again later is checked too."""
    sink = f"sqlite3.Connection.{method}"

    def call(self: Any, *args: Any, **kwargs: Any) -> Any:
        if _on and not _depth.active:
            _sql_check(sink, argument(args, kwargs, 0, "sql", "sql_script"), "sqlite")
        with _depth:
            cur = self.cursor()
            getattr(cur, method)(*args, **kwargs)
            return cur

    call.__name__ = call.__qualname__ = method
    mark(call)
    return call


def _sqlite_connect(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
    def connect(*args: Any, **kwargs: Any) -> Any:
        if entry.on and _on:
            try:
                import sqlite3  # pylint: disable=import-outside-toplevel  # loaded: the app is calling it

                if len(args) > 5:
                    args = args[:5] + (_sqlite_connection(args[5] or sqlite3.Connection),) + args[6:]
                else:
                    kwargs = dict(kwargs, factory=_sqlite_connection(kwargs.get("factory") or sqlite3.Connection))
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        return fn(*args, **kwargs)

    return connect


def _psycopg2_connection(base: type) -> type:
    known = _connection_classes.get(base)
    if known is not None or base in _connection_classes.values():
        return known or base

    def cursor(self: Any, *args: Any, **kwargs: Any) -> Any:
        if _on:
            try:
                import psycopg2.extensions  # pylint: disable=import-outside-toplevel  # loaded with psycopg2

                given = args[1] if len(args) > 1 else kwargs.get("cursor_factory")
                factory = checking_cursor(given or self.cursor_factory or psycopg2.extensions.cursor, "psycopg2", "postgres")
                if len(args) > 1:
                    args = args[:1] + (factory,) + args[2:]
                else:
                    kwargs = dict(kwargs, cursor_factory=factory)
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        return base.cursor(self, *args, **kwargs)

    cls = _subclass(base, {"cursor": cursor})
    _connection_classes[base] = cls
    return cls


def _psycopg2_connect(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
    def connect(*args: Any, **kwargs: Any) -> Any:
        if entry.on and _on:
            try:
                import psycopg2.extensions  # pylint: disable=import-outside-toplevel  # loaded with psycopg2

                if len(args) > 1:
                    args = args[:1] + (_psycopg2_connection(args[1] or psycopg2.extensions.connection),) + args[2:]
                else:
                    kwargs = dict(
                        kwargs,
                        connection_factory=_psycopg2_connection(kwargs.get("connection_factory") or psycopg2.extensions.connection),
                    )
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        return fn(*args, **kwargs)

    return connect


def _patch_sqlite3(module: Any) -> None:
    _add(wrap(module, "connect", _sqlite_connect))


def _patch_psycopg2(module: Any) -> None:
    _add(wrap(module, "connect", _psycopg2_connect))


def _patch_function_driver(module_name: str) -> Callable[[Any], None]:
    functions, dialect = FUNCTION_DRIVERS[module_name]

    def before_for(name: str) -> Callable[[Sequence[Any], Dict[str, Any]], None]:
        def before(args: Sequence[Any], kwargs: Dict[str, Any]) -> None:
            _sql_check(f"{module_name}.{name}", argument(args, kwargs, 1, "statement", "stmt", "sql"), dialect)

        return before

    def patch(module: Any) -> None:
        for name in functions:
            _add(wrap_call(module, name, before_for(name), depth=_depth))

    return patch


# ---- cx_Oracle: subclassable built-in types ----------------------------------------


def _cx_oracle_connection(base: type, cursor_base: type) -> type:
    known = _connection_classes.get(base)
    if known is not None or base in _connection_classes.values():
        return known or base

    def cursor(self: Any, *args: Any, **kwargs: Any) -> Any:
        if _on:
            try:
                # prepare too: execute(None) then runs the prepared text.
                return checking_cursor(cursor_base, "cx_Oracle", "oracle", ("prepare",))(self, *args, **kwargs)
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        return base.cursor(self, *args, **kwargs)

    cls = _subclass(base, {"cursor": cursor})
    _connection_classes[base] = cls
    return cls


def _cx_oracle_connect(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
    def connect(*args: Any, **kwargs: Any) -> Any:
        cls = None
        if entry.on and _on:
            try:
                import cx_Oracle  # type: ignore  # pylint: disable=import-outside-toplevel,import-error  # loaded: the app is calling it

                base = fn if isinstance(fn, type) else cx_Oracle.Connection
                cls = _cx_oracle_connection(base, cx_Oracle.Cursor)
            except Exception:  # pylint: disable=broad-exception-caught
                cls = None
        return (cls or fn)(*args, **kwargs)

    return connect


def _patch_cx_oracle(module: Any) -> None:
    _add(wrap(module, "connect", _cx_oracle_connect))


# ---- pyodbc, pymssql: proxies around types that cannot be changed -----------------


class _Proxy:
    """Forwards everything to the real driver object."""

    __slots__ = ("_rasp_target", "_rasp_driver", "_rasp_dialect")

    def __init__(self, target: Any, driver: str, dialect: str) -> None:
        object.__setattr__(self, "_rasp_target", target)
        object.__setattr__(self, "_rasp_driver", driver)
        object.__setattr__(self, "_rasp_dialect", dialect)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_rasp_target"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._rasp_target, name, value)

    def __delattr__(self, name: str) -> None:
        delattr(self._rasp_target, name)

    def __enter__(self) -> Any:
        got = self._rasp_target.__enter__()
        return self if got is self._rasp_target else got

    def __exit__(self, *exc: Any) -> Any:
        return self._rasp_target.__exit__(*exc)

    def __repr__(self) -> str:
        return repr(self._rasp_target)

    def _rasp_run(self, kind: str, method: str, args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Any:
        fn = getattr(self._rasp_target, method)
        if _on and not _depth.active:
            _sql_check(
                f"{self._rasp_driver}.{kind}.{method}",
                argument(args, kwargs, 0, "query", "operation", "sql", "statement", "query_string"),
                self._rasp_dialect,
            )
        with _depth:
            return fn(*args, **kwargs)


class _CheckingCursor(_Proxy):
    __slots__ = ()

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        got = self._rasp_run("Cursor", "execute", args, kwargs)
        return self if got is self._rasp_target else got

    def executemany(self, *args: Any, **kwargs: Any) -> Any:
        got = self._rasp_run("Cursor", "executemany", args, kwargs)
        return self if got is self._rasp_target else got

    @property
    def connection(self) -> Any:
        """The cursor's connection, checking too (the driver's own would not be)."""
        return _CheckingConnection(self._rasp_target.connection, self._rasp_driver, self._rasp_dialect)

    def __iter__(self) -> Any:
        return iter(self._rasp_target)

    def __next__(self) -> Any:
        return next(self._rasp_target)


class _CheckingConnection(_Proxy):
    __slots__ = ()

    def cursor(self, *args: Any, **kwargs: Any) -> Any:
        return _CheckingCursor(self._rasp_target.cursor(*args, **kwargs), self._rasp_driver, self._rasp_dialect)

    @property
    def _conn(self) -> Any:
        # pymssql: the low-level connection behind the DB-API one, checking too.
        return _CheckingMssqlConnection(self._rasp_target._conn, self._rasp_driver, self._rasp_dialect)

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        # pyodbc's shortcut: a new cursor, executed. The cursor it returns checks when run again.
        got = self._rasp_run("Connection", "execute", args, kwargs)
        return _CheckingCursor(got, self._rasp_driver, self._rasp_dialect) if got is not None else got


class _CheckingMssqlConnection(_Proxy):
    """pymssql's low-level ``_mssql`` connection."""

    __slots__ = ()

    def execute_query(self, *args: Any, **kwargs: Any) -> Any:
        return self._rasp_run("MSSQLConnection", "execute_query", args, kwargs)

    def execute_non_query(self, *args: Any, **kwargs: Any) -> Any:
        return self._rasp_run("MSSQLConnection", "execute_non_query", args, kwargs)

    def execute_scalar(self, *args: Any, **kwargs: Any) -> Any:
        return self._rasp_run("MSSQLConnection", "execute_scalar", args, kwargs)

    def execute_row(self, *args: Any, **kwargs: Any) -> Any:
        return self._rasp_run("MSSQLConnection", "execute_row", args, kwargs)

    def __iter__(self) -> Any:
        return iter(self._rasp_target)


def _mssql_connect(module_name: str) -> Callable[[Callable[..., Any], Entry], Callable[..., Any]]:
    def build(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
        def connect(*args: Any, **kwargs: Any) -> Any:
            conn = fn(*args, **kwargs)
            if not (entry.on and _on) or conn is None:
                return conn
            try:
                return _CheckingMssqlConnection(conn, module_name, "mssql")
            except Exception:  # pylint: disable=broad-exception-caught
                return conn

        return connect

    return build


def _patch_mssql_low_level(module_name: str) -> Callable[[Any], None]:
    def patch(module: Any) -> None:
        _add(wrap(module, "connect", _mssql_connect(module_name)))

    return patch


def _proxy_connect(driver: str) -> Callable[[Callable[..., Any], Entry], Callable[..., Any]]:
    dialect = PROXY_DRIVERS[driver]

    def build(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
        def connect(*args: Any, **kwargs: Any) -> Any:
            conn = fn(*args, **kwargs)
            if not (entry.on and _on) or conn is None:
                return conn
            try:
                return _CheckingConnection(conn, driver, dialect)
            except Exception:  # pylint: disable=broad-exception-caught
                return conn

        return connect

    return build


def _patch_proxy_driver(driver: str) -> Callable[[Any], None]:
    def patch(module: Any) -> None:
        _add(wrap(module, "connect", _proxy_connect(driver)))

    return patch


# ---- SQLAlchemy ------------------------------------------------------------------


def _sqlalchemy_before(method: str) -> Callable[..., Any]:
    def build(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
        def execute(self: Any, *args: Any, **kwargs: Any) -> Any:
            statement = argument(args, kwargs, 0, "statement")
            text = statement if isinstance(statement, str) else None
            if text is None and getattr(statement, "__visit_name__", None) == "textclause":
                text = getattr(statement, "text", None)
            if not isinstance(text, str) or _depth.active or not entry.on:
                return fn(self, *args, **kwargs)
            name = getattr(getattr(self, "dialect", None), "name", None)
            _sql_check(f"sqlalchemy.Connection.{method}", text, _SQLALCHEMY_DIALECTS.get(str(name), "generic"))
            with _depth:
                return fn(self, *args, **kwargs)

        return execute

    return build


def _patch_sqlalchemy(module: Any) -> None:
    conn = getattr(module, "Connection", None)
    if isinstance(conn, type):
        for method in ("execute", "exec_driver_sql"):
            _add(wrap(conn, method, _sqlalchemy_before(method)))


# ---- pymongo ---------------------------------------------------------------------


def _mongo_before(method: str, cls_name: str) -> Callable[[Sequence[Any], Dict[str, Any]], None]:
    def before(args: Sequence[Any], kwargs: Dict[str, Any]) -> None:
        ctx = current_context()
        if ctx is None:
            return

        def run() -> Optional[Finding]:
            inputs = inputs_of(ctx)
            if method == "aggregate":
                pipeline = argument(args, kwargs, 0, "pipeline")
                docs = list(pipeline) if isinstance(pipeline, (list, tuple)) else []
            elif method in _MONGO_TWO_DOCS:
                docs = [argument(args, kwargs, 0, "filter"), argument(args, kwargs, 1, "update", "replacement")]
            else:
                docs = [argument(args, kwargs, 0, "filter")]
            for doc in docs:
                found = _detect.detect_nosql(doc, ctx.trees, inputs)
                if found:
                    return found
            return None

        run_check(f"pymongo.{cls_name}.{method}", run)

    return before


def _patch_pymongo(cls_name: str) -> Callable[[Any], None]:
    def patch(module: Any) -> None:
        cls = getattr(module, cls_name, None)
        if isinstance(cls, type):
            for method in MONGO_METHODS:
                if method in vars(cls):
                    _add(wrap_call(cls, method, _mongo_before(method, cls_name), depth=_depth))

    return patch


def _patches() -> List[Tuple[str, Callable[[Any], None]]]:
    out: List[Tuple[str, Callable[[Any], None]]] = [(m, _patch_cursor_driver(m)) for m in CURSOR_DRIVERS]
    out += [(m, _patch_function_driver(m)) for m in FUNCTION_DRIVERS]
    out += [(m, _patch_proxy_driver(m)) for m in PROXY_DRIVERS]
    out += [(m, _patch_mssql_low_level(m)) for m in MSSQL_LOW_LEVEL]
    out += [
        ("sqlite3", _patch_sqlite3),
        ("sqlite3.dbapi2", _patch_sqlite3),
        ("psycopg2", _patch_psycopg2),
        ("cx_Oracle", _patch_cx_oracle),
        ("sqlalchemy.engine.base", _patch_sqlalchemy),
        ("pymongo.collection", _patch_pymongo("Collection")),
        ("pymongo.asynchronous.collection", _patch_pymongo("AsyncCollection")),
    ]
    return out


def install_db_hooks() -> bool:
    """Patches the drivers the app has loaded, and the others when it loads them. Idempotent; never raises."""
    global _installed, _on
    if _installed:
        return True
    try:
        _installed = _on = True
        for name, patch in _patches():
            _imports.when_imported(name, _TAG, patch)
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        uninstall_db_hooks()
        return False


def uninstall_db_hooks() -> None:
    """Switches every check off (open connections' checking cursors too) and
    puts the originals back where RASP's wrapper is on top. Idempotent."""
    global _installed, _on
    _installed = _on = False
    _imports.forget(_TAG)
    for entry in reversed(_entries):
        restore(entry)
    _entries.clear()

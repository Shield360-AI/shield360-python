"""File sink hook: open, os file operations, shutil copies and moves, and
pathlib through them. Every file lives in a temporary directory.

Mirrors sdk/typescript/src/rasp/__tests__/fs-hook.test.ts.
"""

import builtins
import io
import os
import pathlib
import shutil
import sys
import types

import pytest

from rasp_hook_kit import in_request, stop_engine, use_engine
from shield360.rasp import RaspBlockedError, _detect
from shield360.rasp._hooks.files import flags_op, install_file_hooks, mode_op, path_text, uninstall_file_hooks


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    uninstall_file_hooks()
    stop_engine()


@pytest.fixture(name="tree")
def _tree(tmp_path):
    (tmp_path / "child").mkdir()
    (tmp_path / "escape.txt").write_text("fixture", encoding="utf-8")
    return tmp_path


def test_operations_from_modes_and_flags():
    assert mode_op("r") == "read" and mode_op("rb") == "read"
    assert mode_op("w") == "write" and mode_op("x") == "write" and mode_op("r+") == "write"
    assert mode_op("ab") == "append"
    assert flags_op(os.O_RDONLY) == "read"
    assert flags_op(os.O_WRONLY | os.O_CREAT) == "write"


def test_paths_normalize_and_descriptors_are_skipped():
    assert path_text("a/b") == "a/b"
    assert path_text(b"a/b") == "a/b"
    assert path_text(pathlib.Path("a") / "b") == os.path.join("a", "b")
    assert path_text(3) is None
    assert path_text(None) is None


def test_block_refuses_before_the_file_is_opened(tree, monkeypatch):
    events = use_engine("block")
    install_file_hooks()
    with pytest.raises(RaspBlockedError) as e:
        in_request(["../escape.txt"], lambda: open(f"{tree}/child/../escape.txt", encoding="utf-8"))  # pylint: disable=consider-using-with
    assert e.value.rule == "path.traversal"
    assert events.sinks() == ["open"]


def test_monitor_reports_and_permits_the_io(tree):
    events = use_engine("monitor")
    install_file_hooks()

    def read():
        with open(f"{tree}/child/../escape.txt", encoding="utf-8") as f:
            return f.read()

    assert in_request(["../escape.txt"], read) == "fixture"
    assert events.attacks() == [("path_traversal", "path.traversal", "monitored")]


def test_pathlib_goes_through_io_open_and_os(tree):
    events = use_engine("monitor")
    install_file_hooks()
    target = pathlib.Path(f"{tree}/child/../escape.txt")
    assert in_request(["../escape.txt"], target.read_text) == "fixture"
    in_request(["../gone.txt"], lambda: pathlib.Path(f"{tree}/child/../escape.txt").rename(tree / "child" / "../gone.txt"))
    assert [a for a, _, _ in events.attacks()] == ["path_traversal", "path_traversal"]


def test_os_operations_are_checked(tree):
    events = use_engine("monitor")
    install_file_hooks()
    (tree / "a.txt").write_text("x", encoding="utf-8")

    def ops():
        os.listdir(f"{tree}/child/../")
        fd = os.open(f"{tree}/child/../a.txt", os.O_RDONLY)
        os.close(fd)
        os.replace(f"{tree}/child/../a.txt", f"{tree}/b.txt")
        os.remove(f"{tree}/child/../b.txt")

    in_request(["child/../"], ops)
    assert events.sinks() == ["os.listdir", "os.open", "os.replace", "os.remove"]


def test_shutil_copy_is_one_check_not_one_per_file_it_opens(tree):
    events = use_engine("monitor")
    install_file_hooks()
    in_request(["../escape.txt"], lambda: shutil.copy(f"{tree}/child/../escape.txt", tree / "copy.txt"))
    assert (tree / "copy.txt").read_text(encoding="utf-8") == "fixture"
    in_request(["../moved.txt"], lambda: shutil.move(str(tree / "copy.txt"), f"{tree}/child/../moved.txt"))
    assert events.sinks() == ["shutil.copy", "shutil.move"]


def test_a_script_write_during_a_request_is_file_write(tree):
    events = use_engine("block")
    install_file_hooks()
    with pytest.raises(RaspBlockedError) as e:
        in_request(["shell.php"], lambda: open(tree / "shell.php", "w", encoding="utf-8"))  # pylint: disable=consider-using-with
    assert e.value.attack == "file_write"
    assert not (tree / "shell.php").exists()
    assert events.sinks() == ["open"]


def test_reads_and_writes_without_input_pass(tree):
    events = use_engine("block")
    install_file_hooks()
    (tree / "plain.txt").write_text("ok", encoding="utf-8")
    assert in_request(["hello world"], (tree / "plain.txt").read_text) == "ok"
    with open(tree / "out.txt", "w", encoding="utf-8") as f:
        f.write("ok")
    assert not events


def test_off_skips_detection(tree, monkeypatch):
    stop_engine()
    calls = []
    monkeypatch.setattr(_detect, "detect_path", lambda *a, **k: calls.append(a))
    install_file_hooks()
    assert in_request(["../escape.txt"], (tree / "child" / ".." / "escape.txt").read_text) == "fixture"
    assert not calls


def test_detector_errors_fail_open(tree, monkeypatch):
    events = use_engine("block")

    def broken(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(_detect, "detect_path", broken)
    install_file_hooks()
    assert in_request(["../escape.txt"], (tree / "child" / ".." / "escape.txt").read_text) == "fixture"
    assert not events


def test_install_is_idempotent_and_uninstall_restores_exactly():
    before = (builtins.open, io.open, os.open, os.remove, shutil.copy)
    assert install_file_hooks() and install_file_hooks()
    assert builtins.open is not before[0] and builtins.open.__name__ == "open"
    uninstall_file_hooks()
    uninstall_file_hooks()
    assert (builtins.open, io.open, os.open, os.remove, shutil.copy) == before


def test_python_310_pathlib_accessor_is_wrapped_without_binding(tree, monkeypatch):
    # Python 3.10's pathlib keeps the os functions as attributes of _NormalAccessor.
    accessor = type("_NormalAccessor", (), {"unlink": os.unlink, "open": io.open, "listdir": os.listdir})
    fake = types.ModuleType("pathlib")
    fake._NormalAccessor = accessor  # pylint: disable=protected-access
    monkeypatch.setitem(sys.modules, "pathlib", fake)
    events = use_engine("monitor")
    install_file_hooks()
    (tree / "gone.txt").write_text("x", encoding="utf-8")
    in_request(["child/../"], lambda: accessor().unlink(f"{tree}/child/../gone.txt"))
    assert not (tree / "gone.txt").exists()
    assert in_request(["child/../"], lambda: accessor().listdir(f"{tree}/child/../")) is not None
    assert events.sinks() == ["pathlib.unlink", "pathlib.listdir"]
    uninstall_file_hooks()
    assert vars(accessor)["unlink"] is os.unlink


def test_copying_a_script_into_a_directory_checks_the_file_it_writes(tree):
    events = use_engine("block")
    install_file_hooks()
    (tree / "src").mkdir()
    (tree / "src" / "shell.php").write_text("<?php ?>", encoding="utf-8")
    (tree / "dst").mkdir()
    with pytest.raises(RaspBlockedError) as e:
        in_request(["shell.php"], lambda: shutil.copy(tree / "src" / "shell.php", tree / "dst"))
    assert e.value.rule == "file_write.script"
    assert not (tree / "dst" / "shell.php").exists()
    with pytest.raises(RaspBlockedError):
        in_request(["shell.php"], lambda: shutil.copytree(tree / "src", tree / "tree-copy"))
    assert not (tree / "tree-copy" / "shell.php").exists()
    assert events.sinks() == ["shutil.copy", "shutil.copyfile"]

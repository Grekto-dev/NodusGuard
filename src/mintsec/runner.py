"""Subprocess runner estruturado e testável com streaming e cancelamento."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable, Protocol


@dataclass(frozen=True)
class CommandResult:
    """Resultado padronizado de execução de comando externo."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    cancelled: bool = False
    timed_out: bool = False


class CommandRunner(Protocol):
    """Interface de execução injetável para serviços e testes."""

    def which(self, binary: str) -> str | None:
        ...

    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
        on_line: Callable[[str], None] | None = None,
        cancel_event: threading.Event | None = None,
        pause_event: threading.Event | None = None,
    ) -> CommandResult:
        ...


class SubprocessRunner:
    """Implementação padrão sobre subprocess.Popen com cancelamento limpo e fast-path."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._which_cache: dict[str, str | None] = {}
        self._which_path: str = os.environ.get("PATH", "")

    def clear_which_cache(self) -> None:
        """Limpa cache de resolução de binários no PATH."""
        with self._lock:
            self._which_cache.clear()

    def which(self, binary: str) -> str | None:
        current_path = os.environ.get("PATH", "")
        with self._lock:
            if current_path != self._which_path:
                self._which_cache.clear()
                self._which_path = current_path
            if binary in self._which_cache:
                return self._which_cache[binary]
        resolved = shutil.which(binary)
        with self._lock:
            if self._which_path == current_path:
                self._which_cache[binary] = resolved
        return resolved

    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
        on_line: Callable[[str], None] | None = None,
        cancel_event: threading.Event | None = None,
        pause_event: threading.Event | None = None,
    ) -> CommandResult:
        # Caminho rápido síncrono sem threads nem polling quando não há streaming/cancelamento/pausa
        if on_line is None and cancel_event is None and pause_event is None:
            try:
                res = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    env=env,
                )
                return CommandResult(
                    argv=tuple(argv),
                    returncode=int(res.returncode),
                    stdout=res.stdout or "",
                    stderr=res.stderr or "",
                    cancelled=False,
                    timed_out=False,
                )
            except subprocess.TimeoutExpired as exc:
                out = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
                err = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
                return CommandResult(
                    argv=tuple(argv),
                    returncode=-1,
                    stdout=out,
                    stderr=err,
                    cancelled=False,
                    timed_out=True,
                )
            except FileNotFoundError as exc:
                return CommandResult(
                    argv=tuple(argv),
                    returncode=127,
                    stdout="",
                    stderr=str(exc),
                    cancelled=False,
                    timed_out=False,
                )

        try:
            proc_cm = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            return CommandResult(
                argv=tuple(argv),
                returncode=127,
                stdout="",
                stderr=str(exc),
                cancelled=False,
                timed_out=False,
            )

        def _signal_pg(p: subprocess.Popen[str], sig: int) -> None:
            try:
                os.killpg(p.pid, sig)
            except ProcessLookupError:
                pass

        def _terminate_pg(p: subprocess.Popen[str]) -> None:
            # Garante retomada antes do SIGTERM caso o grupo esteja em SIGSTOP
            _signal_pg(p, signal.SIGCONT)
            _signal_pg(p, signal.SIGTERM)
            try:
                p.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                _signal_pg(p, signal.SIGKILL)

        with proc_cm as proc:
            stdout_lines: list[str] = []
            stderr_lines: list[str] = []
            cancelled = False
            timed_out = False

            def _drain(pipe: object, collector: list[str], emit: bool) -> None:
                if pipe is None:
                    return
                for line in pipe:  # type: ignore[attr-defined]
                    collector.append(line)
                    if emit and on_line is not None:
                        on_line(line.rstrip("\r\n"))

            t_out = threading.Thread(target=_drain, args=(proc.stdout, stdout_lines, True), daemon=True)
            t_err = threading.Thread(target=_drain, args=(proc.stderr, stderr_lines, False), daemon=True)
            t_out.start()
            t_err.start()

            deadline = time.monotonic() + timeout if timeout is not None else None
            paused_pg = False
            pause_started: float | None = None
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                    paused_pg = False
                    _terminate_pg(proc)
                    break

                want_pause = pause_event is not None and pause_event.is_set()
                if want_pause and not paused_pg:
                    _signal_pg(proc, signal.SIGSTOP)
                    paused_pg = True
                    pause_started = time.monotonic()
                elif not want_pause and paused_pg:
                    _signal_pg(proc, signal.SIGCONT)
                    paused_pg = False
                    if deadline is not None and pause_started is not None:
                        deadline += time.monotonic() - pause_started
                    pause_started = None

                if paused_pg:
                    if proc.poll() is not None:
                        _signal_pg(proc, signal.SIGCONT)
                        paused_pg = False
                        break
                    time.sleep(0.05)
                    continue

                if deadline is not None and time.monotonic() > deadline:
                    timed_out = True
                    _terminate_pg(proc)
                    break
                try:
                    proc.wait(timeout=0.05)
                    break
                except subprocess.TimeoutExpired:
                    continue

            if paused_pg:
                _signal_pg(proc, signal.SIGCONT)
            proc.wait()
            t_out.join(timeout=2.0)
            t_err.join(timeout=2.0)

        return CommandResult(
            argv=tuple(argv),
            returncode=proc.returncode if proc.returncode is not None else -1,
            stdout="".join(stdout_lines),
            stderr="".join(stderr_lines),
            cancelled=cancelled,
            timed_out=timed_out,
        )

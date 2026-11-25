"""Ações compartilhadas de ativação, instalação e desativação para Início e Proteções."""

from __future__ import annotations

import threading
from typing import Any, Callable

import gi

gi.require_version("GLib", "2.0")
from gi.repository import GLib  # noqa: E402

from mintsec.contracts import ModuleState  # noqa: E402
from mintsec.formatting import format_error_message  # noqa: E402
from mintsec.services.catalog import SYSTEM_PRIVILEGED_MODULES  # noqa: E402
from mintsec_ui.dialogs.confirm import ask_action_confirmation  # noqa: E402
from mintsec_ui.i18n import tr  # noqa: E402
from mintsec_ui.widgets import friendly_module_name  # noqa: E402


def run_ui_task(
    app_window: Any,
    work_fn: Callable[..., Any],
    *,
    on_success: Callable[[Any], None],
    on_error: Callable[[Exception], None],
    busy_widget: Any = None,
    activity_label: str | None = None,
    category: str = "action",
    pass_progress: bool = False,
) -> None:
    """Executa operação longa fora da thread GTK no host real, mantendo testes síncronos."""
    def _invoke_work(on_prog: Callable[[int, int, str], None] | None) -> Any:
        if pass_progress:
            return work_fn(on_prog)
        return work_fn()

    if not app_window.controller.is_live_host_runner:
        try:
            res = _invoke_work(None)
        except Exception as exc:  # noqa: BLE001
            on_error(exc)
            return
        on_success(res)
        return

    if busy_widget is not None:
        busy_widget.set_sensitive(False)
    tid = (
        app_window.begin_activity(
            activity_label,
            category=category,
            fraction=0.0 if pass_progress else None,
        )
        if activity_label and hasattr(app_window, "begin_activity")
        else None
    )

    def _on_prog(done: int, total: int, _tag: str) -> None:
        if tid is None:
            return

        def _upd() -> bool:
            if not getattr(app_window, "_destroyed", False):
                frac = float(done) / float(max(1, total))
                app_window.update_activity(tid, fraction=frac)
            return False

        GLib.idle_add(_upd)

    def _worker() -> None:
        try:
            res = _invoke_work(_on_prog if pass_progress else None)
            err: Exception | None = None
        except Exception as exc:  # noqa: BLE001
            res = None
            err = exc

        def _finish() -> bool:
            if getattr(app_window, "_destroyed", False):
                return False
            if tid is not None and hasattr(app_window, "end_activity"):
                app_window.end_activity(
                    tid,
                    status="error" if err is not None else "ok",
                    detail=format_error_message(err) if err is not None else "",
                )
            if busy_widget is not None:
                busy_widget.set_sensitive(True)
            if err is not None:
                on_error(err)
            else:
                on_success(res)
            return False

        GLib.idle_add(_finish)

    threading.Thread(target=_worker, daemon=True).start()


def _report_ui_error(
    app_window: Any,
    error: Exception | str,
    *,
    title: str,
    operation: str,
    source: str,
    evidence: str,
) -> None:
    if hasattr(app_window, "show_error"):
        app_window.show_error(error, operation=operation, source=source, title=title)
        return
    summary = format_error_message(error) if isinstance(error, Exception) else str(error)
    ask_action_confirmation(
        app_window,
        title=title,
        summary=summary,
        actor=source,
        evidence=evidence,
        confirm_label=tr("common.understood"),
        confirm_effect=tr("common.close_notice"),
    )


def trigger_module_install(app_window: Any, mod_id: str) -> None:
    """Solicita confirmação e instala pacotes do módulo via aptkit."""
    controller = app_window.controller
    manifest = controller.manifests[mod_id]
    friendly_name = friendly_module_name(mod_id, manifest.display_name)
    pkgs = ", ".join(manifest.packages)
    ok = ask_action_confirmation(
        app_window,
        title=tr("actions.install_title", name=friendly_name),
        summary=tr("actions.install_summary", name=friendly_name),
        actor=tr("actions.install_actor"),
        evidence=tr("actions.install_evidence", packages=pkgs),
        confirm_label=tr("actions.install_confirm"),
        confirm_effect=tr("actions.install_effect"),
    )
    if not ok:
        return

    def _on_ok(res: dict[str, Any]) -> None:
        if not res.get("ok"):
            err_txt = str(res.get("error") or res.get("message") or tr("actions.install_err_fallback"))
            _report_ui_error(
                app_window,
                err_txt,
                title=tr("actions.install_err_title", name=friendly_name),
                operation=tr("actions.install_title", name=friendly_name),
                source=tr("actions.install_err_actor"),
                evidence=tr("actions.install_err_evidence", packages=pkgs),
            )
            return
        controller.invalidate_cache(include_packages=True)
        for page in (app_window.home_page, app_window.protections_page):
            page._last_render_sig = None
        app_window.refresh_all(force=True)

    run_ui_task(
        app_window,
        lambda: controller.installer.install_packages(manifest.packages),
        on_success=_on_ok,
        on_error=lambda exc: _report_ui_error(
            app_window,
            exc,
            title=tr("actions.install_err_title", name=friendly_name),
            operation=tr("actions.install_title", name=friendly_name),
            source=tr("actions.install_err_actor"),
            evidence=tr("actions.install_err_evidence", packages=pkgs),
        ),
        activity_label=tr("win.activity_install_mod", name=friendly_name),
        category=mod_id,
    )


def handle_module_switch(app_window: Any, mod_id: str, desired_active: bool) -> bool:
    """Executa troca direta pelo Gtk.Switch mantendo confirmação segura."""
    controller = app_window.controller
    manifest = controller.manifests[mod_id]
    friendly_name = friendly_module_name(mod_id, manifest.display_name)

    if desired_active:
        if mod_id == "firewall":
            app_window.open_module_detail(mod_id)
            return True
        st = controller.get_module_status(mod_id, use_cache=True)
        if st.state == ModuleState.AUSENTE:
            trigger_module_install(app_window, mod_id)
            return True
        if mod_id == "recovery" and st.needs_setup:
            app_window.navigate_to("recovery", tab="files")
            return True

        def _on_enable_ok(new_st: Any) -> None:
            app_window.apply_module_status(mod_id, new_st)

        def _on_enable_err(exc: Exception) -> None:
            _report_ui_error(
                app_window,
                exc,
                title=tr("actions.enable_err_title", name=friendly_name),
                operation=tr("win.activity_enable_mod", name=friendly_name),
                source=friendly_name,
                evidence=tr("actions.enable_err_evidence"),
            )
            app_window.refresh_all(force=False)

        if controller.is_live_host_runner and mod_id in SYSTEM_PRIVILEGED_MODULES:
            run_ui_task(
                app_window,
                lambda: controller.enable_module(mod_id),
                on_success=_on_enable_ok,
                on_error=_on_enable_err,
                activity_label=tr("win.activity_enable_mod", name=friendly_name),
                category=mod_id,
            )
            return True

        try:
            new_st = controller.enable_module(mod_id)
            _on_enable_ok(new_st)
            return False
        except Exception as exc:  # noqa: BLE001
            _on_enable_err(exc)
            return True

    # Desativação com confirmação reversível
    ok = ask_action_confirmation(
        app_window,
        title=tr("actions.disable_title", name=friendly_name),
        summary=tr("actions.disable_summary", name=friendly_name),
        actor="NodusGuard",
        evidence=tr("actions.disable_evidence"),
        confirm_label=tr("actions.disable_confirm"),
        confirm_effect=tr("actions.disable_effect"),
    )
    if not ok:
        return True

    def _on_disable_ok(new_st: Any) -> None:
        app_window.apply_module_status(mod_id, new_st)

    def _on_disable_err(exc: Exception) -> None:
        _report_ui_error(
            app_window,
            exc,
            title=tr("actions.disable_err_title", name=friendly_name),
            operation=tr("win.activity_disable_mod", name=friendly_name),
            source=friendly_name,
            evidence=tr("actions.disable_err_evidence"),
        )
        app_window.refresh_all(force=False)

    if controller.is_live_host_runner and mod_id in SYSTEM_PRIVILEGED_MODULES:
        run_ui_task(
            app_window,
            lambda: controller.disable_module(mod_id, revert_suite_changes=True),
            on_success=_on_disable_ok,
            on_error=_on_disable_err,
            activity_label=tr("win.activity_disable_mod", name=friendly_name),
            category=mod_id,
        )
        return True

    try:
        new_st = controller.disable_module(mod_id, revert_suite_changes=True)
        _on_disable_ok(new_st)
        return False
    except Exception as exc:  # noqa: BLE001
        _on_disable_err(exc)
        return True

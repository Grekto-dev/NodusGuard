"""Ações compartilhadas de ativação, instalação e desativação para Início e Proteções."""

from __future__ import annotations

from typing import Any

from mintsec.contracts import ModuleState  # noqa: E402
from mintsec_ui.dialogs.confirm import ask_action_confirmation  # noqa: E402
from mintsec_ui.i18n import tr  # noqa: E402
from mintsec_ui.widgets import friendly_module_name  # noqa: E402


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
    if ok:
        res = controller.installer.install_packages(manifest.packages)
        if not res.get("ok"):
            ask_action_confirmation(
                app_window,
                title=tr("actions.install_err_title", name=friendly_name),
                summary=str(res.get("error") or res.get("message") or tr("actions.install_err_fallback")),
                actor=tr("actions.install_err_actor"),
                evidence=tr("actions.install_err_evidence", packages=pkgs),
                confirm_label=tr("common.understood"),
                confirm_effect=tr("common.close_notice"),
            )
            return
        controller.invalidate_cache(include_packages=True)
        for page in (app_window.home_page, app_window.protections_page):
            page._last_render_sig = None
        app_window.refresh_all(force=True)


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
        try:
            new_st = controller.services[mod_id].enable()
            app_window.apply_module_status(mod_id, new_st)
            return False
        except Exception as exc:
            ask_action_confirmation(
                app_window,
                title=tr("actions.enable_err_title", name=friendly_name),
                summary=str(exc),
                actor=friendly_name,
                evidence=tr("actions.enable_err_evidence"),
                confirm_label=tr("common.understood"),
                confirm_effect=tr("common.close_notice"),
            )
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
    try:
        new_st = controller.services[mod_id].disable(revert_suite_changes=True)
        app_window.apply_module_status(mod_id, new_st)
        return False
    except Exception as exc:
        ask_action_confirmation(
            app_window,
            title=tr("actions.disable_err_title", name=friendly_name),
            summary=str(exc),
            actor=friendly_name,
            evidence=tr("actions.disable_err_evidence"),
            confirm_label=tr("common.understood"),
            confirm_effect=tr("common.close_notice"),
        )
        return True

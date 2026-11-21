"""Blocos visuais minimalistas, ilustrações e linguagem amigável do NodusGuard."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import gi

gi.require_version("GdkPixbuf", "2.0")
gi.require_version("Gtk", "3.0")
gi.require_version("Pango", "1.0")
from gi.repository import GdkPixbuf, Gtk, Pango  # noqa: E402

from mintsec.contracts import ModuleState  # noqa: E402
from mintsec_ui.a11y import set_accessible  # noqa: E402
from mintsec_ui.i18n import tr  # noqa: E402

ASSETS_DIR = Path(__file__).resolve().parent / "assets"
_PIXBUF_CACHE: dict[tuple[str, int], GdkPixbuf.Pixbuf] = {}
_APP_ICON_INSTALLED = False

APP_ICON_FILES: tuple[str, ...] = (
    "nodusguard_icon_48.png",
    "nodusguard_icon_64.png",
    "nodusguard_logo.png",
    "nodusguard_icon_256.png",
)

MODULE_ICONS: dict[str, str] = {
    "antimalware": "system-search-symbolic",
    "firewall": "security-high-symbolic",
    "recovery": "document-revert-symbolic",
    "network": "network-wireless-symbolic",
    "browsing": "web-browser-symbolic",
    "isolation": "changes-prevent-symbolic",
    "rescue": "drive-removable-media-symbolic",
}

FRIENDLY_MODULE_NAMES: dict[str, str] = {
    "antimalware": "Antivírus",
    "firewall": "Barreira de rede",
    "recovery": "Cópias de segurança",
    "network": "Rede Wi-Fi",
    "browsing": "Navegação segura",
    "isolation": "Navegador protegido",
    "rescue": "Pendrive de emergência",
}

FRIENDLY_MODULE_TAGLINES: dict[str, str] = {
    "antimalware": "Verifica seus arquivos contra ameaças.",
    "firewall": "Bloqueia acessos indesejados ao computador.",
    "recovery": "Guarda seus arquivos para restaurar quando precisar.",
    "network": "Avisa quando um novo aparelho entra na sua rede.",
    "browsing": "Bloqueia sites falsos e golpes automaticamente.",
    "isolation": "Abre sites sensíveis em uma janela isolada.",
    "rescue": "Ajuda a recuperar o computador fora do sistema.",
}

MODULE_LABELS = FRIENDLY_MODULE_NAMES

CONFIRMATION_LABELS: dict[str, str] = {
    "confirmed": "Confirmado",
    "incomplete": "Incompleto",
    "failed": "Falhou",
    "cancelled": "Cancelado",
}


def install_app_icon() -> None:
    """Registra lista multi-resolução de ícones padrão para todas as janelas GTK."""
    global _APP_ICON_INSTALLED
    if _APP_ICON_INSTALLED:
        return
    pixbufs: list[GdkPixbuf.Pixbuf] = []
    for filename in APP_ICON_FILES:
        path = ASSETS_DIR / filename
        if path.is_file():
            try:
                pixbufs.append(GdkPixbuf.Pixbuf.new_from_file(str(path)))
            except Exception:
                pass
    if pixbufs:
        Gtk.Window.set_default_icon_list(pixbufs)
        _APP_ICON_INSTALLED = True
    else:
        try:
            Gtk.Window.set_default_icon_name("nodusguard")
            _APP_ICON_INSTALLED = True
        except Exception:
            pass


def friendly_module_name(mod_id: str, fallback: str | None = None) -> str:
    """Retorna o nome amigável do módulo no idioma ativo."""
    key = f"mod.name.{mod_id}"
    translated = tr(key)
    if translated != key:
        return translated
    return fallback or FRIENDLY_MODULE_NAMES.get(mod_id, mod_id)


def friendly_module_tagline(mod_id: str, fallback: str = "") -> str:
    """Retorna a descrição curta amigável do módulo no idioma ativo."""
    key = f"mod.tagline.{mod_id}"
    translated = tr(key)
    if translated != key:
        return translated
    return fallback or FRIENDLY_MODULE_TAGLINES.get(mod_id, "")


def friendly_module_state_label(state: ModuleState) -> str:
    """Retorna rótulo legível de ModuleState para diálogos no idioma ativo."""
    key = f"mod_state.{state.name}"
    translated = tr(key)
    return translated if translated != key else state.ui_label


def confirmation_label(state: str) -> str:
    """Retorna rótulo traduzido de estado de confirmação."""
    key = f"confirm_state.{state}"
    translated = tr(key)
    return translated if translated != key else CONFIRMATION_LABELS.get(state, state)


def load_pixbuf(filename: str, size: int) -> GdkPixbuf.Pixbuf | None:
    """Carrega e escala ilustração RGBA em cache de memória."""
    key = (filename, int(size))
    if key in _PIXBUF_CACHE:
        return _PIXBUF_CACHE[key]
    path = ASSETS_DIR / filename
    if not path.is_file():
        return None
    try:
        pix = GdkPixbuf.Pixbuf.new_from_file_at_scale(str(path), int(size), int(size), True)
    except Exception:
        return None
    _PIXBUF_CACHE[key] = pix
    return pix


def make_illustration(
    filename: str,
    size: int,
    *,
    fallback_icon: str = "security-high-symbolic",
    a11y_name: str = "",
) -> Gtk.Image:
    """Cria Gtk.Image transparente com ilustração editorial ou ícone simbólico."""
    pix = load_pixbuf(filename, size)
    if pix is not None:
        img = Gtk.Image.new_from_pixbuf(pix)
    else:
        img = Gtk.Image.new_from_icon_name(fallback_icon, Gtk.IconSize.DIALOG)
        img.set_pixel_size(min(size, 64))
    if a11y_name:
        set_accessible(img, a11y_name, a11y_name)
    return img


def friendly_state_text(mod_id: str, st: Any) -> str:
    """Retorna frase curta em linguagem amigável para o estado atual do módulo."""
    if st.state == ModuleState.AUSENTE:
        return tr("mod.state.available_install")
    if st.state == ModuleState.ATIVO:
        return tr("mod.state.protecting_now")
    if st.state == ModuleState.DESATIVADO:
        if mod_id == "recovery" and st.needs_setup:
            return tr("mod.state.choose_backup_dest")
        return tr("mod.state.off")
    if st.state == ModuleState.DEGRADADO:
        if mod_id == "recovery" and st.needs_setup:
            return tr("mod.state.choose_backup_dest")
        return tr("mod.state.needs_attention")
    if st.state == ModuleState.VERIFICACAO_INCOMPLETA:
        return tr("mod.state.incomplete_scan")
    return tr("mod.state.check_options")


def friendly_verdict_text(
    verdict: Any,
    *,
    statuses: dict[str, Any] | None = None,
    open_pending: list[Any] | None = None,
) -> tuple[str, str]:
    """Adapta título e subtítulo do Hero no idioma ativo de forma acolhedora e direta."""
    if verdict.severity == "ok":
        return tr("verdict.ok_headline"), tr("verdict.ok_subtitle")
    action = getattr(verdict, "primary_cta_action", None)
    target = getattr(verdict, "primary_cta_target", None)

    if verdict.severity == "critical" or action == "review_pending":
        paused = None
        if open_pending:
            for item in open_pending:
                if item.pending_id == target or item.kind == "paused_app":
                    paused = item
                    break
        if paused is not None:
            app = paused.app_name or tr("verdict.paused_app_fallback")
            return tr("verdict.paused_headline"), tr(
                "verdict.paused_subtitle", app=app, evidence=paused.evidence
            )
        return tr("verdict.paused_headline"), verdict.evidence_text

    if action == "open_pending":
        if open_pending:
            first = open_pending[0]
            return tr("verdict.pending_headline", count=len(open_pending)), tr(
                "verdict.pending_subtitle", title=first.title, evidence=first.evidence
            )
        return verdict.headline, verdict.evidence_text

    if action == "open_first_run":
        return tr("verdict.first_run_headline"), tr("verdict.first_run_subtitle")

    if action == "open_scans":
        ev = verdict.evidence_text
        if statuses and "antimalware" in statuses:
            ev = statuses["antimalware"].evidence
        return tr("verdict.incomplete_headline"), ev

    if action == "open_module" and target:
        name = friendly_module_name(target)
        st = statuses.get(target) if statuses else None
        if st is not None:
            if st.state == ModuleState.INDISPONIVEL:
                return tr("verdict.unavailable_headline", name=name), st.evidence
            return tr("verdict.degraded_headline", name=name), st.degraded_reason or st.evidence
        return tr("verdict.degraded_headline", name=name), verdict.evidence_text

    if action == "open_protections":
        return tr("verdict.protections_headline"), tr("verdict.protections_subtitle")

    return verdict.headline, verdict.evidence_text


def friendly_cta_label(verdict: Any, *, statuses: dict[str, Any] | None = None) -> str | None:
    """Retorna rótulo traduzido do botão principal do Hero."""
    if not getattr(verdict, "primary_cta_label", None):
        return None
    action = getattr(verdict, "primary_cta_action", None)
    target = getattr(verdict, "primary_cta_target", None)
    if action == "review_pending":
        return tr("cta.review_paused")
    if action == "open_pending":
        return tr("cta.review_pending")
    if action == "open_first_run":
        return tr("cta.protect_now")
    if action == "open_scans":
        return tr("cta.view_unverified")
    if action == "open_protections":
        return tr("cta.choose_modules")
    if action == "open_module" and target:
        st = statuses.get(target) if statuses else None
        if st is not None:
            if st.state == ModuleState.INDISPONIVEL:
                return tr("cta.open_protection")
            if st.state == ModuleState.DEGRADADO and target == "recovery" and st.needs_setup:
                return tr("cta.setup_backup")
        return tr("cta.view_details")
    return verdict.primary_cta_label


def clear_container(container: Gtk.Container) -> None:
    """Remove e destrói filhos antigos para evitar acúmulo de objetos GTK em memória."""
    for child in list(container.get_children()):
        container.remove(child)
        child.destroy()


def status_tone(state: ModuleState) -> str:
    """Mapeia ModuleState em tom visual semântico."""
    if state == ModuleState.ATIVO:
        return "ok"
    if state in (ModuleState.DEGRADADO, ModuleState.VERIFICACAO_INCOMPLETA, ModuleState.INDISPONIVEL):
        return "warn"
    return "neutral"


def make_pill(label: str, tone: str = "neutral") -> Gtk.Label:
    """Cria etiqueta pill plana e discreta (ok | warn | crit | neutral)."""
    lbl = Gtk.Label(label=label, xalign=0.5)
    lbl.set_valign(Gtk.Align.CENTER)
    ctx = lbl.get_style_context()
    ctx.add_class("mintsec-pill")
    ctx.add_class(f"mintsec-pill-{tone}")
    return lbl


def make_icon_chip(icon_name: str, *, pixel_size: int = 18, tone: str = "neutral") -> Gtk.Box:
    """Contêiner tonal plano para ícone simbólico."""
    chip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
    chip.set_valign(Gtk.Align.CENTER)
    chip.set_halign(Gtk.Align.CENTER)
    ctx = chip.get_style_context()
    ctx.add_class("mintsec-icon-chip")
    if tone != "neutral":
        ctx.add_class(f"mintsec-icon-chip-{tone}")
    img = Gtk.Image.new_from_icon_name(icon_name, Gtk.IconSize.BUTTON)
    img.set_pixel_size(pixel_size)
    chip.pack_start(img, True, True, 0)
    return chip


def make_section_header(
    title: str,
    *,
    action_label: str | None = None,
    on_action: Callable[..., Any] | None = None,
    action_a11y_name: str | None = None,
    action_a11y_desc: str | None = None,
) -> Gtk.Box:
    """Cabeçalho uniforme de seção com título e botão ghost opcional."""
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    lbl = Gtk.Label(label=title, xalign=0.0)
    lbl.set_ellipsize(Pango.EllipsizeMode.END)
    lbl.get_style_context().add_class("mintsec-section-title")
    row.pack_start(lbl, True, True, 0)

    if action_label and on_action is not None:
        btn = Gtk.Button(label=action_label)
        btn.get_style_context().add_class("mintsec-ghost-btn")
        set_accessible(btn, action_a11y_name or action_label, action_a11y_desc or action_label)
        btn.connect("clicked", on_action)
        row.pack_start(btn, False, False, 0)
    return row


def make_metric_chip(label: str, value: str) -> Gtk.Box:
    """Bloco plano compacto exibindo métrica ou data relevante."""
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    box.get_style_context().add_class("mintsec-metric-chip")
    cap = Gtk.Label(label=label, xalign=0.0)
    cap.get_style_context().add_class("mintsec-caption")
    val = Gtk.Label(label=value, xalign=0.0)
    val.set_line_wrap(True)
    val.get_style_context().add_class("mintsec-metric-value")
    box.pack_start(cap, False, False, 0)
    box.pack_start(val, False, False, 0)
    return box


def make_empty_state(
    icon_name: str,
    title: str,
    subtitle: str,
    *,
    illustration: str | None = None,
    illustration_size: int = 88,
) -> Gtk.Box:
    """Estado vazio sereno em formato Flat Design, com ilustração opcional."""
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
    box.get_style_context().add_class("mintsec-empty")
    if illustration:
        art = make_illustration(illustration, illustration_size, fallback_icon=icon_name)
        art.set_valign(Gtk.Align.CENTER)
        box.pack_start(art, False, False, 0)
    else:
        box.pack_start(make_icon_chip(icon_name, pixel_size=20, tone="neutral"), False, False, 0)

    col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
    col.set_valign(Gtk.Align.CENTER)
    t_lbl = Gtk.Label(label=title, xalign=0.0)
    t_lbl.get_style_context().add_class("mintsec-subtitle")
    s_lbl = Gtk.Label(label=subtitle, xalign=0.0)
    s_lbl.set_line_wrap(True)
    s_lbl.get_style_context().add_class("mintsec-muted")
    col.pack_start(t_lbl, False, False, 0)
    col.pack_start(s_lbl, False, False, 0)
    box.pack_start(col, True, True, 0)
    return box

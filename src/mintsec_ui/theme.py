"""Sistema visual Flat Design adaptativo: escuro moderno, claro lavanda/neutro e alto contraste."""

from __future__ import annotations

from dataclasses import dataclass

import gi

gi.require_version("Gdk", "3.0")
gi.require_version("Gtk", "3.0")
from gi.repository import Gdk, Gio, Gtk  # noqa: E402

LAVENDER_TOKENS: dict[str, str] = {
    "sidebar_bg": "#E9E7F6",
    "sidebar_hover": "#DFDCF2",
    "page_bg": "#F0EFFA",
    "card_bg": "#FFFFFF",
    "card_hover": "#FAF9FF",
    "surface_elevated": "#ECEAF8",
    "surface_subtle": "#F6F5FC",
    "divider": "#DDD9EE",
    "text_primary": "#1F1835",
    "text_secondary": "#50476B",
    "border": "#827A99",
    "accent": "#5E3DD6",
    "accent_hover": "#4E30BE",
    "accent_fg": "#FFFFFF",
    "accent_soft": "rgba(94, 61, 214, 0.12)",
    "accent_text": "#4E30BE",
    "danger_bg": "#C81E3E",
    "danger_fg": "#FFFFFF",
    "danger_soft": "#FDE8EC",
    "danger_text": "#8B1126",
    "badge_ok_bg": "#E6F6EE",
    "badge_ok_fg": "#115E38",
    "badge_warn_bg": "#FEF3D6",
    "badge_warn_fg": "#6E4700",
    "badge_crit_bg": "#FDE8EC",
    "badge_crit_fg": "#8B1126",
    "badge_neutral_bg": "#ECEAF8",
    "badge_neutral_fg": "#4A4163",
}

DARK_FLAT_TOKENS: dict[str, str] = {
    "sidebar_bg": "#11141C",
    "sidebar_hover": "#1A1F2C",
    "page_bg": "#161A23",
    "card_bg": "#1E2330",
    "card_hover": "#252B3B",
    "surface_elevated": "#262C3C",
    "surface_subtle": "#1A1F2B",
    "divider": "#2A3142",
    "text_primary": "#F2F4F8",
    "text_secondary": "#A5B0C2",
    "border": "#8893A8",
    "accent": "#8B7CFF",
    "accent_hover": "#9D90FF",
    "accent_fg": "#100E24",
    "accent_soft": "rgba(139, 124, 255, 0.16)",
    "accent_text": "#C4BAFF",
    "danger_bg": "#D92D4B",
    "danger_fg": "#FFFFFF",
    "danger_soft": "#3B151F",
    "danger_text": "#FDA4AF",
    "badge_ok_bg": "#143026",
    "badge_ok_fg": "#6EE7B7",
    "badge_warn_bg": "#332610",
    "badge_warn_fg": "#FCD34D",
    "badge_crit_bg": "#3B151F",
    "badge_crit_fg": "#FDA4AF",
    "badge_neutral_bg": "#262C3C",
    "badge_neutral_fg": "#B5BFCF",
}

THEME_PRESETS: dict[str, dict[str, str]] = {
    "lavender": LAVENDER_TOKENS,
    "neutral_light": {
        "sidebar_bg": "#ECEFF4",
        "sidebar_hover": "#E2E6EE",
        "page_bg": "#F4F6FA",
        "card_bg": "#FFFFFF",
        "card_hover": "#F8FAFC",
        "surface_elevated": "#E9EDF4",
        "surface_subtle": "#F7F9FC",
        "divider": "#DCE1EA",
        "text_primary": "#151922",
        "text_secondary": "#4B5565",
        "border": "#7A8494",
        "accent": "#2563EB",
        "accent_hover": "#1D4ED8",
        "accent_fg": "#FFFFFF",
        "accent_soft": "rgba(37, 99, 235, 0.12)",
        "accent_text": "#1D4ED8",
        "danger_bg": "#C81E3E",
        "danger_fg": "#FFFFFF",
        "danger_soft": "#FDE8EC",
        "danger_text": "#8B1126",
        "badge_ok_bg": "#E6F6EE",
        "badge_ok_fg": "#115E38",
        "badge_warn_bg": "#FEF3D6",
        "badge_warn_fg": "#6E4700",
        "badge_crit_bg": "#FDE8EC",
        "badge_crit_fg": "#8B1126",
        "badge_neutral_bg": "#E9EDF4",
        "badge_neutral_fg": "#475161",
    },
    "graphite_dark": DARK_FLAT_TOKENS,
}


def srgb_to_linear(channel: float) -> float:
    """Converte componente sRGB [0..1] em luminância linear conforme WCAG 2.2."""
    if channel <= 0.04045:
        return channel / 12.92
    return ((channel + 0.055) / 1.055) ** 2.4


def relative_luminance(rgb: tuple[float, float, float]) -> float:
    """Calcula luminância relativa WCAG 2.2 de uma tupla (r, g, b) em [0..1]."""
    r, g, b = (srgb_to_linear(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(c1: tuple[float, float, float], c2: tuple[float, float, float]) -> float:
    """Calcula razão de contraste WCAG entre duas cores RGB [0..1]."""
    l1 = relative_luminance(c1)
    l2 = relative_luminance(c2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def hex_to_rgb(hex_color: str) -> tuple[float, float, float]:
    """Converte '#RRGGBB' em tupla (r, g, b) normalizada [0..1]."""
    clean = hex_color.strip().lstrip("#")
    if len(clean) != 6:
        raise ValueError(f"Cor hexadecimal inválida: {hex_color}")
    return (
        int(clean[0:2], 16) / 255.0,
        int(clean[2:4], 16) / 255.0,
        int(clean[4:6], 16) / 255.0,
    )


def rgba_to_rgb(rgba: Gdk.RGBA) -> tuple[float, float, float]:
    return (float(rgba.red), float(rgba.green), float(rgba.blue))


def rgba_to_hex(rgba: Gdk.RGBA) -> str:
    return "#{:02X}{:02X}{:02X}".format(
        round(rgba.red * 255),
        round(rgba.green * 255),
        round(rgba.blue * 255),
    )


@dataclass(frozen=True)
class ThemeInfo:
    """Resultado da resolução do modo visual atual."""

    mode: str  # 'light_lavender' | 'light_neutral' | 'dark' | 'dark_graphite' | 'high_contrast'
    gtk_theme_name: str
    accent_bg: str | None = None
    accent_fg: str | None = None
    preset: str = "lavender"


def _read_portal_appearance() -> tuple[int | None, int | None]:
    """Lê (color_scheme, contrast) do org.freedesktop.portal.Settings quando disponível."""
    try:
        import dbus

        bus = dbus.SessionBus()
        obj = bus.get_object("org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop")
        iface = dbus.Interface(obj, "org.freedesktop.portal.Settings")
        color_scheme = None
        contrast = None
        try:
            color_scheme = int(iface.Read("org.freedesktop.appearance", "color-scheme"))
        except Exception:
            pass
        try:
            contrast = int(iface.Read("org.freedesktop.appearance", "contrast"))
        except Exception:
            pass
        return color_scheme, contrast
    except Exception:
        return None, None


def _read_gsettings_bool(schema_id: str, key: str) -> bool:
    try:
        source = Gio.SettingsSchemaSource.get_default()
        if source is None or source.lookup(schema_id, True) is None:
            return False
        settings = Gio.Settings.new(schema_id)
        return bool(settings.get_boolean(key))
    except Exception:
        return False


def resolve_theme_info(
    *,
    theme_mode: str = "follow_system",
    theme_preset: str = "lavender",
    probe_widget: Gtk.Widget | None = None,
) -> ThemeInfo:
    """Identifica o tema ativo: alto contraste (sem CSS), escuro flat ou claro flat."""
    gtk_settings = Gtk.Settings.get_default()
    gtk_theme_name = ""
    prefer_dark_prop = False
    if gtk_settings is not None:
        gtk_theme_name = str(gtk_settings.get_property("gtk-theme-name") or "")
        prefer_dark_prop = bool(gtk_settings.get_property("gtk-application-prefer-dark-theme"))

    a11y_hc = _read_gsettings_bool("org.gnome.desktop.a11y.interface", "high-contrast")
    xapp_hc = _read_gsettings_bool("org.x.apps.portal", "high-contrast")

    # 1. Alto contraste: omitir CSS próprio
    if a11y_hc or xapp_hc or "highcontrast" in gtk_theme_name.lower():
        return ThemeInfo(mode="high_contrast", gtk_theme_name=gtk_theme_name)

    style_ctx = probe_widget.get_style_context() if probe_widget is not None else None
    if style_ctx is not None:
        ok_bg, bg_rgba = style_ctx.lookup_color("theme_bg_color")
        ok_fg, fg_rgba = style_ctx.lookup_color("theme_fg_color")
        if ok_bg and ok_fg:
            cr = contrast_ratio(rgba_to_rgb(fg_rgba), rgba_to_rgb(bg_rgba))
            if cr >= 15.0:
                return ThemeInfo(mode="high_contrast", gtk_theme_name=gtk_theme_name)

    portal_scheme, portal_contrast = _read_portal_appearance()
    if portal_contrast == 1:
        return ThemeInfo(mode="high_contrast", gtk_theme_name=gtk_theme_name)

    # 2. Modo escuro (luminância real de theme_bg_color + fallback portal)
    is_dark = False
    if theme_mode == "dark":
        is_dark = True
    elif theme_mode == "light":
        is_dark = False
    else:
        if style_ctx is not None:
            ok_bg, bg_rgba = style_ctx.lookup_color("theme_bg_color")
            if ok_bg:
                is_dark = relative_luminance(rgba_to_rgb(bg_rgba)) < 0.25
        if not is_dark and (portal_scheme == 1 or prefer_dark_prop or "dark" in gtk_theme_name.lower()):
            is_dark = True

    if is_dark or theme_preset == "graphite_dark":
        if theme_preset == "graphite_dark" and theme_mode != "light":
            return ThemeInfo(
                mode="dark_graphite",
                gtk_theme_name=gtk_theme_name,
                accent_bg=DARK_FLAT_TOKENS["accent"],
                accent_fg=DARK_FLAT_TOKENS["accent_fg"],
                preset="graphite_dark",
            )
        if is_dark:
            return ThemeInfo(
                mode="dark",
                gtk_theme_name=gtk_theme_name,
                accent_bg=DARK_FLAT_TOKENS["accent"],
                accent_fg=DARK_FLAT_TOKENS["accent_fg"],
                preset="system_dark",
            )

    # 3. Modo claro: lavanda ou claro neutro em Flat Design
    chosen_light = theme_preset if theme_preset in ("lavender", "neutral_light") else "lavender"
    tokens = THEME_PRESETS[chosen_light]
    mode_id = "light_neutral" if chosen_light == "neutral_light" else "light_lavender"
    return ThemeInfo(
        mode=mode_id,
        gtk_theme_name=gtk_theme_name,
        accent_bg=tokens["accent"],
        accent_fg=tokens["accent_fg"],
        preset=chosen_light,
    )


def build_css(theme_info: ThemeInfo) -> str:
    """Gera CSS Flat Design para o tema resolvido; retorna vazio em alto contraste."""
    if theme_info.mode == "high_contrast":
        return ""

    if theme_info.mode in ("dark", "dark_graphite"):
        return _build_palette_css(DARK_FLAT_TOKENS)

    tokens = THEME_PRESETS.get(theme_info.preset, LAVENDER_TOKENS)
    return _build_palette_css(tokens)


def _build_palette_css(t: dict[str, str]) -> str:
    """Gera folha CSS Flat Design 100% compatível com GTK 3.24 com transições leves."""
    return f"""
    .mintsec-window button,
    .mintsec-dialog button,
    .mintsec-window notebook.mintsec-tabs > header > tabs > tab,
    .mintsec-window switch,
    .mintsec-window switch slider {{
        transition: background-color 140ms ease-out, border-color 140ms ease-out, color 140ms ease-out;
    }}
    .mintsec-window,
    .mintsec-window:backdrop,
    .mintsec-dialog,
    .mintsec-dialog:backdrop,
    .mintsec-content,
    .mintsec-content:backdrop {{
        background-color: {t['page_bg']};
        color: {t['text_primary']};
    }}
    .mintsec-sidebar,
    .mintsec-sidebar:backdrop {{
        background-color: {t['sidebar_bg']};
        border-right: 1px solid {t['divider']};
        color: {t['text_primary']};
        padding: 16px 12px 14px 12px;
    }}
    .mintsec-brand-row {{
        padding: 4px 8px 12px 8px;
    }}
    .mintsec-brand-icon {{
        color: {t['accent_text']};
    }}
    .mintsec-brand-title {{
        color: {t['text_primary']};
        font-weight: 700;
        font-size: 1.02em;
    }}
    .mintsec-brand-sub {{
        color: {t['text_secondary']};
        font-size: 0.82em;
    }}
    .mintsec-nav-section {{
        color: {t['text_secondary']};
        font-size: 0.74em;
        font-weight: 700;
        letter-spacing: 0.08em;
        padding: 8px 10px 4px 10px;
    }}
    .mintsec-window separator.mintsec-divider,
    .mintsec-dialog separator.mintsec-divider {{
        background-color: {t['divider']};
        min-height: 1px;
        margin-top: 4px;
        margin-bottom: 4px;
    }}
    .mintsec-page-title {{
        color: {t['text_primary']};
        font-size: 1.42em;
        font-weight: 700;
    }}
    .mintsec-hero-title {{
        color: {t['text_primary']};
        font-size: 1.16em;
        font-weight: 700;
    }}
    .mintsec-section-title {{
        color: {t['text_primary']};
        font-size: 1.02em;
        font-weight: 700;
    }}
    .mintsec-subtitle {{
        color: {t['text_primary']};
        font-weight: 600;
    }}
    .mintsec-title {{
        color: {t['text_primary']};
        font-weight: 700;
    }}
    .mintsec-muted {{
        color: {t['text_secondary']};
        font-size: 0.92em;
    }}
    .mintsec-caption {{
        color: {t['text_secondary']};
        font-size: 0.82em;
        font-weight: 600;
    }}
    .mintsec-metric-value {{
        color: {t['text_primary']};
        font-weight: 600;
        font-size: 0.95em;
    }}
    .mintsec-card {{
        background-color: {t['card_bg']};
        color: {t['text_primary']};
        border: 1px solid {t['divider']};
        border-radius: 12px;
        padding: 16px;
        box-shadow: none;
    }}
    .mintsec-hero-card {{
        background-color: {t['card_bg']};
        color: {t['text_primary']};
        border: 1px solid {t['divider']};
        border-radius: 14px;
        padding: 18px 20px;
        box-shadow: none;
    }}
    .mintsec-hero-ok {{
        border-color: {t['badge_ok_fg']};
    }}
    .mintsec-hero-alert {{
        border-color: {t['badge_crit_fg']};
    }}
    .mintsec-meta-pill {{
        background-color: {t['surface_subtle']};
        color: {t['text_secondary']};
        border: 1px solid {t['divider']};
        border-radius: 999px;
        padding: 4px 11px;
        font-size: 0.84em;
        font-weight: 600;
    }}
    .mintsec-rec-row {{
        background-color: {t['surface_subtle']};
        border: 1px solid {t['divider']};
        border-radius: 10px;
        padding: 10px 12px;
    }}
    .mintsec-sidebar-footer {{
        padding-top: 6px;
    }}
    .mintsec-window button.mintsec-sidebar-bell,
    .mintsec-window button.mintsec-sidebar-bell:backdrop {{
        background-image: none;
        background-color: {t['surface_elevated']};
        color: {t['text_secondary']};
        border: 1px solid transparent;
        border-radius: 8px;
        padding: 8px 10px;
        min-width: 44px;
    }}
    .mintsec-window button.mintsec-sidebar-bell:hover {{
        background-color: {t['sidebar_hover']};
        color: {t['text_primary']};
    }}
    .mintsec-window button.mintsec-sidebar-bell.mintsec-active-nav,
    .mintsec-window button.mintsec-sidebar-bell.mintsec-active-nav:backdrop {{
        background-color: {t['accent_soft']};
        color: {t['accent_text']};
        font-weight: 700;
    }}
    .mintsec-window button.mintsec-sidebar-bell.mintsec-bell-alert,
    .mintsec-window button.mintsec-sidebar-bell.mintsec-bell-alert:backdrop {{
        background-color: {t['badge_warn_bg']};
        color: {t['badge_warn_fg']};
    }}
    .mintsec-window progressbar.mintsec-progress trough {{
        background-color: {t['surface_elevated']};
        border: 1px solid {t['divider']};
        border-radius: 999px;
        min-height: 10px;
    }}
    .mintsec-window progressbar.mintsec-progress progress {{
        background-color: {t['accent']};
        border-radius: 999px;
        min-height: 10px;
    }}
    .mintsec-list-card {{
        background-color: {t['card_bg']};
        color: {t['text_primary']};
        border: 1px solid {t['divider']};
        border-radius: 12px;
        padding: 14px 16px;
        box-shadow: none;
    }}
    .mintsec-callout {{
        background-color: {t['surface_subtle']};
        color: {t['text_primary']};
        border: 1px solid {t['divider']};
        border-radius: 10px;
        padding: 12px 14px;
        box-shadow: none;
    }}
    .mintsec-callout-warn {{
        background-color: {t['badge_warn_bg']};
        color: {t['badge_warn_fg']};
        border-color: transparent;
    }}
    .mintsec-metric-chip {{
        background-color: {t['surface_subtle']};
        border: 1px solid {t['divider']};
        border-radius: 10px;
        padding: 10px 14px;
    }}
    .mintsec-icon-chip {{
        background-color: {t['surface_elevated']};
        color: {t['text_secondary']};
        border-radius: 10px;
        padding: 8px;
        min-width: 18px;
        min-height: 18px;
    }}
    .mintsec-icon-chip-accent {{
        background-color: {t['accent_soft']};
        color: {t['accent_text']};
    }}
    .mintsec-icon-chip-ok {{
        background-color: {t['badge_ok_bg']};
        color: {t['badge_ok_fg']};
    }}
    .mintsec-icon-chip-warn {{
        background-color: {t['badge_warn_bg']};
        color: {t['badge_warn_fg']};
    }}
    .mintsec-icon-chip-crit {{
        background-color: {t['badge_crit_bg']};
        color: {t['badge_crit_fg']};
    }}
    .mintsec-shield-badge {{
        color: {t['accent_text']};
    }}
    .mintsec-shield-ok {{
        color: {t['badge_ok_fg']};
    }}
    .mintsec-shield-warn {{
        color: {t['badge_warn_fg']};
    }}
    .mintsec-shield-crit {{
        color: {t['badge_crit_fg']};
    }}
    .mintsec-segmented {{
        background-color: {t['surface_subtle']};
        border: 1px solid {t['divider']};
        border-radius: 10px;
        padding: 3px;
    }}
    .mintsec-window button,
    .mintsec-window button:backdrop,
    .mintsec-dialog button,
    .mintsec-dialog button:backdrop {{
        background-image: none;
        background-color: {t['surface_elevated']};
        color: {t['text_primary']};
        border: 1px solid {t['divider']};
        border-radius: 8px;
        padding: 7px 14px;
        font-weight: 600;
        box-shadow: none;
        text-shadow: none;
        -gtk-icon-shadow: none;
    }}
    .mintsec-window button:hover,
    .mintsec-dialog button:hover {{
        background-color: {t['card_hover']};
        border-color: {t['border']};
    }}
    .mintsec-window headerbar.mintsec-csd-headerbar,
    .mintsec-window headerbar.mintsec-csd-headerbar:backdrop {{
        background-image: none;
        background-color: {t['sidebar_bg']};
        color: {t['text_primary']};
        border-bottom: 1px solid {t['divider']};
        box-shadow: none;
        padding: 4px 10px;
    }}
    .mintsec-window headerbar.mintsec-csd-headerbar .title {{
        color: {t['text_primary']};
        font-weight: 700;
    }}
    .mintsec-window headerbar.mintsec-csd-headerbar .subtitle {{
        color: {t['text_secondary']};
        font-size: 0.86em;
    }}
    .mintsec-window headerbar.mintsec-csd-headerbar button.titlebutton,
    .mintsec-window headerbar.mintsec-csd-headerbar button.titlebutton:backdrop {{
        background-image: none;
        background-color: transparent;
        color: {t['text_secondary']};
        border: 1px solid transparent;
        border-radius: 6px;
        padding: 3px 7px;
        min-height: 24px;
        min-width: 24px;
        box-shadow: none;
    }}
    .mintsec-window headerbar.mintsec-csd-headerbar button.titlebutton:hover {{
        background-color: {t['sidebar_hover']};
        color: {t['text_primary']};
        border-color: {t['divider']};
    }}
    .mintsec-window button:disabled,
    .mintsec-window button:disabled:backdrop,
    .mintsec-dialog button:disabled,
    .mintsec-dialog button:disabled:backdrop {{
        opacity: 0.48;
    }}
    .mintsec-window button:focus,
    .mintsec-dialog button:focus {{
        outline: 2px solid {t['accent']};
        outline-offset: -2px;
    }}
    .mintsec-window button.mintsec-sidebar-btn,
    .mintsec-window button.mintsec-sidebar-btn:backdrop {{
        background-image: none;
        background-color: transparent;
        color: {t['text_secondary']};
        border: 1px solid transparent;
        border-radius: 8px;
        padding: 8px 12px;
        font-weight: 500;
    }}
    .mintsec-window button.mintsec-sidebar-btn:hover {{
        background-color: {t['sidebar_hover']};
        color: {t['text_primary']};
        border-color: transparent;
    }}
    .mintsec-window button.mintsec-sidebar-btn.mintsec-active-nav,
    .mintsec-window button.mintsec-sidebar-btn.mintsec-active-nav:backdrop {{
        background-color: {t['accent_soft']};
        color: {t['accent_text']};
        border-color: transparent;
        font-weight: 700;
    }}
    .mintsec-window button.mintsec-action-card,
    .mintsec-window button.mintsec-action-card:backdrop {{
        background-image: none;
        background-color: {t['card_bg']};
        color: {t['text_primary']};
        border: 1px solid {t['divider']};
        border-radius: 12px;
        padding: 14px 16px;
        box-shadow: none;
    }}
    .mintsec-window button.mintsec-action-card:hover {{
        background-color: {t['card_hover']};
        border-color: {t['accent']};
    }}
    .mintsec-window button.mintsec-ghost-btn,
    .mintsec-window button.mintsec-ghost-btn:backdrop,
    .mintsec-dialog button.mintsec-ghost-btn,
    .mintsec-dialog button.mintsec-ghost-btn:backdrop {{
        background-color: transparent;
        border-color: transparent;
        color: {t['text_secondary']};
        padding: 5px 10px;
    }}
    .mintsec-window button.mintsec-ghost-btn:hover,
    .mintsec-dialog button.mintsec-ghost-btn:hover {{
        background-color: {t['surface_elevated']};
        color: {t['text_primary']};
        border-color: transparent;
    }}
    .mintsec-window button.mintsec-seg-btn,
    .mintsec-window button.mintsec-seg-btn:backdrop {{
        background-color: transparent;
        border-color: transparent;
        color: {t['text_secondary']};
        border-radius: 7px;
        padding: 5px 14px;
        font-weight: 600;
    }}
    .mintsec-window button.mintsec-seg-btn:hover {{
        background-color: {t['surface_elevated']};
        color: {t['text_primary']};
        border-color: transparent;
    }}
    .mintsec-window button.mintsec-seg-btn:checked,
    .mintsec-window button.mintsec-seg-btn:checked:backdrop {{
        background-color: {t['card_bg']};
        color: {t['text_primary']};
        border-color: {t['divider']};
        font-weight: 700;
    }}
    .mintsec-window button.mintsec-primary-cta,
    .mintsec-window button.mintsec-primary-cta:backdrop,
    .mintsec-dialog button.mintsec-primary-cta,
    .mintsec-dialog button.mintsec-primary-cta:backdrop,
    .mintsec-window button.suggested-action,
    .mintsec-window button.suggested-action:backdrop,
    .mintsec-dialog button.suggested-action,
    .mintsec-dialog button.suggested-action:backdrop {{
        background-image: none;
        background-color: {t['accent']};
        color: {t['accent_fg']};
        border-color: {t['accent']};
        font-weight: 700;
    }}
    .mintsec-window button.mintsec-primary-cta:hover,
    .mintsec-dialog button.mintsec-primary-cta:hover,
    .mintsec-window button.suggested-action:hover,
    .mintsec-dialog button.suggested-action:hover {{
        background-color: {t['accent_hover']};
        border-color: {t['accent_hover']};
    }}
    .mintsec-window button.mintsec-primary-cta:disabled,
    .mintsec-window button.mintsec-primary-cta:disabled:backdrop,
    .mintsec-dialog button.mintsec-primary-cta:disabled,
    .mintsec-dialog button.mintsec-primary-cta:disabled:backdrop,
    .mintsec-window button.suggested-action:disabled,
    .mintsec-dialog button.suggested-action:disabled {{
        background-image: none;
        background-color: {t['surface_elevated']};
        color: {t['text_secondary']};
        border-color: {t['divider']};
        opacity: 0.72;
    }}
    .mintsec-window button.destructive-action,
    .mintsec-window button.destructive-action:backdrop,
    .mintsec-dialog button.destructive-action,
    .mintsec-dialog button.destructive-action:backdrop {{
        background-image: none;
        background-color: {t['danger_soft']};
        color: {t['danger_text']};
        border-color: {t['divider']};
    }}
    .mintsec-window button.destructive-action:disabled,
    .mintsec-window button.destructive-action:disabled:backdrop,
    .mintsec-dialog button.destructive-action:disabled,
    .mintsec-dialog button.destructive-action:disabled:backdrop {{
        background-color: transparent;
        border-color: {t['divider']};
        color: {t['text_secondary']};
        opacity: 0.48;
    }}
    .mintsec-window button.destructive-action:hover,
    .mintsec-dialog button.destructive-action:hover {{
        background-color: {t['danger_bg']};
        color: {t['danger_fg']};
        border-color: {t['danger_bg']};
    }}
    .mintsec-window button.mintsec-bell-btn,
    .mintsec-window button.mintsec-bell-btn:backdrop {{
        background-color: {t['card_bg']};
        color: {t['text_primary']};
        border: 1px solid {t['divider']};
        border-radius: 8px;
        padding: 6px 12px;
    }}
    .mintsec-window button.mintsec-bell-btn:hover {{
        background-color: {t['surface_elevated']};
        border-color: {t['border']};
    }}
    .mintsec-window button.mintsec-bell-btn.mintsec-bell-alert,
    .mintsec-window button.mintsec-bell-btn.mintsec-bell-alert:backdrop {{
        background-color: {t['badge_warn_bg']};
        color: {t['badge_warn_fg']};
        border-color: transparent;
    }}
    .mintsec-window button.mintsec-banner-active {{
        background-color: {t['accent_soft']};
        color: {t['accent_text']};
        border: 1px solid {t['accent']};
        border-radius: 10px;
        padding: 8px 14px;
    }}
    .mintsec-pill {{
        border-radius: 999px;
        padding: 3px 10px;
        font-weight: 700;
        font-size: 0.80em;
        border: none;
    }}
    .mintsec-pill-ok {{
        background-color: {t['badge_ok_bg']};
        color: {t['badge_ok_fg']};
    }}
    .mintsec-pill-warn {{
        background-color: {t['badge_warn_bg']};
        color: {t['badge_warn_fg']};
    }}
    .mintsec-pill-crit {{
        background-color: {t['badge_crit_bg']};
        color: {t['badge_crit_fg']};
    }}
    .mintsec-pill-neutral {{
        background-color: {t['badge_neutral_bg']};
        color: {t['badge_neutral_fg']};
    }}
    .mintsec-window notebook.mintsec-tabs,
    .mintsec-window notebook.mintsec-tabs > stack {{
        background-color: transparent;
        border: none;
        box-shadow: none;
    }}
    .mintsec-window notebook.mintsec-tabs > header {{
        background-color: transparent;
        border: none;
        border-bottom: 1px solid {t['divider']};
        margin-bottom: 12px;
        padding-bottom: 6px;
    }}
    .mintsec-window notebook.mintsec-tabs > header > tabs > tab {{
        background-image: none;
        background-color: transparent;
        color: {t['text_secondary']};
        border: none;
        border-radius: 8px;
        padding: 7px 14px;
        margin-right: 4px;
        font-weight: 600;
        box-shadow: none;
        text-shadow: none;
    }}
    .mintsec-window notebook.mintsec-tabs > header > tabs > tab:hover {{
        background-color: {t['surface_elevated']};
        color: {t['text_primary']};
    }}
    .mintsec-window notebook.mintsec-tabs > header > tabs > tab:checked {{
        background-color: {t['accent_soft']};
        color: {t['accent_text']};
        font-weight: 700;
        border: none;
        box-shadow: none;
    }}
    .mintsec-window entry,
    .mintsec-dialog entry {{
        background-image: none;
        background-color: {t['surface_subtle']};
        color: {t['text_primary']};
        border: 1px solid {t['border']};
        border-radius: 8px;
        padding: 7px 11px;
        box-shadow: none;
    }}
    .mintsec-window entry:focus,
    .mintsec-dialog entry:focus {{
        border-color: {t['accent']};
        outline: none;
    }}
    .mintsec-window combobox button.combo,
    .mintsec-dialog combobox button.combo {{
        background-image: none;
        background-color: {t['surface_subtle']};
        color: {t['text_primary']};
        border: 1px solid {t['border']};
        border-radius: 8px;
        padding: 6px 12px;
        box-shadow: none;
    }}
    .mintsec-window combobox button.combo:hover,
    .mintsec-dialog combobox button.combo:hover {{
        border-color: {t['accent']};
    }}
    .mintsec-window checkbutton,
    .mintsec-dialog checkbutton,
    .mintsec-window radiobutton,
    .mintsec-dialog radiobutton {{
        color: {t['text_primary']};
        padding: 3px 0;
    }}
    .mintsec-window scrollbar,
    .mintsec-window scrollbar trough {{
        background-color: transparent;
        border: none;
    }}
    .mintsec-window scrollbar slider {{
        background-color: {t['divider']};
        border: none;
        border-radius: 999px;
        min-width: 7px;
        min-height: 7px;
        margin: 2px;
    }}
    .mintsec-window scrollbar slider:hover {{
        background-color: {t['border']};
    }}
    .mintsec-window popover.background {{
        background-color: {t['card_bg']};
        color: {t['text_primary']};
        border: 1px solid {t['divider']};
        border-radius: 12px;
        box-shadow: none;
    }}
    .mintsec-window button.mintsec-icon-btn,
    .mintsec-window button.mintsec-icon-btn:backdrop {{
        background-image: none;
        background-color: transparent;
        border-color: transparent;
        color: {t['text_secondary']};
        border-radius: 8px;
        padding: 5px 8px;
        min-width: 24px;
    }}
    .mintsec-window button.mintsec-icon-btn:hover {{
        background-color: {t['surface_elevated']};
        color: {t['text_primary']};
        border-color: transparent;
    }}
    .mintsec-window switch,
    .mintsec-window switch:backdrop {{
        background-image: none;
        background-color: {t['surface_elevated']};
        color: transparent;
        border: 1px solid {t['border']};
        border-radius: 999px;
        min-width: 44px;
        min-height: 24px;
        box-shadow: none;
        text-shadow: none;
        font-size: 0;
    }}
    .mintsec-window switch:checked,
    .mintsec-window switch:checked:backdrop {{
        background-color: {t['accent']};
        border-color: {t['accent']};
        color: transparent;
    }}
    .mintsec-window switch slider,
    .mintsec-window switch slider:backdrop {{
        background-image: none;
        background-color: {t['card_bg']};
        border: none;
        border-radius: 999px;
        min-width: 18px;
        min-height: 18px;
        margin: 2px;
        box-shadow: none;
    }}
    .mintsec-window switch:checked slider,
    .mintsec-window switch:checked slider:backdrop {{
        background-color: {t['accent_fg']};
    }}
    .mintsec-window switch:disabled {{
        opacity: 0.45;
    }}
    .mintsec-window expander > title {{
        color: {t['text_secondary']};
        font-weight: 600;
        padding: 4px 2px;
        border-radius: 6px;
    }}
    .mintsec-window expander > title:hover {{
        color: {t['text_primary']};
    }}
    .mintsec-window expander arrow {{
        color: {t['text_secondary']};
    }}
    .mintsec-window .mintsec-activity-bar {{
        background-color: {t['surface_subtle']};
        border: 1px solid {t['divider']};
        border-radius: 10px;
        padding: 7px 12px;
    }}
    .mintsec-window progressbar.mintsec-activity-progress trough {{
        background-color: {t['surface_elevated']};
        border: 1px solid {t['divider']};
        border-radius: 999px;
        min-height: 5px;
    }}
    .mintsec-window progressbar.mintsec-activity-progress progress {{
        background-color: {t['accent']};
        border-radius: 999px;
        min-height: 5px;
    }}
    textview.mintsec-log-view,
    textview.mintsec-log-view text {{
        background-color: {t['surface_subtle']};
        color: {t['text_primary']};
        font-family: monospace;
        font-size: 0.9em;
    }}
    .mintsec-window scrolledwindow undershoot.top,
    .mintsec-window scrolledwindow undershoot.bottom,
    .mintsec-window scrolledwindow undershoot.left,
    .mintsec-window scrolledwindow undershoot.right,
    .mintsec-window scrolledwindow overshoot.top,
    .mintsec-window scrolledwindow overshoot.bottom,
    .mintsec-window scrolledwindow overshoot.left,
    .mintsec-window scrolledwindow overshoot.right {{
        background-image: none;
        background-color: transparent;
        border: none;
        box-shadow: none;
    }}
    """


class ThemeManager:
    """Aplica e atualiza CssProvider no Gdk.Screen respeitando tema do sistema."""

    def __init__(self) -> None:
        self._provider: Gtk.CssProvider | None = None
        self._screen: Gdk.Screen | None = None
        self._applied_css: str = ""
        self.current_info: ThemeInfo = ThemeInfo(mode="light_lavender", gtk_theme_name="")

    def apply(
        self,
        *,
        theme_mode: str = "follow_system",
        theme_preset: str = "lavender",
        probe_widget: Gtk.Widget | None = None,
        screen: Gdk.Screen | None = None,
    ) -> ThemeInfo:
        target_screen = screen or Gdk.Screen.get_default()
        info = resolve_theme_info(
            theme_mode=theme_mode,
            theme_preset=theme_preset,
            probe_widget=probe_widget,
        )
        self.current_info = info
        css = build_css(info)
        if target_screen is self._screen and css == self._applied_css and (bool(css) == (self._provider is not None)):
            return info

        if self._provider is not None and self._screen is not None:
            Gtk.StyleContext.remove_provider_for_screen(self._screen, self._provider)
            self._provider = None

        if css and target_screen is not None:
            provider = Gtk.CssProvider()
            provider.load_from_data(css.encode("utf-8"))
            Gtk.StyleContext.add_provider_for_screen(
                target_screen,
                provider,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
            )
            self._provider = provider
            self._screen = target_screen
        else:
            self._screen = target_screen
        self._applied_css = css
        return info

    def cleanup(self) -> None:
        """Remove o CssProvider associado à tela ao destruir a janela."""
        if self._provider is not None and self._screen is not None:
            Gtk.StyleContext.remove_provider_for_screen(self._screen, self._provider)
        self._provider = None
        self._screen = None
        self._applied_css = ""

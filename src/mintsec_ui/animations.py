"""Animações ultra-leves em Cairo e utilitários de progresso/ETA do NodusGuard."""

from __future__ import annotations

import math
import time

import cairo
import gi

gi.require_version("Gdk", "3.0")
gi.require_version("GLib", "2.0")
gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk  # noqa: E402

from mintsec_ui.i18n import get_language, tr  # noqa: E402


def format_eta(seconds: int | None, *, lang: str | None = None) -> str:
    """Formata tempo restante estimado (ETA) de forma legível em inglês ou português."""
    active_lang = lang or get_language()
    if seconds is None:
        return tr("scans.eta_calculating")
    secs = max(0, int(seconds))
    if secs < 5:
        return tr("scans.eta_few_secs")
    if secs < 60:
        return f"~{secs}s"
    mins, rem_s = divmod(secs, 60)
    if mins < 60:
        return f"~{mins}m {rem_s:02d}s" if rem_s else f"~{mins}m"
    hours, rem_m = divmod(mins, 60)
    suffix_h = "h" if active_lang else "h"
    return f"~{hours}{suffix_h} {rem_m:02d}m" if rem_m else f"~{hours}{suffix_h}"


def _animations_enabled() -> bool:
    settings = Gtk.Settings.get_default()
    if settings is None:
        return True
    try:
        return bool(settings.get_property("gtk-enable-animations"))
    except Exception:
        return True


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def _draw_shield_path(ctx: cairo.Context, cx: float, cy: float, r: float) -> None:
    """Desenha contorno limpo e simétrico de escudo centrado em (cx, cy)."""
    ctx.new_path()
    ctx.move_to(cx, cy - r * 0.96)
    ctx.curve_to(cx + r * 0.42, cy - r * 0.80, cx + r * 0.82, cy - r * 0.72, cx + r * 0.84, cy - r * 0.56)
    ctx.curve_to(cx + r * 0.86, cy + r * 0.14, cx + r * 0.52, cy + r * 0.68, cx, cy + r * 0.98)
    ctx.curve_to(cx - r * 0.52, cy + r * 0.68, cx - r * 0.86, cy + r * 0.14, cx - r * 0.84, cy - r * 0.56)
    ctx.curve_to(cx - r * 0.82, cy - r * 0.72, cx - r * 0.42, cy - r * 0.80, cx, cy - r * 0.96)
    ctx.close_path()


class ProtectionStatusCanvas(Gtk.DrawingArea):
    """Canvas Cairo vetorial (~24 FPS, zero alocações) para o Hero da página inicial."""

    _GREEN_RGB = (0.06, 0.72, 0.50)  # Esmeralda vivo (#10B981)
    _RED_RGB = (0.93, 0.27, 0.27)    # Vermelho alerta (#EF4444)

    def __init__(self) -> None:
        super().__init__()
        self._health: str = "ok"
        self._target_red: float = 0.0
        self._blend_red: float = 0.0
        self._high_contrast: bool = False
        self._active_page: bool = True
        self._phase: float = 0.0
        self._last_tick: float = time.monotonic()
        self._timer_id: int | None = None
        self._settings_sig: int | None = None

        self.set_size_request(210, 178)
        self.set_valign(Gtk.Align.CENTER)
        self.set_halign(Gtk.Align.CENTER)

        self.connect("draw", self._on_draw)
        self.connect("map", lambda *_: self._sync_timer())
        self.connect("unmap", lambda *_: self._stop_timer())
        self.connect("destroy", self._on_destroy)

        settings = Gtk.Settings.get_default()
        if settings is not None:
            self._settings_sig = settings.connect("notify::gtk-enable-animations", lambda *_: self._on_anim_pref_changed())

    def _on_destroy(self, *_args: object) -> None:
        self._stop_timer()
        settings = Gtk.Settings.get_default()
        if settings is not None and self._settings_sig is not None:
            try:
                settings.disconnect(self._settings_sig)
            except Exception:
                pass
            self._settings_sig = None

    def _on_anim_pref_changed(self) -> None:
        self._sync_timer()
        self.queue_draw()

    def set_compact(self, compact: bool) -> None:
        if compact:
            self.set_size_request(116, 104)
        else:
            self.set_size_request(210, 178)

    def set_high_contrast(self, high_contrast: bool) -> None:
        if self._high_contrast != bool(high_contrast):
            self._high_contrast = bool(high_contrast)
            self._sync_timer()
            self.queue_draw()

    def set_active_page(self, active: bool) -> None:
        """Pausa o ticker imediatamente fora da página Início para poupar CPU/GPU."""
        self._active_page = bool(active)
        if self._active_page:
            self._sync_timer()
        else:
            self._stop_timer()

    def set_status(self, health: str) -> None:
        """Atualiza o estado ('ok' verde | 'alert'/'paused' vermelho) com transição suave."""
        new_health = "ok" if health == "ok" else health
        target = 0.0 if new_health == "ok" else 1.0
        changed = (new_health != self._health) or (target != self._target_red)
        self._health = new_health
        self._target_red = target
        if not _animations_enabled():
            self._blend_red = target
        if changed:
            self.queue_draw()

    def _should_animate(self) -> bool:
        return (
            self._active_page
            and self.get_mapped()
            and not self._high_contrast
            and _animations_enabled()
        )

    def _sync_timer(self) -> None:
        if self._should_animate():
            if self._timer_id is None:
                self._last_tick = time.monotonic()
                self._timer_id = GLib.timeout_add(40, self._on_tick)
        else:
            self._stop_timer()

    def _stop_timer(self) -> None:
        if self._timer_id is not None:
            GLib.source_remove(self._timer_id)
            self._timer_id = None

    def _on_tick(self) -> bool:
        if not self._should_animate():
            self._timer_id = None
            return False
        now = time.monotonic()
        dt = min(0.1, max(0.0, now - self._last_tick))
        self._last_tick = now

        speed = 0.42 if self._health == "ok" else 0.72
        self._phase = (self._phase + dt * speed) % 1.0

        # Interpolação suave de cor verde <-> vermelho (~0.35s)
        if abs(self._blend_red - self._target_red) > 0.004:
            step = min(1.0, dt * 3.2)
            self._blend_red = _lerp(self._blend_red, self._target_red, step)
        else:
            self._blend_red = self._target_red

        self.queue_draw()
        return True

    def _on_draw(self, _widget: Gtk.Widget, ctx: cairo.Context) -> bool:
        alloc = self.get_allocation()
        w = max(1, alloc.width)
        h = max(1, alloc.height)
        cx = w * 0.5
        cy = h * 0.5
        min_dim = min(w, h)

        t = self._blend_red if _animations_enabled() else self._target_red
        r = _lerp(self._GREEN_RGB[0], self._RED_RGB[0], t)
        g = _lerp(self._GREEN_RGB[1], self._RED_RGB[1], t)
        b = _lerp(self._GREEN_RGB[2], self._RED_RGB[2], t)

        anim_on = _animations_enabled() and not self._high_contrast
        phase = self._phase if anim_on else 0.18

        # 1. Brilho radial sereno de fundo
        glow_r = min_dim * 0.49
        grad = cairo.RadialGradient(cx, cy, glow_r * 0.08, cx, cy, glow_r)
        grad.add_color_stop_rgba(0.0, r, g, b, 0.24)
        grad.add_color_stop_rgba(0.58, r, g, b, 0.09)
        grad.add_color_stop_rgba(1.0, r, g, b, 0.0)
        ctx.set_source(grad)
        ctx.arc(cx, cy, glow_r, 0.0, math.tau)
        ctx.fill()

        # 2. Três anéis concêntricos com expansão e fade suaves
        shield_r = min_dim * 0.26
        max_ring_r = min_dim * 0.46
        for idx in range(3):
            prog = (phase + idx / 3.0) % 1.0
            ring_r = _lerp(shield_r * 1.06, max_ring_r, prog)
            alpha = (1.0 - prog) ** 1.65 * (0.42 if anim_on else 0.28)
            ctx.set_source_rgba(r, g, b, alpha)
            ctx.set_line_width(max(1.5, min_dim * 0.015))
            ctx.arc(cx, cy, ring_r, 0.0, math.tau)
            ctx.stroke()

        # 3. Anel externo segmentado em rotação sutil
        arc_r = shield_r * 1.38
        rot = phase * math.tau if anim_on else 0.0
        ctx.save()
        ctx.translate(cx, cy)
        ctx.rotate(rot)
        ctx.set_line_cap(cairo.LINE_CAP_ROUND)
        ctx.set_line_width(max(2.0, min_dim * 0.02))
        ctx.set_source_rgba(r, g, b, 0.48)
        for seg in range(4):
            a0 = seg * (math.pi / 2.0) + 0.16
            a1 = a0 + (math.pi / 2.0) - 0.38
            ctx.new_sub_path()
            ctx.arc(0.0, 0.0, arc_r, a0, a1)
        ctx.stroke()
        ctx.restore()

        # 4. Escudo central com respiração leve
        breath = 1.0 + 0.03 * math.sin(phase * math.tau) if anim_on else 1.0
        sr = shield_r * breath

        ctx.save()
        ctx.set_source_rgba(r, g, b, 0.16)
        _draw_shield_path(ctx, cx, cy, sr * 1.13)
        ctx.fill()

        _draw_shield_path(ctx, cx, cy, sr)
        ctx.set_source_rgba(r, g, b, 0.96)
        ctx.fill()

        ctx.set_source_rgba(1.0, 1.0, 1.0, 0.28)
        ctx.set_line_width(max(1.2, sr * 0.06))
        _draw_shield_path(ctx, cx, cy, sr)
        ctx.stroke()

        # 5. Glifo interno branco (check verde | exclamação vermelha)
        ctx.set_source_rgba(1.0, 1.0, 1.0, 0.98)
        ctx.set_line_cap(cairo.LINE_CAP_ROUND)
        ctx.set_line_join(cairo.LINE_JOIN_ROUND)
        if t < 0.5:
            ctx.set_line_width(max(2.6, sr * 0.16))
            ctx.move_to(cx - sr * 0.31, cy + sr * 0.02)
            ctx.line_to(cx - sr * 0.07, cy + sr * 0.27)
            ctx.line_to(cx + sr * 0.34, cy - sr * 0.22)
            ctx.stroke()
        else:
            ctx.set_line_width(max(2.8, sr * 0.17))
            ctx.move_to(cx, cy - sr * 0.34)
            ctx.line_to(cx, cy + sr * 0.08)
            ctx.stroke()
            ctx.arc(cx, cy + sr * 0.31, max(1.8, sr * 0.095), 0.0, math.tau)
            ctx.fill()
        ctx.restore()
        return False

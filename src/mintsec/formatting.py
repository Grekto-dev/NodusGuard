"""Utilitários de formatação de datas locais absolutas e tamanhos."""

from __future__ import annotations

from datetime import datetime, timezone


def now_iso() -> str:
    """Retorna timestamp ISO-8601 no fuso horário local com precisão de segundos."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def parse_timestamp(value: str | datetime | None) -> datetime | None:
    """Converte string ISO-8601 ou datetime para horário local."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return dt.astimezone()


def format_local_datetime(value: str | datetime | None) -> str:
    """Formata data e hora locais absolutas no padrão '21/11/2026 às 14:32'."""
    dt = parse_timestamp(value)
    if dt is None:
        return "Sem registro"
    return f"{dt:%d/%m/%Y} às {dt:%H:%M}"


def format_confirmed_at(value: str | datetime | None) -> str:
    """Formata evidência temporal no padrão 'Confirmado em DD/MM/AAAA às HH:MM'."""
    dt = parse_timestamp(value)
    if dt is None:
        return "Sem confirmação recente"
    return f"Confirmado em {dt:%d/%m/%Y} às {dt:%H:%M}"


def format_bytes(size: int) -> str:
    """Formata quantidade de bytes usando unidades binárias legíveis."""
    if size < 1024:
        return f"{size} B"
    units = ("KiB", "MiB", "GiB", "TiB")
    value = float(size)
    for unit in units:
        value /= 1024.0
        if value < 1024.0 or unit == units[-1]:
            return f"{value:.1f} {unit}".replace(".", ",")
    return f"{size} B"


def utc_now_iso() -> str:
    """Retorna timestamp UTC ISO-8601 para comparações determinísticas."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
